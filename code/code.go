package code

import (
	"context"
	"sync"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/observability/ux"
	"github.com/snyk/snyk-ls/lsp"
)

type SnykCode struct {
	BundleUploader *BundleUploader
	SnykApiClient  SnykApiClient
	errorReporter  error_reporting.ErrorReporter
	analytics      ux.Analytics
}

func NewSnykCode(bundleUploader *BundleUploader, apiClient SnykApiClient, reporter error_reporting.ErrorReporter, analytics ux.Analytics) *SnykCode {
	sc := &SnykCode{
		BundleUploader: bundleUploader,
		SnykApiClient:  apiClient,
		errorReporter:  reporter,
		analytics:      analytics,
	}
	return sc
}

func (sc *SnykCode) ScanFile(ctx context.Context, filePath string, wg *sync.WaitGroup, dChan chan lsp.DiagnosticResult, hoverChan chan hover.DocumentHovers) {
	span := sc.BundleUploader.instrumentor.StartSpan(ctx, "code.ScanFile")
	defer sc.BundleUploader.instrumentor.Finish(span)
	sc.UploadAndAnalyze(span.Context(), []string{filePath}, wg, filePath, dChan, hoverChan)
}

func (sc *SnykCode) ScanWorkspace(ctx context.Context, files []string, workspacePath string, wg *sync.WaitGroup, dChan chan lsp.DiagnosticResult, hoverChan chan hover.DocumentHovers) {
	span := sc.BundleUploader.instrumentor.StartSpan(ctx, "code.ScanWorkspace")
	defer sc.BundleUploader.instrumentor.Finish(span)
	sc.UploadAndAnalyze(span.Context(), files, wg, workspacePath, dChan, hoverChan)
}

func (sc *SnykCode) UploadAndAnalyze(ctx context.Context, files []string, wg *sync.WaitGroup, path string, dChan chan lsp.DiagnosticResult, hoverChan chan hover.DocumentHovers) {
	span := sc.BundleUploader.instrumentor.StartSpan(ctx, "code.UploadAndAnalyze")
	defer sc.BundleUploader.instrumentor.Finish(span)
	if len(files) == 0 {
		return
	}

	if !sc.isSastEnabled() {
		return
	}

	requestId := span.GetTraceId() // use span trace id as code-request-id

	bundle, bundleFiles, err := sc.createBundle(span.Context(), requestId, files)

	if err != nil {
		msg := "error creating bundle..."
		sc.handleCreationAndUploadError(err, msg, dChan)
		return
	}

	uploadedBundle, err := sc.BundleUploader.Upload(ctx, bundle, bundleFiles)
	// TODO LSP error handling should be pushed UP to the LSP layer
	if err != nil {
		msg := "error uploading files..."
		sc.handleCreationAndUploadError(err, msg, dChan)
		return
	}
	if uploadedBundle.BundleHash == "" {
		log.Info().Msg("empty bundle, no Snyk Code analysis")
		return
	}

	wg.Add(1)
	uploadedBundle.FetchDiagnosticsData(ctx, path, wg, dChan, hoverChan)
	sc.trackResult(true)
}

func (sc *SnykCode) handleCreationAndUploadError(err error, msg string, dChan chan lsp.DiagnosticResult) {
	log.Error().Err(err).Msg(msg)
	dChan <- lsp.DiagnosticResult{Err: err}
	sc.trackResult(err == nil)
	return
}

func (sc *SnykCode) createBundle(ctx context.Context, requestId string, filePaths []string) (b Bundle, bundleFiles map[string]BundleFile, err error) {
	span := sc.BundleUploader.instrumentor.StartSpan(ctx, "code.createBundle")
	defer sc.BundleUploader.instrumentor.Finish(span)
	b = Bundle{
		SnykCode:     sc.BundleUploader.SnykCode,
		instrumentor: sc.BundleUploader.instrumentor,
		requestId:    requestId,
	}

	fileHashes := make(map[string]string)
	bundleFiles = make(map[string]BundleFile)
	for _, filePath := range filePaths {
		if !sc.BundleUploader.isSupported(ctx, filePath) {
			continue
		}
		fileContent, err := loadContent(filePath)
		if err != nil {
			log.Error().Err(err).Str("filePath", filePath).Msg("could not load content of file")
			continue
		}

		if !(len(fileContent) > 0 && len(fileContent) <= maxFileSize) {
			continue
		}
		file := getFileFrom(filePath, fileContent)
		bundleFiles[filePath] = file
		fileHashes[filePath] = file.Hash
	}
	b.BundleHash, b.missingFiles, err = sc.BundleUploader.SnykCode.CreateBundle(span.Context(), fileHashes)
	return b, bundleFiles, err
}

func (sc *SnykCode) isSastEnabled() bool {
	sastEnabled, localCodeEngineEnabled, _, err := sc.SnykApiClient.SastEnabled()
	if err != nil {
		log.Error().Err(err).Str("method", "isSastEnabled").Msg("couldn't get sast enablement")
		sc.errorReporter.CaptureError(err)
		return false
	}
	if !sastEnabled {
		notification.Send(sglsp.ShowMessageParams{Message: "Snyk Code is disabled by your organisation's configuration."})
		return false
	} else {
		if localCodeEngineEnabled {
			notification.Send(sglsp.ShowMessageParams{Message: "Snyk Code is configured to use a Local Code Engine instance. This setup is not yet supported."})
			return false
		}
		return true
	}
}

type UploadStatus struct {
	UploadedFiles int
	TotalFiles    int
}

func (sc *SnykCode) trackResult(success bool) {
	var result ux.Result
	if success {
		result = ux.Success
	} else {
		result = ux.Error
	}
	sc.analytics.AnalysisIsReady(ux.AnalysisIsReadyProperties{
		AnalysisType: ux.CodeSecurity,
		Result:       result,
	})
}
