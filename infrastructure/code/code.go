package code

import (
	"context"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	ux2 "github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/notification"
)

type Scanner struct {
	BundleUploader *BundleUploader
	SnykApiClient  snyk_api.SnykApiClient
	errorReporter  error_reporting.ErrorReporter
	analytics      ux2.Analytics
}

func New(bundleUploader *BundleUploader, apiClient snyk_api.SnykApiClient, reporter error_reporting.ErrorReporter, analytics ux2.Analytics) *Scanner {
	sc := &Scanner{
		BundleUploader: bundleUploader,
		SnykApiClient:  apiClient,
		errorReporter:  reporter,
		analytics:      analytics,
	}
	return sc
}

func (sc *Scanner) IsEnabled() bool {
	return config.CurrentConfig().IsSnykCodeEnabled()
}

func (sc *Scanner) Product() snyk.Product {
	return snyk.ProductCode
}

func (sc *Scanner) Scan(ctx context.Context, _ string, workspacePath string, files []string) []snyk.Issue {
	span := sc.BundleUploader.instrumentor.StartSpan(ctx, "code.ScanWorkspace")
	defer sc.BundleUploader.instrumentor.Finish(span)
	return sc.UploadAndAnalyze(span.Context(), files, workspacePath)
}

func (sc *Scanner) UploadAndAnalyze(ctx context.Context, files []string, path string) (issues []snyk.Issue) {
	span := sc.BundleUploader.instrumentor.StartSpan(ctx, "code.uploadAndAnalyze")
	defer sc.BundleUploader.instrumentor.Finish(span)
	if len(files) == 0 {
		return issues
	}

	if !sc.isSastEnabled() {
		return issues
	}

	requestId := span.GetTraceId() // use span trace id as code-request-id

	bundle, bundleFiles, err := sc.createBundle(span.Context(), requestId, path, files)

	if err != nil {
		msg := "error creating bundle..."
		sc.handleCreationAndUploadError(err, msg)
		return issues
	}

	uploadedBundle, err := sc.BundleUploader.Upload(span.Context(), bundle, bundleFiles)
	// TODO LSP error handling should be pushed UP to the LSP layer
	if err != nil {
		msg := "error uploading files..."
		sc.handleCreationAndUploadError(err, msg)
		return issues
	}
	if uploadedBundle.BundleHash == "" {
		log.Info().Msg("empty bundle, no Snyk Code analysis")
		return issues
	}

	issues = uploadedBundle.FetchDiagnosticsData(span.Context())
	sc.trackResult(true)
	return issues
}

func (sc *Scanner) handleCreationAndUploadError(err error, msg string) {
	log.Error().Err(err).Msg(msg)
	//di.ErrorReporter().CaptureError(err) import cycle
	sc.trackResult(err == nil)
}

func (sc *Scanner) createBundle(ctx context.Context, requestId string, rootPath string, filePaths []string) (b Bundle, bundleFiles map[string]BundleFile, err error) {
	span := sc.BundleUploader.instrumentor.StartSpan(ctx, "code.createBundle")
	defer sc.BundleUploader.instrumentor.Finish(span)
	b = Bundle{
		SnykCode:      sc.BundleUploader.SnykCode,
		instrumentor:  sc.BundleUploader.instrumentor,
		requestId:     requestId,
		rootPath:      rootPath,
		errorReporter: sc.errorReporter,
	}

	fileHashes := make(map[string]string)
	bundleFiles = make(map[string]BundleFile)
	for _, filePath := range filePaths {
		if !sc.BundleUploader.isSupported(span.Context(), filePath) {
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

func (sc *Scanner) isSastEnabled() bool {
	sastEnabled, localCodeEngineEnabled, _, err := sc.SnykApiClient.SastEnabled()
	if err != nil {
		log.Error().Err(err).Str("method", "isSastEnabled").Msg("couldn't get sast enablement")
		sc.errorReporter.CaptureError(err)
		return false
	}
	if !sastEnabled {
		notification.Send(sglsp.ShowMessageParams{Type: sglsp.Warning, Message: "Snyk Code is disabled by your organisation's configuration."})
		return false
	} else {
		if localCodeEngineEnabled {
			notification.Send(sglsp.ShowMessageParams{Type: sglsp.Warning, Message: "Snyk Code is configured to use a Local Code Engine instance. This setup is not yet supported."})
			return false
		}
		return true
	}
}

type UploadStatus struct {
	UploadedFiles int
	TotalFiles    int
}

func (sc *Scanner) trackResult(success bool) {
	var result ux2.Result
	if success {
		result = ux2.Success
	} else {
		result = ux2.Error
	}
	sc.analytics.AnalysisIsReady(ux2.AnalysisIsReadyProperties{
		AnalysisType: ux2.CodeSecurity,
		Result:       result,
	})
}
