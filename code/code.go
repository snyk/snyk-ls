package code

import (
	"context"
	"sync"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

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

func (sc *SnykCode) ScanFile(ctx context.Context, documentURI sglsp.DocumentURI, wg *sync.WaitGroup, dChan chan lsp.DiagnosticResult, hoverChan chan lsp.Hover) {
	span := sc.BundleUploader.instrumentor.StartSpan(ctx, "code.ScanFile")
	defer sc.BundleUploader.instrumentor.Finish(span)
	sc.UploadAndAnalyze(span.Context(), []sglsp.DocumentURI{documentURI}, wg, documentURI, dChan, hoverChan)
}

func (sc *SnykCode) ScanWorkspace(ctx context.Context, documents []sglsp.DocumentURI, documentURI sglsp.DocumentURI, wg *sync.WaitGroup, dChan chan lsp.DiagnosticResult, hoverChan chan lsp.Hover) {
	span := sc.BundleUploader.instrumentor.StartSpan(ctx, "code.ScanWorkspace")
	defer sc.BundleUploader.instrumentor.Finish(span)
	sc.UploadAndAnalyze(span.Context(), documents, wg, documentURI, dChan, hoverChan)
}

func (sc *SnykCode) UploadAndAnalyze(ctx context.Context, files []sglsp.DocumentURI, wg *sync.WaitGroup, documentURI sglsp.DocumentURI, dChan chan lsp.DiagnosticResult, hoverChan chan lsp.Hover) {
	if len(files) == 0 {
		return
	}

	if !sc.isSastEnabled() {
		return
	}

	uploadedBundle, err := sc.BundleUploader.Upload(ctx, files)
	// TODO LSP error handling should be pushed UP to the LSP layer
	if err != nil {
		log.Error().Err(err).Msg("error uploading files...")
		dChan <- lsp.DiagnosticResult{Err: err}
		sc.trackResult(err == nil)
		return
	}
	if uploadedBundle.BundleHash == "" {
		log.Info().Msg("empty bundle, no Snyk Code analysis")
		return
	}

	wg.Add(1)
	uploadedBundle.FetchDiagnosticsData(ctx, string(documentURI), wg, dChan, hoverChan)
	sc.trackResult(true)
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
