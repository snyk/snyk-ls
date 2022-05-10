package code

import (
	"sync"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/lsp"
)

type SnykCode struct {
	BundleUploader *BundleUploader
}

func NewSnykCode(bundleUploader *BundleUploader) *SnykCode {
	return &SnykCode{
		BundleUploader: bundleUploader,
	}
}

func (sc *SnykCode) ScanFile(documentURI sglsp.DocumentURI, p *progress.Tracker, wg *sync.WaitGroup, dChan chan lsp.DiagnosticResult, hoverChan chan lsp.Hover) {
	sc.uploadAndAnalyze([]sglsp.DocumentURI{documentURI}, p, wg, documentURI, dChan, hoverChan)
}

func (sc *SnykCode) ScanWorkspace(documents []sglsp.DocumentURI, documentURI sglsp.DocumentURI, p *progress.Tracker, wg *sync.WaitGroup, dChan chan lsp.DiagnosticResult, hoverChan chan lsp.Hover) {
	sc.uploadAndAnalyze(documents, p, wg, documentURI, dChan, hoverChan)
}

func (sc *SnykCode) uploadAndAnalyze(files []sglsp.DocumentURI, p *progress.Tracker, wg *sync.WaitGroup, documentURI sglsp.DocumentURI, dChan chan lsp.DiagnosticResult, hoverChan chan lsp.Hover) {
	if len(files) == 0 {
		return
	}
	uploadedBundle, err := sc.BundleUploader.Upload(files, func(status UploadStatus) {
		p.Report(20 + uint32((status.UploadedFiles/status.TotalFiles)*50))
	})

	// TODO LSP error handling should be pushed UP to the LSP layer
	if err != nil {
		log.Error().Err(err).Msg("error uploading files...")
		dChan <- lsp.DiagnosticResult{Err: err}
		return
	}

	wg.Add(1)
	uploadedBundle.FetchDiagnosticsData(string(documentURI), wg, dChan, hoverChan)
}

type UploadStatus struct {
	UploadedFiles int
	TotalFiles    int
}
