package code

import (
	"sync"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

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

func (sc *SnykCode) ScanFile(documentURI sglsp.DocumentURI, wg *sync.WaitGroup, dChan chan lsp.DiagnosticResult, hoverChan chan lsp.Hover) {
	sc.uploadAndAnalyze([]sglsp.DocumentURI{documentURI}, wg, documentURI, dChan, hoverChan)
}

func (sc *SnykCode) ScanWorkspace(documents []sglsp.DocumentURI, documentURI sglsp.DocumentURI, wg *sync.WaitGroup, dChan chan lsp.DiagnosticResult, hoverChan chan lsp.Hover) {
	sc.uploadAndAnalyze(documents, wg, documentURI, dChan, hoverChan)
}

func (sc *SnykCode) uploadAndAnalyze(files []sglsp.DocumentURI, wg *sync.WaitGroup, documentURI sglsp.DocumentURI, dChan chan lsp.DiagnosticResult, hoverChan chan lsp.Hover) {
	if len(files) == 0 {
		return
	}
	uploadedBundle, err := sc.BundleUploader.Upload(files)
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
