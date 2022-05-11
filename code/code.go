package code

import (
	"github.com/rs/zerolog/log"
	"github.com/snyk/snyk-ls/internal/concurrency"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/lsp"
	sglsp "github.com/sourcegraph/go-lsp"
	"path/filepath"
	"sync"
)

//TODO turn into type/prop
var BundlerThatNeedsToBecomeAProp Bundler

var (
	supportedExtensions = concurrency.AtomicMap{}
)

func IsSupported(service SnykCodeService, documentURI sglsp.DocumentURI) bool {
	if supportedExtensions.Length() == 0 {
		// query
		_, exts, err := service.GetFilters()
		if err != nil {
			log.Error().Err(err).Msg("could not get filters")
			return false
		}

		// cache
		for _, ext := range exts {
			supportedExtensions.Put(ext, true)
		}
	}

	supported := supportedExtensions.Get(filepath.Ext(uri.PathFromUri(documentURI)))

	return supported != nil && supported.(bool)
}

func ScanFile(documentURI sglsp.DocumentURI, p *progress.Tracker, wg *sync.WaitGroup, dChan chan lsp.DiagnosticResult, hoverChan chan lsp.Hover) {
	uploadAndAnalyze([]sglsp.DocumentURI{documentURI}, p, wg, documentURI, dChan, hoverChan)
}

// TODO remove documentRegistry, use root path instead
func ScanWorkspace(documentRegistry *concurrency.AtomicMap, documentURI sglsp.DocumentURI, p *progress.Tracker, wg *sync.WaitGroup, dChan chan lsp.DiagnosticResult, hoverChan chan lsp.Hover) {
	uploadAndAnalyze(toDocumentsURI(documentRegistry), p, wg, documentURI, dChan, hoverChan)
}

func uploadAndAnalyze(files []sglsp.DocumentURI, p *progress.Tracker, wg *sync.WaitGroup, documentURI sglsp.DocumentURI, dChan chan lsp.DiagnosticResult, hoverChan chan lsp.Hover) {
	uploadedBundle, err := BundlerThatNeedsToBecomeAProp.UploadFiles(files, func(status UploadStatus) {
		p.Report(uint32((status.UploadedFiles / status.TotalFiles) * 50))
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
