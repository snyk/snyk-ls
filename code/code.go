package code

import (
	"github.com/rs/zerolog/log"
	"github.com/snyk/snyk-ls/internal/concurrency"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/lsp"
	sglsp "github.com/sourcegraph/go-lsp"
	"path/filepath"
	"sync"
)

//TODO
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

func ScanFile(documentURI sglsp.DocumentURI, wg *sync.WaitGroup, dChan chan lsp.DiagnosticResult, hoverChan chan lsp.Hover) {
	var bundles = make([]*BundleImpl, 0, 10)
	var bundleDocs = map[sglsp.DocumentURI]bool{}
	bundleDocs[documentURI] = true
	BundlerThatNeedsToBecomeAProp.createOrExtendBundles(bundleDocs, &bundles)
	wg.Add(1)
	go bundles[0].FetchDiagnosticsData(string(documentURI), wg, dChan, hoverChan)
}

func ScanWorkspace(documentRegistry *concurrency.AtomicMap, documentURI sglsp.DocumentURI, wg *sync.WaitGroup, dChan chan lsp.DiagnosticResult, hoverChan chan lsp.Hover) {
	var bundles = make([]*BundleImpl, 0, 10)
	var bundleDocs = toDocumentURIMap(documentRegistry)
	BundlerThatNeedsToBecomeAProp.createOrExtendBundles(bundleDocs, &bundles)
	for _, myBundle := range bundles {
		wg.Add(1)
		go myBundle.FetchDiagnosticsData(string(documentURI), wg, dChan, hoverChan)
	}
}
