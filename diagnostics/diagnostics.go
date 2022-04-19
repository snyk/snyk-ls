package diagnostics

import (
	"sync"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/code"
	"github.com/snyk/snyk-ls/iac"
	"github.com/snyk/snyk-ls/lsp"
	"github.com/snyk/snyk-ls/oss"
)

var (
	registeredDocuments     = map[sglsp.DocumentURI]bool{}
	documentDiagnosticCache = map[sglsp.DocumentURI][]lsp.Diagnostic{}
	SnykCode                code.SnykCodeService
)

func ClearDiagnosticsCache(uri sglsp.DocumentURI) {
	delete(documentDiagnosticCache, uri)
}

func ClearEntireDiagnosticsCache() {
	documentDiagnosticCache = map[sglsp.DocumentURI][]lsp.Diagnostic{}
}

func ClearRegisteredDocuments() {
	registeredDocuments = map[sglsp.DocumentURI]bool{}
}

func UpdateDocument(uri sglsp.DocumentURI, changes []sglsp.TextDocumentContentChangeEvent) {
	// don't do anything but update registered to true
	registeredDocuments[uri] = true
}

func RegisterDocument(file sglsp.TextDocumentItem) {
	registeredDocuments[file.URI] = true
}

func UnRegisterDocument(file sglsp.DocumentURI) {
	delete(registeredDocuments, file)
}

func GetDiagnostics(uri sglsp.DocumentURI) []lsp.Diagnostic {
	// serve from cache
	diagnosticSlice := documentDiagnosticCache[uri]
	if len(diagnosticSlice) > 0 {
		log.Info().Str("method", "GetDiagnostics").
			Msgf("Cached: Diagnostics for %s", uri)

		return diagnosticSlice
	}

	var diagnostics map[sglsp.DocumentURI][]lsp.Diagnostic
	var codeLenses map[sglsp.DocumentURI][]sglsp.CodeLens

	diagnostics, codeLenses = fetchAllRegisteredDocumentDiagnostics(uri, lsp.ScanLevelFile)
	addToCache(diagnostics, codeLenses)

	return documentDiagnosticCache[uri]
}

func fetchAllRegisteredDocumentDiagnostics(uri sglsp.DocumentURI, level lsp.ScanLevel) (map[sglsp.DocumentURI][]lsp.Diagnostic, map[sglsp.DocumentURI][]sglsp.CodeLens) {
	log.Info().
		Str("method", "fetchAllRegisteredDocumentDiagnostics").
		Msg("started.")

	defer log.Info().
		Str("method", "fetchAllRegisteredDocumentDiagnostics").
		Msg("done.")

	var diagnostics = map[sglsp.DocumentURI][]lsp.Diagnostic{}
	var codeLenses []sglsp.CodeLens
	var bundles = make([]*code.BundleImpl, 0, 10)

	var bundleDocs = map[sglsp.DocumentURI]bool{}
	if level == lsp.ScanLevelFile {
		bundleDocs[uri] = true
	} else {
		registeredDocsMutex.Lock()
		bundleDocs = registeredDocuments
		registeredDocsMutex.Unlock()
	}

	// we need a pointer to the array of bundle pointers to be able to grow it

	createOrExtendBundles(bundleDocs, &bundles)

	wg := sync.WaitGroup{}
	bundleCount := len(bundles)
	wg.Add(2 + bundleCount)

	dChan := make(chan lsp.DiagnosticResult, 10)
	clChan := make(chan lsp.CodeLensResult, 10)

	for _, myBundle := range bundles {
		go myBundle.FetchDiagnosticsData(string(uri), &wg, dChan, clChan)
	}

	if level == lsp.ScanLevelWorkspace {
		go iac.ScanWorkspace(uri, &wg, dChan, clChan)
		go oss.ScanWorkspace(uri, &wg, dChan, clChan)
	} else {
		go iac.ScanFile(uri, &wg, dChan, clChan)
		go oss.ScanFile(uri, &wg, dChan, clChan)
	}

	wg.Wait()
	log.Debug().
		Str("method", "fetchAllRegisteredDocumentDiagnostics").
		Msg("finished waiting for goroutines.")

	return processResults(dChan, diagnostics, clChan, codeLenses)
}

func processResults(
	dChan chan lsp.DiagnosticResult,
	diagnostics map[sglsp.DocumentURI][]lsp.Diagnostic,
	clChan chan lsp.CodeLensResult,
	codeLenses []sglsp.CodeLens,
) (
	map[sglsp.DocumentURI][]lsp.Diagnostic,
	map[sglsp.DocumentURI][]sglsp.CodeLens,
) {
	for {
		select {
		case result := <-dChan:
			log.Trace().
				Str("method", "fetchAllRegisteredDocumentDiagnostics").
				Str("uri", string(result.Uri)).
				Msg("reading diag from chan.")

			logError(result.Err, "fetchAllRegisteredDocumentDiagnostics")

			diagnostics[result.Uri] = append(diagnostics[result.Uri], result.Diagnostics...)
			documentDiagnosticCache[result.Uri] = diagnostics[result.Uri]

		case result := <-clChan:
			log.Trace().
				Str("method", "fetchAllRegisteredDocumentDiagnostics").
				Str("uri", string(result.Uri)).
				Msg("reading lens from chan.")

			logError(result.Err, "fetchAllRegisteredDocumentDiagnostics")

			codeLenses = append(codeLenses, result.CodeLenses...)
			codeLenseCache[result.Uri] = codeLenses

		default: // return results once channels are empty
			log.Debug().
				Str("method", "fetchAllRegisteredDocumentDiagnostics").
				Msg("done reading diags & lenses.")

			return diagnostics, codeLenseCache
		}
	}
}

func createOrExtendBundles(documents map[sglsp.DocumentURI]bool, bundles *[]*code.BundleImpl) {
	// we need a pointer to the array of bundle pointers to be able to grow it
	log.Debug().Str("method", "createOrExtendBundles").Msg("started")
	defer log.Debug().Str("method", "createOrExtendBundles").Msg("done")
	var bundle *code.BundleImpl
	toAdd := documents
	bundleIndex := len(*bundles) - 1
	var bundleFull bool
	for len(toAdd) > 0 {
		if bundleIndex == -1 || bundleFull {
			bundle = createBundle(bundles)
			log.Debug().Int("bundleCount", len(*bundles)).Str("bundle", bundle.BundleHash).Msg("created new bundle")
		} else {
			bundle = (*bundles)[bundleIndex]
			log.Debug().Int("bundleCount", len(*bundles)).Str("bundle", bundle.BundleHash).Msg("re-using bundle ")
		}
		toAdd = bundle.AddToBundleDocuments(toAdd).Files
		if len(toAdd) > 0 {
			bundleFull = true
		}
	}
}

func createBundle(bundles *[]*code.BundleImpl) *code.BundleImpl {
	bundle := code.BundleImpl{SnykCode: SnykCode}
	*bundles = append(*bundles, &bundle)
	return &bundle
}

func addToCache(diagnostics map[sglsp.DocumentURI][]lsp.Diagnostic, codeLenses map[sglsp.DocumentURI][]sglsp.CodeLens) {
	// add all diagnostics to cache
	for uri := range diagnostics {
		documentDiagnosticCache[uri] = diagnostics[uri]
	}

	// add all code lenses to cache
	for uri := range codeLenses {
		codeLenseCache[uri] = codeLenses[uri]
	}
}

func logError(err error, method string) {
	if err != nil {
		log.Err(err).Str("method", method)
	}
}
