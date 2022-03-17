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
	registeredDocuments     = map[sglsp.DocumentURI]sglsp.TextDocumentItem{}
	documentDiagnosticCache = map[sglsp.DocumentURI][]lsp.Diagnostic{}
	bundles                 []*code.BundleImpl
	CodeBackend             code.BackendService
)

func ClearDiagnosticsCache(uri sglsp.DocumentURI) {
	documentDiagnosticCache[uri] = []lsp.Diagnostic{}
}

func UpdateDocument(uri sglsp.DocumentURI, changes []sglsp.TextDocumentContentChangeEvent) {
	file := registeredDocuments[uri]
	for i := range changes {
		change := changes[i]
		file.Text = change.Text
	}
	registeredDocuments[uri] = file
}

func RegisterDocument(file sglsp.TextDocumentItem) {
	registeredDocuments[file.URI] = file
}

func UnRegisterDocument(file sglsp.DocumentURI) {
	delete(registeredDocuments, file)
}

func GetDiagnostics(uri sglsp.DocumentURI) []lsp.Diagnostic {
	// serve from cache
	diagnosticSlice := documentDiagnosticCache[uri]
	if len(diagnosticSlice) > 0 {
		return diagnosticSlice
	}

	diagnostics, codeLenses := fetch(uri)

	// add all diagnostics to cache
	for uri := range diagnostics {
		documentDiagnosticCache[uri] = diagnostics[uri]
	}

	// add all code lenses to cache
	for uri := range codeLenses {
		codeLenseCache[uri] = codeLenses[uri]
	}

	return documentDiagnosticCache[uri]
}

func fetch(uri sglsp.DocumentURI) (map[sglsp.DocumentURI][]lsp.Diagnostic, map[sglsp.DocumentURI][]sglsp.CodeLens) {
	log.Debug().Str("method", "fetch").Msg("started.")
	defer log.Debug().Str("method", "fetch").Msg("done.")
	var diagnostics = map[sglsp.DocumentURI][]lsp.Diagnostic{}
	var codeLenses []sglsp.CodeLens

	wg := sync.WaitGroup{}
	dChan := make(chan lsp.DiagnosticResult, len(registeredDocuments))
	clChan := make(chan lsp.CodeLensResult, len(registeredDocuments))

	createBundles(registeredDocuments)
	bundleCount := len(bundles)
	wg.Add(2 + bundleCount)

	for _, myBundle := range bundles {
		go myBundle.DiagnosticData(&wg, dChan, clChan)
	}

	go iac.HandleFile(uri, &wg, dChan, clChan)
	go oss.HandleFile(registeredDocuments[uri], &wg, dChan, clChan)
	wg.Wait()
	log.Debug().Str("method", "fetch").Msg("finished waiting for goroutines.")

	for {
		select {
		case result := <-dChan:
			log.Trace().Str("method", "fetch").Str("uri", string(result.Uri)).Msg("reading diag from chan.")
			logError(result.Err, "fetch")
			diagnostics[result.Uri] = append(diagnostics[result.Uri], result.Diagnostics...)
			documentDiagnosticCache[result.Uri] = diagnostics[result.Uri]
		case result := <-clChan:
			log.Trace().Str("method", "fetch").Str("uri", string(result.Uri)).Msg("reading lens from chan.")
			logError(result.Err, "fetch")
			codeLenses = append(codeLenses, result.CodeLenses...)
			codeLenseCache[result.Uri] = codeLenses
		default: // return results once channels are empty
			log.Debug().Str("method", "fetch").Msg("done reading diags & lenses.")
			return diagnostics, codeLenseCache
		}
	}
}

func createBundles(documents map[sglsp.DocumentURI]sglsp.TextDocumentItem) {
	var bundle *code.BundleImpl
	toAdd := documents
	bundleIndex := len(bundles) - 1
	for len(toAdd) > 0 {
		if bundleIndex == -1 {
			bundle = createBundle()
			log.Debug().Int("bundleCount", bundleIndex).Str("bundle", bundle.BundleHash).Msg("created new bundle")
		} else {
			bundle = bundles[bundleIndex]
			log.Debug().Int("bundleCount", bundleIndex).Str("bundle", bundle.BundleHash).Msg("re-using bundle ")
		}
		toAdd = bundle.AddToBundleDocuments(toAdd).Files
	}
}

func createBundle() *code.BundleImpl {
	bundle := code.BundleImpl{Backend: CodeBackend}
	bundles = append(bundles, &bundle)
	return &bundle
}

func logError(err error, method string) {
	if err != nil {
		log.Err(err).Str("method", method)
	}
}
