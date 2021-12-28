package diagnostics

import (
	"github.com/rs/zerolog/log"
	"github.com/snyk/snyk-lsp/code"
	"github.com/snyk/snyk-lsp/iac"
	"github.com/snyk/snyk-lsp/lsp"
	"github.com/snyk/snyk-lsp/oss"
	sglsp "github.com/sourcegraph/go-lsp"
	"sync"
)

var (
	registeredDocuments     = map[sglsp.DocumentURI]sglsp.TextDocumentItem{}
	documentDiagnosticCache = map[sglsp.DocumentURI][]lsp.Diagnostic{}
	myBundle                *code.BundleImpl
	initialized             = false
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

func GetDiagnostics(uri sglsp.DocumentURI, backend code.BackendService) []lsp.Diagnostic {
	if !initialized {
		myBundle = &code.BundleImpl{Backend: backend}
		initialized = true
	}

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
	dChan := make(chan lsp.DiagnosticResult, 10)
	clChan := make(chan lsp.CodeLensResult, 10)
	wg.Add(3)

	go myBundle.DiagnosticData(registeredDocuments, &wg, dChan, clChan)
	go iac.HandleFile(uri, &wg, dChan, clChan)
	go oss.HandleFile(registeredDocuments[uri], &wg, dChan, clChan)
	wg.Wait()
	log.Debug().Str("method", "fetch").Msg("finished waiting for goroutines.")

	for {
		select {
		case result := <-dChan:
			log.Debug().Str("method", "fetch").Msg("reading diag from chan.")
			logError(result.Err, "fetch")
			diagnostics[result.Uri] = append(diagnostics[result.Uri], result.Diagnostics...)
			documentDiagnosticCache[result.Uri] = diagnostics[result.Uri]
		case result := <-clChan:
			log.Debug().Str("method", "fetch").Msg("reading lens from chan.")
			logError(result.Err, "fetch")
			codeLenses = append(codeLenses, result.CodeLenses...)
			codeLenseCache[result.Uri] = codeLenses
		default: // return results once channels are empty
			log.Debug().Str("method", "fetch").Msg("done reading diags & lenses.")
			return diagnostics, codeLenseCache
		}
	}
}

func logError(err error, method string) {
	if err != nil {
		log.Err(err).Str("method", method)
	}
}
