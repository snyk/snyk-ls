package diagnostics

import (
	"github.com/sirupsen/logrus"
	"github.com/snyk/snyk-lsp/code"
	"github.com/snyk/snyk-lsp/iac"
	"github.com/snyk/snyk-lsp/lsp"
	"github.com/snyk/snyk-lsp/oss"
	sglsp "github.com/sourcegraph/go-lsp"
)

var (
	registeredDocuments     = map[sglsp.DocumentURI]sglsp.TextDocumentItem{}
	documentDiagnosticCache = map[sglsp.DocumentURI][]lsp.Diagnostic{}
	myBundle                *code.BundleImpl
	initialized             = false
	logger                  = logrus.New()
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

func GetDiagnostics(uri sglsp.DocumentURI, backend code.BackendService) ([]lsp.Diagnostic, error) {
	if !initialized {
		myBundle = &code.BundleImpl{Backend: backend}
		initialized = true
	}

	// serve from cache
	diagnosticSlice := documentDiagnosticCache[uri]
	if len(diagnosticSlice) > 0 {
		return diagnosticSlice, nil
	}

	diagnostics, codeLenses, err := fetch(uri)

	// add all diagnostics to cache
	for uri := range diagnostics {
		documentDiagnosticCache[uri] = diagnostics[uri]
	}

	// add all code lenses to cache
	for uri := range codeLenses {
		codeLenseCache[uri] = codeLenses[uri]
	}

	return documentDiagnosticCache[uri], err
}

func fetch(
	uri sglsp.DocumentURI,
) (
	map[sglsp.DocumentURI][]lsp.Diagnostic,
	map[sglsp.DocumentURI][]sglsp.CodeLens,
	error,
) {
	var diagnostics = map[sglsp.DocumentURI][]lsp.Diagnostic{}
	var codeLenses []sglsp.CodeLens

	// todo: make them run in parallel as go routines
	// waiting group with go routines
	codeDiagnostics, codeCodeLenses, err := myBundle.DiagnosticData(registeredDocuments)
	logError(err, "GetDiagnostics")
	iacDiagnostics, iacCodeLenses, err := iac.HandleFile(uri)
	logError(err, "GetDiagnostics")
	ossDiagnostics, err := oss.HandleFile(registeredDocuments[uri])
	logError(err, "GetDiagnostics")

	mergeDiagnosticsAndAddToCache(uri, codeDiagnostics, iacDiagnostics, ossDiagnostics)
	codeLenses = append(codeCodeLenses[uri], iacCodeLenses...)

	codeLenseCache[uri] = codeLenses
	return diagnostics, codeLenseCache, err
}

func mergeDiagnosticsAndAddToCache(uri sglsp.DocumentURI, codeDiagnostics map[sglsp.DocumentURI][]lsp.Diagnostic, iacDiagnostics []lsp.Diagnostic, ossDiagnostics []lsp.Diagnostic) {
	diagnosticSlice := codeDiagnostics[uri]
	diagnosticSlice = append(diagnosticSlice, iacDiagnostics...)
	diagnosticSlice = append(diagnosticSlice, ossDiagnostics...)
	documentDiagnosticCache[uri] = diagnosticSlice
}

func logError(err error, method string) {
	if err != nil {
		logger.WithField("method", method).Error(err)
	}
}
