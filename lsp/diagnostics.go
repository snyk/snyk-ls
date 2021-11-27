package lsp

import (
	"github.com/sirupsen/logrus"
	"github.com/snyk/snyk-lsp/code"
	"github.com/snyk/snyk-lsp/iac"
	"github.com/snyk/snyk-lsp/oss"
	"github.com/sourcegraph/go-lsp"
)

var (
	registeredDocuments = map[lsp.DocumentURI]lsp.TextDocumentItem{}
	documentDiagnostics = map[lsp.DocumentURI][]lsp.Diagnostic{}
	myBundle            = code.CodeBundleImpl{}
	initialized         = false
	logger              = logrus.New()
)

func ClearDiagnosticsCache() {
	documentDiagnostics = map[lsp.DocumentURI][]lsp.Diagnostic{}
}

func UpdateDocument(uri lsp.DocumentURI, changes []lsp.TextDocumentContentChangeEvent) {
	file := registeredDocuments[uri]
	for i := range changes {
		change := changes[i]
		file.Text = change.Text
	}
	registeredDocuments[uri] = file
}

func RegisterDocument(file lsp.TextDocumentItem) {
	registeredDocuments[file.URI] = file
}

func UnRegisterDocument(file lsp.DocumentURI) {
	delete(registeredDocuments, file)
}

func GetDiagnostics(uri lsp.DocumentURI, backend code.BackendService) ([]lsp.Diagnostic, error) {
	if !initialized {
		myBundle = code.CodeBundleImpl{Backend: backend}
		initialized = true
	}

	// serve from cache
	diagnosticSlice := documentDiagnostics[uri]
	if len(diagnosticSlice) > 0 {
		return diagnosticSlice, nil
	}

	diagnostics, err := fetch(uri, diagnosticSlice)

	// add all diagnostics to cache
	for uri, diagnosticSlice := range diagnostics {
		documentDiagnostics[uri] = diagnosticSlice
	}
	return documentDiagnostics[uri], err
}

func fetch(uri lsp.DocumentURI, diagnosticSlice []lsp.Diagnostic) (map[lsp.DocumentURI][]lsp.Diagnostic, error) {
	diagnostics, err := myBundle.DiagnosticData(registeredDocuments)
	logError(err, "GetDiagnostics")
	iacDiagnostics, err := iac.HandleFile(uri)
	ossDiagnostics, err := oss.HandleFile(uri)
	logError(err, "GetDiagnostics")
	diagnosticSlice = diagnostics[uri]
	diagnosticSlice = append(diagnosticSlice, iacDiagnostics...)
	diagnosticSlice = append(diagnosticSlice, ossDiagnostics...)
	// add this one in case diagnostics doesn't have anything
	documentDiagnostics[uri] = diagnosticSlice
	return diagnostics, err
}

func logError(err error, method string) {
	if err != nil {
		logger.WithField("method", method).Error(err)
	}
}
