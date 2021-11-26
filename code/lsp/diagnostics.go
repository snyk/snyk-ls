package lsp

import (
	"github.com/snyk/snyk-lsp/code/bundle"
	"github.com/snyk/snyk-lsp/code/interfaces"
	"github.com/sourcegraph/go-lsp"
)

var (
	registeredDocuments = map[lsp.DocumentURI]lsp.TextDocumentItem{}
	documentDiagnostics = map[lsp.DocumentURI][]lsp.Diagnostic{}
	myBundle            = bundle.CodeBundleImpl{}
	initialized         = false
)

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

func GetDiagnostics(uri lsp.DocumentURI, backend interfaces.BackendService) ([]lsp.Diagnostic, error) {
	if !initialized {
		myBundle = bundle.CodeBundleImpl{Backend: backend}
		initialized = true
	}
	diagnostics, err := myBundle.DiagnosticData(registeredDocuments)
	if err != nil {
		return nil, err
	}
	// add all diagnostics to cache
	for uri, diagnosticSlice := range diagnostics {
		documentDiagnostics[uri] = diagnosticSlice
	}
	return diagnostics[uri], err
}
