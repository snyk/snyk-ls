package lsp

import (
	"github.com/snyk/snyk-lsp/code/bundle"
	"github.com/sourcegraph/go-lsp"
)

var (
	registeredDocuments = map[lsp.DocumentURI]lsp.TextDocumentItem{}
	documentDiagnostics = map[lsp.DocumentURI][]lsp.Diagnostic{}
)

func RegisterDocument(file lsp.TextDocumentItem) lsp.DocumentURI {
	registeredDocuments[file.URI] = file
	return file.URI
}

func UnRegisterDocument(file lsp.DocumentURI) {
	delete(registeredDocuments, file)
}

func GetDiagnostics(uri lsp.DocumentURI, backend bundle.BackendService) []lsp.Diagnostic {
	bundle := bundle.CodeBundleImpl{Backend: backend}
	diagnostics := bundle.DiagnosticData(registeredDocuments)
	// add all diagnostics to cache
	for uri, diagnosticSlice := range diagnostics {
		documentDiagnostics[uri] = diagnosticSlice
	}
	return diagnostics[uri]
}
