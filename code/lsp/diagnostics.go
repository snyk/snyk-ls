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

func GetDiagnostics(uri lsp.DocumentURI) []lsp.Diagnostic {
	diagnostics := bundle.GetDiagnosticData(registeredDocuments)
	for uri, diagnostic := range diagnostics {
		documentDiagnostics[uri] = diagnostic
	}
	return documentDiagnostics[uri]
}
