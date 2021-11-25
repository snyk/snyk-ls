package snyk_code

import (
	"github.com/snyk/snyk-lsp/snyk-code/bundle"
	"github.com/sourcegraph/go-lsp"
)

var (
	registeredDocuments = map[lsp.DocumentURI]lsp.TextDocumentItem{}
	bundleDocuments     = map[lsp.DocumentURI]bundle.File{}
	documentDiagnostics = map[bundle.File][]lsp.Diagnostic{}
	bundleHash          = ""
)

func RegisterDocument(file lsp.TextDocumentItem) lsp.DocumentURI {
	registeredDocuments[file.URI] = file
	return file.URI
}

func UnRegisterDocument(file lsp.DocumentURI) {
	delete(registeredDocuments, file)
}

func getCachedDocument(uri lsp.DocumentURI) lsp.TextDocumentItem {
	return registeredDocuments[uri]
}

func createBundleFromSource(files map[string]bundle.File) string {
	return ""
}

func extendBundleFromSource(files map[string]bundle.File) string {
	return ""
}

func GetDiagnostics(uri lsp.DocumentURI, change []lsp.TextDocumentContentChangeEvent) []lsp.Diagnostic {

	return nil
}
