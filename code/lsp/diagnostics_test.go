package lsp

import (
	"github.com/snyk/snyk-lsp/code/bundle"
	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"testing"
)

var (
	doc = lsp.TextDocumentItem{
		URI:        bundle.DummyUri,
		LanguageID: "java",
		Version:    0,
		Text:       "public void class",
	}
)

func Test_RegisterDocument_shouldRegisterDocumentInCache(t *testing.T) {
	assert.Equal(t, doc.URI, RegisterDocument(doc))
}

func Test_RegisterDocument_shouldGetDocumentFromCache(t *testing.T) {
	registeredDocuments = map[lsp.DocumentURI]lsp.TextDocumentItem{}
	uri := RegisterDocument(doc)
	assert.Equal(t, doc, registeredDocuments[uri])
}

func Test_UnRegisterDocument_shouldDeleteDocumentFromCache(t *testing.T) {
	registeredDocuments = map[lsp.DocumentURI]lsp.TextDocumentItem{}
	uri := RegisterDocument(doc)
	UnRegisterDocument(uri)
	assert.Equal(t, lsp.TextDocumentItem{}, registeredDocuments[uri])
}

func Test_GetDiagnostics_shouldReturnDiagnosticForCachedFile(t *testing.T) {
	registeredDocuments = map[lsp.DocumentURI]lsp.TextDocumentItem{}
	documentDiagnostics = map[lsp.DocumentURI][]lsp.Diagnostic{}
	uri := RegisterDocument(doc)

	diagnostics := GetDiagnostics(uri, &bundle.FakeBackendService{BundleHash: "dummy-hash"})

	assert.NotNil(t, diagnostics)
	assert.NotEmpty(t, documentDiagnostics[uri])
	assert.Equal(t, len(documentDiagnostics[uri]), len(diagnostics))
}
