package snyk_code

import (
	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_RegisterDocument_shouldRegisterDocumentInCache(t *testing.T) {
	doc := lsp.TextDocumentItem{
		URI:        "/test",
		LanguageID: "java",
		Version:    0,
		Text:       "class",
	}
	assert.Equal(t, doc.URI, RegisterDocument(doc))
}

func Test_RegisterDocument_shouldGetDocumentFromCache(t *testing.T) {
	registeredDocuments = map[lsp.DocumentURI]lsp.TextDocumentItem{}
	doc := lsp.TextDocumentItem{
		URI:        "/test",
		LanguageID: "java",
		Version:    0,
		Text:       "class",
	}
	uri := RegisterDocument(doc)
	assert.Equal(t, doc, getCachedDocument(uri))
}

func Test_UnRegisterDocument_shouldGetDocumentFromCache(t *testing.T) {
	registeredDocuments = map[lsp.DocumentURI]lsp.TextDocumentItem{}
	doc := lsp.TextDocumentItem{
		URI:        "/test",
		LanguageID: "java",
		Version:    0,
		Text:       "class",
	}
	uri := RegisterDocument(doc)
	UnRegisterDocument(uri)
	assert.Equal(t, lsp.TextDocumentItem{}, getCachedDocument(uri))
}

func Test_GetDiagnostics_shouldReturnDiagnosticForCachedFile(t *testing.T) {
	registeredDocuments = map[lsp.DocumentURI]lsp.TextDocumentItem{}
	doc := lsp.TextDocumentItem{
		URI:        "/test",
		LanguageID: "java",
		Version:    0,
		Text:       "class",
	}
	uri := RegisterDocument(doc)
	diagnostics := GetDiagnostics(uri, []lsp.TextDocumentContentChangeEvent{})
	assert.NotNil(t, diagnostics)
}
