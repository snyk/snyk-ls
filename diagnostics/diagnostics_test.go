package diagnostics

import (
	"github.com/snyk/snyk-lsp/code"
	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"testing"
)

var (
	doc = lsp.TextDocumentItem{
		URI:        code.FakeDiagnosticUri,
		LanguageID: "java",
		Version:    0,
		Text:       "public void class",
	}
)

func Test_RegisterDocument_shouldRegisterDocumentInCache(t *testing.T) {
	registeredDocuments = map[lsp.DocumentURI]lsp.TextDocumentItem{}
	RegisterDocument(doc)
	assert.Equal(t, doc, registeredDocuments[doc.URI])
}

func Test_UnRegisterDocument_shouldDeleteDocumentFromCache(t *testing.T) {
	registeredDocuments = map[lsp.DocumentURI]lsp.TextDocumentItem{}
	RegisterDocument(doc)
	UnRegisterDocument(doc.URI)
	assert.Equal(t, lsp.TextDocumentItem{}, registeredDocuments[doc.URI])
}

func Test_GetDiagnostics_shouldReturnDiagnosticForCachedFile(t *testing.T) {
	registeredDocuments = map[lsp.DocumentURI]lsp.TextDocumentItem{}
	documentDiagnostics = map[lsp.DocumentURI][]lsp.Diagnostic{}
	RegisterDocument(doc)

	diagnostics, _ := GetDiagnostics(doc.URI, &code.FakeBackendService{BundleHash: "dummy-hash"})

	assert.NotNil(t, diagnostics)
	assert.NotEmpty(t, documentDiagnostics[doc.URI])
	assert.Equal(t, len(documentDiagnostics[doc.URI]), len(diagnostics))
}

func Test_UpdateDocument_shouldUpdateTextOfDocument(t *testing.T) {
	registeredDocuments = map[lsp.DocumentURI]lsp.TextDocumentItem{}
	documentDiagnostics = map[lsp.DocumentURI][]lsp.Diagnostic{}
	RegisterDocument(doc)

	change := lsp.TextDocumentContentChangeEvent{
		Text: "hurz",
	}
	UpdateDocument(doc.URI, []lsp.TextDocumentContentChangeEvent{change})

	assert.Equal(t, registeredDocuments[doc.URI].Text, change.Text)
}
