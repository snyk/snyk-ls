package diagnostics

import (
	"testing"

	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-lsp/code"
	"github.com/snyk/snyk-lsp/lsp"
)

var (
	doc = sglsp.TextDocumentItem{
		URI:        code.FakeDiagnosticUri,
		LanguageID: "java",
		Version:    0,
		Text:       "public void class",
	}
)

func Test_RegisterDocument_shouldRegisterDocumentInCache(t *testing.T) {
	registeredDocuments = map[sglsp.DocumentURI]sglsp.TextDocumentItem{}
	RegisterDocument(doc)
	assert.Equal(t, doc, registeredDocuments[doc.URI])
}

func Test_UnRegisterDocument_shouldDeleteDocumentFromCache(t *testing.T) {
	registeredDocuments = map[sglsp.DocumentURI]sglsp.TextDocumentItem{}
	RegisterDocument(doc)
	UnRegisterDocument(doc.URI)
	assert.Equal(t, sglsp.TextDocumentItem{}, registeredDocuments[doc.URI])
}

func Test_GetDiagnostics_shouldReturnDiagnosticForCachedFile(t *testing.T) {
	registeredDocuments = map[sglsp.DocumentURI]sglsp.TextDocumentItem{}
	documentDiagnosticCache = map[sglsp.DocumentURI][]lsp.Diagnostic{}
	RegisterDocument(doc)
	documentDiagnosticCache[doc.URI] = []lsp.Diagnostic{code.FakeDiagnostic}

	diagnostics := GetDiagnostics(doc.URI, &code.FakeBackendService{BundleHash: "dummy-hash"})

	assert.NotNil(t, diagnostics)
	assert.NotEmpty(t, documentDiagnosticCache[doc.URI])
	assert.Equal(t, len(documentDiagnosticCache[doc.URI]), len(diagnostics))
}

func Test_UpdateDocument_shouldUpdateTextOfDocument(t *testing.T) {
	registeredDocuments = map[sglsp.DocumentURI]sglsp.TextDocumentItem{}
	documentDiagnosticCache = map[sglsp.DocumentURI][]lsp.Diagnostic{}
	RegisterDocument(doc)

	change := sglsp.TextDocumentContentChangeEvent{
		Text: "hurz",
	}
	UpdateDocument(doc.URI, []sglsp.TextDocumentContentChangeEvent{change})

	assert.Equal(t, registeredDocuments[doc.URI].Text, change.Text)
}

func Test_GetDiagnostics_shouldAddCodeLenses(t *testing.T) {
	registeredDocuments = map[sglsp.DocumentURI]sglsp.TextDocumentItem{}
	documentDiagnosticCache = map[sglsp.DocumentURI][]lsp.Diagnostic{}
	RegisterDocument(doc)

	diagnostics := GetDiagnostics(doc.URI, &code.FakeBackendService{BundleHash: "dummy-hash"})

	assert.Equal(t, len(documentDiagnosticCache[doc.URI]), len(diagnostics))
	lenses, _ := GetCodeLenses(doc.URI)
	assert.Equal(t, 1, len(lenses))
}

func Test_GetDiagnostics_shouldNotTryToAnalyseEmptyFiles(t *testing.T) {
	registeredDocuments = map[sglsp.DocumentURI]sglsp.TextDocumentItem{}
	documentDiagnosticCache = map[sglsp.DocumentURI][]lsp.Diagnostic{}
	backendMock := &code.FakeBackendService{BundleHash: "dummy-hash"}

	empty := sglsp.TextDocumentItem{
		URI:        code.FakeDiagnosticUri,
		LanguageID: "java",
		Version:    0,
		Text:       "",
	}

	RegisterDocument(empty)

	GetDiagnostics(doc.URI, backendMock)

	// verify that create bundle has NOT been called on backend service
	params := backendMock.GetCallParams(0, code.CreateBundleWithSourceOperation)
	assert.Nil(t, params)
}
