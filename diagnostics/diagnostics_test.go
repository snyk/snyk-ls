package diagnostics

import (
	"os"
	"testing"

	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/code"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/lsp"
)

func Test_RegisterDocument_shouldRegisterDocumentInCache(t *testing.T) {
	registeredDocuments = map[sglsp.DocumentURI]bool{}
	diagnosticUri, path := code.FakeDiagnosticUri()
	defer os.RemoveAll(path)
	RegisterDocument(sglsp.TextDocumentItem{URI: diagnosticUri})
	assert.Equal(t, true, registeredDocuments[diagnosticUri])
}

func Test_UnRegisterDocument_shouldDeleteDocumentFromCache(t *testing.T) {
	registeredDocuments = map[sglsp.DocumentURI]bool{}
	diagnosticUri, path := code.FakeDiagnosticUri()
	defer os.RemoveAll(path)
	RegisterDocument(sglsp.TextDocumentItem{URI: diagnosticUri})
	UnRegisterDocument(diagnosticUri)
	assert.Equal(t, false, registeredDocuments[diagnosticUri])
}

func Test_GetDiagnostics_shouldReturnDiagnosticForCachedFile(t *testing.T) {
	registeredDocuments = map[sglsp.DocumentURI]bool{}
	documentDiagnosticCache = map[sglsp.DocumentURI][]lsp.Diagnostic{}
	diagnosticUri, path := code.FakeDiagnosticUri()
	defer os.RemoveAll(path)
	RegisterDocument(sglsp.TextDocumentItem{URI: diagnosticUri})
	documentDiagnosticCache[diagnosticUri] = []lsp.Diagnostic{code.FakeDiagnostic}

	diagnostics := GetDiagnostics(diagnosticUri)

	assert.NotNil(t, diagnostics)
	assert.NotEmpty(t, documentDiagnosticCache[diagnosticUri])
	assert.Equal(t, len(documentDiagnosticCache[diagnosticUri]), len(diagnostics))
}

func Test_UpdateDocument_shouldUpdateTextOfDocument(t *testing.T) {
	registeredDocuments = map[sglsp.DocumentURI]bool{}
	documentDiagnosticCache = map[sglsp.DocumentURI][]lsp.Diagnostic{}
	diagnosticUri, path := code.FakeDiagnosticUri()
	defer os.RemoveAll(path)
	RegisterDocument(sglsp.TextDocumentItem{URI: diagnosticUri})

	change := sglsp.TextDocumentContentChangeEvent{
		Text: "hurz",
	}
	UpdateDocument(diagnosticUri, []sglsp.TextDocumentContentChangeEvent{change})

	assert.Equal(t, true, registeredDocuments[diagnosticUri])
}

func Test_GetDiagnostics_shouldAddCodeLenses(t *testing.T) {
	registeredDocuments = map[sglsp.DocumentURI]bool{}
	documentDiagnosticCache = map[sglsp.DocumentURI][]lsp.Diagnostic{}
	diagnosticUri, path := code.FakeDiagnosticUri()
	defer os.RemoveAll(path)
	RegisterDocument(sglsp.TextDocumentItem{URI: diagnosticUri})
	SnykCode = &code.FakeSnykCodeApiService{}

	diagnostics := GetDiagnostics(diagnosticUri)

	assert.Equal(t, len(documentDiagnosticCache[diagnosticUri]), len(diagnostics))
	lenses, _ := GetCodeLenses(diagnosticUri)
	assert.Equal(t, 1, len(lenses))
}

func Test_GetDiagnostics_shouldNotTryToAnalyseEmptyFiles(t *testing.T) {
	registeredDocuments = map[sglsp.DocumentURI]bool{}
	documentDiagnosticCache = map[sglsp.DocumentURI][]lsp.Diagnostic{}
	empty := sglsp.TextDocumentItem{
		URI:        uri.PathToUri("test123"),
		LanguageID: "java",
		Version:    0,
		Text:       "",
	}
	RegisterDocument(empty)
	SnykCode = &code.FakeSnykCodeApiService{}

	GetDiagnostics(empty.URI)

	// verify that create bundle has NOT been called on backend service
	params := SnykCode.(*code.FakeSnykCodeApiService).GetCallParams(0, code.CreateBundleWithSourceOperation)
	assert.Nil(t, params)
}

func Test_ClearWorkspaceFolderDiagnostics_shouldRemoveDiagnosticsOfAllFilesInFolder(t *testing.T) {
	registeredDocuments = map[sglsp.DocumentURI]bool{}
	documentDiagnosticCache = map[sglsp.DocumentURI][]lsp.Diagnostic{}
	diagnosticUri, path := code.FakeDiagnosticUri()
	defer os.RemoveAll(path)
	RegisterDocument(sglsp.TextDocumentItem{URI: diagnosticUri})
	SnykCode = &code.FakeSnykCodeApiService{}
	diagnostics := GetDiagnostics(diagnosticUri)
	assert.Equal(t, len(documentDiagnosticCache[diagnosticUri]), len(diagnostics))

	ClearWorkspaceFolderDiagnostics(lsp.WorkspaceFolder{Uri: uri.PathToUri(path)})

	assert.Empty(t, documentDiagnosticCache)
}
