package diagnostics

import (
	"os"
	"testing"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/code"
	"github.com/snyk/snyk-ls/lsp"
)

func setupDoc() (string, sglsp.DocumentURI) {
	path, err := os.MkdirTemp(os.TempDir(), "fakeDiagnosticsCodeTest")
	if err != nil {
		log.Fatal().Err(err).Msg("Couldn't create test directory")
	}
	var filePath = path + string(os.PathSeparator) + "faketest.java"
	err = os.WriteFile(filePath, []byte("public void class"), 0600)
	if err != nil {
		os.RemoveAll(path)
		log.Fatal().Err(err).Msg("Couldn't create test file")
	}
	code.FakeDiagnosticUri = sglsp.DocumentURI("file://" + filePath)
	return path, code.FakeDiagnosticUri
}

func Test_RegisterDocument_shouldRegisterDocumentInCache(t *testing.T) {
	registeredDocuments = map[sglsp.DocumentURI]bool{}
	path, uri := setupDoc()
	defer os.RemoveAll(path)
	RegisterDocument(sglsp.TextDocumentItem{URI: uri})
	assert.Equal(t, true, registeredDocuments[uri])
}

func Test_UnRegisterDocument_shouldDeleteDocumentFromCache(t *testing.T) {
	registeredDocuments = map[sglsp.DocumentURI]bool{}
	path, uri := setupDoc()
	defer os.RemoveAll(path)
	RegisterDocument(sglsp.TextDocumentItem{URI: uri})
	UnRegisterDocument(uri)
	assert.Equal(t, false, registeredDocuments[uri])
}

func Test_GetDiagnostics_shouldReturnDiagnosticForCachedFile(t *testing.T) {
	registeredDocuments = map[sglsp.DocumentURI]bool{}
	documentDiagnosticCache = map[sglsp.DocumentURI][]lsp.Diagnostic{}
	path, uri := setupDoc()
	defer os.RemoveAll(path)
	RegisterDocument(sglsp.TextDocumentItem{URI: uri})
	documentDiagnosticCache[uri] = []lsp.Diagnostic{code.FakeDiagnostic}

	diagnostics := GetDiagnostics(uri)

	assert.NotNil(t, diagnostics)
	assert.NotEmpty(t, documentDiagnosticCache[uri])
	assert.Equal(t, len(documentDiagnosticCache[uri]), len(diagnostics))
}

func Test_UpdateDocument_shouldUpdateTextOfDocument(t *testing.T) {
	registeredDocuments = map[sglsp.DocumentURI]bool{}
	documentDiagnosticCache = map[sglsp.DocumentURI][]lsp.Diagnostic{}
	path, uri := setupDoc()
	defer os.RemoveAll(path)
	RegisterDocument(sglsp.TextDocumentItem{URI: uri})

	change := sglsp.TextDocumentContentChangeEvent{
		Text: "hurz",
	}
	UpdateDocument(uri, []sglsp.TextDocumentContentChangeEvent{change})

	assert.Equal(t, true, registeredDocuments[uri])
}

func Test_GetDiagnostics_shouldAddCodeLenses(t *testing.T) {
	registeredDocuments = map[sglsp.DocumentURI]bool{}
	documentDiagnosticCache = map[sglsp.DocumentURI][]lsp.Diagnostic{}
	path, uri := setupDoc()
	defer os.RemoveAll(path)
	RegisterDocument(sglsp.TextDocumentItem{URI: uri})
	SnykCode = &code.FakeSnykCodeApiService{}

	diagnostics := GetDiagnostics(uri)

	assert.Equal(t, len(documentDiagnosticCache[uri]), len(diagnostics))
	lenses, _ := GetCodeLenses(uri)
	assert.Equal(t, 1, len(lenses))
}

func Test_GetDiagnostics_shouldNotTryToAnalyseEmptyFiles(t *testing.T) {
	registeredDocuments = map[sglsp.DocumentURI]bool{}
	documentDiagnosticCache = map[sglsp.DocumentURI][]lsp.Diagnostic{}

	empty := sglsp.TextDocumentItem{
		URI:        code.FakeDiagnosticUri,
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
