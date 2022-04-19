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

func setupDoc() (string, sglsp.TextDocumentItem) {
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
	return path, sglsp.TextDocumentItem{
		URI:        code.FakeDiagnosticUri,
		LanguageID: "java",
		Version:    0,
	}
}

func Test_RegisterDocument_shouldRegisterDocumentInCache(t *testing.T) {
	registeredDocuments = map[sglsp.DocumentURI]sglsp.TextDocumentItem{}
	path, doc := setupDoc()
	defer os.RemoveAll(path)
	RegisterDocument(doc)
	assert.Equal(t, doc, registeredDocuments[doc.URI])
}

func Test_UnRegisterDocument_shouldDeleteDocumentFromCache(t *testing.T) {
	registeredDocuments = map[sglsp.DocumentURI]sglsp.TextDocumentItem{}
	path, doc := setupDoc()
	defer os.RemoveAll(path)
	RegisterDocument(doc)
	UnRegisterDocument(doc.URI)
	assert.Equal(t, sglsp.TextDocumentItem{}, registeredDocuments[doc.URI])
}

func Test_GetDiagnostics_shouldReturnDiagnosticForCachedFile(t *testing.T) {
	registeredDocuments = map[sglsp.DocumentURI]sglsp.TextDocumentItem{}
	documentDiagnosticCache = map[sglsp.DocumentURI][]lsp.Diagnostic{}
	path, doc := setupDoc()
	defer os.RemoveAll(path)
	RegisterDocument(doc)
	documentDiagnosticCache[doc.URI] = []lsp.Diagnostic{code.FakeDiagnostic}

	diagnostics := GetDiagnostics(doc.URI)

	assert.NotNil(t, diagnostics)
	assert.NotEmpty(t, documentDiagnosticCache[doc.URI])
	assert.Equal(t, len(documentDiagnosticCache[doc.URI]), len(diagnostics))
}

func Test_UpdateDocument_shouldUpdateTextOfDocument(t *testing.T) {
	registeredDocuments = map[sglsp.DocumentURI]sglsp.TextDocumentItem{}
	documentDiagnosticCache = map[sglsp.DocumentURI][]lsp.Diagnostic{}
	path, doc := setupDoc()
	defer os.RemoveAll(path)
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
	path, doc := setupDoc()
	defer os.RemoveAll(path)
	RegisterDocument(doc)
	SnykCode = &code.FakeSnykCodeApiService{}

	diagnostics := GetDiagnostics(doc.URI)

	assert.Equal(t, len(documentDiagnosticCache[doc.URI]), len(diagnostics))
	lenses, _ := GetCodeLenses(doc.URI)
	assert.Equal(t, 1, len(lenses))
}

func Test_GetDiagnostics_shouldNotTryToAnalyseEmptyFiles(t *testing.T) {
	registeredDocuments = map[sglsp.DocumentURI]sglsp.TextDocumentItem{}
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
