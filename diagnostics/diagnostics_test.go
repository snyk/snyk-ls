package diagnostics

import (
	"os"
	"testing"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/snyk/snyk-ls/code"
	"github.com/snyk/snyk-ls/config/environment"
	"github.com/snyk/snyk-ls/internal/snyk/cli"
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

func Test_GetDiagnostics_shouldNotRunCodeIfNotEnabled(t *testing.T) {
	// disable snyk code
	_ = os.Setenv(environment.ActivateSnykCodeKey, "false")
	environment.CurrentEnabledProducts = environment.EnabledProductsFromEnv()
	defer os.Clearenv()
	registeredDocuments = map[sglsp.DocumentURI]bool{}
	documentDiagnosticCache = map[sglsp.DocumentURI][]lsp.Diagnostic{}
	diagnosticUri, path := code.FakeDiagnosticUri()
	defer os.RemoveAll(path)
	RegisterDocument(sglsp.TextDocumentItem{URI: diagnosticUri})
	SnykCode = &code.FakeSnykCodeApiService{}

	diagnostics := GetDiagnostics(diagnosticUri)

	assert.Equal(t, len(documentDiagnosticCache[diagnosticUri]), len(diagnostics))
	params := SnykCode.(*code.FakeSnykCodeApiService).GetCallParams(0, code.CreateBundleWithSourceOperation)
	assert.Nil(t, params)
}

func Test_GetDiagnostics_shouldRunCodeIfEnabled(t *testing.T) {
	// disable snyk code
	_ = os.Setenv(environment.ActivateSnykCodeKey, "true")
	environment.CurrentEnabledProducts = environment.EnabledProductsFromEnv()
	defer os.Clearenv()
	registeredDocuments = map[sglsp.DocumentURI]bool{}
	documentDiagnosticCache = map[sglsp.DocumentURI][]lsp.Diagnostic{}
	diagnosticUri, path := code.FakeDiagnosticUri()
	defer os.RemoveAll(path)
	RegisterDocument(sglsp.TextDocumentItem{URI: diagnosticUri})
	SnykCode = &code.FakeSnykCodeApiService{}

	diagnostics := GetDiagnostics(diagnosticUri)

	assert.Equal(t, len(documentDiagnosticCache[diagnosticUri]), len(diagnostics))
	params := SnykCode.(*code.FakeSnykCodeApiService).GetCallParams(0, code.CreateBundleWithSourceOperation)
	assert.NotNil(t, params)
}

type mockCli struct {
	mock.Mock
}

func (m *mockCli) Execute(cmd []string) (resp []byte, err error) {
	args := m.Called(cmd)
	log.Debug().Interface("cmd", cmd).Msg("Using mock CLI")
	return []byte(args.String(0)), args.Error(1)
}

func Test_GetDiagnostics_shouldRunOssIfEnabled(t *testing.T) {
	os.Clearenv()
	_ = os.Setenv(environment.ActivateSnykCodeKey, "false")
	_ = os.Setenv(environment.ActivateSnykIacKey, "false")
	_ = os.Setenv(environment.ActivateSnykOssKey, "true")
	environment.CurrentEnabledProducts = environment.EnabledProductsFromEnv()
	defer os.Clearenv()
	registeredDocuments = map[sglsp.DocumentURI]bool{}
	documentDiagnosticCache = map[sglsp.DocumentURI][]lsp.Diagnostic{}
	documentURI := sglsp.DocumentURI("package.json")
	RegisterDocument(sglsp.TextDocumentItem{URI: documentURI})
	SnykCode = &code.FakeSnykCodeApiService{}
	mockCli := mockCli{}
	Cli = &mockCli
	mockCli.Mock.On("Execute", mock.Anything).Return("test", nil)

	diagnostics := GetDiagnostics(documentURI)

	assert.Equal(t, len(documentDiagnosticCache[documentURI]), len(diagnostics))
	assert.Equal(t, 1, len(mockCli.Calls))
}

func Test_GetDiagnostics_shouldNotRunOssIfNotEnabled(t *testing.T) {
	os.Clearenv()
	_ = os.Setenv(environment.ActivateSnykCodeKey, "false")
	_ = os.Setenv(environment.ActivateSnykIacKey, "false")
	_ = os.Setenv(environment.ActivateSnykOssKey, "false")
	environment.CurrentEnabledProducts = environment.EnabledProductsFromEnv()
	defer os.Clearenv()
	registeredDocuments = map[sglsp.DocumentURI]bool{}
	documentDiagnosticCache = map[sglsp.DocumentURI][]lsp.Diagnostic{}
	documentURI := sglsp.DocumentURI("package.json")
	RegisterDocument(sglsp.TextDocumentItem{URI: documentURI})
	SnykCode = &code.FakeSnykCodeApiService{}
	mockCli := mockCli{}
	Cli = &mockCli
	mockCli.Mock.On("Execute", mock.Anything).Return("test", nil)

	diagnostics := GetDiagnostics(documentURI)

	assert.Equal(t, len(documentDiagnosticCache[documentURI]), len(diagnostics))
	assert.Equal(t, 0, len(mockCli.Calls))
}

func Test_GetDiagnostics_shouldRunIacIfEnabled(t *testing.T) {
	os.Clearenv()
	_ = os.Setenv(environment.ActivateSnykCodeKey, "false")
	_ = os.Setenv(environment.ActivateSnykIacKey, "true")
	_ = os.Setenv(environment.ActivateSnykOssKey, "false")
	environment.CurrentEnabledProducts = environment.EnabledProductsFromEnv()
	defer os.Clearenv()
	registeredDocuments = map[sglsp.DocumentURI]bool{}
	documentDiagnosticCache = map[sglsp.DocumentURI][]lsp.Diagnostic{}
	documentURI := sglsp.DocumentURI("package.json")
	RegisterDocument(sglsp.TextDocumentItem{URI: documentURI})
	SnykCode = &code.FakeSnykCodeApiService{}
	cli.CurrentSettings.AdditionalParameters = []string{"-d", "--all-projects"}
	cli.CurrentSettings.Insecure = true
	cli.CurrentSettings.Endpoint = "asd"
	mockCli := mockCli{}
	Cli = &mockCli
	mockCli.Mock.On("Execute", mock.Anything).Return("test", nil)

	diagnostics := GetDiagnostics(documentURI)

	assert.Equal(t, len(documentDiagnosticCache[documentURI]), len(diagnostics))
	assert.Equal(t, 1, len(mockCli.Calls))
	call := mockCli.Calls[0]
	assert.Contains(t, call.Arguments[0], "--insecure")
	assert.Contains(t, call.Arguments[0], "-d")
	assert.Contains(t, call.Arguments[0], "--all-projects")
	assert.Equal(t, "asd", os.Getenv("SNYK_API"))
}

func Test_GetDiagnostics_shouldNotIacIfNotEnabled(t *testing.T) { // disable snyk code
	_ = os.Setenv(environment.ActivateSnykCodeKey, "false")
	_ = os.Setenv(environment.ActivateSnykIacKey, "false")
	_ = os.Setenv(environment.ActivateSnykOssKey, "false")
	environment.CurrentEnabledProducts = environment.EnabledProductsFromEnv()
	defer os.Clearenv()
	registeredDocuments = map[sglsp.DocumentURI]bool{}
	documentDiagnosticCache = map[sglsp.DocumentURI][]lsp.Diagnostic{}
	documentURI := sglsp.DocumentURI("package.json")
	RegisterDocument(sglsp.TextDocumentItem{URI: documentURI})
	SnykCode = &code.FakeSnykCodeApiService{}
	mockCli := mockCli{}
	Cli = &mockCli
	mockCli.Mock.On("Execute", mock.Anything).Return("test", nil)

	diagnostics := GetDiagnostics(documentURI)

	assert.Equal(t, len(documentDiagnosticCache[documentURI]), len(diagnostics))
	assert.Equal(t, 0, len(mockCli.Calls))
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
