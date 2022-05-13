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
	"github.com/snyk/snyk-ls/di"
	"github.com/snyk/snyk-ls/internal/cli"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/lsp"
)

func Test_GetDiagnostics_shouldReturnDiagnosticForCachedFile(t *testing.T) {
	ClearEntireDiagnosticsCache()
	diagnosticUri, path := code.FakeDiagnosticUri()
	defer os.RemoveAll(path)
	di.TestInit()
	documentDiagnosticCache.Put(diagnosticUri, []lsp.Diagnostic{code.FakeDiagnostic})

	diagnostics := GetDiagnostics(diagnosticUri)

	assert.NotNil(t, diagnostics)
	assert.NotEmpty(t, DocumentDiagnosticsFromCache(diagnosticUri))
	assert.Equal(t, len(DocumentDiagnosticsFromCache(diagnosticUri)), len(diagnostics))
}

func Test_GetDiagnostics_shouldNotRunCodeIfNotEnabled(t *testing.T) {
	// disable snyk code
	t.Setenv(environment.ActivateSnykCodeKey, "false")
	environment.EnabledProductsFromEnv()
	ClearEntireDiagnosticsCache()
	diagnosticUri, path := code.FakeDiagnosticUri()
	defer os.RemoveAll(path)
	di.TestInit()

	diagnostics := GetDiagnostics(diagnosticUri)

	assert.Equal(t, len(DocumentDiagnosticsFromCache(diagnosticUri)), len(diagnostics))
	params := di.SnykCodeClient.(*code.FakeSnykCodeClient).GetCallParams(0, code.CreateBundleWithSourceOperation)
	assert.Nil(t, params)
}

func Test_GetDiagnostics_shouldRunCodeIfEnabled(t *testing.T) {
	// disable snyk code
	t.Setenv(environment.ActivateSnykCodeKey, "true")
	environment.EnabledProductsFromEnv()
	ClearEntireDiagnosticsCache()
	diagnosticUri, path := code.FakeDiagnosticUri()
	defer os.RemoveAll(path)
	di.TestInit()

	diagnostics := GetDiagnostics(diagnosticUri)

	assert.Equal(t, len(DocumentDiagnosticsFromCache(diagnosticUri)), len(diagnostics))
	params := di.SnykCodeClient.(*code.FakeSnykCodeClient).GetCallParams(0, code.CreateBundleWithSourceOperation)
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
	testutil.CreateDummyProgressListener(t)
	t.Setenv(environment.ActivateSnykCodeKey, "false")
	t.Setenv(environment.ActivateSnykIacKey, "false")
	t.Setenv(environment.ActivateSnykOssKey, "true")
	environment.EnabledProductsFromEnv()
	ClearEntireDiagnosticsCache()
	documentURI := sglsp.DocumentURI("package.json")
	di.TestInit()
	mockCli := mockCli{}
	Cli = &mockCli
	mockCli.Mock.On("Execute", mock.Anything).Return("test", nil)

	diagnostics := GetDiagnostics(documentURI)

	assert.Equal(t, len(DocumentDiagnosticsFromCache(documentURI)), len(diagnostics))
	assert.Equal(t, 1, len(mockCli.Calls))
}

func Test_GetDiagnostics_shouldNotRunOssIfNotEnabled(t *testing.T) {
	t.Setenv(environment.ActivateSnykCodeKey, "false")
	t.Setenv(environment.ActivateSnykIacKey, "false")
	t.Setenv(environment.ActivateSnykOssKey, "false")
	environment.EnabledProductsFromEnv()
	ClearEntireDiagnosticsCache()
	documentURI := sglsp.DocumentURI("package.json")
	di.TestInit()
	mockCli := mockCli{}
	Cli = &mockCli
	mockCli.Mock.On("Execute", mock.Anything).Return("test", nil)

	diagnostics := GetDiagnostics(documentURI)

	assert.Equal(t, len(DocumentDiagnosticsFromCache(documentURI)), len(diagnostics))
	assert.Equal(t, 0, len(mockCli.Calls))
}

func Test_GetDiagnostics_shouldRunIacIfEnabled(t *testing.T) {
	environment.Load()
	t.Setenv(environment.ActivateSnykCodeKey, "false")
	t.Setenv(environment.ActivateSnykIacKey, "true")
	t.Setenv(environment.ActivateSnykOssKey, "false")
	environment.EnabledProductsFromEnv()
	ClearEntireDiagnosticsCache()
	documentURI := sglsp.DocumentURI("package.json")
	di.TestInit()
	cli.CurrentSettings.AdditionalParameters = []string{"-d", "--all-projects"}
	cli.CurrentSettings.Insecure = true
	cli.CurrentSettings.Endpoint = "asd"
	mockCli := mockCli{}
	Cli = &mockCli
	mockCli.Mock.On("Execute", mock.Anything).Return("{}", nil)

	diagnostics := GetDiagnostics(documentURI)

	assert.Equal(t, len(DocumentDiagnosticsFromCache(documentURI)), len(diagnostics))
	assert.Equal(t, 1, len(mockCli.Calls))
	call := mockCli.Calls[0]
	assert.Contains(t, call.Arguments[0], "--insecure")
	assert.Contains(t, call.Arguments[0], "-d")
	assert.Contains(t, call.Arguments[0], "--all-projects")
	assert.Equal(t, "asd", os.Getenv("SNYK_API"))
}

func Test_GetDiagnostics_shouldNotIacIfNotEnabled(t *testing.T) { // disable snyk code
	t.Setenv(environment.ActivateSnykCodeKey, "false")
	t.Setenv(environment.ActivateSnykIacKey, "false")
	t.Setenv(environment.ActivateSnykOssKey, "false")
	environment.EnabledProductsFromEnv()
	ClearEntireDiagnosticsCache()
	documentURI := sglsp.DocumentURI("package.json")
	di.TestInit()
	mockCli := mockCli{}
	Cli = &mockCli
	mockCli.Mock.On("Execute", mock.Anything).Return("test", nil)

	diagnostics := GetDiagnostics(documentURI)

	assert.Equal(t, len(DocumentDiagnosticsFromCache(documentURI)), len(diagnostics))
	assert.Equal(t, 0, len(mockCli.Calls))
}

func Test_GetDiagnostics_shouldNotTryToAnalyseEmptyFiles(t *testing.T) {
	ClearEntireDiagnosticsCache()
	empty := sglsp.TextDocumentItem{
		URI:        uri.PathToUri("test123"),
		LanguageID: "java",
		Version:    0,
		Text:       "",
	}
	di.TestInit()

	GetDiagnostics(empty.URI)

	// verify that create bundle has NOT been called on backend service
	params := di.SnykCodeClient.(*code.FakeSnykCodeClient).GetCallParams(0, code.CreateBundleWithSourceOperation)
	assert.Nil(t, params)
}

func Test_ClearWorkspaceFolderDiagnostics_shouldRemoveDiagnosticsOfAllFilesInFolder(t *testing.T) {
	ClearEntireDiagnosticsCache()
	diagnosticUri, path := code.FakeDiagnosticUri()
	defer os.RemoveAll(path)
	di.TestInit()
	diagnostics := GetDiagnostics(diagnosticUri)
	assert.Equal(t, len(DocumentDiagnosticsFromCache(diagnosticUri)), len(diagnostics))

	ClearWorkspaceFolderDiagnostics(lsp.WorkspaceFolder{Uri: uri.PathToUri(path)})

	assert.Equal(t, 0, documentDiagnosticCache.Length())
}
