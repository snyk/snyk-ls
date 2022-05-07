package diagnostics

import (
	"context"
	"os"
	"testing"

	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/snyk/snyk-ls/code"
	"github.com/snyk/snyk-ls/config/environment"
	"github.com/snyk/snyk-ls/internal/cli"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/lsp"
)

func Test_RegisterDocument_shouldRegisterDocumentInCache(t *testing.T) {
	ClearRegisteredDocuments()
	diagnosticUri, path := code.FakeDiagnosticUri()
	defer os.RemoveAll(path)
	RegisterDocument(sglsp.TextDocumentItem{URI: diagnosticUri})
	assert.Equal(t, true, registeredDocuments.Get(diagnosticUri))
}

func Test_UnRegisterDocument_shouldDeleteDocumentFromCache(t *testing.T) {
	ClearRegisteredDocuments()
	diagnosticUri, path := code.FakeDiagnosticUri()
	defer os.RemoveAll(path)
	RegisterDocument(sglsp.TextDocumentItem{URI: diagnosticUri})
	UnRegisterDocument(diagnosticUri)
	assert.Nil(t, registeredDocuments.Get(diagnosticUri))
}

func Test_GetDiagnostics_shouldReturnDiagnosticForCachedFile(t *testing.T) {
	ClearRegisteredDocuments()
	ClearEntireDiagnosticsCache()
	diagnosticUri, path := code.FakeDiagnosticUri()
	defer os.RemoveAll(path)
	RegisterDocument(sglsp.TextDocumentItem{URI: diagnosticUri})
	documentDiagnosticCache.Put(diagnosticUri, []lsp.Diagnostic{code.FakeDiagnostic})

	diagnostics := GetDiagnostics(context.Background(), diagnosticUri)

	assert.NotNil(t, diagnostics)
	assert.NotEmpty(t, DocumentDiagnosticsFromCache(diagnosticUri))
	assert.Equal(t, len(DocumentDiagnosticsFromCache(diagnosticUri)), len(diagnostics))
}

func Test_GetDiagnostics_shouldNotRunCodeIfNotEnabled(t *testing.T) {
	// disable snyk code
	t.Setenv(environment.ActivateSnykCodeKey, "false")
	environment.EnabledProductsFromEnv(context.Background())
	ClearRegisteredDocuments()
	ClearEntireDiagnosticsCache()
	diagnosticUri, path := code.FakeDiagnosticUri()
	defer os.RemoveAll(path)
	RegisterDocument(sglsp.TextDocumentItem{URI: diagnosticUri})
	SetSnykCodeService(&code.FakeSnykCodeApiService{})

	diagnostics := GetDiagnostics(context.Background(), diagnosticUri)

	assert.Equal(t, len(DocumentDiagnosticsFromCache(diagnosticUri)), len(diagnostics))
	params := SnykCode().(*code.FakeSnykCodeApiService).GetCallParams(0, code.CreateBundleWithSourceOperation)
	assert.Nil(t, params)
}

func Test_GetDiagnostics_shouldRunCodeIfEnabled(t *testing.T) {
	// disable snyk code
	t.Setenv(environment.ActivateSnykCodeKey, "true")
	environment.EnabledProductsFromEnv(context.Background())
	ClearRegisteredDocuments()
	ClearEntireDiagnosticsCache()
	diagnosticUri, path := code.FakeDiagnosticUri()
	defer os.RemoveAll(path)
	RegisterDocument(sglsp.TextDocumentItem{URI: diagnosticUri})
	SetSnykCodeService(&code.FakeSnykCodeApiService{})

	diagnostics := GetDiagnostics(context.Background(), diagnosticUri)

	assert.Equal(t, len(DocumentDiagnosticsFromCache(diagnosticUri)), len(diagnostics))
	params := SnykCode().(*code.FakeSnykCodeApiService).GetCallParams(0, code.CreateBundleWithSourceOperation)
	assert.NotNil(t, params)
}

type mockCli struct {
	mock.Mock
}

func (m *mockCli) Execute(_ context.Context, cmd []string) (resp []byte, err error) {
	args := m.Called(cmd)
	logger.Debug(context.Background(), "using mock cli")
	return []byte(args.String(0)), args.Error(1)
}

func Test_GetDiagnostics_shouldRunOssIfEnabled(t *testing.T) {
	testutil.CreateDummyProgressListener(t)
	t.Setenv(environment.ActivateSnykCodeKey, "false")
	t.Setenv(environment.ActivateSnykIacKey, "false")
	t.Setenv(environment.ActivateSnykOssKey, "true")
	environment.EnabledProductsFromEnv(context.Background())
	ClearRegisteredDocuments()
	ClearEntireDiagnosticsCache()
	documentURI := sglsp.DocumentURI("package.json")
	RegisterDocument(sglsp.TextDocumentItem{URI: documentURI})
	SetSnykCodeService(&code.FakeSnykCodeApiService{})
	mockCli := mockCli{}
	Cli = &mockCli
	mockCli.Mock.On("Execute", mock.Anything).Return("test", nil)

	diagnostics := GetDiagnostics(context.Background(), documentURI)

	assert.Equal(t, len(DocumentDiagnosticsFromCache(documentURI)), len(diagnostics))
	assert.Equal(t, 1, len(mockCli.Calls))
}

func Test_GetDiagnostics_shouldNotRunOssIfNotEnabled(t *testing.T) {
	t.Setenv(environment.ActivateSnykCodeKey, "false")
	t.Setenv(environment.ActivateSnykIacKey, "false")
	t.Setenv(environment.ActivateSnykOssKey, "false")
	environment.EnabledProductsFromEnv(context.Background())
	ClearRegisteredDocuments()
	ClearEntireDiagnosticsCache()
	documentURI := sglsp.DocumentURI("package.json")
	RegisterDocument(sglsp.TextDocumentItem{URI: documentURI})
	SetSnykCodeService(&code.FakeSnykCodeApiService{})
	mockCli := mockCli{}
	Cli = &mockCli
	mockCli.Mock.On("Execute", mock.Anything).Return("test", nil)

	diagnostics := GetDiagnostics(context.Background(), documentURI)

	assert.Equal(t, len(DocumentDiagnosticsFromCache(documentURI)), len(diagnostics))
	assert.Equal(t, 0, len(mockCli.Calls))
}

func Test_GetDiagnostics_shouldRunIacIfEnabled(t *testing.T) {
	environment.Load()
	t.Setenv(environment.ActivateSnykCodeKey, "false")
	t.Setenv(environment.ActivateSnykIacKey, "true")
	t.Setenv(environment.ActivateSnykOssKey, "false")
	environment.EnabledProductsFromEnv(context.Background())
	ClearRegisteredDocuments()
	ClearEntireDiagnosticsCache()
	documentURI := sglsp.DocumentURI("package.json")
	RegisterDocument(sglsp.TextDocumentItem{URI: documentURI})
	SetSnykCodeService(&code.FakeSnykCodeApiService{})
	cli.CurrentSettings.AdditionalParameters = []string{"-d", "--all-projects"}
	cli.CurrentSettings.Insecure = true
	cli.CurrentSettings.Endpoint = "asd"
	mockCli := mockCli{}
	Cli = &mockCli
	mockCli.Mock.On("Execute", mock.Anything).Return("{}", nil)

	diagnostics := GetDiagnostics(context.Background(), documentURI)

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
	environment.EnabledProductsFromEnv(context.Background())
	ClearRegisteredDocuments()
	ClearEntireDiagnosticsCache()
	documentURI := sglsp.DocumentURI("package.json")
	RegisterDocument(sglsp.TextDocumentItem{URI: documentURI})
	SetSnykCodeService(&code.FakeSnykCodeApiService{})
	mockCli := mockCli{}
	Cli = &mockCli
	mockCli.Mock.On("Execute", mock.Anything).Return("test", nil)

	diagnostics := GetDiagnostics(context.Background(), documentURI)

	assert.Equal(t, len(DocumentDiagnosticsFromCache(documentURI)), len(diagnostics))
	assert.Equal(t, 0, len(mockCli.Calls))
}

func Test_GetDiagnostics_shouldNotTryToAnalyseEmptyFiles(t *testing.T) {
	ClearRegisteredDocuments()
	ClearEntireDiagnosticsCache()
	empty := sglsp.TextDocumentItem{
		URI:        uri.PathToUri("test123"),
		LanguageID: "java",
		Version:    0,
		Text:       "",
	}
	RegisterDocument(empty)
	SetSnykCodeService(&code.FakeSnykCodeApiService{})

	GetDiagnostics(context.Background(), empty.URI)

	// verify that create bundle has NOT been called on backend service
	params := SnykCode().(*code.FakeSnykCodeApiService).GetCallParams(0, code.CreateBundleWithSourceOperation)
	assert.Nil(t, params)
}

func Test_ClearWorkspaceFolderDiagnostics_shouldRemoveDiagnosticsOfAllFilesInFolder(t *testing.T) {
	ClearRegisteredDocuments()
	ClearEntireDiagnosticsCache()
	diagnosticUri, path := code.FakeDiagnosticUri()
	defer os.RemoveAll(path)
	RegisterDocument(sglsp.TextDocumentItem{URI: diagnosticUri})
	SetSnykCodeService(&code.FakeSnykCodeApiService{})
	diagnostics := GetDiagnostics(context.Background(), diagnosticUri)
	assert.Equal(t, len(DocumentDiagnosticsFromCache(diagnosticUri)), len(diagnostics))

	ClearWorkspaceFolderDiagnostics(context.Background(), lsp.WorkspaceFolder{Uri: uri.PathToUri(path)})

	assert.Equal(t, 0, documentDiagnosticCache.Length())
}
