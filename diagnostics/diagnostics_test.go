package diagnostics

import (
	"context"
	"os"
	"testing"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/snyk/snyk-ls/code"
	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/di"
	"github.com/snyk/snyk-ls/internal/observability/instrumentation"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/lsp"
)

func Test_GetDiagnostics_shouldReturnDiagnosticForCachedFile(t *testing.T) {
	testutil.UnitTest(t)
	ClearEntireDiagnosticsCache()
	diagnosticUri, path := code.FakeDiagnosticUri()
	defer os.RemoveAll(path)
	di.TestInit(t)
	documentDiagnosticCache.Put(diagnosticUri, []lsp.Diagnostic{code.FakeDiagnostic})

	diagnostics := GetDiagnostics(context.Background(), diagnosticUri)

	assert.NotNil(t, diagnostics)
	assert.NotEmpty(t, DocumentDiagnosticsFromCache(diagnosticUri))
	assert.Equal(t, len(DocumentDiagnosticsFromCache(diagnosticUri)), len(diagnostics))
	recorder := &di.Instrumentor().(*instrumentation.TestInstrumentor).SpanRecorder
	spans := recorder.Spans()
	assert.Len(t, spans, 1)
	assert.Equal(t, "GetDiagnostics", spans[0].GetOperation())
	assert.Equal(t, "GetDiagnostics", spans[0].GetTxName())
}

func Test_GetDiagnostics_shouldNotRunCodeIfNotEnabled(t *testing.T) {
	testutil.UnitTest(t)
	di.TestInit(t)
	config.CurrentConfig().SetSnykCodeEnabled(false)
	ClearEntireDiagnosticsCache()
	diagnosticUri, path := code.FakeDiagnosticUri()
	defer os.RemoveAll(path)

	diagnostics := GetDiagnostics(context.Background(), diagnosticUri)

	assert.Equal(t, len(DocumentDiagnosticsFromCache(diagnosticUri)), len(diagnostics))
	params := di.SnykCodeClient.(*code.FakeSnykCodeClient).GetCallParams(0, code.CreateBundleWithSourceOperation)
	assert.Nil(t, params)
}

func Test_GetDiagnostics_shouldNotRunCodeIfNotSastEnabled(t *testing.T) {
	testutil.UnitTest(t)
	di.TestInit(t)
	config.CurrentConfig().SetSnykCodeEnabled(true)
	ClearEntireDiagnosticsCache()
	diagnosticUri, path := code.FakeDiagnosticUri()
	defer os.RemoveAll(path)
	fakeApiClient := di.SnykCode.SnykApiClient.(*code.FakeApiClient)
	fakeApiClient.CodeEnabled = false

	diagnostics := GetDiagnostics(context.Background(), diagnosticUri)

	assert.Equal(t, len(DocumentDiagnosticsFromCache(diagnosticUri)), len(diagnostics))
	assert.Len(t, fakeApiClient.GetAllCalls(code.SastEnabledOperation), 1)
	assert.Len(t, di.SnykCodeClient.(*code.FakeSnykCodeClient).GetAllCalls(code.CreateBundleWithSourceOperation), 0)
}

func Test_GetDiagnostics_shouldRunCodeIfEnabled(t *testing.T) {
	testutil.UnitTest(t)
	di.TestInit(t)
	config.CurrentConfig().SetSnykCodeEnabled(true)
	ClearEntireDiagnosticsCache()
	diagnosticUri, path := code.FakeDiagnosticUri()
	defer os.RemoveAll(path)

	diagnostics := GetDiagnostics(context.Background(), diagnosticUri)

	assert.Equal(t, len(DocumentDiagnosticsFromCache(diagnosticUri)), len(diagnostics))
	params := di.SnykCodeClient.(*code.FakeSnykCodeClient).GetCallParams(0, code.CreateBundleWithSourceOperation)
	assert.NotNil(t, params)
}

type mockCli struct {
	mock.Mock
}

func (m *mockCli) Execute(cmd []string, workDir string) (resp []byte, err error) {
	args := m.Called(cmd, workDir)
	log.Debug().Interface("cmd", cmd).Msg("Using mock CLI")
	return []byte(args.String(0)), args.Error(1)
}

func Test_GetDiagnostics_shouldRunOssIfEnabled(t *testing.T) {
	testutil.CreateDummyProgressListener(t)
	testutil.UnitTest(t)
	di.TestInit(t)
	ClearEntireDiagnosticsCache()
	config.CurrentConfig().SetSnykCodeEnabled(false)
	config.CurrentConfig().SetSnykIacEnabled(false)
	config.CurrentConfig().SetSnykOssEnabled(true)
	documentURI := sglsp.DocumentURI("package.json")
	mockCli := mockCli{}
	Cli = &mockCli
	mockCli.Mock.On("Execute", mock.Anything, mock.Anything).Return("test", nil)

	diagnostics := GetDiagnostics(context.Background(), documentURI)

	assert.Equal(t, len(DocumentDiagnosticsFromCache(documentURI)), len(diagnostics))
	assert.Equal(t, 1, len(mockCli.Calls))
}

func Test_GetDiagnostics_shouldNotRunOssIfNotEnabled(t *testing.T) {
	testutil.UnitTest(t)
	di.TestInit(t)
	ClearEntireDiagnosticsCache()
	config.CurrentConfig().SetSnykCodeEnabled(false)
	config.CurrentConfig().SetSnykIacEnabled(false)
	config.CurrentConfig().SetSnykOssEnabled(false)
	documentURI := sglsp.DocumentURI("package.json")
	mockCli := mockCli{}
	Cli = &mockCli
	mockCli.Mock.On("Execute", mock.Anything, mock.Anything).Return("test", nil)

	diagnostics := GetDiagnostics(context.Background(), documentURI)

	assert.Equal(t, len(DocumentDiagnosticsFromCache(documentURI)), len(diagnostics))
	assert.Equal(t, 0, len(mockCli.Calls))
}

func Test_GetDiagnostics_shouldRunIacIfEnabled(t *testing.T) {
	testutil.UnitTest(t)
	di.TestInit(t)
	ClearEntireDiagnosticsCache()
	config.CurrentConfig().SetSnykCodeEnabled(false)
	config.CurrentConfig().SetSnykIacEnabled(true)
	config.CurrentConfig().SetSnykOssEnabled(false)
	documentURI := sglsp.DocumentURI("package.json")
	settings := config.CurrentConfig().CliSettings()
	settings.AdditionalParameters = []string{"-d", "--all-projects"}
	settings.Insecure = true
	settings.Endpoint = "asd"
	config.CurrentConfig().SetCliSettings(settings)

	mockCli := mockCli{}
	Cli = &mockCli
	mockCli.Mock.On("Execute", mock.Anything, mock.Anything).Return("{}", nil)

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
	testutil.UnitTest(t)
	di.TestInit(t)
	ClearEntireDiagnosticsCache()
	config.CurrentConfig().SetSnykCodeEnabled(false)
	config.CurrentConfig().SetSnykIacEnabled(false)
	config.CurrentConfig().SetSnykOssEnabled(false)
	documentURI := sglsp.DocumentURI("package.json")
	mockCli := mockCli{}
	Cli = &mockCli
	mockCli.Mock.On("Execute", mock.Anything, mock.Anything).Return("test", nil)

	diagnostics := GetDiagnostics(context.Background(), documentURI)

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
	di.TestInit(t)

	GetDiagnostics(context.Background(), empty.URI)

	// verify that create bundle has NOT been called on backend service
	params := di.SnykCodeClient.(*code.FakeSnykCodeClient).GetCallParams(0, code.CreateBundleWithSourceOperation)
	assert.Nil(t, params)
}

func Test_ClearWorkspaceFolderDiagnostics_shouldRemoveDiagnosticsOfAllFilesInFolder(t *testing.T) {
	ClearEntireDiagnosticsCache()
	diagnosticUri, path := code.FakeDiagnosticUri()
	defer os.RemoveAll(path)
	di.TestInit(t)
	diagnostics := GetDiagnostics(context.Background(), diagnosticUri)
	assert.Equal(t, len(DocumentDiagnosticsFromCache(diagnosticUri)), len(diagnostics))

	ClearWorkspaceFolderDiagnostics(lsp.WorkspaceFolder{Uri: uri.PathToUri(path)})

	assert.Equal(t, 0, documentDiagnosticCache.Length())
}
