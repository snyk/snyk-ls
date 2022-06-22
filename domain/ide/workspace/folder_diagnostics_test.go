package workspace

import (
	"context"
	"os"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/snyk/snyk-ls/code"
	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/di"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/lsp"
)

type mockCli struct {
	mock.Mock
}

func (m *mockCli) Execute(cmd []string, workDir string) (resp []byte, err error) {
	args := m.Called(cmd, workDir)
	log.Debug().Interface("cmd", cmd).Msg("Using mock CLI")
	return []byte(args.String(0)), args.Error(1)
}

func (m *mockCli) ExpandParametersFromConfig(base []string) []string {
	args := m.Called(base)
	log.Debug().Interface("base", base).Msg("Using mock CLI")
	return args.Get(0).([]string)
}

func (m *mockCli) HandleErrors(ctx context.Context, output string, err error) (fail bool) {
	args := m.Called(err)
	log.Debug().Err(err).Msg("Using mock CLI")
	return args.Bool(0)
}

func Test_GetDiagnostics_shouldReturnDiagnosticForCachedFile(t *testing.T) {
	testutil.UnitTest(t)
	diagnosticUri, path := code.FakeDiagnosticUri()
	defer os.RemoveAll(path)
	di.TestInit(t)
	workspace := &Workspace{}
	f := NewFolder(path, "Test", workspace)
	workspace.AddFolder(f)
	f.documentDiagnosticCache.Put(diagnosticUri, []lsp.Diagnostic{code.FakeDiagnostic})

	diagnostics := workspace.GetDiagnostics(context.Background(), diagnosticUri)

	assert.NotNil(t, diagnostics)
	assert.NotEmpty(t, f.documentDiagnosticsFromCache(diagnosticUri))
	assert.Equal(t, len(f.documentDiagnosticsFromCache(diagnosticUri)), len(diagnostics))
	recorder := &di.Instrumentor().(*performance.TestInstrumentor).SpanRecorder
	spans := recorder.Spans()
	assert.Len(t, spans, 1)
	assert.Equal(t, "GetDiagnostics", spans[0].GetOperation())
	assert.Equal(t, "GetDiagnostics", spans[0].GetTxName())
}

func Test_GetDiagnostics_shouldNotRunCodeIfNotEnabled(t *testing.T) {
	testutil.UnitTest(t)
	di.TestInit(t)
	config.CurrentConfig().SetSnykCodeEnabled(false)
	diagnosticUri, path := code.FakeDiagnosticUri()
	defer os.RemoveAll(path)
	workspace := &Workspace{}
	f := NewFolder(path, "Test", workspace)
	workspace.AddFolder(f)

	diagnostics := workspace.GetDiagnostics(context.Background(), diagnosticUri)

	assert.Equal(t, len(f.documentDiagnosticsFromCache(diagnosticUri)), len(diagnostics))
	params := di.SnykCodeClient().(*code.FakeSnykCodeClient).GetCallParams(0, code.CreateBundleWithSourceOperation)
	assert.Nil(t, params)
}

func Test_GetDiagnostics_shouldNotRunCodeIfNotSastEnabled(t *testing.T) {
	testutil.UnitTest(t)
	di.TestInit(t)
	config.CurrentConfig().SetSnykCodeEnabled(true)
	diagnosticUri, path := code.FakeDiagnosticUri()
	defer os.RemoveAll(path)
	fakeApiClient := di.SnykCode().SnykApiClient.(*code.FakeApiClient)
	fakeApiClient.CodeEnabled = false
	workspace := &Workspace{}
	f := NewFolder(path, "Test", workspace)
	workspace.AddFolder(f)

	diagnostics := workspace.GetDiagnostics(context.Background(), diagnosticUri)

	assert.Equal(t, len(f.documentDiagnosticsFromCache(diagnosticUri)), len(diagnostics))
	assert.Len(t, fakeApiClient.GetAllCalls(code.SastEnabledOperation), 1)
	assert.Len(t, di.SnykCodeClient().(*code.FakeSnykCodeClient).GetAllCalls(code.CreateBundleWithSourceOperation), 0)
}

func Test_GetDiagnostics_shouldRunCodeIfEnabled(t *testing.T) {
	testutil.UnitTest(t)
	di.TestInit(t)
	config.CurrentConfig().SetSnykCodeEnabled(true)
	diagnosticUri, path := code.FakeDiagnosticUri()
	defer os.RemoveAll(path)
	workspace := &Workspace{}
	f := NewFolder(path, "Test", workspace)
	workspace.AddFolder(f)

	diagnostics := workspace.GetDiagnostics(context.Background(), diagnosticUri)

	assert.Equal(t, len(f.documentDiagnosticsFromCache(diagnosticUri)), len(diagnostics))
	params := di.SnykCodeClient().(*code.FakeSnykCodeClient).GetCallParams(0, code.CreateBundleWithSourceOperation)
	assert.NotNil(t, params)
}

func Test_GetDiagnostics_shouldRunOssIfEnabled(t *testing.T) {
	testutil.CreateDummyProgressListener(t)
	testutil.UnitTest(t)
	di.TestInit(t)
	workspace := &Workspace{}
	f := NewFolder(".", "Test", workspace)
	workspace.AddFolder(f)
	config.CurrentConfig().SetSnykCodeEnabled(false)
	config.CurrentConfig().SetSnykIacEnabled(false)
	config.CurrentConfig().SetSnykOssEnabled(true)
	filePath := "package.json"
	mockCli := mockCli{}
	f.cli = &mockCli
	mockCli.Mock.On("Execute", mock.Anything, mock.Anything).Return("test", nil)
	mockCli.Mock.On("ExpandParametersFromConfig", mock.Anything).Return([]string{"test", "iac", "--insecure", "-d", "--all-projects"})

	diagnostics := workspace.GetDiagnostics(context.Background(), filePath)

	assert.Equal(t, len(f.documentDiagnosticsFromCache(filePath)), len(diagnostics))
	assert.Equal(t, 2, len(mockCli.Calls))
}

func Test_GetDiagnostics_shouldNotRunOssIfNotEnabled(t *testing.T) {
	testutil.UnitTest(t)
	di.TestInit(t)
	config.CurrentConfig().SetSnykCodeEnabled(false)
	config.CurrentConfig().SetSnykIacEnabled(false)
	config.CurrentConfig().SetSnykOssEnabled(false)
	workspace := &Workspace{}
	f := NewFolder(".", "Test", workspace)
	workspace.AddFolder(f)
	filePath := "package.json"
	mockCli := mockCli{}
	f.cli = &mockCli
	mockCli.Mock.On("Execute", mock.Anything, mock.Anything).Return("test", nil)
	mockCli.Mock.On("ExpandParametersFromConfig", mock.Anything).Return([]string{"test", "iac", "--insecure", "-d", "--all-projects"})

	diagnostics := workspace.GetDiagnostics(context.Background(), filePath)

	assert.Equal(t, len(f.documentDiagnosticsFromCache(filePath)), len(diagnostics))
	assert.Equal(t, 0, len(mockCli.Calls))
}

func Test_GetDiagnostics_shouldRunIacIfEnabled(t *testing.T) {
	testutil.UnitTest(t)
	di.TestInit(t)
	config.CurrentConfig().SetSnykCodeEnabled(false)
	config.CurrentConfig().SetSnykIacEnabled(true)
	config.CurrentConfig().SetSnykOssEnabled(false)
	workspace := &Workspace{}
	f := NewFolder(".", "Test", workspace)
	workspace.AddFolder(f)
	filePath := "package.json"
	settings := config.CurrentConfig().CliSettings()
	settings.AdditionalParameters = []string{"-d", "--all-projects"}
	settings.Insecure = true
	settings.Endpoint = "asd"
	config.CurrentConfig().SetCliSettings(settings)

	mockCli := mockCli{}
	f.cli = &mockCli
	mockCli.Mock.On("Execute", mock.Anything, mock.Anything).Return("{}", nil)
	mockCli.Mock.On("ExpandParametersFromConfig", mock.Anything).Return([]string{"test", "iac", "--insecure", "-d", "--all-projects"})

	diagnostics := workspace.GetDiagnostics(context.Background(), filePath)

	assert.Equal(t, len(f.documentDiagnosticsFromCache(filePath)), len(diagnostics))
	assert.Equal(t, 2, len(mockCli.Calls))
	call := mockCli.Calls[1]
	assert.Contains(t, call.Arguments[0], "--insecure")
	assert.Contains(t, call.Arguments[0], "-d")
	assert.Contains(t, call.Arguments[0], "--all-projects")
}

func Test_GetDiagnostics_shouldNotIacIfNotEnabled(t *testing.T) { // disable snyk code
	testutil.UnitTest(t)
	di.TestInit(t)
	config.CurrentConfig().SetSnykCodeEnabled(false)
	config.CurrentConfig().SetSnykIacEnabled(false)
	config.CurrentConfig().SetSnykOssEnabled(false)
	workspace := &Workspace{}
	f := NewFolder(".", "Test", workspace)
	workspace.AddFolder(f)
	filePath := "package.json"
	mockCli := mockCli{}
	f.cli = &mockCli
	mockCli.Mock.On("Execute", mock.Anything, mock.Anything).Return("test", nil)
	mockCli.Mock.On("ExpandParametersFromConfig", mock.Anything).Return([]string{"test", "iac", "--insecure", "-d", "--all-projects"})

	diagnostics := workspace.GetDiagnostics(context.Background(), filePath)

	assert.Equal(t, len(f.documentDiagnosticsFromCache(filePath)), len(diagnostics))
	assert.Equal(t, 0, len(mockCli.Calls))
}

func Test_GetDiagnostics_shouldNotTryToAnalyseEmptyFiles(t *testing.T) {
	di.TestInit(t)
	workspace := &Workspace{}
	f := NewFolder(".", "Test", workspace)
	workspace.AddFolder(f)

	workspace.GetDiagnostics(context.Background(), "test123")

	// verify that create bundle has NOT been called on backend service
	params := di.SnykCodeClient().(*code.FakeSnykCodeClient).GetCallParams(0, code.CreateBundleWithSourceOperation)
	assert.Nil(t, params)
}
