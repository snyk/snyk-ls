package snyk_test

//todo after introducing product line abstraction this should be trivial to UNIT test as we can use product line mocks
//
//import (
//	"context"
//	"os"
//	"sync"
//	"testing"
//	"time"
//
//	"github.com/rs/zerolog/log"
//	"github.com/stretchr/testify/assert"
//	"github.com/stretchr/testify/mock"
//
//	"github.com/snyk/snyk-ls/code"
//	"github.com/snyk/snyk-ls/config"
//	"github.com/snyk/snyk-ls/di"
//	"github.com/snyk/snyk-ls/domain/ide/workspace/folder"
//	"github.com/snyk/snyk-ls/internal/testutil"
//)
//
//type mockCli struct {
//	mock.Mock
//	mutex sync.Mutex
//}
//
//func (m *mockCli) Execute(cmd []string, workDir string) (resp []byte, err error) {
//	args := m.Called(cmd, workDir)
//	log.Debug().Interface("cmd", cmd).Msg("Using mock CLI")
//	return []byte(args.String(0)), args.Error(1)
//}
//
//func (m *mockCli) ExpandParametersFromConfig(base []string) []string {
//	args := m.Called(base)
//	log.Debug().Interface("base", base).Msg("Using mock CLI")
//	return args.Get(0).([]string)
//}
//
//func (m *mockCli) HandleErrors(ctx context.Context, output string, err error) (fail bool) {
//	args := m.Called(err)
//	log.Debug().Err(err).Msg("Using mock CLI")
//	return args.Bool(0)
//}
//
//func (m *mockCli) Calls() []mock.Call {
//	return m.Mock.Calls
//}
//
//func Test_GetDiagnostics_shouldNotRunCodeIfNotEnabled(t *testing.T) {
//	testutil.UnitTest(t)
//	di.TestInit(t)
//	config.CurrentConfig().SetSnykCodeEnabled(false)
//	diagnosticUri, path := code.FakeDiagnosticUri()
//	defer os.RemoveAll(path)
//	f := folder.NewFolder(path, "Test")
//
//	f.ScanFile(context.Background(), diagnosticUri)
//
//	assert.Equal(t, len(f.documentDiagnosticsFromCache(diagnosticUri)), len(diagnostics))
//	params := di.SnykCodeClient().(*code.FakeSnykCodeClient).GetCallParams(0, code.CreateBundleWithSourceOperation)
//	assert.Nil(t, params)
//}
//
//func Test_GetDiagnostics_shouldNotRunCodeIfNotSastEnabled(t *testing.T) {
//	testutil.UnitTest(t)
//	di.TestInit(t)
//	config.CurrentConfig().SetSnykCodeEnabled(true)
//	diagnosticUri, path := code.FakeDiagnosticUri()
//	defer os.RemoveAll(path)
//	fakeApiClient := di.SnykCode().SnykApiClient.(*code.FakeApiClient)
//	fakeApiClient.CodeEnabled = false
//	f := folder.NewFolder(path, "Test")
//
//	f.ScanFile(context.Background(), diagnosticUri)
//
//	assert.Equal(t, len(f.documentDiagnosticsFromCache(diagnosticUri)), len(diagnostics))
//	assert.Eventually(t, func() bool {
//		return len(fakeApiClient.GetAllCalls(code.SastEnabledOperation)) == 1 &&
//			len(di.SnykCodeClient().(*code.FakeSnykCodeClient).GetAllCalls(code.CreateBundleWithSourceOperation)) == 0
//	}, time.Second*10, time.Millisecond)
//}
//
//func Test_GetDiagnostics_shouldRunCodeIfEnabled(t *testing.T) {
//	testutil.UnitTest(t)
//	di.TestInit(t)
//	config.CurrentConfig().SetSnykCodeEnabled(true)
//	diagnosticUri, path := code.FakeDiagnosticUri()
//	defer os.RemoveAll(path)
//	f := folder.NewFolder(path, "Test")
//
//	f.ScanFile(context.Background(), diagnosticUri)
//
//	assert.Eventually(t, func() bool {
//		return len(f.documentDiagnosticsFromCache(diagnosticUri)) == len(diagnostics)
//	}, time.Second*10, time.Millisecond)
//
//	params := di.SnykCodeClient().(*code.FakeSnykCodeClient).GetCallParams(0, code.CreateBundleWithSourceOperation)
//	assert.NotNil(t, params)
//}
//
//func Test_GetDiagnostics_shouldRunOssIfEnabled(t *testing.T) {
//	testutil.UnitTest(t)
//	di.TestInit(t)
//	f := folder.NewFolder("/test", "Test")
//	config.CurrentConfig().SetSnykCodeEnabled(false)
//	config.CurrentConfig().SetSnykIacEnabled(false)
//	config.CurrentConfig().SetSnykOssEnabled(true)
//	mockCli := mockCli{}
//	mockCli.Mock.On("Execute", mock.Anything, mock.Anything).Return("test", nil)
//	mockCli.Mock.On("ExpandParametersFromConfig", mock.Anything).Return([]string{"test", "iac", "--insecure", "-d", "--all-projects"})
//
//	f.ScanFile(context.Background(), "/test/package.json")
//
//	assert.Eventually(t, func() bool {
//		return len(mockCli.Calls()) == 2
//	}, 2*time.Second, time.Millisecond)
//}
//
//func Test_GetDiagnostics_shouldNotRunOssIfNotEnabled(t *testing.T) {
//	testutil.UnitTest(t)
//	di.TestInit(t)
//	config.CurrentConfig().SetSnykCodeEnabled(false)
//	config.CurrentConfig().SetSnykIacEnabled(false)
//	config.CurrentConfig().SetSnykOssEnabled(false)
//	f := folder.NewFolder("/test", "Test")
//	filePath := "/test/package.json"
//	mockCli := mockCli{}
//	f.cli = &mockCli
//	mockCli.Mock.On("Execute", mock.Anything, mock.Anything).Return("test", nil)
//	mockCli.Mock.On("ExpandParametersFromConfig", mock.Anything).Return([]string{"test", "iac", "--insecure", "-d", "--all-projects"})
//
//	f.ScanFile(context.Background(), filePath)
//
//	assert.Equal(t, len(f.documentDiagnosticsFromCache(filePath)), len(diagnostics))
//	assert.Equal(t, 0, len(mockCli.Calls()))
//}
//
//func Test_GetDiagnostics_shouldRunIacIfEnabled(t *testing.T) {
//	testutil.UnitTest(t)
//	di.TestInit(t)
//	f := folder.NewFolder("/test", "Test")
//	config.CurrentConfig().SetSnykCodeEnabled(false)
//	config.CurrentConfig().SetSnykIacEnabled(true)
//	config.CurrentConfig().SetSnykOssEnabled(false)
//	mockCli := mockCli{}
//	f.cli = &mockCli
//	mockCli.Mock.On("Execute", mock.Anything, mock.Anything).Return("test", nil)
//	mockCli.Mock.On("ExpandParametersFromConfig", mock.Anything).Return([]string{"test", "iac", "--insecure", "-d", "--all-projects"})
//
//	f.ScanFile(context.Background(), "/test/package.json")
//
//	assert.Eventually(t, func() bool {
//		return len(mockCli.Calls()) == 2
//	}, 2*time.Second, time.Millisecond)
//}
//
//func Test_GetDiagnostics_shouldNotIacIfNotEnabled(t *testing.T) { // disable snyk code
//	testutil.UnitTest(t)
//	di.TestInit(t)
//	config.CurrentConfig().SetSnykCodeEnabled(false)
//	config.CurrentConfig().SetSnykIacEnabled(false)
//	config.CurrentConfig().SetSnykOssEnabled(false)
//	f := folder.NewFolder("/test", "Test")
//	filePath := "/test/package.json"
//	mockCli := mockCli{}
//	f.cli = &mockCli
//	mockCli.Mock.On("Execute", mock.Anything, mock.Anything).Return("test", nil)
//	mockCli.Mock.On("ExpandParametersFromConfig", mock.Anything).Return([]string{"test", "iac", "--insecure", "-d", "--all-projects"})
//
//	f.ScanFile(context.Background(), filePath)
//
//	assert.Equal(t, len(f.documentDiagnosticsFromCache(filePath)), len(diagnostics))
//	assert.Equal(t, 0, len(mockCli.Calls()))
//}
//
//func Test_GetDiagnostics_shouldNotTryToAnalyseEmptyFiles(t *testing.T) {
//	di.TestInit(t)
//	f := folder.NewFolder("/test", "Test")
//
//	f.ScanFile(context.Background(), "/test/test123")
//
//	// verify that create bundle has NOT been called on backend service
//	params := di.SnykCodeClient().(*code.FakeSnykCodeClient).GetCallParams(0, code.CreateBundleWithSourceOperation)
//	assert.Nil(t, params)
//}
