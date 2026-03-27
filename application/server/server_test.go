/*
 * © 2022-2026 Snyk Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package server

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/handler"
	"github.com/creachadair/jrpc2/server"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	mock_command "github.com/snyk/snyk-ls/domain/ide/command/mock"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/infrastructure/cli/cli_constants"
	"github.com/snyk/snyk-ls/infrastructure/cli/install"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/folderconfig"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

const maxIntegTestDuration = 15 * time.Minute

var (
	supportedCommands = []string{
		types.WorkspaceScanCommand,
		types.OpenBrowserCommand,
		types.NavigateToRangeCommand,
		types.LoginCommand,
	}
)

func didOpenTextParams(t *testing.T) (sglsp.DidOpenTextDocumentParams, types.FilePath) {
	t.Helper()
	filePath, dirPath := code.TempWorkdirWithIssues(t)
	didOpenParams := sglsp.DidOpenTextDocumentParams{
		TextDocument: sglsp.TextDocumentItem{URI: uri.PathToUri(filePath)},
	}

	return didOpenParams, dirPath
}

func setupServer(t *testing.T, engine workflow.Engine, tokenService *config.TokenServiceImpl) (server.Local, *testsupport.JsonRPCRecorder) {
	t.Helper()
	return setupCustomServer(t, engine, tokenService, nil)
}

func setupServerWithCustomDI(t *testing.T, engine workflow.Engine, tokenService *config.TokenServiceImpl, useMocks bool) (server.Local, *testsupport.JsonRPCRecorder) {
	t.Helper()
	s, jsonRPCRecorder := setupCustomServer(t, engine, tokenService, nil)
	if !useMocks {
		di.Init(engine, tokenService)
	}
	return s, jsonRPCRecorder
}

func setupCustomServer(t *testing.T, engine workflow.Engine, tokenService *config.TokenServiceImpl, callBackFn onCallbackFn) (server.Local, *testsupport.JsonRPCRecorder) {
	t.Helper()

	// Ensure SNYK_API endpoint is set in config if environment variable is present
	endpoint := os.Getenv("SNYK_API")
	if endpoint != "" {
		config.UpdateApiEndpointsOnConfig(engine.GetConfiguration(), endpoint)
	}

	di.TestInit(t, engine, tokenService)
	jsonRPCRecorder := &testsupport.JsonRPCRecorder{}
	loc := startServer(engine, tokenService, callBackFn, jsonRPCRecorder)
	cleanupChannels()

	t.Cleanup(func() {
		_, _ = loc.Client.Call(context.Background(), "shutdown", nil)
		_ = loc.Close()
		cleanupChannels()
		jsonRPCRecorder.ClearCallbacks()
		jsonRPCRecorder.ClearNotifications()
	})
	return loc, jsonRPCRecorder
}

func cleanupChannels() {
	disposeProgressListener()
	progress.CleanupChannels()
	di.HoverService().ClearAllHovers()
}

func TestPeriodicallyCheckForExpiredCache_StopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()

	done := make(chan struct{})
	go func() {
		periodicallyCheckForExpiredCache(ctx, conf)
		close(done)
	}()

	cancel()

	select {
	case <-done:
		// goroutine stopped as expected
	case <-time.After(2 * time.Second):
		t.Fatal("periodicallyCheckForExpiredCache did not stop after context cancellation")
	}
}

type onCallbackFn = func(ctx context.Context, request *jrpc2.Request) (any, error)

func startServer(engine workflow.Engine, tokenService *config.TokenServiceImpl, callBackFn onCallbackFn, jsonRPCRecorder *testsupport.JsonRPCRecorder) server.Local {
	var srv *jrpc2.Server
	logger := engine.GetLogger()

	opts := &server.LocalOptions{
		Client: &jrpc2.ClientOptions{
			OnNotify: func(request *jrpc2.Request) {
				jsonRPCRecorder.Record(*request)
			},
			OnCallback: func(ctx context.Context, request *jrpc2.Request) (any, error) {
				jsonRPCRecorder.Record(*request)
				if callBackFn != nil {
					return callBackFn(ctx, request)
				}
				return *request, nil
			},
		},
		Server: &jrpc2.ServerOptions{
			AllowPush:   true,
			Concurrency: 0, // set concurrency to < 1 causes initialization with number of cores
			Logger: func(text string) {
				logger.Trace().Str("method", "json-rpc").Msg(text)
			},
			RPCLog: RPCLogger{logger: logger},
		},
	}

	handlers := handler.Map{}
	loc := server.NewLocal(handlers, opts)
	srv = loc.Server

	config.SetLogLevel(zerolog.LevelDebugValue)
	// we don't want lsp logging in test runs
	config.SetupLogging(engine, tokenService, nil)

	conf := engine.GetConfiguration()
	initHandlers(srv, handlers, conf, engine, logger)

	return loc
}

func Test_dummy_shouldNotBeServed(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, _ := setupServer(t, engine, tokenService)

	_, err := loc.Client.Call(t.Context(), "dummy", nil)
	if err == nil {
		t.Fatal(err, "call succeeded")
	}
}

func Test_initialize_shouldBeServed(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, _ := setupServer(t, engine, tokenService)

	rsp, err := loc.Client.Call(t.Context(), "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	var result types.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		t.Fatal(err)
	}
}

func Test_shutdown_shouldBeServed(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, _ := setupServer(t, engine, tokenService)

	rsp, err := loc.Client.Call(t.Context(), "shutdown", nil)
	assert.NoError(t, err)
	assert.NotNil(t, rsp)
}

func Test_initialize_containsServerInfo(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, _ := setupServer(t, engine, tokenService)

	rsp, err := loc.Client.Call(t.Context(), "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	var result types.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, config.LsProtocolVersion, result.ServerInfo.Version)
}

func Test_initialized_shouldCheckRequiredProtocolVersion(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRpcRecorder := setupServer(t, engine, tokenService)

	params := types.InitializeParams{
		InitializationOptions: types.InitializationOptions{RequiredProtocolVersion: "23"},
	}

	config.LsProtocolVersion = "12"

	rsp, err := loc.Client.Call(t.Context(), "initialize", params)
	require.NoError(t, err)
	var result types.InitializeResult
	err = rsp.UnmarshalResult(&result)
	require.NoError(t, err)

	_, err = loc.Client.Call(t.Context(), "initialized", params)
	require.NoError(t, err)
	assert.Eventuallyf(t, func() bool {
		callbacks := jsonRpcRecorder.Callbacks()
		return len(callbacks) > 0
	}, time.Second*10, time.Millisecond,
		"did not receive callback because of wrong protocol version")
}

func Test_initialize_shouldSupportAllCommands(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, _ := setupServer(t, engine, tokenService)

	rsp, err := loc.Client.Call(t.Context(), "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	var result types.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		t.Fatal(err)
	}

	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, types.NavigateToRangeCommand)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, types.WorkspaceScanCommand)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, types.WorkspaceFolderScanCommand)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, types.OpenBrowserCommand)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, types.LoginCommand)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, types.CopyAuthLinkCommand)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, types.LogoutCommand)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, types.TrustWorkspaceFoldersCommand)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, types.GetLearnLesson)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, types.ReportAnalyticsCommand)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, types.OpenLearnLesson)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, types.GetSettingsSastEnabled)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, types.GetFeatureFlagStatus)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, types.GetActiveUserCommand)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, types.CodeFixCommand)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, types.CodeSubmitFixFeedback)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, types.CodeFixDiffsCommand)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, types.ExecuteCLICommand)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, types.ConnectivityCheckCommand)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, types.DirectoryDiagnosticsCommand)
}

func Test_initialize_shouldSupportDocumentSaving(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, _ := setupServer(t, engine, tokenService)

	rsp, err := loc.Client.Call(t.Context(), "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	var result types.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, result.Capabilities.TextDocumentSync.Options.Save, &sglsp.SaveOptions{IncludeText: true})
	assert.Equal(t, result.Capabilities.TextDocumentSync.Options.WillSave, true)
	assert.Equal(t, result.Capabilities.TextDocumentSync.Options.WillSaveWaitUntil, true)
}

func Test_initialize_shouldSupportCodeLenses(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, _ := setupServer(t, engine, tokenService)

	rsp, err := loc.Client.Call(t.Context(), "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	var result types.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, result.Capabilities.CodeLensProvider.ResolveProvider, false)
}

func Test_initialized_shouldInitializeAndTriggerCliDownload(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, _ := setupServer(t, engine, tokenService)

	initOpts := types.InitializationOptions{
		Settings: map[string]*types.ConfigSetting{
			types.SettingAutomaticDownload: {Value: true, Changed: true},
			types.SettingCliPath:           {Value: filepath.Join(t.TempDir(), "notexistent"), Changed: true},
		},
	}
	_, err := loc.Client.Call(t.Context(), "initialize", types.InitializeParams{InitializationOptions: initOpts})
	if err != nil {
		t.Fatal(err)
	}
	_, err = loc.Client.Call(t.Context(), "initialized", nil)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, 1, di.Installer().(*install.FakeInstaller).Installs())
}

func Test_initialized_shouldRedactToken(t *testing.T) {
	t.Skipf("this is causing race conditions, because the global stderr is redirected")
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, _ := setupServer(t, engine, tokenService)
	oldStdErr := os.Stderr
	file, err := os.Create(filepath.Join(t.TempDir(), "stderr"))
	require.NoError(t, err)

	t.Cleanup(func() {
		os.Stderr = oldStdErr
		_ = file.Close()
	})

	toBeRedacted := "uhuhuhu"
	initOpts := types.InitializationOptions{
		Settings: map[string]*types.ConfigSetting{
			types.SettingToken: {Value: toBeRedacted, Changed: true},
		},
	}
	os.Stderr, _ = file, err

	_, err = loc.Client.Call(t.Context(), "initialize", types.InitializeParams{InitializationOptions: initOpts})
	if err != nil {
		t.Fatal(err)
	}

	defer func() { os.Stderr = oldStdErr }()
	actual, err := os.ReadFile(file.Name())
	require.NoError(t, err)
	require.NotContainsf(t, string(actual), toBeRedacted, "token should be redacted")
}

func codeLensInitParams(t *testing.T, dir types.FilePath) types.InitializeParams {
	t.Helper()
	return types.InitializeParams{
		RootURI: uri.PathToUri(dir),
		InitializationOptions: types.InitializationOptions{
			Settings: map[string]*types.ConfigSetting{
				types.SettingSnykCodeEnabled:   {Value: true, Changed: true},
				types.SettingSnykOssEnabled:    {Value: false, Changed: true},
				types.SettingSnykIacEnabled:    {Value: false, Changed: true},
				types.SettingOrganization:      {Value: "fancy org", Changed: true},
				types.SettingToken:             {Value: "xxx", Changed: true},
				types.SettingAutomaticDownload: {Value: true, Changed: true},
				types.SettingCliPath:           {Value: filepath.Join(t.TempDir(), "cli"), Changed: true},
				types.SettingEnabledSeverities: {Value: map[string]interface{}{"critical": true, "high": true, "medium": true, "low": true}, Changed: true},
				types.SettingTrustEnabled:      {Value: false, Changed: true},
			},
		},
	}
}

func Test_TextDocumentCodeLenses_shouldReturnCodeLenses(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, _ := setupServer(t, engine, tokenService)
	didOpenParams, dir := didOpenTextParams(t)
	fakeAuthenticationProvider := di.AuthenticationService().Provider().(*authentication.FakeAuthenticationProvider)
	fakeAuthenticationProvider.IsAuthenticated = true
	testutil.EnableSastAndAutoFix(engine)

	clientParams := codeLensInitParams(t, dir)
	_, err := loc.Client.Call(t.Context(), "initialize", clientParams)
	if err != nil {
		t.Fatal(err, "couldn't initialize")
	}
	_, err = loc.Client.Call(t.Context(), "initialized", nil)
	if err != nil {
		t.Fatal(err, "couldn't send initialized")
	}

	// wait for publish
	assert.Eventually(
		t,
		func() bool {
			path := uri.PathFromUri(didOpenParams.TextDocument.URI)
			folder := config.GetWorkspace(engine.GetConfiguration()).GetFolderContaining(path)
			ip, ok := folder.(snyk.IssueProvider)
			if !ok {
				t.FailNow()
			}
			return ip.IssuesForFile(path) != nil
		},
		50*time.Second,
		time.Millisecond,
		"Couldn't get diagnostics from cache",
	)

	rsp, _ := loc.Client.Call(t.Context(), "textDocument/codeLens", sglsp.CodeLensParams{
		TextDocument: sglsp.TextDocumentIdentifier{
			URI: didOpenParams.TextDocument.URI,
		},
	})

	var lenses []sglsp.CodeLens
	if err := rsp.UnmarshalResult(&lenses); err != nil {
		t.Fatal(err)
	}
	assert.NotNil(t, lenses)
	assert.Len(t, lenses, 1)
	assert.Equal(t, lenses[0].Command.Title, code.FixIssuePrefix+code.DontUsePrintStackTrace)
}

func Test_TextDocumentCodeLenses_dirtyFileShouldFilterCodeLenses(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, _ := setupServer(t, engine, tokenService)
	didOpenParams, dir := didOpenTextParams(t)
	fakeAuthenticationProvider := di.AuthenticationService().Provider().(*authentication.FakeAuthenticationProvider)
	fakeAuthenticationProvider.IsAuthenticated = true
	testutil.EnableSastAndAutoFix(engine)

	clientParams := codeLensInitParams(t, dir)
	_, err := loc.Client.Call(t.Context(), "initialize", clientParams)
	if err != nil {
		t.Fatal(err, "couldn't initialize")
	}
	_, err = loc.Client.Call(t.Context(), "initialized", nil)
	if err != nil {
		t.Fatal(err, "couldn't send initialized")
	}

	// wait for publish
	assert.Eventually(
		t,
		func() bool {
			path := uri.PathFromUri(didOpenParams.TextDocument.URI)
			folder := config.GetWorkspace(engine.GetConfiguration()).GetFolderContaining(path)
			ip, ok := folder.(snyk.IssueProvider)
			require.Truef(t, ok, "Expected to find snyk issue provider")
			return ip.IssuesForFile(path) != nil
		},
		50*time.Second,
		time.Millisecond,
		"Couldn't get diagnostics from cache",
	)

	// fake edit the file under test
	di.FileWatcher().SetFileAsChanged(didOpenParams.TextDocument.URI)

	rsp, _ := loc.Client.Call(t.Context(), "textDocument/codeLens", sglsp.CodeLensParams{
		TextDocument: sglsp.TextDocumentIdentifier{
			URI: didOpenParams.TextDocument.URI,
		},
	})

	var lenses []sglsp.CodeLens
	if err := rsp.UnmarshalResult(&lenses); err != nil {
		t.Fatal(err)
	}
	assert.Len(t, lenses, 0)
}

func Test_initialize_updatesSettings(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, _ := setupServer(t, engine, tokenService)

	orgUuid, _ := uuid.NewRandom()
	expectedOrgId := orgUuid.String()

	clientParams := types.InitializeParams{
		InitializationOptions: types.InitializationOptions{
			Settings: map[string]*types.ConfigSetting{
				types.SettingOrganization:      {Value: expectedOrgId, Changed: true},
				types.SettingToken:             {Value: "xxx", Changed: true},
				types.SettingEnabledSeverities: {Value: map[string]interface{}{"critical": true, "high": true, "medium": true, "low": true}, Changed: true},
			},
		},
	}

	rsp, err := loc.Client.Call(t.Context(), "initialize", clientParams)
	if err != nil {
		t.Fatal(err)
	}
	var result types.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		t.Fatal(err)
	}
	// PreferredOrg is set globally during initialization
	assert.Equal(t, expectedOrgId, engine.GetConfiguration().GetString(configuration.ORGANIZATION))
	assert.Equal(t, "xxx", config.GetToken(engine.GetConfiguration()))
}

func Test_initialize_integrationInInitializationOptions_readFromInitializationOptions(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	// Arrange
	const expectedIntegrationName = "ECLIPSE"
	const expectedIntegrationVersion = "0.0.1rc1"

	// The info in initializationOptions takes priority over env-vars
	t.Setenv(cli.IntegrationNameEnvVarKey, "NOT_"+expectedIntegrationName)
	t.Setenv(cli.IntegrationVersionEnvVarKey, "NOT_"+expectedIntegrationVersion)

	loc, _ := setupServer(t, engine, tokenService)
	clientParams := types.InitializeParams{
		InitializationOptions: types.InitializationOptions{
			IntegrationName:    expectedIntegrationName,
			IntegrationVersion: expectedIntegrationVersion,
		},
		ClientInfo: sglsp.ClientInfo{ // the info in initializationOptions takes priority over ClientInfo
			Name:    "NOT_" + expectedIntegrationName,
			Version: "NOT_" + expectedIntegrationVersion,
		},
	}

	// Act
	_, err := loc.Client.Call(t.Context(), "initialize", clientParams)
	if err != nil {
		t.Fatal(err)
	}

	// Assert
	assert.Equal(t, expectedIntegrationName, engine.GetConfiguration().GetString(configuration.INTEGRATION_NAME))
	assert.Equal(t, expectedIntegrationVersion, engine.GetConfiguration().GetString(configuration.INTEGRATION_VERSION))
}

func Test_initialize_integrationInClientInfo_readFromClientInfo(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	// Arrange
	const expectedIntegrationName = "ECLIPSE"
	const expectedIntegrationVersion = "8.0.0ServicePack92-preview4"
	const expectedIdeVersion = "0.0.1rc1"

	// The data in clientInfo takes priority over env-vars
	t.Setenv(cli.IntegrationNameEnvVarKey, "NOT_"+expectedIntegrationName)
	t.Setenv(cli.IntegrationVersionEnvVarKey, "NOT_"+expectedIdeVersion)

	loc, _ := setupServer(t, engine, tokenService)
	clientParams := types.InitializeParams{
		ClientInfo: sglsp.ClientInfo{
			Name:    expectedIntegrationName,
			Version: expectedIdeVersion,
		},
		InitializationOptions: types.InitializationOptions{
			IntegrationName:    expectedIntegrationName,
			IntegrationVersion: expectedIntegrationVersion,
		},
	}

	// Act
	_, err := loc.Client.Call(t.Context(), "initialize", clientParams)
	if err != nil {
		t.Fatal(err)
	}

	// Assert
	assert.Equal(t, expectedIntegrationName, engine.GetConfiguration().GetString(configuration.INTEGRATION_NAME))
	assert.Equal(t, expectedIntegrationVersion, engine.GetConfiguration().GetString(configuration.INTEGRATION_VERSION))
	assert.Equal(t, expectedIdeVersion, engine.GetConfiguration().GetString(configuration.INTEGRATION_ENVIRONMENT_VERSION))
}

func Test_initialize_integrationOnlyInEnvVars_readFromEnvVars(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	// Arrange
	const expectedIntegrationName = "ECLIPSE"
	const expectedIntegrationVersion = "0.0.1rc1"

	t.Setenv(cli.IntegrationNameEnvVarKey, expectedIntegrationName)
	t.Setenv(cli.IntegrationVersionEnvVarKey, expectedIntegrationVersion)
	loc, _ := setupServer(t, engine, tokenService)

	// Act
	_, err := loc.Client.Call(t.Context(), "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Assert
	assert.Equal(t, expectedIntegrationName, engine.GetConfiguration().GetString(configuration.INTEGRATION_NAME))
	assert.Equal(t, expectedIntegrationVersion, engine.GetConfiguration().GetString(configuration.INTEGRATION_VERSION))
}

func Test_initialize_shouldOfferAllCommands(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, _ := setupServer(t, engine, tokenService)

	sc := &scanner.TestScanner{}
	config.GetWorkspace(engine.GetConfiguration()).AddFolder(workspace.NewFolder(engine.GetConfiguration(), engine.GetLogger(), types.PathKey("dummy"),
		"dummy",
		sc,
		di.HoverService(),
		di.ScanNotifier(),
		di.Notifier(),
		di.ScanPersister(),
		di.ScanStateAggregator(),
		featureflag.NewFakeService(),
		types.NewConfigResolver(engine.GetLogger()),
		engine))

	rsp, err := loc.Client.Call(t.Context(), "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	var result types.InitializeResult
	err = rsp.UnmarshalResult(&result)
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range supportedCommands {
		name := "CommandData \"" + c + "\" is supported"
		t.Run(name, func(t *testing.T) {
			assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, c)
		})
	}
}

func Test_initialize_autoAuthenticateSetCorrectly(t *testing.T) {
	t.Run("true when not included", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		loc, _ := setupServer(t, engine, tokenService)
		initializationOptions := types.InitializationOptions{}
		params := types.InitializeParams{InitializationOptions: initializationOptions}
		_, err := loc.Client.Call(t.Context(), "initialize", params)

		assert.Nil(t, err)
		assert.True(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingAutomaticAuthentication)))
	})

	t.Run("Parses true value", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		loc, _ := setupServer(t, engine, tokenService)
		initializationOptions := types.InitializationOptions{
			Settings: map[string]*types.ConfigSetting{
				types.SettingAutomaticAuthentication: {Value: true, Changed: true},
			},
		}
		params := types.InitializeParams{InitializationOptions: initializationOptions}
		_, err := loc.Client.Call(t.Context(), "initialize", params)

		assert.Nil(t, err)
		assert.True(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingAutomaticAuthentication)))
	})

	t.Run("Parses false value", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		loc, _ := setupServer(t, engine, tokenService)

		initializationOptions := types.InitializationOptions{
			Settings: map[string]*types.ConfigSetting{
				types.SettingAutomaticAuthentication: {Value: false, Changed: true},
			},
		}
		params := types.InitializeParams{InitializationOptions: initializationOptions}
		_, err := loc.Client.Call(t.Context(), "initialize", params)
		assert.Nil(t, err)
		assert.False(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingAutomaticAuthentication)))
	})
}

func Test_initialize_handlesUntrustedFoldersWhenAutomaticAuthentication(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder := setupServer(t, engine, tokenService)
	initializationOptions := types.InitializationOptions{
		Settings: map[string]*types.ConfigSetting{
			types.SettingTrustEnabled: {Value: true, Changed: true},
			types.SettingCliPath:      {Value: filepath.Join(t.TempDir(), "cli"), Changed: true},
		},
	}
	params := types.InitializeParams{
		InitializationOptions: initializationOptions,
		WorkspaceFolders:      []types.WorkspaceFolder{{Uri: uri.PathToUri("/untrusted/dummy"), Name: "dummy"}},
	}
	_, err := loc.Client.Call(t.Context(), "initialize", params)
	if err != nil {
		t.Fatal(err, "couldn't send initialized")
	}

	_, err = loc.Client.Call(t.Context(), "initialized", nil)
	if err != nil {
		t.Fatal(err, "couldn't send initialized")
	}

	assert.Nil(t, err)
	assert.Eventually(t, func() bool { return checkTrustMessageRequest(jsonRPCRecorder, engine) }, time.Second*5, time.Millisecond)
}

func Test_initialize_handlesUntrustedFoldersWhenAuthenticated(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder := setupServer(t, engine, tokenService)
	initializationOptions := types.InitializationOptions{
		Settings: map[string]*types.ConfigSetting{
			types.SettingTrustEnabled: {Value: true, Changed: true},
			types.SettingToken:        {Value: "token", Changed: true},
			types.SettingCliPath:      {Value: filepath.Join(t.TempDir(), "cli"), Changed: true},
		},
	}

	fakeAuthenticationProvider := di.AuthenticationService().Provider().(*authentication.FakeAuthenticationProvider)
	fakeAuthenticationProvider.IsAuthenticated = true

	params := types.InitializeParams{
		InitializationOptions: initializationOptions,
		WorkspaceFolders:      []types.WorkspaceFolder{{Uri: uri.PathToUri("/untrusted/dummy"), Name: "dummy"}},
	}
	_, err := loc.Client.Call(t.Context(), "initialize", params)
	if err != nil {
		t.Fatal(err, "couldn't send initialized")
	}

	_, err = loc.Client.Call(t.Context(), "initialized", nil)
	if err != nil {
		t.Fatal(err, "couldn't send initialized")
	}

	assert.Nil(t, err)
	assert.Eventually(t, func() bool { return checkTrustMessageRequest(jsonRPCRecorder, engine) }, time.Second*5, time.Millisecond)
}

func Test_initialize_doesnotHandleUntrustedFolders(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder := setupServer(t, engine, tokenService)
	initializationOptions := types.InitializationOptions{
		Settings: map[string]*types.ConfigSetting{
			types.SettingTrustEnabled: {Value: true, Changed: true},
			types.SettingCliPath:      {Value: filepath.Join(t.TempDir(), "cli"), Changed: true},
		},
	}
	params := types.InitializeParams{
		InitializationOptions: initializationOptions,
		WorkspaceFolders:      []types.WorkspaceFolder{{Uri: uri.PathToUri("/untrusted/dummy"), Name: "dummy"}},
	}
	_, err := loc.Client.Call(t.Context(), "initialize", params)
	if err != nil {
		t.Fatal(err, "couldn't send initialized")
	}
	_, err = loc.Client.Call(t.Context(), "initialized", nil)
	if err != nil {
		t.Fatal(err, "couldn't send initialized")
	}

	assert.NoError(t, err)
	assert.Eventually(t, func() bool { return checkTrustMessageRequest(jsonRPCRecorder, engine) }, time.Second, time.Millisecond)
}

func Test_textDocumentDidSaveHandler_shouldAcceptDocumentItemAndPublishDiagnostics(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder := setupServer(t, engine, tokenService)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	fakeAuthenticationProvider := di.AuthenticationService().Provider().(*authentication.FakeAuthenticationProvider)
	fakeAuthenticationProvider.IsAuthenticated = true

	_, err := loc.Client.Call(t.Context(), "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}

	engine.GetConfiguration().Set(types.SettingIsLspInitialized, true)

	filePath, fileDir := code.TempWorkdirWithIssues(t)
	fileUri := sendFileSavedMessage(t, engine, filePath, fileDir, loc)

	// wait for publish
	assert.Eventually(
		t,
		checkForPublishedDiagnostics(t, engine, uri.PathFromUri(fileUri), -1, jsonRPCRecorder),
		5*time.Second,
		time.Millisecond,
	)
}

func createTemporaryDirectoryWithSnykFile(t *testing.T) (snykFilePath types.FilePath, folderPath types.FilePath) {
	t.Helper()

	temp := t.TempDir()
	temp = filepath.Clean(temp)
	temp, err := filepath.Abs(temp)
	if err != nil {
		t.Fatalf("couldn't get abs folder path of temp dir: %v", err)
	}

	snykFilePath = types.FilePath(filepath.Join(temp, ".snyk"))
	yamlContent := `
ignore:
  SNYK-JS-QS-3153490:
    - '*':
        reason: Ignore me 30 days
        expires: 2024-08-26T13:55:05.414Z
        created: 2024-07-26T13:55:05.417Z
patch: {}
`
	err = os.WriteFile(string(snykFilePath), []byte(yamlContent), 0o600)
	assert.NoError(t, err)
	return snykFilePath, types.FilePath(temp)
}

func Test_textDocumentDidSaveHandler_shouldTriggerScanForDotSnykFile(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder := setupServer(t, engine, tokenService)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), false)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingAuthenticationMethod), string(types.FakeAuthentication))
	di.AuthenticationService().ConfigureProviders(engine.GetConfiguration(), engine.GetLogger())

	fakeAuthenticationProvider := di.AuthenticationService().Provider()
	fakeAuthenticationProvider.(*authentication.FakeAuthenticationProvider).IsAuthenticated = true

	_, err := loc.Client.Call(t.Context(), "initialize", nil)
	if err != nil {
		t.Fatalf("initialization failed: %v", err)
	}

	engine.GetConfiguration().Set(types.SettingIsLspInitialized, true)

	snykFilePath, folderPath := createTemporaryDirectoryWithSnykFile(t)

	sendFileSavedMessage(t, engine, snykFilePath, folderPath, loc)

	// Wait for $/snyk.scan notification
	assert.Eventually(
		t,
		checkForSnykScan(t, jsonRPCRecorder),
		5*time.Second,
		time.Millisecond,
	)
}

func Test_textDocumentDidOpenHandler_shouldNotPublishIfNotCached(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, _ := setupServer(t, engine, tokenService)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	_, err := loc.Client.Call(t.Context(), "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}

	filePath, fileDir := code.TempWorkdirWithIssues(t)

	didOpenParams := sglsp.DidOpenTextDocumentParams{TextDocument: sglsp.TextDocumentItem{
		URI: uri.PathToUri(filePath),
	}}

	folder := workspace.NewFolder(engine.GetConfiguration(), engine.GetLogger(), fileDir, "Test", di.Scanner(), di.HoverService(), di.ScanNotifier(), di.Notifier(),
		di.ScanPersister(), di.ScanStateAggregator(), featureflag.NewFakeService(), di.ConfigResolver(), engine)
	config.GetWorkspace(engine.GetConfiguration()).AddFolder(folder)

	_, err = loc.Client.Call(t.Context(), textDocumentDidOpenOperation, didOpenParams)
	if err != nil {
		t.Fatal(err)
	}

	assert.False(t, folder.IsScanned())
}

func Test_textDocumentDidOpenHandler_shouldPublishIfCached(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder := setupServer(t, engine, tokenService)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	fakeAuthenticationProvider := di.AuthenticationService().Provider().(*authentication.FakeAuthenticationProvider)
	fakeAuthenticationProvider.IsAuthenticated = true
	_, err := loc.Client.Call(t.Context(), "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}

	engine.GetConfiguration().Set(types.SettingIsLspInitialized, true)

	filePath, fileDir := code.TempWorkdirWithIssues(t)
	fileUri := sendFileSavedMessage(t, engine, filePath, fileDir, loc)

	require.Eventually(
		t,
		checkForPublishedDiagnostics(t, engine, uri.PathFromUri(fileUri), 0, jsonRPCRecorder),
		5*time.Second,
		time.Millisecond,
	)

	jsonRPCRecorder.ClearNotifications()

	didOpenParams := sglsp.DidOpenTextDocumentParams{
		TextDocument: sglsp.TextDocumentItem{
			URI:     fileUri,
			Version: 1,
			Text:    "",
		},
	}

	_, err = loc.Client.Call(t.Context(), textDocumentDidOpenOperation, didOpenParams)
	if err != nil {
		t.Fatal(err)
	}

	assert.Eventually(
		t,
		checkForPublishedDiagnostics(t, engine, uri.PathFromUri(fileUri), 2, jsonRPCRecorder),
		5*time.Second,
		time.Millisecond,
	)
}

func Test_textDocumentDidSave_manualScanningMode_doesNotScan(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder := setupServer(t, engine, tokenService)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	_, err := loc.Client.Call(t.Context(), "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingScanAutomatic), false)

	filePath, fileDir := code.TempWorkdirWithIssues(t)
	fileUri := sendFileSavedMessage(t, engine, filePath, fileDir, loc)

	assert.Never(
		t,
		checkForPublishedDiagnostics(t, engine, uri.PathFromUri(fileUri), -1, jsonRPCRecorder),
		5*time.Second,
		time.Millisecond,
	)
}

func sendFileSavedMessage(t *testing.T, engine workflow.Engine, filePath types.FilePath, fileDir types.FilePath, loc server.Local) sglsp.DocumentURI {
	t.Helper()
	didSaveParams := sglsp.DidSaveTextDocumentParams{
		TextDocument: sglsp.TextDocumentIdentifier{URI: uri.PathToUri(filePath)},
	}
	config.GetWorkspace(engine.GetConfiguration()).AddFolder(workspace.NewFolder(engine.GetConfiguration(), engine.GetLogger(), fileDir,
		"Test",
		di.Scanner(),
		di.HoverService(),
		di.ScanNotifier(),
		di.Notifier(),
		di.ScanPersister(),
		di.ScanStateAggregator(),
		featureflag.NewFakeService(),
		di.ConfigResolver(),
		engine))

	// Populate folder config with SAST settings after adding the folder
	folderConfig := config.GetFolderConfigFromEngine(engine, testutil.DefaultConfigResolver(engine), fileDir, engine.GetLogger())
	di.FeatureFlagService().PopulateFolderConfig(folderConfig)

	_, err := loc.Client.Call(t.Context(), textDocumentDidSaveOperation, didSaveParams)
	if err != nil {
		t.Fatal(err)
	}

	return didSaveParams.TextDocument.URI
}

func Test_textDocumentWillSaveWaitUntilHandler_shouldBeServed(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, _ := setupServer(t, engine, tokenService)

	_, err := loc.Client.Call(t.Context(), "textDocument/willSaveWaitUntil", nil)
	if err != nil {
		t.Fatal(err)
	}
}

func Test_textDocumentWillSaveHandler_shouldBeServed(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, _ := setupServer(t, engine, tokenService)

	_, err := loc.Client.Call(t.Context(), "textDocument/willSave", nil)
	if err != nil {
		t.Fatal(err)
	}
}

func Test_workspaceDidChangeWorkspaceFolders_shouldProcessChanges(t *testing.T) {
	engine, tokenService := testutil.IntegTestWithEngine(t)
	loc, _ := setupServer(t, engine, tokenService)
	testutil.CreateDummyProgressListener(t)
	file := testsupport.CreateTempFile(t, t.TempDir())
	w := config.GetWorkspace(engine.GetConfiguration())

	f := types.WorkspaceFolder{Name: filepath.Dir(file.Name()), Uri: uri.PathToUri(types.FilePath(file.Name()))}
	_, err := loc.Client.Call(t.Context(), "workspace/didChangeWorkspaceFolders", types.DidChangeWorkspaceFoldersParams{
		Event: types.WorkspaceFoldersChangeEvent{
			Added: []types.WorkspaceFolder{f},
		},
	})
	if err != nil {
		t.Fatal(err, "error calling server")
	}

	assert.Eventually(t, func() bool {
		folder := w.GetFolderContaining(uri.PathFromUri(f.Uri))
		return folder != nil && folder.IsScanned()
	}, 120*time.Second, time.Millisecond)

	_, err = loc.Client.Call(t.Context(), "workspace/didChangeWorkspaceFolders", types.DidChangeWorkspaceFoldersParams{
		Event: types.WorkspaceFoldersChangeEvent{
			Removed: []types.WorkspaceFolder{f},
		},
	})
	if err != nil {
		t.Fatal(err, "error calling server")
	}

	assert.Nil(t, w.GetFolderContaining(uri.PathFromUri(f.Uri)))
}

func Test_workspaceDidChangeWorkspaceFolders_CallsRefreshConfigFromLdxSync(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)

	// Configure authentication method before server setup
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingAuthenticationMethod), string(types.FakeAuthentication))

	// Setup server
	loc, _ := setupServerWithCustomDI(t, engine, tokenService, false)

	// Setup mock LdxSyncService AFTER setupServer to avoid it being overwritten by di.TestInit
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockLdxSyncService := mock_command.NewMockLdxSyncService(ctrl)
	originalService := di.LdxSyncService()
	di.SetLdxSyncService(mockLdxSyncService)
	defer di.SetLdxSyncService(originalService)

	// Setup authentication service to be authenticated
	di.AuthenticationService().ConfigureProviders(engine.GetConfiguration(), engine.GetLogger())
	fakeAuthenticationProvider := di.AuthenticationService().Provider().(*authentication.FakeAuthenticationProvider)
	fakeAuthenticationProvider.IsAuthenticated = true

	// Expect RefreshConfigFromLdxSync to be called during initialization (with empty folders)
	mockLdxSyncService.EXPECT().
		RefreshConfigFromLdxSync(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Times(1)

	// Initialize server
	_, err := loc.Client.Call(t.Context(), "initialize", nil)
	require.NoError(t, err)

	// Add a workspace folder
	newFolderPath := t.TempDir()
	newFolder := types.WorkspaceFolder{
		Name: "test-folder",
		Uri:  uri.PathToUri(types.FilePath(newFolderPath)),
	}

	// Expect RefreshConfigFromLdxSync to be called with the added folder
	// The call will happen with the actual folder object created by the workspace
	mockLdxSyncService.EXPECT().
		RefreshConfigFromLdxSync(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Times(1).
		Do(func(_ interface{}, _ interface{}, _ interface{}, _ interface{}, folders []types.Folder, _ interface{}) {
			// Verify that we received exactly one folder
			assert.Len(t, folders, 1)
			// Verify the folder path matches what we added
			assert.Equal(t, types.FilePath(newFolderPath), folders[0].Path())
		})

	// Trigger workspace folder change
	params := types.DidChangeWorkspaceFoldersParams{
		Event: types.WorkspaceFoldersChangeEvent{
			Added: []types.WorkspaceFolder{newFolder},
		},
	}

	_, err = loc.Client.Call(t.Context(), "workspace/didChangeWorkspaceFolders", params)
	assert.NoError(t, err)
}

func Test_initialized_CallsRefreshConfigFromLdxSync(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)

	// Setup workspace folders before initialization
	folder1Path := t.TempDir()
	folder2Path := t.TempDir()
	folder1 := types.WorkspaceFolder{
		Uri:  uri.PathToUri(types.FilePath(folder1Path)),
		Name: "workspace1",
	}
	folder2 := types.WorkspaceFolder{
		Uri:  uri.PathToUri(types.FilePath(folder2Path)),
		Name: "workspace2",
	}

	// Setup server
	loc, _ := setupServerWithCustomDI(t, engine, tokenService, false)

	// Setup mock LdxSyncService AFTER setupServer to avoid it being overwritten by di.TestInit
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockLdxSyncService := mock_command.NewMockLdxSyncService(ctrl)
	originalService := di.LdxSyncService()
	di.SetLdxSyncService(mockLdxSyncService)
	defer di.SetLdxSyncService(originalService)

	// Expect RefreshConfigFromLdxSync to be called during initialization with all workspace folders
	mockLdxSyncService.EXPECT().
		RefreshConfigFromLdxSync(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Times(1).
		Do(func(_ interface{}, _ interface{}, _ interface{}, _ interface{}, folders []types.Folder, _ interface{}) {
			// Verify that we received two folders
			assert.Len(t, folders, 2)
			// Verify the folder paths match
			folderPaths := []types.FilePath{folders[0].Path(), folders[1].Path()}
			assert.Contains(t, folderPaths, types.FilePath(folder1Path))
			assert.Contains(t, folderPaths, types.FilePath(folder2Path))
		})

	// Initialize with workspace folders
	params := types.InitializeParams{
		WorkspaceFolders: []types.WorkspaceFolder{folder1, folder2},
	}

	_, err := loc.Client.Call(t.Context(), "initialize", params)
	assert.NoError(t, err)
}

// Check if published diagnostics for given testPath match the expectedNumber.
// If expectedNumber == -1 assume check for expectedNumber > 0
func checkForPublishedDiagnostics(t *testing.T, engine workflow.Engine, testPath types.FilePath, expectedNumber int, jsonRPCRecorder *testsupport.JsonRPCRecorder) func() bool {
	t.Helper()
	return func() bool {
		w := config.GetWorkspace(engine.GetConfiguration())
		notifications := jsonRPCRecorder.FindNotificationsByMethod("textDocument/publishDiagnostics")
		if len(notifications) < 1 {
			return false
		}
		for _, n := range notifications {
			diagnosticsParams := types.PublishDiagnosticsParams{}
			_ = n.UnmarshalParams(&diagnosticsParams)
			if diagnosticsParams.URI == uri.PathToUri(testPath) {
				f := w.GetFolderContaining(testPath)
				hasExpectedDiagnostics := f != nil && ((expectedNumber == -1 && len(diagnosticsParams.Diagnostics) > 0) || (len(diagnosticsParams.Diagnostics) == expectedNumber))
				if hasExpectedDiagnostics {
					return true
				}
			}
		}
		return false
	}
}

func checkForSnykScan(t *testing.T, jsonRPCRecorder *testsupport.JsonRPCRecorder) func() bool {
	t.Helper()
	return func() bool {
		notifications := jsonRPCRecorder.FindNotificationsByMethod("$/snyk.scan")
		return len(notifications) > 0
	}
}

func Test_IntegrationHoverResults(t *testing.T) {
	engine, tokenService := testutil.IntegTestWithEngine(t)
	loc, _ := setupServer(t, engine, tokenService)

	fakeAuthenticationProvider := di.AuthenticationService().Provider().(*authentication.FakeAuthenticationProvider)
	fakeAuthenticationProvider.IsAuthenticated = true

	cloneTargetDir, err := folderconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), testsupport.NodejsGoof, "0336589", engine.GetLogger(), false)
	defer func(path string) { _ = os.RemoveAll(path) }(string(cloneTargetDir))
	if err != nil {
		t.Fatal(err, "Couldn't setup test repo")
	}
	folder := types.WorkspaceFolder{
		Name: "Test Repo",
		Uri:  uri.PathToUri(cloneTargetDir),
	}
	clientParams := types.InitializeParams{
		WorkspaceFolders: []types.WorkspaceFolder{folder},
	}

	_, err = loc.Client.Call(t.Context(), "initialize", clientParams)
	if err != nil {
		t.Fatal(err, "Initialize failed")
	}
	_, err = loc.Client.Call(t.Context(), "initialized", clientParams)
	if err != nil {
		t.Fatal(err, "Initialized failed")
	}

	// wait till the whole workspace is scanned
	assert.Eventually(t, func() bool {
		w := config.GetWorkspace(engine.GetConfiguration())
		f := w.GetFolderContaining(cloneTargetDir)
		return f != nil && f.IsScanned()
	}, maxIntegTestDuration, 100*time.Millisecond)

	testPath := string(cloneTargetDir) + string(os.PathSeparator) + "package.json"
	testPosition := sglsp.Position{
		Line:      17,
		Character: 7,
	}

	hoverResp, err := loc.Client.Call(t.Context(), "textDocument/hover", hover.Params{
		TextDocument: sglsp.TextDocumentIdentifier{URI: uri.PathToUri(types.FilePath(testPath))},
		Position:     testPosition,
	})
	if err != nil {
		t.Fatal(err, "Hover retrieval failed")
	}

	hoverResult := hover.Result{}
	err = hoverResp.UnmarshalResult(&hoverResult)
	if err != nil {
		t.Fatal(err, "Hover retrieval failed")
	}

	assert.Equal(t,
		hoverResult.Contents.Value,
		di.HoverService().GetHover(types.FilePath(testPath), converter.FromPosition(testPosition)).Contents.Value)
	assert.Equal(t, hoverResult.Contents.Kind, "markdown")
}

//goland:noinspection ALL
func Test_MonitorClientProcess(t *testing.T) {
	testsupport.NotOnWindows(t, "sleep doesn't exist on windows")
	engine := testutil.IntegTest(t)
	// start process that just sleeps
	pidChan := make(chan int)
	go func() {
		cmd := exec.Command("sleep", "5")
		err := cmd.Start()
		if err != nil {
			engine.GetLogger().Err(err).Msg("Couldn't sleep. Stopping test")
			t.Fail()
		}
		pidChan <- cmd.Process.Pid
		err = cmd.Wait()
		assert.NoError(t, err)
	}()
	pid := <-pidChan
	// make sure that we actually waited & monitored
	expectedMinimumDuration, _ := time.ParseDuration("999ms")
	assert.True(t, monitorClientProcess(pid) > expectedMinimumDuration)
}

func Test_getDownloadURL(t *testing.T) {
	t.Run("CLI", func(t *testing.T) {
		engine, _ := testutil.UnitTestWithEngine(t)
		conf := engine.GetConfiguration()
		conf.Set(cli_constants.EXECUTION_MODE_KEY, cli_constants.EXECUTION_MODE_VALUE_EXTENSION)

		downloadURL := getDownloadURL(conf, engine, config.LsProtocolVersion)

		// default CLI fallback, as we're not mocking the CLI calls
		assert.Contains(t, downloadURL, "cli")
	})

	t.Run("LS standalone", func(t *testing.T) {
		testsupport.NotOnWindows(t, "don't want to handle the exe extension")
		engine, _ := testutil.UnitTestWithEngine(t)
		conf := engine.GetConfiguration()
		conf.Set(cli_constants.EXECUTION_MODE_KEY, cli_constants.EXECUTION_MODE_VALUE_STANDALONE)
		engine.SetRuntimeInfo(
			runtimeinfo.New(
				runtimeinfo.WithName("snyk-ls"),
				runtimeinfo.WithVersion("v1.234"),
			),
		)

		downloadURL := getDownloadURL(conf, engine, config.LsProtocolVersion)

		prefix := "https://static.snyk.io/snyk-ls/12/snyk-ls"
		assert.True(t, strings.HasPrefix(downloadURL, prefix), downloadURL+" does not start with "+prefix)
	})
}

func Test_handleProtocolVersion(t *testing.T) {
	t.Run("required != current", func(t *testing.T) {
		engine, _ := testutil.UnitTestWithEngine(t)
		// Set CLI extension mode to test CLI download path
		engine.GetConfiguration().Set(cli_constants.EXECUTION_MODE_KEY, cli_constants.EXECUTION_MODE_VALUE_EXTENSION)

		ourProtocolVersion := "17"
		reqProtocolVersion := "18"

		notificationReceived := make(chan types.ShowMessageRequest)
		f := func(params any) {
			mrq, ok := params.(types.ShowMessageRequest)
			require.True(t, ok)
			notificationReceived <- mrq
		}
		testNotifier := notification.NewNotifier()
		go testNotifier.CreateListener(f)

		// Act
		conf := engine.GetConfiguration()
		logger := engine.GetLogger()
		handleProtocolVersion(
			conf,
			engine,
			testNotifier,
			logger,
			ourProtocolVersion,
			reqProtocolVersion,
		)

		// Wait for notification
		var mrq *types.ShowMessageRequest
		require.Eventually(t, func() bool {
			select {
			case receivedNotification := <-notificationReceived:
				mrq = &receivedNotification
				return true
			default:
				return false
			}
		}, 10*time.Second, time.Millisecond, "no message sent via notifier")
		require.NotNil(t, mrq, "expected message sent via notifier")

		require.Contains(t, mrq.Message, "does not match")

		// Find the "Download manually in browser" action
		var downloadAction *types.CommandData
		for _, actionKey := range mrq.Actions.Keys() {
			if actionData, ok := mrq.Actions.Get(actionKey); ok {
				if actionData.Title == "Download manually in browser" {
					downloadAction = &actionData
					break
				}
			}
		}

		require.NotNil(t, downloadAction, "\"Download manually in browser\" action not found")
		require.Equal(t, types.OpenBrowserCommand, downloadAction.CommandId)
		require.Len(t, downloadAction.Arguments, 1, "Expected exactly one argument (download URL)")
		assert.Contains(t, downloadAction.Arguments[0].(string), "downloads.snyk.io/cli/v1.1296.2/", "Should be CLI download URL with version v1.1296.2 for protocol 18")
	})

	t.Run("required == current", func(t *testing.T) {
		engine, _ := testutil.UnitTestWithEngine(t)
		ourProtocolVersion := "11"
		f := func(params any) {
			require.FailNow(t, "did not expect a message")
		}

		testNotifier := notification.NewNotifier()
		go testNotifier.CreateListener(f)

		conf := engine.GetConfiguration()
		logger := engine.GetLogger()
		handleProtocolVersion(
			conf,
			engine,
			testNotifier,
			logger,
			ourProtocolVersion,
			ourProtocolVersion,
		)
		// give goroutine of callback function a chance to fail the test
		time.Sleep(time.Second)
	})
}

func Test_shouldHandleFilesOutsideWorkspace(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, _ := setupServer(t, engine, tokenService)

	_, err := loc.Client.Call(t.Context(), "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}

	workspaceDir := types.FilePath(t.TempDir())
	workspaceFolder := types.WorkspaceFolder{
		Uri:  uri.PathToUri(workspaceDir),
		Name: "workspace",
	}

	_, err = loc.Client.Call(t.Context(), "workspace/didChangeWorkspaceFolders", types.DidChangeWorkspaceFoldersParams{
		Event: types.WorkspaceFoldersChangeEvent{
			Added: []types.WorkspaceFolder{workspaceFolder},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingTrustEnabled), true)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingTrustedFolders), []types.FilePath{workspaceDir})

	outsideDir := types.FilePath(t.TempDir())
	outsideFilePath := types.FilePath(filepath.Join(string(outsideDir), "outside.js"))
	err = os.WriteFile(string(outsideFilePath), []byte("console.log('test');"), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("textDocument/didSave", func(t *testing.T) {
		didSaveParams := sglsp.DidSaveTextDocumentParams{
			TextDocument: sglsp.TextDocumentIdentifier{
				URI: uri.PathToUri(outsideFilePath),
			},
		}

		_, err := loc.Client.Call(t.Context(), "textDocument/didSave", didSaveParams)
		assert.NoError(t, err)

		folder := config.GetWorkspace(engine.GetConfiguration()).GetFolderContaining(outsideFilePath)
		assert.Nil(t, folder)
	})

	t.Run("textDocument/codeAction", func(t *testing.T) {
		codeActionParams := types.CodeActionParams{
			TextDocument: sglsp.TextDocumentIdentifier{
				URI: uri.PathToUri(outsideFilePath),
			},
			Range: sglsp.Range{
				Start: sglsp.Position{Line: 0, Character: 0},
				End:   sglsp.Position{Line: 0, Character: 10},
			},
		}

		rsp, err := loc.Client.Call(t.Context(), "textDocument/codeAction", codeActionParams)
		assert.NoError(t, err)

		var actions []types.LSPCodeAction
		if rsp != nil {
			err = rsp.UnmarshalResult(&actions)
			if err != nil {
				t.Fatal(err)
			}
		}

		assert.Empty(t, actions)
	})

	t.Run("textDocument/didChange", func(t *testing.T) {
		didChangeParams := sglsp.DidChangeTextDocumentParams{
			TextDocument: sglsp.VersionedTextDocumentIdentifier{
				TextDocumentIdentifier: sglsp.TextDocumentIdentifier{
					URI: uri.PathToUri(outsideFilePath),
				},
				Version: 1,
			},
		}

		_, err := loc.Client.Call(t.Context(), "textDocument/didChange", didChangeParams)
		assert.NoError(t, err)
	})

	t.Run("textDocument/didOpen", func(t *testing.T) {
		didOpenParams := sglsp.DidOpenTextDocumentParams{
			TextDocument: sglsp.TextDocumentItem{
				URI: uri.PathToUri(outsideFilePath),
			},
		}

		_, err := loc.Client.Call(t.Context(), "textDocument/didOpen", didOpenParams)
		assert.NoError(t, err)
	})
}
