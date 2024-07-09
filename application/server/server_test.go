/*
 * © 2022-2024 Snyk Limited
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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/handler"
	"github.com/creachadair/jrpc2/server"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/runtimeinfo"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/infrastructure/cli/cli_constants"
	"github.com/snyk/snyk-ls/infrastructure/cli/install"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/internal/lsp"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/ux"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

const maxIntegTestDuration = 45 * time.Minute

var (
	ctx               = context.Background()
	supportedCommands = []string{
		types.WorkspaceScanCommand,
		types.OpenBrowserCommand,
		types.NavigateToRangeCommand,
		types.LoginCommand,
	}
)

func didOpenTextParams(t *testing.T) (sglsp.DidOpenTextDocumentParams, string) {
	t.Helper()
	filePath, dirPath := code.TempWorkdirWithVulnerabilities(t)
	didOpenParams := sglsp.DidOpenTextDocumentParams{
		TextDocument: sglsp.TextDocumentItem{URI: uri.PathToUri(filePath)},
	}

	return didOpenParams, dirPath
}

func setupServer(t *testing.T) (server.Local, *testutil.JsonRPCRecorder) {
	t.Helper()
	return setupCustomServer(t, nil)
}

func setupServerWithCustomDI(t *testing.T, useMocks bool) (server.Local, *testutil.JsonRPCRecorder) {
	t.Helper()
	s, jsonRPCRecorder := setupCustomServer(t, nil)
	if !useMocks {
		di.Init()
	}
	return s, jsonRPCRecorder
}

func setupCustomServer(t *testing.T, callBackFn onCallbackFn) (server.Local, *testutil.JsonRPCRecorder) {
	t.Helper()
	c := testutil.UnitTest(t)
	jsonRPCRecorder := &testutil.JsonRPCRecorder{}
	loc := startServer(callBackFn, jsonRPCRecorder)
	di.TestInit(t)
	cleanupChannels()

	t.Cleanup(func() {
		err := loc.Close()
		if err != nil {
			c.Logger().Error().Err(err).Msg("Error when closing down server")
		}
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

type onCallbackFn = func(ctx context.Context, request *jrpc2.Request) (any, error)

func startServer(callBackFn onCallbackFn, jsonRPCRecorder *testutil.JsonRPCRecorder) server.Local {
	var srv *jrpc2.Server

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
			AllowPush: true,
		},
	}

	handlers := handler.Map{}
	loc := server.NewLocal(handlers, opts)
	srv = loc.Server

	c := config.CurrentConfig()
	c.SetLogLevel(zerolog.LevelDebugValue)
	// we don't want lsp logging in test runs
	c.ConfigureLogging(nil)

	// the learn service isnt needed as the smoke tests use it directly
	initHandlers(srv, handlers)

	return loc
}

func Test_serverShouldStart(t *testing.T) {
	loc, _ := setupServer(t)

	si := loc.Server.ServerInfo()

	fmt.Println(strings.Join(si.Methods, "\n"))
}

func Test_dummy_shouldNotBeServed(t *testing.T) {
	loc, _ := setupServer(t)

	_, err := loc.Client.Call(ctx, "dummy", nil)
	if err == nil {
		t.Fatal(err, "call succeeded")
	}
}

func Test_initialize_shouldBeServed(t *testing.T) {
	loc, _ := setupServer(t)

	rsp, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	var result lsp.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		t.Fatal(err)
	}
}

func Test_shutdown_shouldBeServed(t *testing.T) {
	loc, _ := setupServer(t)

	rsp, err := loc.Client.Call(ctx, "shutdown", nil)
	assert.NoError(t, err)
	assert.NotNil(t, rsp)
}

func Test_initialize_containsServerInfo(t *testing.T) {
	loc, _ := setupServer(t)

	rsp, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	var result lsp.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, config.LsProtocolVersion, result.ServerInfo.Version)
}

func Test_initialized_shouldCheckRequiredProtocolVersion(t *testing.T) {
	loc, jsonRpcRecorder := setupServer(t)

	params := lsp.InitializeParams{
		InitializationOptions: lsp.Settings{RequiredProtocolVersion: "22"},
	}

	config.LsProtocolVersion = "12"

	rsp, err := loc.Client.Call(ctx, "initialize", params)
	require.NoError(t, err)
	var result lsp.InitializeResult
	err = rsp.UnmarshalResult(&result)
	require.NoError(t, err)

	_, err = loc.Client.Call(ctx, "initialized", params)
	require.NoError(t, err)
	assert.Eventuallyf(t, func() bool {
		callbacks := jsonRpcRecorder.Callbacks()
		return len(callbacks) > 0
	}, time.Second*10, time.Millisecond,
		"did not receive callback because of wrong protocol version")
}

func Test_initialize_shouldSupportAllCommands(t *testing.T) {
	loc, _ := setupServer(t)

	rsp, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	var result lsp.InitializeResult
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
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, types.OpenLearnLesson)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, types.GetSettingsSastEnabled)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, types.GetFeatureFlagStatus)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, types.GetActiveUserCommand)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, types.CodeFixCommand)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, types.CodeSubmitFixFeedback)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, types.CodeFixDiffsCommand)
}

func Test_initialize_shouldSupportDocumentSaving(t *testing.T) {
	loc, _ := setupServer(t)

	rsp, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	var result lsp.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, result.Capabilities.TextDocumentSync.Options.Save, &sglsp.SaveOptions{IncludeText: true})
	assert.Equal(t, result.Capabilities.TextDocumentSync.Options.WillSave, true)
	assert.Equal(t, result.Capabilities.TextDocumentSync.Options.WillSaveWaitUntil, true)
}

func Test_initialize_shouldSupportCodeLenses(t *testing.T) {
	loc, _ := setupServer(t)

	rsp, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	var result lsp.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, result.Capabilities.CodeLensProvider.ResolveProvider, false)
}

func Test_initialized_shouldInitializeAndTriggerCliDownload(t *testing.T) {
	loc, _ := setupServer(t)

	settings := lsp.Settings{ManageBinariesAutomatically: "true", CliPath: filepath.Join(t.TempDir(), "notexistent")}

	_, err := loc.Client.Call(ctx, "initialize", lsp.InitializeParams{InitializationOptions: settings})
	if err != nil {
		t.Fatal(err)
	}
	_, err = loc.Client.Call(ctx, "initialized", nil)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, 1, di.Installer().(*install.FakeInstaller).Installs())
}

func Test_initialized_shouldRedactToken(t *testing.T) {
	loc, _ := setupServer(t)
	oldStdErr := os.Stderr
	file, err := os.Create(filepath.Join(t.TempDir(), "stderr"))
	require.NoError(t, err)

	t.Cleanup(func() {
		os.Stderr = oldStdErr
		_ = file.Close()
	})

	toBeRedacted := "uhuhuhu"
	settings := lsp.Settings{Token: toBeRedacted}

	os.Stderr, _ = file, err

	_, err = loc.Client.Call(ctx, "initialize", lsp.InitializeParams{InitializationOptions: settings})
	if err != nil {
		t.Fatal(err)
	}

	os.Stderr = oldStdErr
	actual, err := os.ReadFile(file.Name())
	require.NoError(t, err)
	require.NotContainsf(t, string(actual), toBeRedacted, "token should be redacted")
}

func Test_TextDocumentCodeLenses_shouldReturnCodeLenses(t *testing.T) {
	testutil.IntegTest(t) // this needs an authenticated user
	loc, _ := setupServer(t)
	didOpenParams, dir := didOpenTextParams(t)
	fakeAuthenticationProvider := di.AuthenticationService().Providers()[0].(*authentication.FakeAuthenticationProvider)
	fakeAuthenticationProvider.IsAuthenticated = true

	clientParams := lsp.InitializeParams{
		RootURI: uri.PathToUri(dir),
		InitializationOptions: lsp.Settings{
			ActivateSnykCode:            "true",
			ActivateSnykOpenSource:      "false",
			ActivateSnykIac:             "false",
			Organization:                "fancy org",
			Token:                       "xxx",
			ManageBinariesAutomatically: "true",
			CliPath:                     "",
			FilterSeverity:              lsp.DefaultSeverityFilter(),
			EnableTrustedFoldersFeature: "false",
		},
	}
	_, err := loc.Client.Call(ctx, "initialize", clientParams)
	if err != nil {
		t.Fatal(err, "couldn't initialize")
	}
	_, err = loc.Client.Call(ctx, "initialized", nil)
	if err != nil {
		t.Fatal(err, "couldn't send initialized")
	}

	// wait for publish
	assert.Eventually(
		t,
		func() bool {
			path := uri.PathFromUri(didOpenParams.TextDocument.URI)
			return workspace.Get().GetFolderContaining(path).IssuesForFile(path) != nil
		},
		50*time.Second,
		time.Millisecond,
		"Couldn't get diagnostics from cache",
	)

	rsp, _ := loc.Client.Call(ctx, "textDocument/codeLens", sglsp.CodeLensParams{
		TextDocument: sglsp.TextDocumentIdentifier{
			URI: didOpenParams.TextDocument.URI,
		},
	})

	var lenses []sglsp.CodeLens
	if err := rsp.UnmarshalResult(&lenses); err != nil {
		t.Fatal(err)
	}
	assert.NotNil(t, lenses)
	assert.Len(t, lenses, 2)
	assert.Equal(t, lenses[0].Command.Command, code.FakeCommand.CommandId)
}

func Test_TextDocumentCodeLenses_dirtyFileShouldFilterCodeFixLenses(t *testing.T) {
	testutil.IntegTest(t) // this needs an authenticated user
	loc, _ := setupServer(t)
	didOpenParams, dir := didOpenTextParams(t)
	fakeAuthenticationProvider := di.AuthenticationService().Providers()[0].(*authentication.FakeAuthenticationProvider)
	fakeAuthenticationProvider.IsAuthenticated = true

	clientParams := lsp.InitializeParams{
		RootURI: uri.PathToUri(dir),
		InitializationOptions: lsp.Settings{
			ActivateSnykCode:            "true",
			ActivateSnykOpenSource:      "false",
			ActivateSnykIac:             "false",
			Organization:                "fancy org",
			Token:                       "xxx",
			ManageBinariesAutomatically: "true",
			CliPath:                     "",
			FilterSeverity:              lsp.DefaultSeverityFilter(),
			EnableTrustedFoldersFeature: "false",
		},
	}
	_, err := loc.Client.Call(ctx, "initialize", clientParams)
	if err != nil {
		t.Fatal(err, "couldn't initialize")
	}
	_, err = loc.Client.Call(ctx, "initialized", nil)
	if err != nil {
		t.Fatal(err, "couldn't send initialized")
	}

	// wait for publish
	assert.Eventually(
		t,
		func() bool {
			path := uri.PathFromUri(didOpenParams.TextDocument.URI)
			return workspace.Get().GetFolderContaining(path).IssuesForFile(path) != nil
		},
		50*time.Second,
		time.Millisecond,
		"Couldn't get diagnostics from cache",
	)

	// fake edit the file under test
	di.FileWatcher().SetFileAsChanged(didOpenParams.TextDocument.URI)

	rsp, _ := loc.Client.Call(ctx, "textDocument/codeLens", sglsp.CodeLensParams{
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
	assert.Equal(t, lenses[0].Command.Command, code.FakeCommand.CommandId)
}

func Test_initialize_updatesSettings(t *testing.T) {
	loc, _ := setupServer(t)

	orgUuid, _ := uuid.NewRandom()
	expectedOrgId := orgUuid.String()

	clientParams := lsp.InitializeParams{
		InitializationOptions: lsp.Settings{
			Organization:   expectedOrgId,
			Token:          "xxx",
			FilterSeverity: lsp.DefaultSeverityFilter(),
		},
	}

	rsp, err := loc.Client.Call(ctx, "initialize", clientParams)
	if err != nil {
		t.Fatal(err)
	}
	var result lsp.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, expectedOrgId, config.CurrentConfig().Organization())
	assert.Equal(t, "xxx", config.CurrentConfig().Token())
}

func Test_initialize_integrationInInitializationOptions_readFromInitializationOptions(t *testing.T) {
	// Arrange
	const expectedIntegrationName = "ECLIPSE"
	const expectedIntegrationVersion = "0.0.1rc1"

	// The info in initializationOptions takes priority over env-vars
	t.Setenv(cli.IntegrationNameEnvVarKey, "NOT_"+expectedIntegrationName)
	t.Setenv(cli.IntegrationVersionEnvVarKey, "NOT_"+expectedIntegrationVersion)

	loc, _ := setupServer(t)
	clientParams := lsp.InitializeParams{
		InitializationOptions: lsp.Settings{
			IntegrationName:    expectedIntegrationName,
			IntegrationVersion: expectedIntegrationVersion,
		},
		ClientInfo: sglsp.ClientInfo{ // the info in initializationOptions takes priority over ClientInfo
			Name:    "NOT_" + expectedIntegrationName,
			Version: "NOT_" + expectedIntegrationVersion,
		},
	}

	// Act
	_, err := loc.Client.Call(ctx, "initialize", clientParams)
	if err != nil {
		t.Fatal(err)
	}

	// Assert
	currentConfig := config.CurrentConfig()
	assert.Equal(t, expectedIntegrationName, currentConfig.IntegrationName())
	assert.Equal(t, expectedIntegrationVersion, currentConfig.IntegrationVersion())
}

func Test_initialize_integrationInClientInfo_readFromClientInfo(t *testing.T) {
	// Arrange
	const expectedIntegrationName = "ECLIPSE"
	const expectedIntegrationVersion = "8.0.0ServicePack92-preview4"
	const expectedIdeVersion = "0.0.1rc1"

	// The data in clientInfo takes priority over env-vars
	t.Setenv(cli.IntegrationNameEnvVarKey, "NOT_"+expectedIntegrationName)
	t.Setenv(cli.IntegrationVersionEnvVarKey, "NOT_"+expectedIdeVersion)

	loc, _ := setupServer(t)
	clientParams := lsp.InitializeParams{
		ClientInfo: sglsp.ClientInfo{
			Name:    expectedIntegrationName,
			Version: expectedIdeVersion,
		},
		InitializationOptions: lsp.Settings{
			IntegrationName:    expectedIntegrationName,
			IntegrationVersion: expectedIntegrationVersion,
		},
	}

	// Act
	_, err := loc.Client.Call(ctx, "initialize", clientParams)
	if err != nil {
		t.Fatal(err)
	}

	// Assert
	currentConfig := config.CurrentConfig()
	assert.Equal(t, expectedIntegrationName, currentConfig.IntegrationName())
	assert.Equal(t, expectedIntegrationVersion, currentConfig.IntegrationVersion())
	assert.Equal(t, expectedIdeVersion, currentConfig.IdeVersion())
}

func Test_initialize_integrationOnlyInEnvVars_readFromEnvVars(t *testing.T) {
	// Arrange
	const expectedIntegrationName = "ECLIPSE"
	const expectedIntegrationVersion = "0.0.1rc1"

	t.Setenv(cli.IntegrationNameEnvVarKey, expectedIntegrationName)
	t.Setenv(cli.IntegrationVersionEnvVarKey, expectedIntegrationVersion)
	loc, _ := setupServer(t)

	// Act
	_, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Assert
	currentConfig := config.CurrentConfig()
	assert.Equal(t, expectedIntegrationName, currentConfig.IntegrationName())
	assert.Equal(t, expectedIntegrationVersion, currentConfig.IntegrationVersion())
}

func Test_initialize_callsInitializeOnAnalytics(t *testing.T) {
	// Analytics should be initialized only after the "initialize" message was received from the client.
	// The "initialize" message contains the IDE data that's used in the "Plugin is installed" event.

	// Arrange
	loc, _ := setupServer(t)
	params := lsp.InitializeParams{
		ClientInfo: sglsp.ClientInfo{
			Name:    "ECLIPSE",
			Version: "1.0.0",
		},
	}
	analytics := di.Analytics().(*ux.TestAnalytics)
	assert.False(t, analytics.Initialized)

	// Act
	_, err := loc.Client.Call(ctx, "initialize", params)
	if err != nil {
		t.Fatal(err)
	}

	// Assert
	assert.True(t, analytics.Initialized)
}

func Test_initialize_shouldOfferAllCommands(t *testing.T) {
	loc, _ := setupServer(t)
	c := config.CurrentConfig()

	scanner := &snyk.TestScanner{}
	workspace.Get().AddFolder(workspace.NewFolder(c, "dummy",
		"dummy",
		scanner,
		di.HoverService(),
		di.ScanNotifier(),
		di.Notifier()))

	rsp, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	var result lsp.InitializeResult
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
		loc, _ := setupServer(t)
		initializationOptions := lsp.Settings{}
		params := lsp.InitializeParams{InitializationOptions: initializationOptions}
		_, err := loc.Client.Call(ctx, "initialize", params)

		assert.Nil(t, err)
		assert.True(t, config.CurrentConfig().AutomaticAuthentication())
	})

	t.Run("Parses true value", func(t *testing.T) {
		loc, _ := setupServer(t)
		initializationOptions := lsp.Settings{
			AutomaticAuthentication: "true",
		}
		params := lsp.InitializeParams{InitializationOptions: initializationOptions}
		_, err := loc.Client.Call(ctx, "initialize", params)

		assert.Nil(t, err)
		assert.True(t, config.CurrentConfig().AutomaticAuthentication())
	})

	t.Run("Parses false value", func(t *testing.T) {
		loc, _ := setupServer(t)

		initializationOptions := lsp.Settings{
			AutomaticAuthentication: "false",
		}
		params := lsp.InitializeParams{InitializationOptions: initializationOptions}
		_, err := loc.Client.Call(ctx, "initialize", params)
		assert.Nil(t, err)
		assert.False(t, config.CurrentConfig().AutomaticAuthentication())
	})
}

func Test_initialize_handlesUntrustedFoldersWhenAutomaticAuthentication(t *testing.T) {
	loc, jsonRPCRecorder := setupServer(t)
	initializationOptions := lsp.Settings{
		EnableTrustedFoldersFeature: "true",
	}
	params := lsp.InitializeParams{
		InitializationOptions: initializationOptions,
		WorkspaceFolders:      []lsp.WorkspaceFolder{{Uri: uri.PathToUri("/untrusted/dummy"), Name: "dummy"}}}
	_, err := loc.Client.Call(ctx, "initialize", params)
	if err != nil {
		t.Fatal(err, "couldn't send initialized")
	}

	_, err = loc.Client.Call(ctx, "initialized", nil)
	if err != nil {
		t.Fatal(err, "couldn't send initialized")
	}

	assert.Nil(t, err)
	assert.Eventually(t, func() bool { return checkTrustMessageRequest(jsonRPCRecorder) }, time.Second, time.Millisecond)
}

func Test_initialize_handlesUntrustedFoldersWhenAuthenticated(t *testing.T) {
	loc, jsonRPCRecorder := setupServer(t)
	initializationOptions := lsp.Settings{
		EnableTrustedFoldersFeature: "true",
		Token:                       "token",
	}

	fakeAuthenticationProvider := di.AuthenticationService().Providers()[0].(*authentication.FakeAuthenticationProvider)
	fakeAuthenticationProvider.IsAuthenticated = true

	params := lsp.InitializeParams{
		InitializationOptions: initializationOptions,
		WorkspaceFolders:      []lsp.WorkspaceFolder{{Uri: uri.PathToUri("/untrusted/dummy"), Name: "dummy"}}}
	_, err := loc.Client.Call(ctx, "initialize", params)
	if err != nil {
		t.Fatal(err, "couldn't send initialized")
	}

	_, err = loc.Client.Call(ctx, "initialized", nil)
	if err != nil {
		t.Fatal(err, "couldn't send initialized")
	}

	assert.Nil(t, err)
	assert.Eventually(t, func() bool { return checkTrustMessageRequest(jsonRPCRecorder) }, time.Second, time.Millisecond)
}

func Test_initialize_doesnotHandleUntrustedFolders(t *testing.T) {
	loc, jsonRPCRecorder := setupServer(t)
	initializationOptions := lsp.Settings{
		EnableTrustedFoldersFeature: "true",
	}
	params := lsp.InitializeParams{
		InitializationOptions: initializationOptions,
		WorkspaceFolders:      []lsp.WorkspaceFolder{{Uri: uri.PathToUri("/untrusted/dummy"), Name: "dummy"}}}
	_, err := loc.Client.Call(ctx, "initialize", params)
	if err != nil {
		t.Fatal(err, "couldn't send initialized")
	}
	_, err = loc.Client.Call(ctx, "initialized", nil)
	if err != nil {
		t.Fatal(err, "couldn't send initialized")
	}

	assert.NoError(t, err)
	assert.Eventually(t, func() bool { return checkTrustMessageRequest(jsonRPCRecorder) }, time.Second, time.Millisecond)
}

func Test_textDocumentDidSaveHandler_shouldAcceptDocumentItemAndPublishDiagnostics(t *testing.T) {
	loc, jsonRPCRecorder := setupServer(t)
	config.CurrentConfig().SetSnykCodeEnabled(true)
	fakeAuthenticationProvider := di.AuthenticationService().Providers()[0].(*authentication.FakeAuthenticationProvider)
	fakeAuthenticationProvider.IsAuthenticated = true

	_, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}

	filePath, fileDir := code.TempWorkdirWithVulnerabilities(t)
	fileUri := sendFileSavedMessage(t, filePath, fileDir, loc)

	// wait for publish
	assert.Eventually(
		t,
		checkForPublishedDiagnostics(t, uri.PathFromUri(fileUri), -1, jsonRPCRecorder),
		5*time.Second,
		50*time.Millisecond,
	)
}

func createTemporaryDirectoryWithSnykFile(t *testing.T) (snykFilePath string, folderPath string) {
	t.Helper()

	temp := t.TempDir()
	temp = filepath.Clean(temp)
	temp, err := filepath.Abs(temp)
	if err != nil {
		t.Fatalf("couldn't get abs folder path of temp dir: %v", err)
	}

	snykFilePath = filepath.Join(temp, ".snyk")
	yamlContent := `
ignore:
  SNYK-JS-QS-3153490:
    - '*':
        reason: Ignore me 30 days
        expires: 2024-08-26T13:55:05.414Z
        created: 2024-07-26T13:55:05.417Z
patch: {}
`
	err = os.WriteFile(snykFilePath, []byte(yamlContent), 0600)
	assert.NoError(t, err)
	return snykFilePath, temp
}

func Test_textDocumentDidSaveHandler_shouldTriggerScanForDotSnykFile(t *testing.T) {
	loc, jsonRPCRecorder := setupServer(t)
	c := config.CurrentConfig()
	c.SetSnykCodeEnabled(false)
	c.SetAuthenticationMethod(lsp.FakeAuthentication)
	di.AuthenticationService().ConfigureProviders(c)

	fakeAuthenticationProvider := di.AuthenticationService().Providers()[0]
	fakeAuthenticationProvider.(*authentication.FakeAuthenticationProvider).IsAuthenticated = true

	_, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatalf("initialization failed: %v", err)
	}

	snykFilePath, folderPath := createTemporaryDirectoryWithSnykFile(t)

	sendFileSavedMessage(t, snykFilePath, folderPath, loc)

	// Wait for $/snyk.scan notification
	assert.Eventually(
		t,
		checkForSnykScan(t, jsonRPCRecorder),
		5*time.Second,
		50*time.Millisecond,
	)
}

func Test_textDocumentDidOpenHandler_shouldNotPublishIfNotCached(t *testing.T) {
	loc, _ := setupServer(t)
	c := config.CurrentConfig()
	c.SetSnykCodeEnabled(true)
	_, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}

	filePath, fileDir := code.TempWorkdirWithVulnerabilities(t)

	didOpenParams := sglsp.DidOpenTextDocumentParams{TextDocument: sglsp.TextDocumentItem{
		URI: uri.PathToUri(filePath),
	}}

	folder := workspace.NewFolder(c, fileDir, "Test", di.Scanner(), di.HoverService(), di.ScanNotifier(), di.Notifier())
	workspace.Get().AddFolder(folder)

	_, err = loc.Client.Call(ctx, "textDocument/didOpen", didOpenParams)

	if err != nil {
		t.Fatal(err)
	}

	assert.False(t, folder.IsScanned())
}

func Test_textDocumentDidOpenHandler_shouldPublishIfCached(t *testing.T) {
	loc, jsonRPCRecorder := setupServer(t)
	config.CurrentConfig().SetSnykCodeEnabled(true)
	fakeAuthenticationProvider := di.AuthenticationService().Providers()[0].(*authentication.FakeAuthenticationProvider)
	fakeAuthenticationProvider.IsAuthenticated = true
	_, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}

	filePath, fileDir := code.TempWorkdirWithVulnerabilities(t)
	fileUri := sendFileSavedMessage(t, filePath, fileDir, loc)

	assert.Eventually(
		t,
		checkForPublishedDiagnostics(t, uri.PathFromUri(fileUri), 1, jsonRPCRecorder),
		time.Second,
		time.Millisecond,
	)

	jsonRPCRecorder.ClearNotifications()

	didOpenParams := sglsp.DidOpenTextDocumentParams{
		TextDocument: sglsp.TextDocumentItem{
			URI:     fileUri,
			Version: 1,
			Text:    "",
		}}

	_, err = loc.Client.Call(ctx, textDocumentDidOpenOperation, didOpenParams)

	if err != nil {
		t.Fatal(err)
	}

	assert.Eventually(
		t,
		checkForPublishedDiagnostics(t, uri.PathFromUri(fileUri), 1, jsonRPCRecorder),
		5*time.Second,
		time.Millisecond,
	)
}

func Test_textDocumentDidSave_manualScanningMode_doesNotScan(t *testing.T) {
	loc, jsonRPCRecorder := setupServer(t)
	config.CurrentConfig().SetSnykCodeEnabled(true)
	_, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	config.CurrentConfig().SetAutomaticScanning(false)

	filePath, fileDir := code.TempWorkdirWithVulnerabilities(t)
	fileUri := sendFileSavedMessage(t, filePath, fileDir, loc)

	assert.Never(
		t,
		checkForPublishedDiagnostics(t, uri.PathFromUri(fileUri), -1, jsonRPCRecorder),
		5*time.Second,
		50*time.Millisecond,
	)
}

func sendFileSavedMessage(t *testing.T, filePath, fileDir string, loc server.Local) sglsp.DocumentURI {
	t.Helper()
	c := config.CurrentConfig()
	didSaveParams := sglsp.DidSaveTextDocumentParams{
		TextDocument: sglsp.TextDocumentIdentifier{URI: uri.PathToUri(filePath)},
	}
	workspace.Get().AddFolder(workspace.NewFolder(c, fileDir,
		"Test",
		di.Scanner(),
		di.HoverService(),
		di.ScanNotifier(),
		di.Notifier()))

	_, err := loc.Client.Call(ctx, textDocumentDidSaveOperation, didSaveParams)
	if err != nil {
		t.Fatal(err)
	}

	return didSaveParams.TextDocument.URI
}

func Test_textDocumentWillSaveWaitUntilHandler_shouldBeServed(t *testing.T) {
	loc, _ := setupServer(t)

	_, err := loc.Client.Call(ctx, "textDocument/willSaveWaitUntil", nil)
	if err != nil {
		t.Fatal(err)
	}
}

func Test_textDocumentWillSaveHandler_shouldBeServed(t *testing.T) {
	loc, _ := setupServer(t)

	_, err := loc.Client.Call(ctx, "textDocument/willSave", nil)
	if err != nil {
		t.Fatal(err)
	}
}

func Test_workspaceDidChangeWorkspaceFolders_shouldProcessChanges(t *testing.T) {
	loc, _ := setupServer(t)
	testutil.IntegTest(t)
	testutil.CreateDummyProgressListener(t)
	file := testutil.CreateTempFile(t, t.TempDir())
	w := workspace.Get()

	f := lsp.WorkspaceFolder{Name: filepath.Dir(file.Name()), Uri: uri.PathToUri(file.Name())}
	_, err := loc.Client.Call(ctx, "workspace/didChangeWorkspaceFolders", lsp.DidChangeWorkspaceFoldersParams{
		Event: lsp.WorkspaceFoldersChangeEvent{
			Added: []lsp.WorkspaceFolder{f},
		},
	})
	if err != nil {
		t.Fatal(err, "error calling server")
	}

	assert.Eventually(t, func() bool {
		folder := w.GetFolderContaining(uri.PathFromUri(f.Uri))
		return folder != nil && folder.IsScanned()
	}, 120*time.Second, time.Millisecond)

	_, err = loc.Client.Call(ctx, "workspace/didChangeWorkspaceFolders", lsp.DidChangeWorkspaceFoldersParams{
		Event: lsp.WorkspaceFoldersChangeEvent{
			Removed: []lsp.WorkspaceFolder{f},
		},
	})
	if err != nil {
		t.Fatal(err, "error calling server")
	}

	assert.Nil(t, w.GetFolderContaining(uri.PathFromUri(f.Uri)))
}

func Test_CodeActionResolve_ShouldExecuteCommands(t *testing.T) {
	loc, _ := setupServer(t)
	testutil.IntegTest(t)
	_, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	config.CurrentConfig().SetAutomaticScanning(false)

	expected := types.OpenBrowserCommand
	serviceMock := types.NewCommandServiceMock()
	command.SetService(serviceMock)

	_, err = loc.Client.Call(ctx, "codeAction/resolve", lsp.CodeAction{
		Title: "My super duper test action",
		Command: &sglsp.Command{
			Title:     expected,
			Command:   expected,
			Arguments: []any{"https://snyk.io"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, expected, serviceMock.ExecutedCommands()[0].CommandId)
}

// Check if published diagnostics for given testPath match the expectedNumber.
// If expectedNumber == -1 assume check for expectedNumber > 0
func checkForPublishedDiagnostics(t *testing.T, testPath string, expectedNumber int, jsonRPCRecorder *testutil.JsonRPCRecorder) func() bool {
	t.Helper()
	return func() bool {
		w := workspace.Get()
		notifications := jsonRPCRecorder.FindNotificationsByMethod("textDocument/publishDiagnostics")
		if len(notifications) < 1 {
			return false
		}
		for _, n := range notifications {
			diagnosticsParams := lsp.PublishDiagnosticsParams{}
			_ = n.UnmarshalParams(&diagnosticsParams)
			if diagnosticsParams.URI == uri.PathToUri(testPath) {
				f := w.GetFolderContaining(testPath)
				hasExpectedDiagnostics := f != nil && (expectedNumber == -1 && len(diagnosticsParams.Diagnostics) > 0) || (len(diagnosticsParams.Diagnostics) == expectedNumber)
				if hasExpectedDiagnostics {
					return true
				}
			}
		}
		return false
	}
}

func checkForSnykScan(t *testing.T, jsonRPCRecorder *testutil.JsonRPCRecorder) func() bool {
	t.Helper()
	return func() bool {
		notifications := jsonRPCRecorder.FindNotificationsByMethod("$/snyk.scan")
		return len(notifications) > 0
	}
}

func Test_IntegrationHoverResults(t *testing.T) {
	loc, _ := setupServer(t)
	c := testutil.IntegTest(t)

	fakeAuthenticationProvider := di.AuthenticationService().Providers()[0].(*authentication.FakeAuthenticationProvider)
	fakeAuthenticationProvider.IsAuthenticated = true

	var cloneTargetDir, err = setupCustomTestRepo(t, "https://github.com/snyk-labs/nodejs-goof", "0336589", c.Logger())
	defer func(path string) { _ = os.RemoveAll(path) }(cloneTargetDir)
	if err != nil {
		t.Fatal(err, "Couldn't setup test repo")
	}
	folder := lsp.WorkspaceFolder{
		Name: "Test Repo",
		Uri:  uri.PathToUri(cloneTargetDir),
	}
	clientParams := lsp.InitializeParams{
		WorkspaceFolders: []lsp.WorkspaceFolder{folder},
	}

	_, err = loc.Client.Call(ctx, "initialize", clientParams)
	if err != nil {
		t.Fatal(err, "Initialize failed")
	}
	_, err = loc.Client.Call(ctx, "initialized", clientParams)
	if err != nil {
		t.Fatal(err, "Initialized failed")
	}

	// wait till the whole workspace is scanned
	assert.Eventually(t, func() bool {
		w := workspace.Get()
		f := w.GetFolderContaining(cloneTargetDir)
		return f != nil && f.IsScanned()
	}, maxIntegTestDuration, 100*time.Millisecond)

	testPath := cloneTargetDir + string(os.PathSeparator) + "package.json"
	testPosition := sglsp.Position{
		Line:      17,
		Character: 7,
	}

	hoverResp, err := loc.Client.Call(ctx, "textDocument/hover", hover.Params{
		TextDocument: sglsp.TextDocumentIdentifier{URI: uri.PathToUri(testPath)},
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
		di.HoverService().GetHover(testPath, converter.FromPosition(testPosition)).Contents.Value)
	assert.Equal(t, hoverResult.Contents.Kind, "markdown")
}

func setupCustomTestRepo(t *testing.T, url string, targetCommit string, logger *zerolog.Logger) (string, error) {
	t.Helper()
	tempDir := t.TempDir()
	repoDir := "1"
	absoluteCloneRepoDir := filepath.Join(tempDir, repoDir)
	cmd := []string{"clone", url, repoDir}
	logger.Debug().Interface("cmd", cmd).Msg("clone command")
	clone := exec.Command("git", cmd...)
	clone.Dir = tempDir
	reset := exec.Command("git", "reset", "--hard", targetCommit)
	reset.Dir = absoluteCloneRepoDir

	clean := exec.Command("git", "clean", "--force")
	clean.Dir = absoluteCloneRepoDir

	output, err := clone.CombinedOutput()
	if err != nil {
		t.Fatal(err, "clone didn't work")
	}

	logger.Debug().Msg(string(output))
	output, _ = reset.CombinedOutput()

	logger.Debug().Msg(string(output))
	output, err = clean.CombinedOutput()

	logger.Debug().Msg(string(output))
	return absoluteCloneRepoDir, err
}

//goland:noinspection ALL
func Test_MonitorClientProcess(t *testing.T) {
	c := testutil.IntegTest(t)
	testutil.NotOnWindows(t, "sleep doesn't exist on windows")
	// start process that just sleeps
	pidChan := make(chan int)
	go func() {
		cmd := exec.Command("sleep", "5")
		err := cmd.Start()
		if err != nil {
			c.Logger().Err(err).Msg("Couldn't sleep. Stopping test")
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
		c := testutil.UnitTest(t)
		c.Engine().GetConfiguration().Set(cli_constants.EXECUTION_MODE_KEY, cli_constants.EXECUTION_MODE_VALUE_EXTENSION)

		downloadURL := getDownloadURL(c)

		// default CLI fallback, as we're not mocking the CLI calls
		assert.Contains(t, downloadURL, "cli")
	})

	t.Run("LS standalone", func(t *testing.T) {
		testutil.NotOnWindows(t, "don't want to handle the exe extension")
		c := testutil.UnitTest(t)
		engine := c.Engine()
		engine.GetConfiguration().Set(cli_constants.EXECUTION_MODE_KEY, cli_constants.EXECUTION_MODE_VALUE_STANDALONE)
		engine.SetRuntimeInfo(
			runtimeinfo.New(
				runtimeinfo.WithName("snyk-ls"),
				runtimeinfo.WithVersion("v1.234"),
			),
		)

		downloadURL := getDownloadURL(c)

		prefix := "https://static.snyk.io/snyk-ls/12/snyk-ls"
		assert.True(t, strings.HasPrefix(downloadURL, prefix), downloadURL+" does not start with "+prefix)
	})
}

func Test_handleProtocolVersion(t *testing.T) {
	t.Run("required != current", func(t *testing.T) {
		c := testutil.UnitTest(t)

		ourProtocolVersion := "12"
		reqProtocolVersion := "1"

		notificationReceived := make(chan bool)
		f := func(params any) {
			mrq, ok := params.(types.ShowMessageRequest)
			require.True(t, ok)
			require.Contains(t, mrq.Message, "does not match")
			notificationReceived <- true
		}
		testNotifier := notification.NewNotifier()
		go testNotifier.CreateListener(f)
		handleProtocolVersion(
			c,
			testNotifier,
			ourProtocolVersion,
			reqProtocolVersion,
		)

		assert.Eventuallyf(t, func() bool {
			return <-notificationReceived
		}, 10*time.Second, 10*time.Millisecond, "no message sent via notifier")
	})

	t.Run("required == current", func(t *testing.T) {
		c := testutil.UnitTest(t)
		ourProtocolVersion := "11"
		f := func(params any) {
			require.FailNow(t, "did not expect a message")
		}

		testNotifier := notification.NewNotifier()
		go testNotifier.CreateListener(f)

		handleProtocolVersion(
			c,
			testNotifier,
			ourProtocolVersion,
			ourProtocolVersion,
		)
		// give goroutine of callback function a chance to fail the test
		time.Sleep(time.Second)
	})
}
