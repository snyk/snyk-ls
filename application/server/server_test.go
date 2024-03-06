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
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/handler"
	"github.com/creachadair/jrpc2/server"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/infrastructure/cli/install"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/internal/lsp"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/uri"
)

const maxIntegTestDuration = 45 * time.Minute

var (
	ctx               = context.Background()
	jsonRPCRecorder   = testutil.JsonRPCRecorder{}
	supportedCommands = []string{
		snyk.WorkspaceScanCommand,
		snyk.OpenBrowserCommand,
		snyk.NavigateToRangeCommand,
		snyk.LoginCommand,
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

func setupServer(t *testing.T) server.Local {
	t.Helper()
	return setupCustomServer(t, nil)
}

func setupServerWithCustomDI(t *testing.T, useMocks bool) server.Local {
	t.Helper()
	s := setupCustomServer(t, nil)
	if !useMocks {
		di.Init()
	}
	return s
}

func setupCustomServer(t *testing.T, callBackFn onCallbackFn) server.Local {
	t.Helper()
	testutil.UnitTest(t)
	loc := startServer(callBackFn)
	di.TestInit(t)
	jsonRPCRecorder.ClearCallbacks()
	jsonRPCRecorder.ClearNotifications()
	cleanupChannels()

	t.Cleanup(func() {
		err := loc.Close()
		if err != nil {
			log.Error().Err(err).Msg("Error when closing down server")
		}
		cleanupChannels()
		jsonRPCRecorder.ClearCallbacks()
		jsonRPCRecorder.ClearNotifications()
	})
	return loc
}

func cleanupChannels() {
	disposeProgressListener()
	progress.CleanupChannels()
	di.HoverService().ClearAllHovers()
}

type onCallbackFn = func(ctx context.Context, request *jrpc2.Request) (any, error)

func startServer(callBackFn onCallbackFn) server.Local {
	var srv *jrpc2.Server

	opts := &server.LocalOptions{
		Client: &jrpc2.ClientOptions{
			OnNotify: func(request *jrpc2.Request) {
				jsonRPCRecorder.Record(*request)
			},
			OnCallback: func(ctx context.Context, request *jrpc2.Request) (any, error) {
				if callBackFn != nil {
					return callBackFn(ctx, request)
				}

				jsonRPCRecorder.Record(*request)
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
	initHandlers(c, srv, handlers)

	return loc
}

func Test_serverShouldStart(t *testing.T) {
	loc := setupServer(t)

	si := loc.Server.ServerInfo()

	fmt.Println(strings.Join(si.Methods, "\n"))
}

func Test_dummy_shouldNotBeServed(t *testing.T) {
	loc := setupServer(t)

	_, err := loc.Client.Call(ctx, "dummy", nil)
	if err == nil {
		t.Fatal(err, "call succeeded")
	}
}

func Test_initialize_shouldBeServed(t *testing.T) {
	loc := setupServer(t)

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
	loc := setupServer(t)

	rsp, err := loc.Client.Call(ctx, "shutdown", nil)
	assert.NoError(t, err)
	assert.NotNil(t, rsp)
}

func Test_initialize_containsServerInfo(t *testing.T) {
	loc := setupServer(t)

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

func Test_initialize_shouldDefaultToTokenAuthentication(t *testing.T) {
	loc := setupServer(t)

	_, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, lsp.TokenAuthentication, config.CurrentConfig().AuthenticationMethod())
	assert.Equal(t, "*snyk.FakeAuthenticationProvider", reflect.TypeOf(di.AuthenticationService().Provider()).String())
}

func Test_initialize_shouldInitToOauthAuthenticationWhenConfigured(t *testing.T) {
	loc := setupServer(t)

	settings := lsp.Settings{AuthenticationMethod: lsp.OAuthAuthentication}

	_, err := loc.Client.Call(ctx, "initialize", lsp.InitializeParams{InitializationOptions: settings})
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, lsp.OAuthAuthentication, config.CurrentConfig().AuthenticationMethod())
	assert.Equal(t, "*oauth.oAuthProvider", reflect.TypeOf(di.AuthenticationService().Provider()).String())
}

func Test_initialize_shouldInitToTokenAuthenticationWhenConfigured(t *testing.T) {
	loc := setupServer(t)

	settings := lsp.Settings{AuthenticationMethod: lsp.OAuthAuthentication}

	_, err := loc.Client.Call(ctx, "initialize", lsp.InitializeParams{InitializationOptions: settings})
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "*oauth.oAuthProvider", reflect.TypeOf(di.AuthenticationService().Provider()).String())

	_, err = loc.Client.Call(ctx,
		"workspace/didChangeConfiguration",
		lsp.DidChangeConfigurationParams{Settings: lsp.Settings{AuthenticationMethod: lsp.TokenAuthentication}})
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, lsp.TokenAuthentication, config.CurrentConfig().AuthenticationMethod())
	assert.Equal(t, "*auth.CliAuthenticationProvider", reflect.TypeOf(di.AuthenticationService().Provider()).String())
}

func Test_initialize_shouldSupportAllCommands(t *testing.T) {
	loc := setupServer(t)

	rsp, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	var result lsp.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		t.Fatal(err)
	}

	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, snyk.NavigateToRangeCommand)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, snyk.WorkspaceScanCommand)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, snyk.WorkspaceFolderScanCommand)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, snyk.OpenBrowserCommand)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, snyk.LoginCommand)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, snyk.CopyAuthLinkCommand)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, snyk.LogoutCommand)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, snyk.TrustWorkspaceFoldersCommand)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, snyk.GetLearnLesson)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, snyk.OpenLearnLesson)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, snyk.GetSettingsSastEnabled)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, snyk.GetActiveUserCommand)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, snyk.CodeFixCommand)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, snyk.CodeSubmitFixFeedback)
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, snyk.CodeFixDiffsCommand)
}

func Test_initialize_shouldSupportDocumentSaving(t *testing.T) {
	loc := setupServer(t)

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
	loc := setupServer(t)

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
	loc := setupServer(t)

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
	loc := setupServer(t)
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
	loc := setupServer(t)
	didOpenParams, dir := didOpenTextParams(t)
	fakeAuthenticationProvider := di.AuthenticationService().Provider().(*snyk.FakeAuthenticationProvider)
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
			return workspace.Get().GetFolderContaining(path).DocumentDiagnosticsFromCache(path) != nil
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
	loc := setupServer(t)
	didOpenParams, dir := didOpenTextParams(t)
	fakeAuthenticationProvider := di.AuthenticationService().Provider().(*snyk.FakeAuthenticationProvider)
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
			return workspace.Get().GetFolderContaining(path).DocumentDiagnosticsFromCache(path) != nil
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
	loc := setupServer(t)

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

	loc := setupServer(t)
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

	loc := setupServer(t)
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
	loc := setupServer(t)

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
	loc := setupServer(t)
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
	loc := setupServer(t)

	scanner := &snyk.TestScanner{}
	workspace.Get().AddFolder(workspace.NewFolder("dummy",
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
		loc := setupServer(t)
		initializationOptions := lsp.Settings{}
		params := lsp.InitializeParams{InitializationOptions: initializationOptions}
		_, err := loc.Client.Call(ctx, "initialize", params)

		assert.Nil(t, err)
		assert.True(t, config.CurrentConfig().AutomaticAuthentication())
	})

	t.Run("Parses true value", func(t *testing.T) {
		loc := setupServer(t)
		initializationOptions := lsp.Settings{
			AutomaticAuthentication: "true",
		}
		params := lsp.InitializeParams{InitializationOptions: initializationOptions}
		_, err := loc.Client.Call(ctx, "initialize", params)

		assert.Nil(t, err)
		assert.True(t, config.CurrentConfig().AutomaticAuthentication())
	})

	t.Run("Parses false value", func(t *testing.T) {
		loc := setupServer(t)

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
	loc := setupServer(t)
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
	assert.Eventually(t, func() bool { return checkTrustMessageRequest() }, time.Second, time.Millisecond)
}

func Test_initialize_handlesUntrustedFoldersWhenAuthenticated(t *testing.T) {
	loc := setupServer(t)
	initializationOptions := lsp.Settings{
		EnableTrustedFoldersFeature: "true",
		Token:                       "token",
	}

	fakeAuthenticationProvider := di.AuthenticationService().Provider().(*snyk.FakeAuthenticationProvider)
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
	assert.Eventually(t, func() bool { return checkTrustMessageRequest() }, time.Second, time.Millisecond)
}

func Test_initialize_doesnotHandleUntrustedFolders(t *testing.T) {
	loc := setupServer(t)
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
	assert.Eventually(t, func() bool { return checkTrustMessageRequest() }, time.Second, time.Millisecond)
}

func Test_textDocumentDidSaveHandler_shouldAcceptDocumentItemAndPublishDiagnostics(t *testing.T) {
	loc := setupServer(t)
	config.CurrentConfig().SetSnykCodeEnabled(true)
	fakeAuthenticationProvider := di.AuthenticationService().Provider().(*snyk.FakeAuthenticationProvider)
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
		checkForPublishedDiagnostics(uri.PathFromUri(fileUri), -1),
		5*time.Second,
		50*time.Millisecond,
	)
}

func Test_textDocumentDidOpenHandler_shouldNotPublishIfNotCached(t *testing.T) {
	loc := setupServer(t)
	config.CurrentConfig().SetSnykCodeEnabled(true)
	_, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}

	filePath, fileDir := code.TempWorkdirWithVulnerabilities(t)

	didOpenParams := sglsp.DidOpenTextDocumentParams{TextDocument: sglsp.TextDocumentItem{
		URI: uri.PathToUri(filePath),
	}}

	folder := workspace.NewFolder(fileDir, "Test", di.Scanner(), di.HoverService(), di.ScanNotifier(), di.Notifier())
	workspace.Get().AddFolder(folder)

	_, err = loc.Client.Call(ctx, "textDocument/didOpen", didOpenParams)

	if err != nil {
		t.Fatal(err)
	}

	assert.False(t, folder.IsScanned())
}

func Test_textDocumentDidOpenHandler_shouldPublishIfCached(t *testing.T) {
	loc := setupServer(t)
	config.CurrentConfig().SetSnykCodeEnabled(true)
	fakeAuthenticationProvider := di.AuthenticationService().Provider().(*snyk.FakeAuthenticationProvider)
	fakeAuthenticationProvider.IsAuthenticated = true
	_, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}

	filePath, fileDir := code.TempWorkdirWithVulnerabilities(t)
	fileUri := sendFileSavedMessage(t, filePath, fileDir, loc)

	assert.Eventually(
		t,
		checkForPublishedDiagnostics(uri.PathFromUri(fileUri), 1),
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
		checkForPublishedDiagnostics(uri.PathFromUri(fileUri), 1),
		5*time.Second,
		time.Millisecond,
	)
}

func Test_textDocumentDidSave_manualScanningMode_doesNotScan(t *testing.T) {
	loc := setupServer(t)
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
		checkForPublishedDiagnostics(uri.PathFromUri(fileUri), -1),
		5*time.Second,
		50*time.Millisecond,
	)
}

func sendFileSavedMessage(t *testing.T, filePath, fileDir string, loc server.Local) sglsp.DocumentURI {
	t.Helper()
	didSaveParams := sglsp.DidSaveTextDocumentParams{
		TextDocument: sglsp.TextDocumentIdentifier{URI: uri.PathToUri(filePath)},
	}
	workspace.Get().AddFolder(workspace.NewFolder(fileDir,
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
	loc := setupServer(t)

	_, err := loc.Client.Call(ctx, "textDocument/willSaveWaitUntil", nil)
	if err != nil {
		t.Fatal(err)
	}
}

func Test_textDocumentWillSaveHandler_shouldBeServed(t *testing.T) {
	loc := setupServer(t)

	_, err := loc.Client.Call(ctx, "textDocument/willSave", nil)
	if err != nil {
		t.Fatal(err)
	}
}

func Test_workspaceDidChangeWorkspaceFolders_shouldProcessChanges(t *testing.T) {
	loc := setupServer(t)
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
	loc := setupServer(t)
	testutil.IntegTest(t)
	_, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	config.CurrentConfig().SetAutomaticScanning(false)

	expected := snyk.OpenBrowserCommand
	serviceMock := snyk.NewCommandServiceMock()
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

func Test_SmokeWorkspaceScanOssAndCode(t *testing.T) {
	ossFile := "package.json"
	codeFile := "app.js"
	runSmokeTest(t, "https://github.com/snyk-labs/nodejs-goof", "0336589", ossFile, codeFile)
}

func Test_SmokeWorkspaceScanIacAndCode(t *testing.T) {
	iacFile := "main.tf"
	codeFile := "app.js"
	runSmokeTest(t, "https://github.com/deepcodeg/snykcon-goof.git", "eba8407", iacFile, codeFile)
}

func Test_SmokeWorkspaceScanWithTwoUploadBatches(t *testing.T) {
	ossFile := ""
	codeFile := "maven-compat/src/test/java/org/apache/maven/repository/legacy/LegacyRepositorySystemTest.java"
	runSmokeTest(t, "https://github.com/apache/maven", "18725ec1e", ossFile, codeFile)
}

func runSmokeTest(t *testing.T, repo string, commit string, file1 string, file2 string) {
	t.Helper()
	loc := setupServer(t)
	testutil.SmokeTest(t)
	config.CurrentConfig().SetSnykCodeEnabled(true)
	config.CurrentConfig().SetSnykIacEnabled(true)
	config.CurrentConfig().SetSnykOssEnabled(true)
	jsonRPCRecorder.ClearCallbacks()
	jsonRPCRecorder.ClearNotifications()
	cleanupChannels()
	di.Init()

	var cloneTargetDir, err = setupCustomTestRepo(t, repo, commit)
	if err != nil {
		t.Fatal(err, "Couldn't setup test repo")
	}

	folder := lsp.WorkspaceFolder{
		Name: "Test Repo",
		Uri:  uri.PathToUri(cloneTargetDir),
	}

	clientParams := lsp.InitializeParams{
		WorkspaceFolders: []lsp.WorkspaceFolder{folder},
		InitializationOptions: lsp.Settings{
			Endpoint:                    os.Getenv("SNYK_API"),
			Token:                       os.Getenv("SNYK_TOKEN"),
			EnableTrustedFoldersFeature: "false",
			FilterSeverity:              lsp.DefaultSeverityFilter(),
		},
	}

	_, err = loc.Client.Call(ctx, "initialize", clientParams)
	if err != nil {
		t.Fatal(err, "Initialize failed")
	}
	_, err = loc.Client.Call(ctx, "initialized", nil)
	if err != nil {
		t.Fatal(err, "Initialized failed")
	}

	// wait till the whole workspace is scanned
	assert.Eventually(t, func() bool {
		f := workspace.Get().GetFolderContaining(cloneTargetDir)
		return f != nil && f.IsScanned()
	}, maxIntegTestDuration, 2*time.Millisecond)

	jsonRPCRecorder.ClearNotifications()
	var testPath string
	if file1 != "" {
		testPath = filepath.Join(cloneTargetDir, file1)
		textDocumentDidSave(t, &loc, testPath)
		// serve diagnostics from file scan
		assert.Eventually(t, checkForPublishedDiagnostics(testPath, -1), maxIntegTestDuration, 10*time.Millisecond)
	}

	jsonRPCRecorder.ClearNotifications()
	testPath = filepath.Join(cloneTargetDir, file2)
	textDocumentDidSave(t, &loc, testPath)

	assert.Eventually(t, checkForPublishedDiagnostics(testPath, -1), maxIntegTestDuration, 10*time.Millisecond)

	// check for snyk scan message & check autofix
	var notifications []jrpc2.Request
	var scanParams lsp.SnykScanParams
	assert.Eventually(t, func() bool {
		notifications = jsonRPCRecorder.FindNotificationsByMethod("$/snyk.scan")
		for _, n := range notifications {
			_ = n.UnmarshalParams(&scanParams)
			if scanParams.Product != "code" ||
				scanParams.FolderPath != uri.PathFromUri(folder.Uri) ||
				scanParams.Status != "success" {
				continue
			}
			return true
		}
		return false
	}, 10*time.Second, 10*time.Millisecond)

	if config.CurrentConfig().SnykCodeApi() != "https://deeproxy.snyk.io" {
		return
	}

	// check for autofix diff on mt-us
	assert.Greater(t, len(scanParams.Issues), 0)
	for _, issue := range scanParams.Issues {
		codeIssueData, ok := issue.AdditionalData.(map[string]interface{})
		if !ok || codeIssueData["hasAIFix"] == false {
			continue
		}
		call, err := loc.Client.Call(ctx, "workspace/executeCommand", sglsp.ExecuteCommandParams{
			Command:   snyk.CodeFixDiffsCommand,
			Arguments: []any{uri.PathToUri(scanParams.FolderPath), uri.PathToUri(issue.FilePath), issue.Id},
		})
		assert.NoError(t, err)
		var unifiedDiffs []code.AutofixUnifiedDiffSuggestion
		err = call.UnmarshalResult(&unifiedDiffs)
		assert.NoError(t, err)
		assert.Greater(t, len(unifiedDiffs), 0)
		// don't check for all issues, just the first
		break
	}
}

// Check if published diagnostics for given testPath match the expectedNumber.
// If expectedNumber == -1 assume check for expectedNumber > 0
func checkForPublishedDiagnostics(testPath string, expectedNumber int) func() bool {
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

func Test_IntegrationHoverResults(t *testing.T) {
	loc := setupServer(t)
	testutil.IntegTest(t)

	fakeAuthenticationProvider := di.AuthenticationService().Provider().(*snyk.FakeAuthenticationProvider)
	fakeAuthenticationProvider.IsAuthenticated = true

	var cloneTargetDir, err = setupCustomTestRepo(t, "https://github.com/snyk-labs/nodejs-goof", "0336589")
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
func Test_SmokeSnykCodeFileScan(t *testing.T) {
	loc := setupServer(t)
	testutil.SmokeTest(t)
	config.CurrentConfig().SetSnykCodeEnabled(true)
	jsonRPCRecorder.ClearCallbacks()
	jsonRPCRecorder.ClearNotifications()
	cleanupChannels()
	di.Init()

	var cloneTargetDir, err = setupCustomTestRepo(t, "https://github.com/snyk-labs/nodejs-goof", "0336589")
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
		InitializationOptions: lsp.Settings{
			Endpoint:                    os.Getenv("SNYK_API"),
			Token:                       os.Getenv("SNYK_TOKEN"),
			EnableTrustedFoldersFeature: "false",
			FilterSeverity:              lsp.DefaultSeverityFilter(),
		},
	}

	_, _ = loc.Client.Call(ctx, "initialize", clientParams)

	testPath := filepath.Join(cloneTargetDir, "app.js")

	w := workspace.Get()
	f := workspace.NewFolder(cloneTargetDir, "Test", di.Scanner(), di.HoverService(), di.ScanNotifier(), di.Notifier())
	w.AddFolder(f)

	_ = textDocumentDidSave(t, &loc, testPath)

	assert.Eventually(t, checkForPublishedDiagnostics(testPath, 6), maxIntegTestDuration, 10*time.Millisecond)
}

func textDocumentDidSave(t *testing.T, loc *server.Local, testPath string) sglsp.DidSaveTextDocumentParams {
	t.Helper()
	didSaveParams := sglsp.DidSaveTextDocumentParams{
		TextDocument: sglsp.TextDocumentIdentifier{
			URI: uri.PathToUri(testPath),
		},
	}

	_, err := loc.Client.Call(ctx, "textDocument/didSave", didSaveParams)
	if err != nil {
		t.Fatal(err, "Call failed")
	}

	return didSaveParams
}

func setupCustomTestRepo(t *testing.T, url string, targetCommit string) (string, error) {
	t.Helper()
	tempDir := t.TempDir()
	repoDir := "1"
	absoluteCloneRepoDir := filepath.Join(tempDir, repoDir)
	cmd := []string{"clone", url, repoDir}
	log.Debug().Interface("cmd", cmd).Msg("clone command")
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

	log.Debug().Msg(string(output))
	output, _ = reset.CombinedOutput()

	log.Debug().Msg(string(output))
	output, err = clean.CombinedOutput()

	log.Debug().Msg(string(output))
	return absoluteCloneRepoDir, err
}

//goland:noinspection ALL
func Test_MonitorClientProcess(t *testing.T) {
	testutil.IntegTest(t)
	testutil.NotOnWindows(t, "sleep doesn't exist on windows")
	// start process that just sleeps
	pidChan := make(chan int)
	go func() {
		cmd := exec.Command("sleep", "5")
		err := cmd.Start()
		if err != nil {
			log.Err(err).Msg("Couldn't sleep. Stopping test")
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
