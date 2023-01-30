/*
 * © 2022 Snyk Limited All rights reserved.
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
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/adrg/xdg"
	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/handler"
	"github.com/creachadair/jrpc2/server"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/observability/performance"
	"github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/infrastructure/cli/install"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/uri"
)

const maxIntegTestDuration = 15 * time.Minute

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
	filePath, dirPath := code.TempWorkdirWithVulnerabilities(t)
	didOpenParams := sglsp.DidOpenTextDocumentParams{
		TextDocument: sglsp.TextDocumentItem{URI: uri.PathToUri(filePath)},
	}

	return didOpenParams, dirPath
}

func setupServer(t *testing.T) server.Local {
	return setupCustomServer(t, nil)
}

func setupCustomServer(t *testing.T, callBackFn onCallbackFn) server.Local {
	testutil.UnitTest(t)
	di.TestInit(t)
	cleanupChannels()
	jsonRPCRecorder.ClearCallbacks()
	jsonRPCRecorder.ClearNotifications()
	workspace.Set(workspace.New(performance.NewTestInstrumentor(), di.Scanner(), di.HoverService(), di.ScanNotifier()))
	loc := startServer(callBackFn)

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
	notification.DisposeListener()
	disposeProgressListener()
	di.HoverService().ClearAllHovers()
}

type onCallbackFn = func(ctx context.Context, request *jrpc2.Request) (any, error)

func startServer(callBackFn onCallbackFn) server.Local {
	var srv *jrpc2.Server

	zerolog.SetGlobalLevel(zerolog.DebugLevel)

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

	handlers := &handler.Map{}
	loc := server.NewLocal(handlers, opts)
	srv = loc.Server
	initHandlers(srv, handlers)

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

func Test_initialize_shouldSupportDocumentOpening(t *testing.T) {
	loc := setupServer(t)

	rsp, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	var result lsp.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, result.Capabilities.TextDocumentSync.Options.OpenClose, true)
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

func Test_TextDocumentCodeLenses_shouldReturnCodeLenses(t *testing.T) {
	loc := setupServer(t)
	didOpenParams, dir := didOpenTextParams(t)

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
	assert.Len(t, lenses, 1)
	assert.Equal(t, lenses[0].Command.Command, code.FakeCommand.Command)
}

func Test_initialize_updatesSettings(t *testing.T) {
	loc := setupServer(t)

	clientParams := lsp.InitializeParams{
		InitializationOptions: lsp.Settings{
			Organization:   "fancy org",
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
	assert.Equal(t, "fancy org", config.CurrentConfig().GetOrganization())
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
	const expectedIntegrationVersion = "0.0.1rc1"

	// The data in clientInfo takes priority over env-vars
	t.Setenv(cli.IntegrationNameEnvVarKey, "NOT_"+expectedIntegrationName)
	t.Setenv(cli.IntegrationVersionEnvVarKey, "NOT_"+expectedIntegrationVersion)

	loc := setupServer(t)
	clientParams := lsp.InitializeParams{
		ClientInfo: sglsp.ClientInfo{
			Name:    expectedIntegrationName,
			Version: expectedIntegrationVersion,
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
	workspace.Get().AddFolder(workspace.NewFolder("dummy", "dummy", scanner, di.HoverService(), di.ScanNotifier()))

	rsp, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	var result lsp.InitializeResult
	err = rsp.UnmarshalResult(&result)
	if err != nil {
		t.Fatal(err)
	}

	for _, command := range supportedCommands {
		name := "Command \"" + command + "\" is supported"
		t.Run(name, func(t *testing.T) {
			assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, command)
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

func Test_textDocumentDidOpenHandler_shouldAcceptDocumentItemAndPublishDiagnostics(t *testing.T) {
	loc := setupServer(t)
	didOpenParams, dir := didOpenTextParams(t)

	clientParams := lsp.InitializeParams{
		RootURI: uri.PathToUri(dir),
		InitializationOptions: lsp.Settings{
			ActivateSnykCode:            "true",
			ActivateSnykOpenSource:      "false",
			ActivateSnykIac:             "false",
			Organization:                "fancy org",
			Token:                       "xxx",
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

	_, err = loc.Client.Call(ctx, "textDocument/didOpen", didOpenParams)
	if err != nil {
		t.Fatal(err)
	}

	// wait for publish
	assert.Eventually(
		t,
		checkForPublishedDiagnostics(uri.PathFromUri(didOpenParams.TextDocument.URI), -1),
		2*time.Second,
		10*time.Millisecond,
	)
}

func Test_textDocumentDidOpenHandler_shouldDownloadCLI(t *testing.T) {
	// Arrange
	loc := setupServer(t)
	testutil.IntegTest(t)
	testutil.CreateDummyProgressListener(t)

	installer := di.Installer()

	err := os.Unsetenv("SNYK_CLI_PATH")
	if err != nil {
		t.Fatal("couldn't unset environment variable SNYK_CLI_PATH")
	}

	didOpenParams, dir := didOpenTextParams(t)
	workspace.Get().AddFolder(workspace.NewFolder(dir, "test", di.Scanner(), di.HoverService(), di.ScanNotifier()))
	config.CurrentConfig().CliSettings().SetPath(t.TempDir() + "not-existing-cli")
	// Act
	_, err = loc.Client.Call(ctx, "textDocument/didOpen", didOpenParams)
	if err != nil {
		t.Fatal(err)
	}

	// Assert
	assert.Eventually(t, func() bool {
		return installer.(*install.FakeInstaller).Installs() > 0
	}, maxIntegTestDuration, 10*time.Millisecond)
}

func Test_textDocumentDidChangeHandler_shouldAcceptUri(t *testing.T) {
	loc := setupServer(t)

	// register our dummy document
	didOpenParams, dir := didOpenTextParams(t)

	workspace.Get().AddFolder(workspace.NewFolder(dir, "test", di.Scanner(), di.HoverService(), di.ScanNotifier()))

	_, err := loc.Client.Call(ctx, "textDocument/didOpen", didOpenParams)
	if err != nil {
		t.Fatal(err)
	}

	didChangeParams := sglsp.DidChangeTextDocumentParams{
		TextDocument: sglsp.VersionedTextDocumentIdentifier{
			TextDocumentIdentifier: sglsp.TextDocumentIdentifier{URI: didOpenParams.TextDocument.URI},
			Version:                0,
		},
		ContentChanges: nil,
	}

	_, err = loc.Client.Call(ctx, "textDocument/didChange", didChangeParams)
	if err != nil {
		t.Fatal(err)
	}
}

func Test_textDocumentDidSaveHandler_shouldAcceptDocumentItemAndPublishDiagnostics(t *testing.T) {
	loc := setupServer(t)
	config.CurrentConfig().SetSnykCodeEnabled(true)
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
	didSaveParams := sglsp.DidSaveTextDocumentParams{
		TextDocument: sglsp.TextDocumentIdentifier{URI: uri.PathToUri(filePath)},
	}
	workspace.Get().AddFolder(workspace.NewFolder(fileDir, "Test", di.Scanner(), di.HoverService(), di.ScanNotifier()))

	_, err := loc.Client.Call(ctx, "textDocument/didSave", didSaveParams)
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
	file := testutil.CreateTempFile(t.TempDir(), t)
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

func Test_SmokeWorkspaceScanOssAndCode(t *testing.T) {
	ossFile := "package.json"
	codeFile := "app.js"
	runSmokeTest("https://github.com/snyk-labs/nodejs-goof", "0336589", ossFile, codeFile, t)
}

func Test_SmokeWorkspaceScanIacAndCode(t *testing.T) {
	iacFile := "main.tf"
	codeFile := "app.js"
	runSmokeTest("https://github.com/deepcodeg/snykcon-goof.git", "eba8407", iacFile, codeFile, t)
}

func Test_SmokeWorkspaceScanWithTwoUploadBatches(t *testing.T) {
	ossFile := ""
	codeFile := "maven-compat/src/test/java/org/apache/maven/repository/legacy/LegacyRepositorySystemTest.java"
	runSmokeTest("https://github.com/apache/maven", "18725ec1e", ossFile, codeFile, t)
}

func runSmokeTest(repo string, commit string, file1 string, file2 string, t *testing.T) {
	loc := setupServer(t)
	testutil.SmokeTest(t)
	config.CurrentConfig().SetSnykCodeEnabled(true)
	config.CurrentConfig().SetSnykIacEnabled(true)
	config.CurrentConfig().SetSnykOssEnabled(true)
	jsonRPCRecorder.ClearCallbacks()
	jsonRPCRecorder.ClearNotifications()
	cleanupChannels()
	di.Init()

	var cloneTargetDir, err = setupCustomTestRepo(repo, commit, t)
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

	_, err = loc.Client.Call(ctx, "initialize", clientParams)
	if err != nil {
		t.Fatal(err, "Initialize failed")
	}
	_, err = loc.Client.Call(ctx, "initialized", nil)
	if err != nil {
		t.Fatal(err, "Initialized failed")
	}

	var testPath string
	if file1 != "" {
		testPath = filepath.Join(cloneTargetDir, file1)
		textDocumentDidOpen(&loc, testPath, t)
		// serve diagnostics from file scan
		assert.Eventually(t, checkForPublishedDiagnostics(testPath, -1), maxIntegTestDuration, 10*time.Millisecond)
	}

	// wait till the whole workspace is scanned
	assert.Eventually(t, func() bool {
		f := workspace.Get().GetFolderContaining(cloneTargetDir)
		return f != nil && f.IsScanned()
	}, maxIntegTestDuration, 2*time.Millisecond)

	testPath = filepath.Join(cloneTargetDir, file2)
	textDocumentDidOpen(&loc, testPath, t)

	assert.Eventually(t, checkForPublishedDiagnostics(testPath, -1), maxIntegTestDuration, 10*time.Millisecond)
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

	var cloneTargetDir, err = setupCustomTestRepo("https://github.com/snyk-labs/nodejs-goof", "0336589", t)
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

	assert.Equal(t, hoverResult.Contents.Value, di.HoverService().GetHover(uri.PathToUri(testPath), converter.FromPosition(testPosition)).Contents.Value)
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
	_, _ = loc.Client.Call(ctx, "initialize", nil)

	var cloneTargetDir, err = setupCustomTestRepo("https://github.com/snyk-labs/nodejs-goof", "0336589", t)
	defer func(path string) { _ = os.RemoveAll(path) }(cloneTargetDir)
	if err != nil {
		t.Fatal(err, "Couldn't setup test repo")
	}

	testPath := filepath.Join(cloneTargetDir, "app.js")

	w := workspace.Get()
	f := workspace.NewFolder(cloneTargetDir, "Test", di.Scanner(), di.HoverService(), di.ScanNotifier())
	w.AddFolder(f)

	_ = textDocumentDidOpen(&loc, testPath, t)

	assert.Eventually(t, checkForPublishedDiagnostics(testPath, 6), maxIntegTestDuration, 10*time.Millisecond)
}

func textDocumentDidOpen(loc *server.Local, testPath string, t *testing.T) sglsp.DidOpenTextDocumentParams {
	testFileContent, err := os.ReadFile(testPath)
	if err != nil {
		t.Fatal(err, "Couldn't read file content of test file")
	}

	didOpenParams := sglsp.DidOpenTextDocumentParams{
		TextDocument: sglsp.TextDocumentItem{
			URI:  uri.PathToUri(testPath),
			Text: string(testFileContent),
		},
	}

	_, err = loc.Client.Call(ctx, "textDocument/didOpen", didOpenParams)
	if err != nil {
		t.Fatal(err, "Call failed")
	}

	return didOpenParams
}

func setupCustomTestRepo(url string, targetCommit string, t *testing.T) (string, error) {
	workDir := xdg.DataHome // tempdir doesn't work well as it gets too long on macOS
	tempDir, err := os.MkdirTemp(workDir, "")
	if err != nil {
		t.Fatal(err, "couldn't create tempDir")
	}
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
	testutil.IntegTest(t) // because we want to test it on windows, too

	// start process that just sleeps
	pidChan := make(chan int)
	go func() {
		var cmd *exec.Cmd
		if runtime.GOOS != "windows" {
			cmd = exec.Command("sleep", "2")
		} else {
			cmd = exec.Command("cmd.exe", "/c", "timeout", "/t", "2")
		}
		err := cmd.Start()
		if err != nil {
			log.Err(err).Msg("Couldn't sleep. Stopping test")
			t.Fail()
		}
		pidChan <- cmd.Process.Pid
		_ = cmd.Wait()
	}()
	pid := <-pidChan
	// make sure that we actually waited & monitored
	expectedMinimumDuration, _ := time.ParseDuration("999ms")
	assert.True(t, monitorClientProcess(pid) > expectedMinimumDuration)
}
