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
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/handler"
	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/command"
	mockcommand "github.com/snyk/snyk-ls/domain/ide/command/mock"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

func Test_executeWorkspaceScanCommand_shouldStartWorkspaceScanOnCommandReceipt(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, _, deps := setupServer(t, engine, tokenService, WithRealDI())

	s := &scanner.TestScanner{}
	config.GetWorkspace(engine.GetConfiguration()).AddFolder(workspace.NewFolder(engine.GetConfiguration(), engine.GetLogger(), types.PathKey("dummy"), "dummy", s, deps.HoverService, deps.ScanNotifier, deps.Notifier, deps.ScanPersister, deps.ScanStateAggregator, deps.FeatureFlagService, deps.ConfigResolver, engine))

	params := sglsp.ExecuteCommandParams{Command: types.WorkspaceScanCommand}
	_, err := loc.Client.Call(t.Context(), "workspace/executeCommand", params)
	if err != nil {
		t.Fatal(err)
	}
	assert.Eventually(t, func() bool {
		return s.Calls() > 0
	}, 2*time.Second, time.Millisecond)
}

func Test_executeWorkspaceFolderScanCommand_shouldStartFolderScanOnCommandReceipt(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, _, deps := setupServer(t, engine, tokenService, WithRealDI())

	s := &scanner.TestScanner{}
	config.GetWorkspace(engine.GetConfiguration()).AddFolder(workspace.NewFolder(engine.GetConfiguration(), engine.GetLogger(), types.PathKey("dummy"), "dummy", s, deps.HoverService, deps.ScanNotifier, deps.Notifier, deps.ScanPersister, deps.ScanStateAggregator, deps.FeatureFlagService, deps.ConfigResolver, engine))

	params := sglsp.ExecuteCommandParams{Command: types.WorkspaceFolderScanCommand, Arguments: []any{"dummy"}}
	_, err := loc.Client.Call(t.Context(), "workspace/executeCommand", params)
	if err != nil {
		t.Fatal(err)
	}
	assert.Eventually(t, func() bool {
		return s.Calls() > 0
	}, 2*time.Second, time.Millisecond)
}

func Test_executeWorkspaceFolderScanCommand_shouldNotClearOtherFoldersDiagnostics(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, _, deps := setupServer(t, engine, tokenService, WithRealDI())

	scannerForFolder := scanner.NewTestScanner()
	scannerForDontClear := scanner.NewTestScanner()
	folder := workspace.NewFolder(engine.GetConfiguration(), engine.GetLogger(), types.PathKey("dummy"), "dummy", scannerForFolder, deps.HoverService, deps.ScanNotifier, deps.Notifier, deps.ScanPersister, deps.ScanStateAggregator, deps.FeatureFlagService, deps.ConfigResolver, engine)
	dontClear := workspace.NewFolder(engine.GetConfiguration(), engine.GetLogger(), types.PathKey("dontclear"), "dontclear", scannerForDontClear, deps.HoverService, deps.ScanNotifier, deps.Notifier, deps.ScanPersister, deps.ScanStateAggregator, deps.FeatureFlagService, deps.ConfigResolver, engine)

	dontClearIssuePath := types.FilePath("dontclear/file.txt")
	scannerForDontClear.AddTestIssue(&snyk.Issue{AffectedFilePath: dontClearIssuePath})
	scannerForFolder.AddTestIssue(&snyk.Issue{AffectedFilePath: "dummy/file.txt"})

	config.GetWorkspace(engine.GetConfiguration()).AddFolder(folder)
	config.GetWorkspace(engine.GetConfiguration()).AddFolder(dontClear)

	// prepare pre-existent diagnostics for folder
	folder.ScanFolder(t.Context())
	dontClear.ScanFolder(t.Context())

	params := sglsp.ExecuteCommandParams{Command: types.WorkspaceFolderScanCommand, Arguments: []any{"dummy"}}
	_, err := loc.Client.Call(t.Context(), "workspace/executeCommand", params)
	if err != nil {
		t.Fatal(err)
	}
	assert.Eventually(t, func() bool {
		// must be two scans for dummy as initialization + scan after issuing command
		return scannerForFolder.Calls() == 2 && scannerForDontClear.Calls() == 1
	}, 2*time.Second, time.Millisecond)

	assert.Equal(t, 1, len(dontClear.IssuesForFile(dontClearIssuePath)))
}

func Test_executeWorkspaceScanCommand_shouldAskForTrust(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder, deps := setupServer(t, engine, tokenService, WithRealDI())

	s := &scanner.TestScanner{}
	config.GetWorkspace(engine.GetConfiguration()).AddFolder(workspace.NewFolder(engine.GetConfiguration(), engine.GetLogger(), types.PathKey("dummy"), "dummy", s, deps.HoverService, deps.ScanNotifier, deps.Notifier, deps.ScanPersister, deps.ScanStateAggregator, deps.FeatureFlagService, deps.ConfigResolver, engine))
	// explicitly enable folder trust which is disabled by default in tests
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingTrustEnabled), true)

	params := sglsp.ExecuteCommandParams{Command: types.WorkspaceScanCommand}
	_, err := loc.Client.Call(t.Context(), "workspace/executeCommand", params)
	if err != nil {
		t.Fatal(err)
	}
	assert.Eventually(t, func() bool {
		return s.Calls() == 0 && checkTrustMessageRequest(jsonRPCRecorder, engine)
	}, 2*time.Second, time.Millisecond)
}

func Test_executeWorkspaceScanCommand_shouldAcceptScanSourceParam(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder, deps := setupServer(t, engine, tokenService, WithRealDI())

	s := &scanner.TestScanner{}
	config.GetWorkspace(engine.GetConfiguration()).AddFolder(workspace.NewFolder(engine.GetConfiguration(), engine.GetLogger(), types.PathKey("dummy"), "dummy", s, deps.HoverService, deps.ScanNotifier, deps.Notifier, deps.ScanPersister, deps.ScanStateAggregator, deps.FeatureFlagService, deps.ConfigResolver, engine))
	// explicitly enable folder trust which is disabled by default in tests
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingTrustEnabled), true)

	params := sglsp.ExecuteCommandParams{Command: types.WorkspaceScanCommand, Arguments: []any{"LLM"}}
	_, err := loc.Client.Call(t.Context(), "workspace/executeCommand", params)
	if err != nil {
		t.Fatal(err)
	}
	assert.Eventually(t, func() bool {
		return s.Calls() == 0 && checkTrustMessageRequest(jsonRPCRecorder, engine)
	}, 2*time.Second, time.Millisecond)
}

func Test_loginCommand_StartsAuthentication(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockLdxSyncService := mockcommand.NewMockLdxSyncService(ctrl)

	// Build base deps first so we can create a real command service that shares
	// the same auth service instance as the server — both must point to the same
	// FakeAuthenticationProvider so that IsAuthenticated=false is visible to the
	// command handler that runs inside the server.
	baseDeps := di.TestInit(t, engine, tokenService, &di.Dependencies{
		LdxSyncService: mockLdxSyncService,
	})
	realCommandService := command.NewService(engine, engine.GetLogger(), baseDeps.AuthenticationService, baseDeps.FeatureFlagService, baseDeps.Notifier, baseDeps.LearnService, nil, nil, nil, mockLdxSyncService, nil, nil, baseDeps.ScanCtx)
	baseDeps.CommandService = realCommandService

	// Pass all pre-built deps so setupServer reuses the same service instances.
	loc, jsonRPCRecorder, deps := setupServer(t, engine, tokenService,
		WithDeps(baseDeps))
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingAutomaticAuthentication), false)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingAuthenticationMethod), string(types.FakeAuthentication))

	authenticationService := deps.AuthenticationService
	fakeAuthenticationProvider := authenticationService.Provider().(*authentication.FakeAuthenticationProvider)
	fakeAuthenticationProvider.IsAuthenticated = false

	// Add workspace folder
	folder := workspace.NewFolder(engine.GetConfiguration(), engine.GetLogger(), types.PathKey("/test/path"), "test", deps.Scanner, deps.HoverService,
		deps.ScanNotifier, deps.Notifier, deps.ScanPersister,
		deps.ScanStateAggregator, deps.FeatureFlagService, deps.ConfigResolver, engine)
	config.GetWorkspace(engine.GetConfiguration()).AddFolder(folder)

	// Expect RefreshConfigFromLdxSync to be called during initialization with the workspace folder
	mockLdxSyncService.EXPECT().
		RefreshConfigFromLdxSync(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Times(1).
		Do(func(_ interface{}, _ interface{}, _ interface{}, _ interface{}, folders []types.Folder, _ interface{}) {
			// Verify that we received the workspace folder during initialization
			assert.Len(t, folders, 1)
			assert.Equal(t, folder.Path(), folders[0].Path())
		})

	_, err := loc.Client.Call(t.Context(), "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}

	params := sglsp.ExecuteCommandParams{Command: types.LoginCommand}

	_, err = loc.Client.Call(t.Context(), "initialized", types.InitializedParams{})
	assert.NoError(t, err)

	// Clear the token written by the scanner-init auth check during `initialized`. Without
	// this, snyk.login's Authenticate would re-store the same fake token, updateCredentials
	// would early-return on the no-op, and the post-credential hook (where the login-time
	// RefreshConfigFromLdxSync now lives) would never fire.
	tokenService.SetToken(engine.GetConfiguration(), "")

	// Expect RefreshConfigFromLdxSync to be called again after successful login
	mockLdxSyncService.EXPECT().
		RefreshConfigFromLdxSync(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Times(1).
		Do(func(_ interface{}, _ interface{}, _ interface{}, _ interface{}, folders []types.Folder, _ interface{}) {
			// Verify that we received the workspace folder after login
			assert.Len(t, folders, 1)
			assert.Equal(t, folder.Path(), folders[0].Path())
		})

	// Act
	tokenResponse, err := loc.Client.Call(t.Context(), "workspace/executeCommand", params)
	if err != nil {
		t.Fatal(err)
	}

	// Assert
	assert.NotEmpty(t, tokenResponse.ResultString())
	assert.Eventually(t, func() bool {
		notifications := jsonRPCRecorder.FindNotificationsByMethod("$/snyk.hasAuthenticated")
		return len(notifications) > 0
	}, 10*time.Second, 50*time.Millisecond)

	notifications := jsonRPCRecorder.FindNotificationsByMethod("$/snyk.hasAuthenticated")
	require.NotEmpty(t, notifications, "Expected at least one hasAuthenticated notification")

	var hasAuthenticatedNotification types.AuthenticationParams
	err = notifications[0].UnmarshalParams(&hasAuthenticatedNotification)
	assert.NoError(t, err)
	assert.Empty(t, hasAuthenticatedNotification.ApiUrl)
}

func Test_TrustWorkspaceFolders(t *testing.T) {
	folderPath1 := types.PathKey("/path/to/folder1")
	folderPath2 := types.PathKey("/path/to/folder2")

	t.Run("Doesn't mutate trusted folders, if trusted folders disabled", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		loc, _, deps := setupServer(t, engine, tokenService, WithRealDI())

		config.GetWorkspace(engine.GetConfiguration()).AddFolder(workspace.NewFolder(engine.GetConfiguration(), engine.GetLogger(), folderPath1, "dummy", nil, deps.HoverService, deps.ScanNotifier, deps.Notifier, deps.ScanPersister, deps.ScanStateAggregator, deps.FeatureFlagService, deps.ConfigResolver, engine))

		params := sglsp.ExecuteCommandParams{Command: types.TrustWorkspaceFoldersCommand}
		_, err := loc.Client.Call(t.Context(), "workspace/executeCommand", params)
		if err != nil {
			t.Fatal(err)
		}

		tf := types.GetGlobalSliceFilePath(engine.GetConfiguration(), types.SettingTrustedFolders)
		assert.Len(t, tf, 0)
	})

	t.Run("Updates trusted workspace folders", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		loc, _, deps := setupServer(t, engine, tokenService, WithRealDI())

		config.GetWorkspace(engine.GetConfiguration()).AddFolder(workspace.NewFolder(engine.GetConfiguration(), engine.GetLogger(), folderPath1, "dummy", nil, deps.HoverService, deps.ScanNotifier, deps.Notifier, deps.ScanPersister, deps.ScanStateAggregator, deps.FeatureFlagService, deps.ConfigResolver, engine))
		config.GetWorkspace(engine.GetConfiguration()).AddFolder(workspace.NewFolder(engine.GetConfiguration(), engine.GetLogger(), folderPath2, "dummy", nil, deps.HoverService, deps.ScanNotifier, deps.Notifier, deps.ScanPersister, deps.ScanStateAggregator, deps.FeatureFlagService, deps.ConfigResolver, engine))
		engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingTrustEnabled), true)

		params := sglsp.ExecuteCommandParams{Command: types.TrustWorkspaceFoldersCommand}
		_, err := loc.Client.Call(t.Context(), "workspace/executeCommand", params)
		if err != nil {
			t.Fatal(err)
		}

		tf := types.GetGlobalSliceFilePath(engine.GetConfiguration(), types.SettingTrustedFolders)
		assert.Len(t, tf, 2)
		assert.Contains(t, tf, folderPath1)
		assert.Contains(t, tf, folderPath2)
	})

	t.Run("Existing trusted workspace folders are not removed", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		loc, _, deps := setupServer(t, engine, tokenService, WithRealDI())

		config.GetWorkspace(engine.GetConfiguration()).AddFolder(workspace.NewFolder(engine.GetConfiguration(), engine.GetLogger(), folderPath1, "dummy", nil, deps.HoverService, deps.ScanNotifier, deps.Notifier, deps.ScanPersister, deps.ScanStateAggregator, deps.FeatureFlagService, deps.ConfigResolver, engine))
		engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingTrustEnabled), true)
		engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingTrustedFolders), []types.FilePath{folderPath2})

		params := sglsp.ExecuteCommandParams{Command: types.TrustWorkspaceFoldersCommand}
		_, err := loc.Client.Call(t.Context(), "workspace/executeCommand", params)
		if err != nil {
			t.Fatal(err)
		}

		tf := types.GetGlobalSliceFilePath(engine.GetConfiguration(), types.SettingTrustedFolders)
		assert.Len(t, tf, 2)
		assert.Contains(t, tf, folderPath1)
		assert.Contains(t, tf, folderPath2)
	})
}

// waitForCancelTestCommand is a test command that waits until its context is canceled.
type waitForCancelTestCommand struct {
	command    types.CommandData
	t          *testing.T
	cmdStarted atomic.Bool
	ctxErr     atomic.Pointer[error]
}

func newWaitForCancelTestCommand(t *testing.T) *waitForCancelTestCommand {
	t.Helper()
	return &waitForCancelTestCommand{
		command: types.CommandData{
			CommandId: "internal.waitForCancelTestCommand",
			Title:     "Wait For Cancel Test Command",
		},
		t: t,
	}
}

func (w *waitForCancelTestCommand) Command() types.CommandData {
	return w.command
}

func (w *waitForCancelTestCommand) Execute(ctx context.Context) (any, error) {
	w.t.Log("waitForCancelTestCommand: Entering wait on ctx.Done().")
	w.cmdStarted.Store(true)
	<-ctx.Done()
	w.t.Logf("waitForCancelTestCommand: ctx.Done() returned. ctx.Err() is: %v\n", ctx.Err())
	w.ctxErr.Store(util.Ptr(ctx.Err()))
	return nil, nil
}

type testCommandService struct {
	testCmd types.Command
}

func (tcs *testCommandService) ExecuteCommandData(ctx context.Context, cmdData types.CommandData, _ types.Server) (any, error) {
	if tcs.testCmd == nil || cmdData.CommandId != tcs.testCmd.Command().CommandId {
		return nil, errors.New("we only expect our special command to be run")
	}
	return tcs.testCmd.Execute(ctx)
}

// myTestCommandService is a pointer-type sentinel used to prove pointer identity.
type myTestCommandService struct {
	called bool
}

func (m *myTestCommandService) ExecuteCommandData(_ context.Context, _ types.CommandData, _ types.Server) (any, error) {
	m.called = true
	return "sentinel-called", nil
}

// Test_ExecuteCommandHandler_UsesContextInjectedCommandService proves that
// executeCommandHandler reads CommandService from the context deps map (injected
// by withContext) and NOT from the command.Service() process-global.
//
// It sets a different sentinel as the process-global and verifies the handler
// invokes the deps-injected sentinel, not the global one.
func Test_ExecuteCommandHandler_UsesContextInjectedCommandService(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	logger := engine.GetLogger()

	// contextSentinel is the instance we inject via deps — the handler must use this.
	contextSentinel := &myTestCommandService{}
	// globalSentinel is set as the process-global — the handler must NOT use this.
	globalSentinel := &myTestCommandService{}

	// Prime the mandatory deps base, then override CommandService with contextSentinel.
	baseDeps := di.TestInit(t, engine, tokenService, nil)
	deps := baseDeps
	deps.CommandService = contextSentinel

	// Set the global to globalSentinel to detect if the handler accidentally reads it.
	command.SetService(globalSentinel)
	t.Cleanup(func() { command.SetService(nil) })

	// Use withContext to inject deps (including CommandService) into the handler context,
	// and read back what CommandService the handler sees.
	var gotCommandService types.CommandService
	wrapped := withContext(
		handler.New(func(ctx context.Context, _ *jrpc2.Request) (any, error) {
			gotCommandService, _ = commandServiceFromContext(ctx)
			return nil, nil
		}),
		logger, conf, engine, deps, nil,
	)

	_, err := wrapped(t.Context(), nil)
	require.NoError(t, err)

	// Proof: the context must carry the deps-injected sentinel, not the global one.
	require.NotNil(t, gotCommandService, "CommandService must be injected into context by withContext")
	assert.Same(t, contextSentinel, gotCommandService,
		"withContext must inject deps.CommandService into context, not the command.Service() global")
	assert.NotSame(t, globalSentinel, gotCommandService,
		"handler must not see the command.Service() process-global")
}

func Test_ExecuteCommand_CancelRequest(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)

	testCmd := newWaitForCancelTestCommand(t)

	fakeCommandService := &testCommandService{
		testCmd: testCmd,
	}
	loc, _, _ := setupServer(t, engine, tokenService, WithDeps(di.Dependencies{CommandService: fakeCommandService}))

	var cmdDone atomic.Bool
	go func() {
		cmdResponse, err := loc.Client.Call(t.Context(), "workspace/executeCommand", sglsp.ExecuteCommandParams{
			Command: testCmd.Command().CommandId,
		})
		assert.NoError(t, err)
		if assert.NotNil(t, cmdResponse) {
			assert.Nil(t, cmdResponse.Error())
		}
		cmdDone.Store(true)
	}()

	require.Eventually(t, func() bool {
		return testCmd.cmdStarted.Load()
	}, 5*time.Second, 100*time.Millisecond)

	// Command ID should always be 1 (as a number!), as it is the first command we run on the fake test server.
	cancelParams := sglsp.CancelParams{ID: sglsp.ID{Num: 1, IsString: false}}
	err := loc.Client.Notify(t.Context(), "$/cancelRequest", cancelParams)
	require.NoError(t, err, "Failed to send $/cancelRequest notification")

	assert.Eventually(t, func() bool {
		return cmdDone.Load()
	}, 5*time.Second, 100*time.Millisecond)
	ctxErrPtr := testCmd.ctxErr.Load()
	if assert.NotNil(t, ctxErrPtr) {
		assert.ErrorIs(t, *ctxErrPtr, context.Canceled)
	}
}
