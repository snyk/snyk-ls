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

	"github.com/golang/mock/gomock"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	c := testutil.UnitTest(t)
	loc, _ := setupServerWithCustomDI(t, c, false)

	s := &scanner.TestScanner{}
	c.Workspace().AddFolder(workspace.NewFolder(c, "dummy", "dummy", s, di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister(), di.ScanStateAggregator(), di.FeatureFlagService(), di.ConfigResolver()))

	params := sglsp.ExecuteCommandParams{Command: types.WorkspaceScanCommand}
	_, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
	if err != nil {
		t.Fatal(err)
	}
	assert.Eventually(t, func() bool {
		return s.Calls() > 0
	}, 2*time.Second, time.Millisecond)
}

func Test_executeWorkspaceFolderScanCommand_shouldStartFolderScanOnCommandReceipt(t *testing.T) {
	c := testutil.UnitTest(t)
	loc, _ := setupServerWithCustomDI(t, c, false)

	s := &scanner.TestScanner{}
	c.Workspace().AddFolder(workspace.NewFolder(c, "dummy", "dummy", s, di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister(), di.ScanStateAggregator(), di.FeatureFlagService(), di.ConfigResolver()))

	params := sglsp.ExecuteCommandParams{Command: types.WorkspaceFolderScanCommand, Arguments: []any{"dummy"}}
	_, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
	if err != nil {
		t.Fatal(err)
	}
	assert.Eventually(t, func() bool {
		return s.Calls() > 0
	}, 2*time.Second, time.Millisecond)
}

func Test_executeWorkspaceFolderScanCommand_shouldNotClearOtherFoldersDiagnostics(t *testing.T) {
	c := testutil.UnitTest(t)
	loc, _ := setupServerWithCustomDI(t, c, false)

	scannerForFolder := scanner.NewTestScanner()
	scannerForDontClear := scanner.NewTestScanner()
	folder := workspace.NewFolder(c, "dummy", "dummy", scannerForFolder, di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister(), di.ScanStateAggregator(), di.FeatureFlagService(), di.ConfigResolver())
	dontClear := workspace.NewFolder(c, "dontclear", "dontclear", scannerForDontClear, di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister(), di.ScanStateAggregator(), di.FeatureFlagService(), di.ConfigResolver())

	dontClearIssuePath := types.FilePath("dontclear/file.txt")
	scannerForDontClear.AddTestIssue(&snyk.Issue{AffectedFilePath: dontClearIssuePath})
	scannerForFolder.AddTestIssue(&snyk.Issue{AffectedFilePath: "dummy/file.txt"})

	c.Workspace().AddFolder(folder)
	c.Workspace().AddFolder(dontClear)

	// prepare pre-existent diagnostics for folder
	folder.ScanFolder(t.Context())
	dontClear.ScanFolder(t.Context())

	params := sglsp.ExecuteCommandParams{Command: types.WorkspaceFolderScanCommand, Arguments: []any{"dummy"}}
	_, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
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
	c := testutil.UnitTest(t)
	loc, jsonRPCRecorder := setupServerWithCustomDI(t, c, false)

	s := &scanner.TestScanner{}
	c.Workspace().AddFolder(workspace.NewFolder(c, "dummy", "dummy", s, di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister(), di.ScanStateAggregator(), di.FeatureFlagService(), di.ConfigResolver()))
	// explicitly enable folder trust which is disabled by default in tests
	c.SetTrustedFolderFeatureEnabled(true)

	params := sglsp.ExecuteCommandParams{Command: types.WorkspaceScanCommand}
	_, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
	if err != nil {
		t.Fatal(err)
	}
	assert.Eventually(t, func() bool {
		return s.Calls() == 0 && checkTrustMessageRequest(jsonRPCRecorder, c)
	}, 2*time.Second, time.Millisecond)
}

func Test_executeWorkspaceScanCommand_shouldAcceptScanSourceParam(t *testing.T) {
	c := testutil.UnitTest(t)
	loc, jsonRPCRecorder := setupServerWithCustomDI(t, c, false)

	s := &scanner.TestScanner{}
	c.Workspace().AddFolder(workspace.NewFolder(c, "dummy", "dummy", s, di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister(), di.ScanStateAggregator(), di.FeatureFlagService(), di.ConfigResolver()))
	// explicitly enable folder trust which is disabled by default in tests
	c.SetTrustedFolderFeatureEnabled(true)

	params := sglsp.ExecuteCommandParams{Command: types.WorkspaceScanCommand, Arguments: []any{"LLM"}}
	_, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
	if err != nil {
		t.Fatal(err)
	}
	assert.Eventually(t, func() bool {
		return s.Calls() == 0 && checkTrustMessageRequest(jsonRPCRecorder, c)
	}, 2*time.Second, time.Millisecond)
}

func Test_loginCommand_StartsAuthentication(t *testing.T) {
	c := testutil.UnitTest(t)

	loc, jsonRPCRecorder := setupServer(t, c)

	// Setup mock LdxSyncService AFTER setupServer to avoid it being overwritten by di.TestInit
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockLdxSyncService := mockcommand.NewMockLdxSyncService(ctrl)
	originalLdxService := di.LdxSyncService()
	di.SetLdxSyncService(mockLdxSyncService)
	defer di.SetLdxSyncService(originalLdxService)
	c.SetAutomaticAuthentication(false)
	c.SetAuthenticationMethod(types.FakeAuthentication)

	authenticationService := di.AuthenticationService()
	fakeAuthenticationProvider := authenticationService.Provider().(*authentication.FakeAuthenticationProvider)
	fakeAuthenticationProvider.IsAuthenticated = false

	// Add workspace folder
	folder := workspace.NewFolder(c, "/test/path", "test", di.Scanner(), di.HoverService(),
		di.ScanNotifier(), di.Notifier(), di.ScanPersister(),
		di.ScanStateAggregator(), di.FeatureFlagService(), di.ConfigResolver())
	c.Workspace().AddFolder(folder)

	// Expect RefreshConfigFromLdxSync to be called during initialization with the workspace folder
	mockLdxSyncService.EXPECT().
		RefreshConfigFromLdxSync(gomock.Any(), c, gomock.Any(), gomock.Any()).
		Times(1).
		Do(func(_ interface{}, _ interface{}, folders []types.Folder, _ interface{}) {
			// Verify that we received the workspace folder during initialization
			assert.Len(t, folders, 1)
			assert.Equal(t, folder.Path(), folders[0].Path())
		})

	// reset to use real service with mock injected
	command.SetService(command.NewService(authenticationService, di.FeatureFlagService(), di.Notifier(), di.LearnService(), nil, nil, nil, mockLdxSyncService, nil, nil))

	_, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}

	params := sglsp.ExecuteCommandParams{Command: types.LoginCommand}

	_, err = loc.Client.Call(ctx, "initialized", types.InitializedParams{})
	assert.NoError(t, err)

	// Expect RefreshConfigFromLdxSync to be called again after successful login
	mockLdxSyncService.EXPECT().
		RefreshConfigFromLdxSync(gomock.Any(), c, gomock.Any(), gomock.Any()).
		Times(1).
		Do(func(_ interface{}, _ interface{}, folders []types.Folder, _ interface{}) {
			// Verify that we received the workspace folder after login
			assert.Len(t, folders, 1)
			assert.Equal(t, folder.Path(), folders[0].Path())
		})

	// Act
	tokenResponse, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
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
		c := testutil.UnitTest(t)
		loc, _ := setupServerWithCustomDI(t, c, false)

		c.Workspace().AddFolder(workspace.NewFolder(c, folderPath1, "dummy", nil, di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister(), di.ScanStateAggregator(), di.FeatureFlagService(), di.ConfigResolver()))

		params := sglsp.ExecuteCommandParams{Command: types.TrustWorkspaceFoldersCommand}
		_, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
		if err != nil {
			t.Fatal(err)
		}

		assert.Len(t, c.TrustedFolders(), 0)
	})

	t.Run("Updates trusted workspace folders", func(t *testing.T) {
		c := testutil.UnitTest(t)
		loc, _ := setupServerWithCustomDI(t, c, false)

		c.Workspace().AddFolder(workspace.NewFolder(c, folderPath1, "dummy", nil, di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister(), di.ScanStateAggregator(), di.FeatureFlagService(), di.ConfigResolver()))
		c.Workspace().AddFolder(workspace.NewFolder(c, folderPath2, "dummy", nil, di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister(), di.ScanStateAggregator(), di.FeatureFlagService(), di.ConfigResolver()))
		c.SetTrustedFolderFeatureEnabled(true)

		params := sglsp.ExecuteCommandParams{Command: types.TrustWorkspaceFoldersCommand}
		_, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
		if err != nil {
			t.Fatal(err)
		}

		assert.Len(t, c.TrustedFolders(), 2)
		assert.Contains(t, c.TrustedFolders(), folderPath1)
		assert.Contains(t, c.TrustedFolders(), folderPath2)
	})

	t.Run("Existing trusted workspace folders are not removed", func(t *testing.T) {
		c := testutil.UnitTest(t)
		loc, _ := setupServerWithCustomDI(t, c, false)

		c.Workspace().AddFolder(workspace.NewFolder(c, folderPath1, "dummy", nil, di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister(), di.ScanStateAggregator(), di.FeatureFlagService(), di.ConfigResolver()))
		c.SetTrustedFolderFeatureEnabled(true)
		c.SetTrustedFolders([]types.FilePath{folderPath2})

		params := sglsp.ExecuteCommandParams{Command: types.TrustWorkspaceFoldersCommand}
		_, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
		if err != nil {
			t.Fatal(err)
		}

		assert.Len(t, c.TrustedFolders(), 2)
		assert.Contains(t, c.TrustedFolders(), folderPath1)
		assert.Contains(t, c.TrustedFolders(), folderPath2)
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

func Test_ExecuteCommand_CancelRequest(t *testing.T) {
	c := testutil.UnitTest(t)
	loc, _ := setupServer(t, c)

	testCmd := newWaitForCancelTestCommand(t)

	originalCmdService := command.Service()
	fakeCommandService := &testCommandService{
		testCmd: testCmd,
	}
	command.SetService(fakeCommandService)
	t.Cleanup(func() {
		command.SetService(originalCmdService)
	})

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
