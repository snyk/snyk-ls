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
	"testing"
	"time"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"
	"github.com/snyk/snyk-ls/internal/testutil"

	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_executeWorkspaceScanCommand_shouldStartWorkspaceScanOnCommandReceipt(t *testing.T) {
	c := testutil.UnitTest(t)
	loc, _ := setupServerWithCustomDI(t, c, false)

	s := &scanner.TestScanner{}
	c.Workspace().AddFolder(workspace.NewFolder(c, "dummy", "dummy", s, di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister(), di.ScanStateAggregator()))

	params := lsp.ExecuteCommandParams{Command: types.WorkspaceScanCommand}
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
	c.Workspace().AddFolder(workspace.NewFolder(c, "dummy", "dummy", s, di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister(), di.ScanStateAggregator()))

	params := lsp.ExecuteCommandParams{Command: types.WorkspaceFolderScanCommand, Arguments: []any{"dummy"}}
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
	folder := workspace.NewFolder(c, "dummy", "dummy", scannerForFolder, di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister(), di.ScanStateAggregator())
	dontClear := workspace.NewFolder(c, "dontclear", "dontclear", scannerForDontClear, di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister(), di.ScanStateAggregator())

	dontClearIssuePath := types.FilePath("dontclear/file.txt")
	scannerForDontClear.AddTestIssue(&snyk.Issue{AffectedFilePath: dontClearIssuePath})
	scannerForFolder.AddTestIssue(&snyk.Issue{AffectedFilePath: "dummy/file.txt"})

	c.Workspace().AddFolder(folder)
	c.Workspace().AddFolder(dontClear)

	// prepare pre-existent diagnostics for folder
	folder.ScanFolder(context.Background())
	dontClear.ScanFolder(context.Background())

	params := lsp.ExecuteCommandParams{Command: types.WorkspaceFolderScanCommand, Arguments: []any{"dummy"}}
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
	c.Workspace().AddFolder(workspace.NewFolder(c, "dummy", "dummy", s, di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister(), di.ScanStateAggregator()))
	// explicitly enable folder trust which is disabled by default in tests
	config.CurrentConfig().SetTrustedFolderFeatureEnabled(true)

	params := lsp.ExecuteCommandParams{Command: types.WorkspaceScanCommand}
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
	c.Workspace().AddFolder(workspace.NewFolder(c, "dummy", "dummy", s, di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister(), di.ScanStateAggregator()))
	// explicitly enable folder trust which is disabled by default in tests
	config.CurrentConfig().SetTrustedFolderFeatureEnabled(true)

	params := lsp.ExecuteCommandParams{Command: types.WorkspaceScanCommand, Arguments: []any{"LLM"}}
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
	c.SetAutomaticAuthentication(false)
	c.SetAuthenticationMethod(types.FakeAuthentication)

	authenticationService := di.AuthenticationService()
	fakeAuthenticationProvider := authenticationService.Provider().(*authentication.FakeAuthenticationProvider)
	fakeAuthenticationProvider.IsAuthenticated = false

	// reset to use real service
	command.SetService(command.NewService(authenticationService, di.Notifier(), di.LearnService(), nil, nil, nil, nil))

	_, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}

	params := lsp.ExecuteCommandParams{Command: types.LoginCommand}

	_, err = loc.Client.Call(ctx, "initialized", types.InitializedParams{})
	assert.NoError(t, err)

	// Act
	tokenResponse, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
	if err != nil {
		t.Fatal(err)
	}

	// Assert
	assert.NotEmpty(t, tokenResponse.ResultString())
	assert.Eventually(t, func() bool { return len(jsonRPCRecorder.Notifications()) > 0 }, 10*time.Second, 50*time.Millisecond)
	notifications := jsonRPCRecorder.FindNotificationsByMethod("$/snyk.hasAuthenticated")
	var hasAuthenticatedNotification types.AuthenticationParams
	err = notifications[0].UnmarshalParams(&hasAuthenticatedNotification)
	assert.NoError(t, err)
	assert.Empty(t, hasAuthenticatedNotification.ApiUrl)
}

func Test_TrustWorkspaceFolders(t *testing.T) {
	t.Run("Doesn't mutate trusted folders, if trusted folders disabled", func(t *testing.T) {
		c := testutil.UnitTest(t)
		loc, _ := setupServerWithCustomDI(t, c, false)

		c.Workspace().AddFolder(workspace.NewFolder(c, "/path/to/folder1", "dummy", nil, di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister(), di.ScanStateAggregator()))

		params := lsp.ExecuteCommandParams{Command: types.TrustWorkspaceFoldersCommand}
		_, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
		if err != nil {
			t.Fatal(err)
		}

		assert.Len(t, c.TrustedFolders(), 0)
	})

	t.Run("Updates trusted workspace folders", func(t *testing.T) {
		c := testutil.UnitTest(t)
		loc, _ := setupServerWithCustomDI(t, c, false)

		c.Workspace().AddFolder(workspace.NewFolder(c, "/path/to/folder1", "dummy", nil, di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister(), di.ScanStateAggregator()))
		c.Workspace().AddFolder(workspace.NewFolder(c, "/path/to/folder2", "dummy", nil, di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister(), di.ScanStateAggregator()))
		c.SetTrustedFolderFeatureEnabled(true)

		params := lsp.ExecuteCommandParams{Command: types.TrustWorkspaceFoldersCommand}
		_, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
		if err != nil {
			t.Fatal(err)
		}

		assert.Len(t, c.TrustedFolders(), 2)
		assert.Contains(t, c.TrustedFolders(), types.FilePath("/path/to/folder1"))
		assert.Contains(t, c.TrustedFolders(), types.FilePath("/path/to/folder2"))
	})

	t.Run("Existing trusted workspace folders are not removed", func(t *testing.T) {
		c := testutil.UnitTest(t)
		loc, _ := setupServerWithCustomDI(t, c, false)

		c.Workspace().AddFolder(workspace.NewFolder(c, "/path/to/folder1", "dummy", nil, di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister(), di.ScanStateAggregator()))
		c.SetTrustedFolderFeatureEnabled(true)
		c.SetTrustedFolders([]types.FilePath{"/path/to/folder2"})

		params := lsp.ExecuteCommandParams{Command: types.TrustWorkspaceFoldersCommand}
		_, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
		if err != nil {
			t.Fatal(err)
		}

		assert.Len(t, c.TrustedFolders(), 2)
		assert.Contains(t, c.TrustedFolders(), types.FilePath("/path/to/folder1"))
		assert.Contains(t, c.TrustedFolders(), types.FilePath("/path/to/folder2"))
	})
}
