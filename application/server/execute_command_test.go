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
	loc, _ := setupServerWithCustomDI(t, false)
	c := config.CurrentConfig()

	s := &scanner.TestScanner{}
	workspace.Get().AddFolder(workspace.NewFolder(c, "dummy", "dummy", s, di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister()))

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
	loc, _ := setupServerWithCustomDI(t, false)
	c := config.CurrentConfig()

	s := &scanner.TestScanner{}
	workspace.Get().AddFolder(workspace.NewFolder(c, "dummy", "dummy", s, di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister()))

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
	loc, _ := setupServerWithCustomDI(t, false)
	c := config.CurrentConfig()

	scannerForFolder := scanner.NewTestScanner()
	scannerForDontClear := scanner.NewTestScanner()
	folder := workspace.NewFolder(c, "dummy", "dummy", scannerForFolder, di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister())
	dontClear := workspace.NewFolder(c, "dontclear", "dontclear", scannerForDontClear, di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister())

	dontClearIssuePath := "dontclear/file.txt"
	scannerForDontClear.AddTestIssue(snyk.Issue{AffectedFilePath: dontClearIssuePath})
	scannerForFolder.AddTestIssue(snyk.Issue{AffectedFilePath: "dummy/file.txt"})

	workspace.Get().AddFolder(folder)
	workspace.Get().AddFolder(dontClear)

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
	loc, jsonRPCRecorder := setupServerWithCustomDI(t, false)
	c := config.CurrentConfig()

	s := &scanner.TestScanner{}
	workspace.Get().AddFolder(workspace.NewFolder(c, "dummy", "dummy", s, di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister()))
	// explicitly enable folder trust which is disabled by default in tests
	config.CurrentConfig().SetTrustedFolderFeatureEnabled(true)

	params := lsp.ExecuteCommandParams{Command: types.WorkspaceScanCommand}
	_, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
	if err != nil {
		t.Fatal(err)
	}
	assert.Eventually(t, func() bool {
		return s.Calls() == 0 && checkTrustMessageRequest(jsonRPCRecorder)
	}, 2*time.Second, time.Millisecond)
}

func Test_loginCommand_StartsAuthentication(t *testing.T) {
	// Arrange
	loc, jsonRPCRecorder := setupServer(t)

	// reset to use real service
	command.SetService(command.NewService(di.AuthenticationService(), nil, nil, nil, nil, nil, nil))

	config.CurrentConfig().SetAutomaticAuthentication(false)
	_, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	fakeAuthenticationProvider := di.AuthenticationService().Provider().(*authentication.FakeAuthenticationProvider)
	fakeAuthenticationProvider.IsAuthenticated = false
	params := lsp.ExecuteCommandParams{Command: types.LoginCommand}

	// Act
	tokenResponse, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
	if err != nil {
		t.Fatal(err)
	}

	// Assert
	assert.NotEmpty(t, tokenResponse.ResultString())
	assert.True(t, fakeAuthenticationProvider.IsAuthenticated)
	assert.Eventually(t, func() bool { return len(jsonRPCRecorder.Notifications()) > 0 }, 5*time.Second, 50*time.Millisecond)
	notifications := jsonRPCRecorder.FindNotificationsByMethod("$/snyk.hasAuthenticated")
	assert.Equal(t, 1, len(notifications))
	var hasAuthencticatedNotification types.AuthenticationParams
	err = notifications[0].UnmarshalParams(&hasAuthencticatedNotification)
	assert.NoError(t, err)
	assert.NotEmpty(t, hasAuthencticatedNotification.ApiUrl)
}

func Test_TrustWorkspaceFolders(t *testing.T) {
	t.Run("Doesn't mutate trusted folders, if trusted folders disabled", func(t *testing.T) {
		loc, _ := setupServerWithCustomDI(t, false)
		c := config.CurrentConfig()

		workspace.Get().AddFolder(workspace.NewFolder(c, "/path/to/folder1", "dummy", nil, di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister()))

		params := lsp.ExecuteCommandParams{Command: types.TrustWorkspaceFoldersCommand}
		_, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
		if err != nil {
			t.Fatal(err)
		}

		assert.Len(t, config.CurrentConfig().TrustedFolders(), 0)
	})

	t.Run("Updates trusted workspace folders", func(t *testing.T) {
		loc, _ := setupServerWithCustomDI(t, false)
		c := config.CurrentConfig()

		workspace.Get().AddFolder(workspace.NewFolder(c, "/path/to/folder1", "dummy", nil, di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister()))
		workspace.Get().AddFolder(workspace.NewFolder(c, "/path/to/folder2", "dummy", nil, di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister()))
		config.CurrentConfig().SetTrustedFolderFeatureEnabled(true)

		params := lsp.ExecuteCommandParams{Command: types.TrustWorkspaceFoldersCommand}
		_, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
		if err != nil {
			t.Fatal(err)
		}

		assert.Len(t, config.CurrentConfig().TrustedFolders(), 2)
		assert.Contains(t, config.CurrentConfig().TrustedFolders(), "/path/to/folder1", "/path/to/folder2")
	})

	t.Run("Existing trusted workspace folders are not removed", func(t *testing.T) {
		loc, _ := setupServerWithCustomDI(t, false)
		c := config.CurrentConfig()

		workspace.Get().AddFolder(workspace.NewFolder(c, "/path/to/folder1", "dummy", nil, di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister()))
		config.CurrentConfig().SetTrustedFolderFeatureEnabled(true)
		config.CurrentConfig().SetTrustedFolders([]string{"/path/to/folder2"})

		params := lsp.ExecuteCommandParams{Command: types.TrustWorkspaceFoldersCommand}
		_, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
		if err != nil {
			t.Fatal(err)
		}

		assert.Len(t, config.CurrentConfig().TrustedFolders(), 2)
		assert.Contains(t, config.CurrentConfig().TrustedFolders(), "/path/to/folder1", "/path/to/folder2")
	})
}
