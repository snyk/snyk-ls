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
	"testing"
	"time"

	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/atotto/clipboard"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/cli/auth"
)

func Test_executeWorkspaceScanCommand_shouldStartWorkspaceScanOnCommandReceipt(t *testing.T) {
	loc := setupServerWithCustomDI(t, false)
	scanner := &snyk.TestScanner{}
	workspace.Get().AddFolder(workspace.NewFolder("dummy", "dummy", scanner, di.HoverService(), di.ScanNotifier()))

	params := lsp.ExecuteCommandParams{Command: snyk.WorkspaceScanCommand}
	_, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
	if err != nil {
		t.Fatal(err)
	}
	assert.Eventually(t, func() bool {
		return scanner.Calls() > 0
	}, 2*time.Second, time.Millisecond)
}

func Test_executeWorkspaceFolderScanCommand_shouldStartFolderScanOnCommandReceipt(t *testing.T) {
	loc := setupServerWithCustomDI(t, false)
	scanner := &snyk.TestScanner{}
	workspace.Get().AddFolder(workspace.NewFolder("dummy", "dummy", scanner, di.HoverService(), di.ScanNotifier()))

	params := lsp.ExecuteCommandParams{Command: snyk.WorkspaceFolderScanCommand, Arguments: []any{"dummy"}}
	_, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
	if err != nil {
		t.Fatal(err)
	}
	assert.Eventually(t, func() bool {
		return scanner.Calls() > 0
	}, 2*time.Second, time.Millisecond)
}

func Test_executeWorkspaceFolderScanCommand_shouldNotClearOtherFoldersDiagnostics(t *testing.T) {
	loc := setupServerWithCustomDI(t, false)

	scannerForFolder := snyk.NewTestScanner()
	scannerForDontClear := snyk.NewTestScanner()
	folder := workspace.NewFolder("dummy", "dummy", scannerForFolder, di.HoverService(), di.ScanNotifier())
	dontClear := workspace.NewFolder("dontclear", "dontclear", scannerForDontClear, di.HoverService(), di.ScanNotifier())

	dontClearIssuePath := "dontclear/file.txt"
	scannerForDontClear.AddTestIssue(snyk.Issue{AffectedFilePath: dontClearIssuePath})
	scannerForFolder.AddTestIssue(snyk.Issue{AffectedFilePath: "dummy/file.txt"})

	workspace.Get().AddFolder(folder)
	workspace.Get().AddFolder(dontClear)

	// prepare pre-existent diagnostics for folder
	folder.ScanFolder(context.Background())
	dontClear.ScanFolder(context.Background())

	params := lsp.ExecuteCommandParams{Command: snyk.WorkspaceFolderScanCommand, Arguments: []any{"dummy"}}
	_, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
	if err != nil {
		t.Fatal(err)
	}
	assert.Eventually(t, func() bool {
		// must be two scans for dummy as initialization + scan after issuing command
		return scannerForFolder.Calls() == 2 && scannerForDontClear.Calls() == 1
	}, 2*time.Second, time.Millisecond)

	assert.Equal(t, 1, len(dontClear.AllIssuesFor(dontClearIssuePath)))
}

func Test_executeWorkspaceScanCommand_shouldAskForTrust(t *testing.T) {
	loc := setupServerWithCustomDI(t, false)

	scanner := &snyk.TestScanner{}
	workspace.Get().AddFolder(workspace.NewFolder("dummy", "dummy", scanner, di.HoverService(), di.ScanNotifier()))
	// explicitly enable folder trust which is disabled by default in tests
	config.CurrentConfig().SetTrustedFolderFeatureEnabled(true)

	params := lsp.ExecuteCommandParams{Command: snyk.WorkspaceScanCommand}
	_, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
	if err != nil {
		t.Fatal(err)
	}
	assert.Eventually(t, func() bool {
		return scanner.Calls() == 0 && checkTrustMessageRequest()
	}, 2*time.Second, time.Millisecond)
}

func Test_loginCommand_StartsAuthentication(t *testing.T) {
	// Arrange
	loc := setupServer(t)
	di.SetCommandService(command.NewCommandService()) // use real command service

	config.CurrentConfig().SetAutomaticAuthentication(false)
	_, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	fakeAuthenticationProvider := di.AuthenticationService().Provider().(*auth.FakeAuthenticationProvider)
	initialAuthenticatedStatus := fakeAuthenticationProvider.IsAuthenticated
	params := lsp.ExecuteCommandParams{Command: snyk.LoginCommand}

	// Act
	_, err = loc.Client.Call(ctx, "workspace/executeCommand", params)
	if err != nil {
		t.Fatal(err)
	}

	// Assert
	assert.False(t, initialAuthenticatedStatus)
	assert.True(t, fakeAuthenticationProvider.IsAuthenticated)
	assert.Eventually(t, func() bool { return len(jsonRPCRecorder.Notifications()) > 0 }, 5*time.Second, 50*time.Millisecond)
	assert.Equal(t, 1, len(jsonRPCRecorder.FindNotificationsByMethod("$/snyk.hasAuthenticated")))
}

func Test_executeCommand_shouldCopyAuthURLToClipboard(t *testing.T) {
	loc := setupServer(t)
	di.SetCommandService(command.NewCommandService()) // use real command service
	authenticationMock := di.AuthenticationService().Provider().(*auth.FakeAuthenticationProvider)
	params := lsp.ExecuteCommandParams{Command: snyk.CopyAuthLinkCommand}

	_, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
	if err != nil {
		t.Fatal(err)
	}
	actualURL, _ := clipboard.ReadAll()

	assert.Equal(t, authenticationMock.ExpectedAuthURL, actualURL)
}

func Test_TrustWorkspaceFolders(t *testing.T) {
	t.Run("Doesn't mutate trusted folders, if trusted folders disabled", func(t *testing.T) {
		loc := setupServerWithCustomDI(t, false)
		workspace.Get().AddFolder(workspace.NewFolder("/path/to/folder1", "dummy", nil, di.HoverService(), di.ScanNotifier()))

		params := lsp.ExecuteCommandParams{Command: snyk.TrustWorkspaceFoldersCommand}
		_, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
		if err != nil {
			t.Fatal(err)
		}

		assert.Len(t, config.CurrentConfig().TrustedFolders(), 0)
	})

	t.Run("Updates trusted workspace folders", func(t *testing.T) {
		loc := setupServerWithCustomDI(t, false)
		workspace.Get().AddFolder(workspace.NewFolder("/path/to/folder1", "dummy", nil, di.HoverService(), di.ScanNotifier()))
		workspace.Get().AddFolder(workspace.NewFolder("/path/to/folder2", "dummy", nil, di.HoverService(), di.ScanNotifier()))
		config.CurrentConfig().SetTrustedFolderFeatureEnabled(true)

		params := lsp.ExecuteCommandParams{Command: snyk.TrustWorkspaceFoldersCommand}
		_, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
		if err != nil {
			t.Fatal(err)
		}

		assert.Len(t, config.CurrentConfig().TrustedFolders(), 2)
		assert.Contains(t, config.CurrentConfig().TrustedFolders(), "/path/to/folder1", "/path/to/folder2")
	})

	t.Run("Existing trusted workspace folders are not removed", func(t *testing.T) {
		loc := setupServerWithCustomDI(t, false)
		workspace.Get().AddFolder(workspace.NewFolder("/path/to/folder1", "dummy", nil, di.HoverService(), di.ScanNotifier()))
		config.CurrentConfig().SetTrustedFolderFeatureEnabled(true)
		config.CurrentConfig().SetTrustedFolders([]string{"/path/to/folder2"})

		params := lsp.ExecuteCommandParams{Command: snyk.TrustWorkspaceFoldersCommand}
		_, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
		if err != nil {
			t.Fatal(err)
		}

		assert.Len(t, config.CurrentConfig().TrustedFolders(), 2)
		assert.Contains(t, config.CurrentConfig().TrustedFolders(), "/path/to/folder1", "/path/to/folder2")
	})
}
