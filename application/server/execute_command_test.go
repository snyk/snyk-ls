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
	"testing"
	"time"

	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/atotto/clipboard"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/cli/auth"
)

func Test_executeWorkspaceScanCommand_shouldStartWorkspaceScanOnCommandReceipt(t *testing.T) {
	loc := setupServer(t)

	scanner := &snyk.TestScanner{}
	workspace.Get().AddFolder(workspace.NewFolder("dummy", "dummy", scanner, di.HoverService()))

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
	loc := setupServer(t)

	scanner := &snyk.TestScanner{}
	workspace.Get().AddFolder(workspace.NewFolder("dummy", "dummy", scanner, di.HoverService()))

	params := lsp.ExecuteCommandParams{Command: snyk.WorkspaceFolderScanCommand, Arguments: []any{"dummy"}}
	_, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
	if err != nil {
		t.Fatal(err)
	}
	assert.Eventually(t, func() bool {
		return scanner.Calls() > 0
	}, 2*time.Second, time.Millisecond)
}

func Test_executeWorkspaceScanCommand_shouldAskForTrust(t *testing.T) {
	loc := setupServer(t)

	scanner := &snyk.TestScanner{}
	workspace.Get().AddFolder(workspace.NewFolder("dummy", "dummy", scanner, di.HoverService()))
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
	_, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	authenticationMock := di.Authenticator().Provider().(*auth.FakeAuthenticationProvider)
	initialAuthenticatedStatus := authenticationMock.IsAuthenticated
	params := lsp.ExecuteCommandParams{Command: snyk.LoginCommand}

	// Act
	_, err = loc.Client.Call(ctx, "workspace/executeCommand", params)
	if err != nil {
		t.Fatal(err)
	}

	// Assert
	assert.False(t, initialAuthenticatedStatus)
	assert.True(t, authenticationMock.IsAuthenticated)
	assert.Eventually(t, func() bool { return len(jsonRPCRecorder.Notifications()) > 0 }, 5*time.Second, 50*time.Millisecond)
	assert.Equal(t, 1, len(jsonRPCRecorder.FindNotificationsByMethod("$/snyk.hasAuthenticated")))
}

func Test_executeCommand_shouldCopyAuthURLToClipboard(t *testing.T) {
	loc := setupServer(t)
	authenticationMock := di.Authenticator().Provider().(*auth.FakeAuthenticationProvider)
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
		loc := setupServer(t)
		workspace.Get().AddFolder(workspace.NewFolder("/path/to/folder1", "dummy", nil, di.HoverService()))

		params := lsp.ExecuteCommandParams{Command: snyk.TrustWorkspaceFoldersCommand}
		_, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
		if err != nil {
			t.Fatal(err)
		}

		assert.Len(t, config.CurrentConfig().TrustedFolders(), 0)
	})

	t.Run("Updates trusted workspace folders", func(t *testing.T) {
		loc := setupServer(t)
		workspace.Get().AddFolder(workspace.NewFolder("/path/to/folder1", "dummy", nil, di.HoverService()))
		workspace.Get().AddFolder(workspace.NewFolder("/path/to/folder2", "dummy", nil, di.HoverService()))
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
		loc := setupServer(t)
		workspace.Get().AddFolder(workspace.NewFolder("/path/to/folder1", "dummy", nil, di.HoverService()))
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
