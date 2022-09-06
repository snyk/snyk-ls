package server

import (
	"testing"
	"time"

	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"golang.design/x/clipboard"

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
	actualURL := string(clipboard.Read(clipboard.FmtText))

	assert.Equal(t, authenticationMock.ExpectedAuthURL, actualURL)
}
