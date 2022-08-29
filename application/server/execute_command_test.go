package server

import (
	"testing"
	"time"

	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

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
	authenticationMock := di.Authenticator().Provider().(*auth.AuthenticationProviderMock)
	assert.False(t, authenticationMock.IsAuthenticated)
	params := lsp.ExecuteCommandParams{Command: snyk.LoginCommand}

	// Act
	_, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
	if err != nil {
		t.Fatal(err)
	}

	// Assert
	assert.True(t, authenticationMock.IsAuthenticated)
}
