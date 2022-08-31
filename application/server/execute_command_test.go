package server

import (
	"testing"
	"time"

	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"golang.design/x/clipboard"

	"github.com/snyk/snyk-ls/application/di"
	lsp2 "github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/snyk"
)

func Test_executeCommand_shouldStartWorkspaceScanOnCommandReceipt(t *testing.T) {
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

func Test_initializeHandler_shouldOfferWorkspaceScanCommand(t *testing.T) {
	loc := setupServer(t)

	scanner := &snyk.TestScanner{}
	workspace.Get().AddFolder(workspace.NewFolder("dummy", "dummy", scanner, di.HoverService()))

	rsp, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	var result lsp2.InitializeResult
	err = rsp.UnmarshalResult(&result)
	if err != nil {
		t.Fatal(err)
	}
	assert.Contains(t, result.Capabilities.ExecuteCommandProvider.Commands, snyk.WorkspaceScanCommand)
}

func Test_executeCommand_shouldCopyAuthURLToClipboard(t *testing.T) {
	loc := setupServer(t)

	params := lsp.ExecuteCommandParams{Command: snyk.CopyAuthLinkCommand}
	_, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
	if err != nil {
		t.Fatal(err)
	}

	url := string(clipboard.Read(clipboard.FmtText))
	expectedURL := "https://app.snyk.io/login?token=someToken"

	assert.Equal(t, expectedURL, url)
}
