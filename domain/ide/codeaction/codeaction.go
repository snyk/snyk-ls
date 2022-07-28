package codeaction

import (
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
)

func GetFor(filePath string, r sglsp.Range) (actions []lsp.CodeAction) {
	requestedRange := workspace.FromRange(r)
	folder := workspace.Get().GetFolderContaining(filePath)
	if folder != nil {
		return workspace.ToCodeActions(folder.CodeActions(filePath, requestedRange))
	}
	return actions
}
