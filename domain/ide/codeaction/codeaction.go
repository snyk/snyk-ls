package codeaction

import (
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
)

func GetFor(filePath string, r sglsp.Range) (actions []lsp.CodeAction) {
	requestedRange := converter.FromRange(r)
	folder := workspace.Get().GetFolderContaining(filePath)
	if folder != nil {
		issues := folder.IssuesFor(filePath, requestedRange)
		return converter.ToCodeActions(issues)
	}
	return actions
}
