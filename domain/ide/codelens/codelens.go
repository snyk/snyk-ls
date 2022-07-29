package codelens

import (
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/snyk"
)

func GetFor(filePath string) (lenses []sglsp.CodeLens) {
	f := workspace.Get().GetFolderContaining(filePath)
	if f == nil {
		return lenses
	}

	issues := f.DocumentDiagnosticsFromCache(filePath)
	for _, issue := range issues {
		for _, command := range issue.Commands {
			lenses = append(lenses, getCodeLensFromCommand(issue, command))
		}
	}
	return lenses
}

func getCodeLensFromCommand(issue snyk.Issue, command snyk.Command) sglsp.CodeLens {
	return sglsp.CodeLens{
		Range: converter.ToRange(issue.Range),
		Command: sglsp.Command{
			Title:     command.Title,
			Command:   command.Command,
			Arguments: command.Arguments,
		},
	}
}
