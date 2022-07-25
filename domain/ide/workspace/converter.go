package workspace

import (
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/uri"
)

func FromRange(lspRange sglsp.Range) snyk.Range {
	return snyk.Range{
		Start: FromPosition(lspRange.Start),
		End:   FromPosition(lspRange.End),
	}
}

func FromPosition(pos sglsp.Position) snyk.Position {
	return snyk.Position{
		Line:      pos.Line,
		Character: pos.Character,
	}
}

func ToCodeActions(codeActions []snyk.CodeAction) (actions []lsp.CodeAction) {
	for _, action := range codeActions {
		actions = append(actions, toCodeAction(action))
	}
	return actions
}

func toCodeAction(action snyk.CodeAction) lsp.CodeAction {
	return lsp.CodeAction{
		Title:       action.Title,
		Kind:        lsp.QuickFix,
		Diagnostics: toDiagnostics(action.Issues),
		IsPreferred: false,
		Edit:        toWorkspaceEdit(action.Edit),
	}
}

func toWorkspaceEdit(edit snyk.WorkspaceEdit) sglsp.WorkspaceEdit {
	lspMap := map[string][]sglsp.TextEdit{}
	for k, v := range edit.Changes {
		lspMap[string(uri.PathToUri(k))] = toTextEdits(v)
	}
	return sglsp.WorkspaceEdit{Changes: lspMap}
}

func toTextEdits(edits []snyk.TextEdit) (lspEdits []sglsp.TextEdit) {
	for _, edit := range edits {
		lspEdits = append(lspEdits, toTextEdit(edit))
	}
	return lspEdits
}

func toTextEdit(edit snyk.TextEdit) sglsp.TextEdit {
	return sglsp.TextEdit{
		Range:   toRange(edit.Range),
		NewText: edit.NewText,
	}
}

func toSeverity(severity snyk.Severity) sglsp.DiagnosticSeverity {
	switch severity {
	case snyk.Critical:
		return sglsp.Error
	case snyk.High:
		return sglsp.Error
	case snyk.Medium:
		return sglsp.Warning
	case snyk.Low:
		return sglsp.Information
	}
	return sglsp.Info
}

func toRange(r snyk.Range) sglsp.Range {
	return sglsp.Range{
		Start: toPosition(r.Start),
		End:   toPosition(r.End),
	}
}

func toPosition(p snyk.Position) sglsp.Position {
	return sglsp.Position{
		Line:      p.Line,
		Character: p.Character,
	}
}

func toDiagnostics(issues []snyk.Issue) (diagnostics []lsp.Diagnostic) {
	for _, issue := range issues {
		s := ""
		if issue.IssueDescriptionURL != nil {
			s = issue.IssueDescriptionURL.String()
		}
		diagnostics = append(diagnostics, lsp.Diagnostic{
			Range:           toRange(issue.Range),
			Severity:        toSeverity(issue.Severity),
			Code:            issue.ID,
			Source:          string(issue.Product),
			Message:         issue.Message,
			CodeDescription: lsp.CodeDescription{Href: lsp.Uri(s)},
		})
	}
	return diagnostics
}

func toHoversDocument(path string, i []snyk.Issue) hover.DocumentHovers {
	return hover.DocumentHovers{
		Uri:   uri.PathToUri(path),
		Hover: toHovers(i),
	}
}

func toHovers(issues []snyk.Issue) (hovers []hover.Hover[hover.Context]) {
	for _, i := range issues {
		message := ""
		if len(i.LegacyMessage) > 0 {
			message = i.LegacyMessage
		} else {
			message = i.Message
		}
		hovers = append(hovers, hover.Hover[hover.Context]{
			Id:      i.ID,
			Range:   toRange(i.Range),
			Message: message,
			Context: i,
		})
	}
	return hovers
}
