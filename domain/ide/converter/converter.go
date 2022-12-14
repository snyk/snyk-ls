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

package converter

import (
	"fmt"
	"regexp"

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

func ToCodeActions(issues []snyk.Issue) (actions []lsp.CodeAction) {
	for _, issue := range issues {
		for _, action := range issue.CodeActions {
			actions = append(actions, ToCodeAction(issue, action))
		}
	}
	return actions
}

func ToCodeAction(issue snyk.Issue, action snyk.CodeAction) lsp.CodeAction {
	return lsp.CodeAction{
		Title:       action.Title,
		Kind:        lsp.QuickFix,
		Diagnostics: ToDiagnostics([]snyk.Issue{issue}),
		IsPreferred: action.IsPreferred,
		Edit:        ToWorkspaceEdit(action.Edit),
		Command:     ToCommand(action.Command),
	}
}

func ToCommand(command snyk.Command) sglsp.Command {
	return sglsp.Command{
		Title:     command.Title,
		Command:   command.Command,
		Arguments: command.Arguments,
	}
}

func ToWorkspaceEdit(edit snyk.WorkspaceEdit) sglsp.WorkspaceEdit {
	lspMap := map[string][]sglsp.TextEdit{}
	for k, v := range edit.Changes {
		lspMap[string(uri.PathToUri(k))] = ToTextEdits(v)
	}
	return sglsp.WorkspaceEdit{Changes: lspMap}
}

func ToTextEdits(edits []snyk.TextEdit) (lspEdits []sglsp.TextEdit) {
	for _, edit := range edits {
		lspEdits = append(lspEdits, ToTextEdit(edit))
	}
	return lspEdits
}

func ToTextEdit(edit snyk.TextEdit) sglsp.TextEdit {
	return sglsp.TextEdit{
		Range:   ToRange(edit.Range),
		NewText: edit.NewText,
	}
}

func ToSeverity(severity snyk.Severity) sglsp.DiagnosticSeverity {
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

func ToRange(r snyk.Range) sglsp.Range {
	return sglsp.Range{
		Start: ToPosition(r.Start),
		End:   ToPosition(r.End),
	}
}

func ToPosition(p snyk.Position) sglsp.Position {
	return sglsp.Position{
		Line:      p.Line,
		Character: p.Character,
	}
}

func ToDiagnostics(issues []snyk.Issue) []lsp.Diagnostic {
	// In JSON, `nil` serializes to `null`, while an empty slice serializes to `[]`.
	// Sending null instead of an empty array leads to stored diagnostics not being cleared.
	// Do not prefer nil over an empty slice in this case. The next line ensures that even if issues is empty,
	// the return value of this function will not be null.
	diagnostics := []lsp.Diagnostic{}

	for _, issue := range issues {
		s := ""
		if issue.IssueDescriptionURL != nil {
			s = issue.IssueDescriptionURL.String()
		}
		diagnostics = append(diagnostics, lsp.Diagnostic{
			Range:           ToRange(issue.Range),
			Severity:        ToSeverity(issue.Severity),
			Code:            issue.ID,
			Source:          string(issue.Product),
			Message:         issue.Message,
			CodeDescription: lsp.CodeDescription{Href: lsp.Uri(s)},
		})
	}
	return diagnostics
}

func ToHoversDocument(path string, issues []snyk.Issue) hover.DocumentHovers {
	return hover.DocumentHovers{
		Uri:   uri.PathToUri(path),
		Hover: ToHovers(issues),
	}
}

func ToHovers(issues []snyk.Issue) (hovers []hover.Hover[hover.Context]) {
	re := regexp.MustCompile(`<br\s?/?>`)
	for _, i := range issues {
		message := ""
		if len(i.FormattedMessage) > 0 {
			message = i.FormattedMessage
		} else {
			message = i.Message
		}

		if len(i.References) > 0 {
			message += "\n\nReferences:\n\n"
			for _, reference := range i.References {
				message += fmt.Sprintf("[%s](%s)\n\n", reference.Title, reference.Url)
			}
		}

		// sanitize the message, substitute <br> with line break
		message = re.ReplaceAllString(message, "\n\n")

		hovers = append(hovers, hover.Hover[hover.Context]{
			Id:      i.ID,
			Range:   ToRange(i.Range),
			Message: message,
			Context: i,
		})
	}
	return hovers
}
