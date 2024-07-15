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

	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/types"
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

func ToCodeActions(issues []snyk.Issue) (actions []types.CodeAction) {
	for _, issue := range issues {
		for _, action := range issue.CodeActions {
			actions = append(actions, ToCodeAction(issue, action))
		}
	}
	return actions
}

func ToCodeAction(issue snyk.Issue, action snyk.CodeAction) types.CodeAction {
	var id *types.CodeActionData = nil
	if action.Uuid != nil {
		i := types.CodeActionData(*action.Uuid)
		id = &i
	}
	return types.CodeAction{
		Title:       action.Title,
		Kind:        types.QuickFix,
		Diagnostics: ToDiagnostics([]snyk.Issue{issue}),
		IsPreferred: action.IsPreferred,
		Edit:        ToWorkspaceEdit(action.Edit),
		Command:     ToCommand(action.Command),
		Data:        id,
	}
}

func ToInlineValue(inlineValue snyk.InlineValue) types.InlineValue {
	return types.InlineValue{
		Range: ToRange(inlineValue.Range()),
		Text:  inlineValue.Text(),
	}
}

func ToInlineValues(inlineValues []snyk.InlineValue) (values []types.InlineValue) {
	for _, inlineValue := range inlineValues {
		values = append(values, ToInlineValue(inlineValue))
	}
	return values
}

func ToCommand(command *types.CommandData) *sglsp.Command {
	if command == nil {
		return nil
	}

	return &sglsp.Command{
		Title:     command.Title,
		Command:   command.CommandId,
		Arguments: command.Arguments,
	}
}

func ToWorkspaceEdit(edit *snyk.WorkspaceEdit) *sglsp.WorkspaceEdit {
	if edit == nil {
		return nil
	}
	lspMap := map[string][]sglsp.TextEdit{}
	for k, v := range edit.Changes {
		lspMap[string(uri.PathToUri(k))] = ToTextEdits(v)
	}

	return &sglsp.WorkspaceEdit{Changes: lspMap}
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

func ToSeverity(severity snyk.Severity) types.DiagnosticSeverity {
	switch severity {
	case snyk.Critical:
		return types.DiagnosticsSeverityError
	case snyk.High:
		return types.DiagnosticsSeverityError
	case snyk.Medium:
		return types.DiagnosticsSeverityWarning
	case snyk.Low:
		return types.DiagnosticsSeverityInformation
	default:
		return types.DiagnosticsSeverityHint
	}
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

func ToDiagnostics(issues []snyk.Issue) []types.Diagnostic {
	// In JSON, `nil` serializes to `null`, while an empty slice serializes to `[]`.
	// Sending null instead of an empty array leads to stored diagnostics not being cleared.
	// Do not prefer nil over an empty slice in this case. The next line ensures that even if issues is empty,
	// the return value of this function will not be null.
	diagnostics := []types.Diagnostic{}

	for _, issue := range issues {
		s := ""
		if issue.IssueDescriptionURL != nil {
			s = issue.IssueDescriptionURL.String()
		}
		diagnostics = append(diagnostics, types.Diagnostic{
			Range:           ToRange(issue.Range),
			Severity:        ToSeverity(issue.Severity),
			Code:            issue.ID,
			Source:          string(issue.Product),
			Message:         issue.Message,
			CodeDescription: types.CodeDescription{Href: types.Uri(s)},
		})
	}
	return diagnostics
}

func ToHoversDocument(path string, issues []snyk.Issue) hover.DocumentHovers {
	return hover.DocumentHovers{
		Path:  path,
		Hover: ToHovers(issues),
	}
}

func ToHovers(issues []snyk.Issue) (hovers []hover.Hover[hover.Context]) {
	re := regexp.MustCompile(`<br\s?/?>`)
	for _, i := range issues {
		var message string
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
			Range:   i.Range,
			Message: message,
			Context: i,
		})
	}
	return hovers
}
