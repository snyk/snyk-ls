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
	"github.com/snyk/snyk-ls/internal/product"
	"regexp"
	"strconv"

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
	dedupMap := map[string]bool{}
	for _, issue := range issues {
		for _, action := range issue.CodeActions {
			if !dedupMap[action.Title] {
				codeAction := ToCodeAction(issue, action)
				actions = append(actions, codeAction)
				dedupMap[action.Title] = true
			}
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
		diagnostic := types.Diagnostic{
			Range:           ToRange(issue.Range),
			Severity:        ToSeverity(issue.Severity),
			Code:            issue.ID,
			Source:          string(issue.Product),
			Message:         issue.Message,
			CodeDescription: types.CodeDescription{Href: types.Uri(s)},
		}
		if issue.Product == product.ProductInfrastructureAsCode {
			diagnostic.Data = getIacIssue(issue)
		} else if issue.Product == product.ProductCode {
			diagnostic.Data = getCodeIssue(issue)
		} else if issue.Product == product.ProductOpenSource {
			diagnostic.Data = getOssIssue(issue)
		}
		diagnostics = append(diagnostics, diagnostic)
	}
	return diagnostics
}

func getOssIssue(issue snyk.Issue) types.ScanIssue {
	additionalData, ok := issue.AdditionalData.(snyk.OssIssueData)
	if !ok {
		return types.ScanIssue{}
	}

	matchingIssues := make([]types.OssIssueData, len(additionalData.MatchingIssues))
	for i, matchingIssue := range additionalData.MatchingIssues {
		matchingIssues[i] = types.OssIssueData{
			License: matchingIssue.License,
			Identifiers: types.OssIdentifiers{
				CWE: issue.CWEs,
				CVE: issue.CVEs,
			},
			Description:       matchingIssue.Description,
			Language:          matchingIssue.Language,
			PackageManager:    matchingIssue.PackageManager,
			PackageName:       matchingIssue.PackageName,
			Name:              matchingIssue.Name,
			Version:           matchingIssue.Version,
			Exploit:           matchingIssue.Exploit,
			CVSSv3:            matchingIssue.CVSSv3,
			CvssScore:         strconv.FormatFloat(matchingIssue.CvssScore, 'f', 2, 64), // convert float64 to string with 2 decimal places
			FixedIn:           matchingIssue.FixedIn,
			From:              matchingIssue.From,
			UpgradePath:       matchingIssue.UpgradePath,
			IsPatchable:       matchingIssue.IsPatchable,
			IsUpgradable:      matchingIssue.IsUpgradable,
			ProjectName:       matchingIssue.ProjectName,
			DisplayTargetFile: matchingIssue.DisplayTargetFile,
			Details:           matchingIssue.Details,
		}
	}

	scanIssue := types.ScanIssue{
		Id:       additionalData.Key,
		Title:    additionalData.Title,
		Severity: issue.Severity.String(),
		FilePath: issue.AffectedFilePath,
		Range:    ToRange(issue.Range),
		AdditionalData: types.OssIssueData{
			RuleId:  issue.ID,
			License: additionalData.License,
			Identifiers: types.OssIdentifiers{
				CWE: issue.CWEs,
				CVE: issue.CVEs,
			},
			Description:       additionalData.Description,
			Language:          additionalData.Language,
			PackageManager:    additionalData.PackageManager,
			PackageName:       additionalData.PackageName,
			Name:              additionalData.Name,
			Version:           additionalData.Version,
			Exploit:           additionalData.Exploit,
			CVSSv3:            additionalData.CVSSv3,
			CvssScore:         strconv.FormatFloat(additionalData.CvssScore, 'f', 2, 64), // convert float64 to string with 2 decimal places
			FixedIn:           additionalData.FixedIn,
			From:              additionalData.From,
			UpgradePath:       additionalData.UpgradePath,
			IsPatchable:       additionalData.IsPatchable,
			IsUpgradable:      additionalData.IsUpgradable,
			ProjectName:       additionalData.ProjectName,
			DisplayTargetFile: additionalData.DisplayTargetFile,
			Details:           additionalData.Details,
			MatchingIssues:    matchingIssues,
			Lesson:            additionalData.Lesson,
		},
	}

	return scanIssue
}

func getIacIssue(issue snyk.Issue) types.ScanIssue {
	additionalData, ok := issue.AdditionalData.(snyk.IaCIssueData)
	if !ok {
		return types.ScanIssue{}
	}

	scanIssue := types.ScanIssue{
		Id:       additionalData.Key,
		Title:    additionalData.Title,
		Severity: issue.Severity.String(),
		FilePath: issue.AffectedFilePath,
		Range:    ToRange(issue.Range),
		AdditionalData: types.IacIssueData{
			PublicId:      additionalData.PublicId,
			Documentation: additionalData.Documentation,
			LineNumber:    additionalData.LineNumber,
			Issue:         additionalData.Issue,
			Impact:        additionalData.Impact,
			Resolve:       additionalData.Resolve,
			Path:          additionalData.Path,
			References:    additionalData.References,
		},
	}

	return scanIssue
}

func getCodeIssue(issue snyk.Issue) types.ScanIssue {
	additionalData, ok := issue.AdditionalData.(snyk.CodeIssueData)
	if !ok {
		return types.ScanIssue{}
	}

	exampleCommitFixes := make([]types.ExampleCommitFix, 0, len(additionalData.ExampleCommitFixes))
	for i := range additionalData.ExampleCommitFixes {
		lines := make([]types.CommitChangeLine, 0, len(additionalData.ExampleCommitFixes[i].Lines))
		for j := range additionalData.ExampleCommitFixes[i].Lines {
			lines = append(lines, types.CommitChangeLine{
				Line:       additionalData.ExampleCommitFixes[i].Lines[j].Line,
				LineNumber: additionalData.ExampleCommitFixes[i].Lines[j].LineNumber,
				LineChange: additionalData.ExampleCommitFixes[i].Lines[j].LineChange,
			})
		}
		exampleCommitFixes = append(exampleCommitFixes, types.ExampleCommitFix{
			CommitURL: additionalData.ExampleCommitFixes[i].CommitURL,
			Lines:     lines,
		})
	}

	markers := make([]types.Marker, 0, len(additionalData.Markers))
	for _, marker := range additionalData.Markers {
		positions := make([]types.MarkerPosition, 0)
		for _, pos := range marker.Pos {
			positions = append(positions, types.MarkerPosition{
				Position: types.Position{
					Rows: pos.Rows,
					Cols: pos.Cols,
				},
				File: pos.File,
			})
		}

		markers = append(markers, types.Marker{
			Msg: marker.Msg,
			Pos: positions,
		})
	}

	dataFlow := make([]types.DataflowElement, 0, len(additionalData.DataFlow))
	for _, flow := range additionalData.DataFlow {
		dataFlow = append(dataFlow, types.DataflowElement{
			Position:  flow.Position,
			FilePath:  flow.FilePath,
			FlowRange: ToRange(flow.FlowRange),
			Content:   flow.Content,
		})
	}

	scanIssue := types.ScanIssue{
		Id:        additionalData.Key,
		Title:     issue.Message,
		Severity:  issue.Severity.String(),
		FilePath:  issue.AffectedFilePath,
		Range:     ToRange(issue.Range),
		IsIgnored: issue.IsIgnored,
		IsNew:     issue.IsNew,
		AdditionalData: types.CodeIssueData{
			Message:            additionalData.Message,
			Rule:               additionalData.Rule,
			RuleId:             additionalData.RuleId,
			RepoDatasetSize:    additionalData.RepoDatasetSize,
			ExampleCommitFixes: exampleCommitFixes,
			CWE:                additionalData.CWE,
			IsSecurityType:     additionalData.IsSecurityType,
			Text:               additionalData.Text,
			Cols:               additionalData.Cols,
			Rows:               additionalData.Rows,
			PriorityScore:      additionalData.PriorityScore,
			Markers:            markers,
			LeadURL:            "",
			HasAIFix:           additionalData.HasAIFix,
			DataFlow:           dataFlow,
			Details:            additionalData.Details,
		},
	}
	if scanIssue.IsIgnored {
		scanIssue.IgnoreDetails =
			types.IgnoreDetails{
				Category:   issue.IgnoreDetails.Category,
				Reason:     issue.IgnoreDetails.Reason,
				Expiration: issue.IgnoreDetails.Expiration,
				IgnoredOn:  issue.IgnoreDetails.IgnoredOn,
				IgnoredBy:  issue.IgnoreDetails.IgnoredBy,
			}
	}

	return scanIssue
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
