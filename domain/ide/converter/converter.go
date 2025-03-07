/*
 * © 2022-2025 Snyk Limited All rights reserved.
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
	"regexp"
	"strconv"

	"github.com/gomarkdown/markdown"
	stripmd "github.com/writeas/go-strip-markdown"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/product"

	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

var htmlEndingRegExp = regexp.MustCompile(`<br\s?/?>`)

func FromRange(lspRange sglsp.Range) types.Range {
	return types.Range{
		Start: FromPosition(lspRange.Start),
		End:   FromPosition(lspRange.End),
	}
}

func FromPosition(pos sglsp.Position) types.Position {
	return types.Position{
		Line:      pos.Line,
		Character: pos.Character,
	}
}

func ToCodeActions(issues []types.Issue) (actions []types.LSPCodeAction) {
	dedupMap := map[string]bool{}
	for _, issue := range issues {
		for _, action := range issue.GetCodeActions() {
			if !dedupMap[action.GetTitle()] {
				codeAction := ToCodeAction(issue, action)
				actions = append(actions, codeAction)
				dedupMap[action.GetTitle()] = true
			}
		}
	}
	return actions
}

func ToCodeAction(issue types.Issue, action types.CodeAction) types.LSPCodeAction {
	var id *types.CodeActionData = nil
	if action.GetUuid() != nil {
		i := types.CodeActionData(*action.GetUuid())
		id = &i
	}
	return types.LSPCodeAction{
		Title:       action.GetTitle(),
		Kind:        types.QuickFix,
		Diagnostics: ToDiagnostics([]types.Issue{issue}),
		IsPreferred: action.GetIsPreferred(),
		Edit:        ToWorkspaceEdit(action.GetEdit()),
		Command:     ToCommand(action.GetCommand()),
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

func ToWorkspaceEdit(edit *types.WorkspaceEdit) *sglsp.WorkspaceEdit {
	if edit == nil {
		return nil
	}
	lspMap := map[string][]sglsp.TextEdit{}
	for k, v := range edit.Changes {
		lspMap[string(uri.PathToUri(types.FilePath(k)))] = ToTextEdits(v)
	}

	return &sglsp.WorkspaceEdit{Changes: lspMap}
}

func ToTextEdits(edits []types.TextEdit) (lspEdits []sglsp.TextEdit) {
	for _, edit := range edits {
		textEdit := ToTextEdit(edit)
		lspEdits = append(lspEdits, textEdit)
	}
	return lspEdits
}

func ToTextEdit(edit types.TextEdit) sglsp.TextEdit {
	return sglsp.TextEdit{
		Range:   ToRange(edit.Range),
		NewText: edit.NewText,
	}
}

func ToSeverity(severity types.Severity) types.DiagnosticSeverity {
	switch severity {
	case types.Critical:
		return types.DiagnosticsSeverityError
	case types.High:
		return types.DiagnosticsSeverityError
	case types.Medium:
		return types.DiagnosticsSeverityWarning
	case types.Low:
		return types.DiagnosticsSeverityInformation
	default:
		return types.DiagnosticsSeverityHint
	}
}

func ToRange(r types.Range) sglsp.Range {
	return sglsp.Range{
		Start: ToPosition(r.Start),
		End:   ToPosition(r.End),
	}
}

func ToPosition(p types.Position) sglsp.Position {
	return sglsp.Position{
		Line:      p.Line,
		Character: p.Character,
	}
}

func ToDiagnostics(issues []types.Issue) []types.Diagnostic {
	// In JSON, `nil` serializes to `null`, while an empty slice serializes to `[]`.
	// Sending null instead of an empty array leads to stored diagnostics not being cleared.
	// Do not prefer nil over an empty slice in this case. The next line ensures that even if issues is empty,
	// the return value of this function will not be null.
	diagnostics := []types.Diagnostic{}

	for _, issue := range issues {
		s := ""
		if issue.GetIssueDescriptionURL() != nil {
			s = issue.GetIssueDescriptionURL().String()
		}
		diagnostic := types.Diagnostic{
			Range:           ToRange(issue.GetRange()),
			Severity:        ToSeverity(issue.GetSeverity()),
			Code:            issue.GetID(),
			Source:          string(issue.GetProduct()),
			Message:         issue.GetMessage(),
			CodeDescription: types.CodeDescription{Href: types.Uri(s)},
		}
		if issue.GetProduct() == product.ProductInfrastructureAsCode {
			diagnostic.Data = getIacIssue(issue)
		} else if issue.GetProduct() == product.ProductCode {
			diagnostic.Data = getCodeIssue(issue)
		} else if issue.GetProduct() == product.ProductOpenSource {
			diagnostic.Data = getOssIssue(issue)
		}
		diagnostics = append(diagnostics, diagnostic)
	}
	return diagnostics
}

func getOssIssue(issue types.Issue) types.ScanIssue {
	additionalData, ok := issue.GetAdditionalData().(snyk.OssIssueData)
	if !ok {
		return types.ScanIssue{}
	}

	matchingIssues := make([]types.OssIssueData, len(additionalData.MatchingIssues))
	for i, matchingIssue := range additionalData.MatchingIssues {
		matchingIssues[i] = types.OssIssueData{
			License: matchingIssue.License,
			Identifiers: types.OssIdentifiers{
				CWE: issue.GetCWEs(),
				CVE: issue.GetCVEs(),
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
		}
	}

	scanIssue := types.ScanIssue{
		Id:                  additionalData.Key,
		Title:               additionalData.Title,
		Severity:            issue.GetSeverity().String(),
		FilePath:            issue.GetAffectedFilePath(),
		Range:               ToRange(issue.GetRange()),
		IsIgnored:           issue.GetIsIgnored(),
		IsNew:               issue.GetIsNew(),
		FilterableIssueType: additionalData.GetFilterableIssueType(),
		AdditionalData: types.OssIssueData{
			Key:     additionalData.Key,
			RuleId:  issue.GetID(),
			License: additionalData.License,
			Identifiers: types.OssIdentifiers{
				CWE: issue.GetCWEs(),
				CVE: issue.GetCVEs(),
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
			MatchingIssues:    matchingIssues,
			Lesson:            additionalData.Lesson,
		},
	}

	return scanIssue
}

func getIacIssue(issue types.Issue) types.ScanIssue {
	additionalData, ok := issue.GetAdditionalData().(snyk.IaCIssueData)
	if !ok {
		return types.ScanIssue{}
	}

	scanIssue := types.ScanIssue{
		Id:                  additionalData.Key,
		Title:               additionalData.Title,
		Severity:            issue.GetSeverity().String(),
		FilePath:            issue.GetAffectedFilePath(),
		Range:               ToRange(issue.GetRange()),
		IsIgnored:           issue.GetIsIgnored(),
		IsNew:               issue.GetIsNew(),
		FilterableIssueType: additionalData.GetFilterableIssueType(),
		AdditionalData: types.IacIssueData{
			Key:           additionalData.Key,
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

func getCodeIssue(issue types.Issue) types.ScanIssue {
	additionalData, ok := issue.GetAdditionalData().(snyk.CodeIssueData)
	if !ok {
		return types.ScanIssue{}
	}

	markers := make([]types.Marker, 0, len(additionalData.Markers))
	for _, marker := range additionalData.Markers {
		positions := make([]types.MarkerPosition, 0)
		for _, pos := range marker.Pos {
			positions = append(positions, types.MarkerPosition{
				CodeFlowPositionInFile: types.CodeFlowPositionInFile{
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
		Id:                  additionalData.Key,
		Title:               issue.GetMessage(),
		Severity:            issue.GetSeverity().String(),
		FilePath:            issue.GetAffectedFilePath(),
		Range:               ToRange(issue.GetRange()),
		IsIgnored:           issue.GetIsIgnored(),
		IsNew:               issue.GetIsNew(),
		FilterableIssueType: additionalData.GetFilterableIssueType(),
		AdditionalData: types.CodeIssueData{
			Key:             additionalData.Key,
			Message:         additionalData.Message,
			Rule:            additionalData.Rule,
			RuleId:          additionalData.RuleId,
			RepoDatasetSize: additionalData.RepoDatasetSize,
			CWE:             additionalData.CWE,
			IsSecurityType:  additionalData.IsSecurityType,
			Text:            additionalData.Text,
			Cols:            additionalData.Cols,
			Rows:            additionalData.Rows,
			PriorityScore:   additionalData.PriorityScore,
			Markers:         markers,
			LeadURL:         "",
			HasAIFix:        additionalData.HasAIFix,
			DataFlow:        dataFlow,
		},
	}
	if scanIssue.IsIgnored {
		scanIssue.IgnoreDetails =
			types.IgnoreDetails{
				Category:   issue.GetIgnoreDetails().Category,
				Reason:     issue.GetIgnoreDetails().Reason,
				Expiration: issue.GetIgnoreDetails().Expiration,
				IgnoredOn:  issue.GetIgnoreDetails().IgnoredOn,
				IgnoredBy:  issue.GetIgnoreDetails().IgnoredBy,
			}
	}

	return scanIssue
}

func ToHoversDocument(p product.Product, path types.FilePath, issues []types.Issue) hover.DocumentHovers {
	return hover.DocumentHovers{
		Path:    path,
		Hover:   ToHovers(issues),
		Product: p,
	}
}

func ToHovers(issues []types.Issue) (hovers []hover.Hover[hover.Context]) {
	c := config.CurrentConfig()
	if c.HoverVerbosity() == 0 {
		return hovers
	}

	for _, i := range issues {
		var message string
		if len(i.GetFormattedMessage()) > 0 {
			message = i.GetFormattedMessage()
		} else {
			message = i.GetMessage()
		}

		hoverOutputFormat := c.Format()
		if hoverOutputFormat == config.FormatHtml {
			message = string(markdown.ToHTML([]byte(message), nil, nil))
		} else if hoverOutputFormat == config.FormatMd {
			// sanitize the message, substitute <br> with line break
			message = htmlEndingRegExp.ReplaceAllString(message, "\n\n")
		} else {
			// if anything else (e.g. plain), strip markdown
			message = stripmd.Strip(message)
		}

		hovers = append(hovers, hover.Hover[hover.Context]{
			Id:      i.GetID(),
			Range:   i.GetRange(),
			Message: message,
			Context: i,
		})
	}
	return hovers
}
