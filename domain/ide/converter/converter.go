/*
 * © 2022-2025 Snyk Limited
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

// Package converter implements conversions between Snyk and LSP types
package converter

import (
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/gomarkdown/markdown"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/workflow"
	stripmd "github.com/writeas/go-strip-markdown"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/product"

	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/internal/util"
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

func ToCodeActions(issues []types.Issue, canonicalRoot types.FilePath) (actions []types.LSPCodeAction) {
	dedupMap := map[string]bool{}
	for _, issue := range issues {
		for _, action := range issue.GetCodeActions() {
			if !dedupMap[action.GetTitle()] {
				codeAction := ToCodeAction(issue, action, canonicalRoot)
				actions = append(actions, codeAction)
				dedupMap[action.GetTitle()] = true
			}
		}
	}
	return actions
}

// ToCodeAction converts a single issue+action to an LSP code action. canonicalRoot
// is the canonical registered workspace-folder root; it is threaded into the
// embedded diagnostics so the code action's FindingId matches the one emitted for
// the same finding by publishDiagnostics (which also anchors to the folder root).
func ToCodeAction(issue types.Issue, action types.CodeAction, canonicalRoot types.FilePath) types.LSPCodeAction {
	var id *types.CodeActionData = nil
	if action.GetUuid() != nil {
		i := types.CodeActionData(*action.GetUuid())
		id = &i
	}
	kind := types.QuickFix
	return types.LSPCodeAction{
		Title:       action.GetTitle(),
		Kind:        kind,
		Diagnostics: ToDiagnosticsForFolder([]types.Issue{issue}, canonicalRoot, nil),
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

// ToDiagnostics converts issues to LSP diagnostics without a known canonical
// workspace root. Prefer ToDiagnosticsForFolder from a folder context so that
// ContentRoot and FindingId are anchored to the canonical registered root.
func ToDiagnostics(issues []types.Issue) []types.Diagnostic {
	return ToDiagnosticsForFolder(issues, "", nil)
}

// ToDiagnosticsForFolder converts issues to LSP diagnostics, stamping every
// resulting ScanIssue with the canonical registered workspace-folder root and a
// root-relative FindingId. canonicalRoot is the registered folder root; when it
// is empty the issue's own ContentRoot is used as a fallback (e.g. for the
// single-issue code-action path where no folder context is available).
func ToDiagnosticsForFolder(issues []types.Issue, canonicalRoot types.FilePath, logger *zerolog.Logger) []types.Diagnostic {
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
			diagnostic.Data = getIacIssue(issue, canonicalRoot, logger)
		} else if issue.GetProduct() == product.ProductCode {
			diagnostic.Data = getCodeIssue(issue, canonicalRoot, logger)
		} else if issue.GetProduct() == product.ProductOpenSource {
			diagnostic.Data = getOssIssue(issue, canonicalRoot, logger)
		} else if issue.GetProduct() == product.ProductSecrets {
			diagnostic.Data = getSecretIssue(issue, canonicalRoot, logger)
		}
		diagnostics = append(diagnostics, diagnostic)
	}
	return diagnostics
}

// canonicalContentRoot returns the canonical registered workspace-folder root to
// stamp on a ScanIssue. It prefers the folder root passed by the caller and
// falls back to the issue's own ContentRoot when no folder context is available.
func canonicalContentRoot(issue types.Issue, canonicalRoot types.FilePath) types.FilePath {
	if canonicalRoot != "" {
		return canonicalRoot
	}
	return issue.GetContentRoot()
}

// rootRelativePath expresses filePath relative to root using forward slashes, so
// the value is identical across a git-worktree copy of the same tree. If a
// relative path cannot be derived (e.g. root is empty), the forward-slashed
// input path is returned unchanged.
func rootRelativePath(root types.FilePath, filePath types.FilePath, logger *zerolog.Logger) string {
	// No folder context: there is nothing to make the path relative to. Return the
	// forward-slashed path as-is. This is an expected degenerate case (e.g. the
	// code-action path with no folder), not an error, so it is handled before Rel
	// and never logs.
	if root == "" {
		return filepath.ToSlash(string(filePath))
	}
	rel, err := filepath.Rel(string(root), string(filePath))
	if err != nil {
		// A non-empty root that cannot be related to the file yields a
		// non-portable (absolute-ish) id; surface it rather than failing silently.
		if logger != nil {
			logger.Warn().Err(err).
				Str("root", string(root)).
				Str("filePath", string(filePath)).
				Msg("could not derive root-relative path for finding identity; falling back to the file path")
		}
		return filepath.ToSlash(string(filePath))
	}
	return filepath.ToSlash(rel)
}

// computeFindingIdentity builds the stable, instance-unique, worktree-portable
// FindingId for an issue from its durable grouping key (issue.GetFindingId())
// combined with the root-relative path and normalized range. This is the single
// product-agnostic seam; per-product grouping-key sourcing is layered upstream.
//
// Products whose per-result-set key is location-independent can use this directly.
// IaC must NOT: its GetKey() bakes the absolute affected path in, so it computes
// its identity via computeFindingIdentityForKey with the location-independent
// publicID instead (see getIacIssue).
func computeFindingIdentity(issue types.Issue, contentRoot types.FilePath, logger *zerolog.Logger) string {
	// The grouping key is the product's durable finding id. Products that do not
	// (yet) emit one return an empty string; fall back to the issue's per-instance
	// key so instance uniqueness holds. When a product later supplies a real
	// finding id, that takes precedence.
	groupingKey := issue.GetFindingId()
	if groupingKey == "" {
		if ad := issue.GetAdditionalData(); ad != nil {
			groupingKey = ad.GetKey()
		}
	}
	return computeFindingIdentityForKey(groupingKey, issue, contentRoot, logger)
}

// computeFindingIdentityForKey composes the FindingId from an explicit grouping
// key plus the issue's root-relative path and normalized range. It lets a product
// supply a grouping key other than issue.GetFindingId()/GetKey() (IaC uses its
// location-independent publicID). When the resolved grouping key is empty, the
// composite reduces to path+range, so two distinct findings at the same location
// would collide; a warning is logged so that condition is diagnosable.
func computeFindingIdentityForKey(groupingKey string, issue types.Issue, contentRoot types.FilePath, logger *zerolog.Logger) string {
	if groupingKey == "" && logger != nil {
		logger.Warn().
			Str("filePath", string(issue.GetAffectedFilePath())).
			Str("product", string(issue.GetProduct())).
			Msg("computing finding identity with an empty grouping key; distinct findings at the same location may collide")
	}
	rel := rootRelativePath(contentRoot, issue.GetAffectedFilePath(), logger)
	r := issue.GetRange()
	return util.ComputeFindingIdentity(
		groupingKey,
		rel,
		r.Start.Line, r.Start.Character, r.End.Line, r.End.Character,
	)
}

func getOssIssue(issue types.Issue, canonicalRoot types.FilePath, logger *zerolog.Logger) types.ScanIssue {
	additionalData, ok := issue.GetAdditionalData().(snyk.OssIssueData)
	if !ok {
		return types.ScanIssue{}
	}

	contentRoot := canonicalContentRoot(issue, canonicalRoot)

	matchingIssues := make([]types.OssIssueData, len(additionalData.MatchingIssues))
	for i, matchingIssue := range additionalData.MatchingIssues {
		matchingIssues[i] = types.OssIssueData{
			License: matchingIssue.License,
			Identifiers: types.OssIdentifiers{
				CWE: issue.GetCWEs(),
				CVE: issue.GetCVEs(),
			},
			Title:             matchingIssue.Title,
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
			CvssSources:       additionalData.CvssSources,
		}
	}

	scanIssue := types.ScanIssue{
		Id:                  additionalData.Key,
		FindingId:           computeFindingIdentity(issue, contentRoot, logger),
		Title:               additionalData.Title,
		Severity:            issue.GetSeverity().String(),
		FilePath:            issue.GetAffectedFilePath(),
		ContentRoot:         contentRoot,
		Range:               ToRange(issue.GetRange()),
		IsIgnored:           issue.GetIsIgnored(),
		IsNew:               issue.GetIsNew(),
		FilterableIssueType: additionalData.GetFilterableIssueType(),
		AdditionalData: types.OssIssueData{
			Key:     additionalData.Key,
			RuleId:  issue.GetID(),
			Title:   additionalData.Title,
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
			CvssSources:       additionalData.CvssSources,
			FixedIn:           additionalData.FixedIn,
			From:              additionalData.From,
			UpgradePath:       additionalData.UpgradePath,
			IsPatchable:       additionalData.IsPatchable,
			IsUpgradable:      additionalData.IsUpgradable,
			ProjectName:       additionalData.ProjectName,
			DisplayTargetFile: additionalData.DisplayTargetFile,
			MatchingIssues:    matchingIssues,
			Lesson:            additionalData.Lesson,
			RiskScore:         additionalData.RiskScore,
		},
	}

	return scanIssue
}

func getIacIssue(issue types.Issue, canonicalRoot types.FilePath, logger *zerolog.Logger) types.ScanIssue {
	additionalData, ok := issue.GetAdditionalData().(snyk.IaCIssueData)
	if !ok {
		return types.ScanIssue{}
	}

	contentRoot := canonicalContentRoot(issue, canonicalRoot)

	// IaC has no GetFindingId(), and its per-result-set Key bakes the ABSOLUTE
	// affected path in, so keying identity off it would give the same finding a
	// different FindingId in a git-worktree copy. Use the location-independent
	// publicID as the grouping key so the identity is worktree-portable; the
	// root-relative path + range still individuate distinct instances that share a
	// publicID (e.g. the same rule firing at two locations).
	scanIssue := types.ScanIssue{
		Id:                  additionalData.Key,
		FindingId:           computeFindingIdentityForKey(additionalData.PublicId, issue, contentRoot, logger),
		Title:               additionalData.Title,
		Severity:            issue.GetSeverity().String(),
		FilePath:            issue.GetAffectedFilePath(),
		ContentRoot:         contentRoot,
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

func getCodeIssue(issue types.Issue, canonicalRoot types.FilePath, logger *zerolog.Logger) types.ScanIssue {
	additionalData, ok := issue.GetAdditionalData().(snyk.CodeIssueData)
	if !ok {
		return types.ScanIssue{}
	}

	contentRoot := canonicalContentRoot(issue, canonicalRoot)

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
		FindingId:           computeFindingIdentity(issue, contentRoot, logger),
		Title:               issue.GetMessage(),
		Severity:            issue.GetSeverity().String(),
		FilePath:            issue.GetAffectedFilePath(),
		ContentRoot:         contentRoot,
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

func getSecretIssue(issue types.Issue, canonicalRoot types.FilePath, logger *zerolog.Logger) types.ScanIssue {
	additionalData, ok := issue.GetAdditionalData().(snyk.SecretsIssueData)
	if !ok {
		return types.ScanIssue{}
	}

	contentRoot := canonicalContentRoot(issue, canonicalRoot)

	scanIssue := types.ScanIssue{
		Id:                  additionalData.Key,
		FindingId:           computeFindingIdentity(issue, contentRoot, logger),
		Title:               additionalData.Title,
		Severity:            issue.GetSeverity().String(),
		FilePath:            issue.GetAffectedFilePath(),
		ContentRoot:         contentRoot,
		Range:               ToRange(issue.GetRange()),
		IsIgnored:           issue.GetIsIgnored(),
		IsNew:               issue.GetIsNew(),
		FilterableIssueType: additionalData.GetFilterableIssueType(),
		AdditionalData: types.SecretIssueData{
			Key:            additionalData.Key,
			Title:          additionalData.Title,
			Message:        additionalData.Message,
			RuleId:         additionalData.RuleId,
			RuleName:       additionalData.RuleName,
			CWE:            additionalData.CWE,
			Categories:     additionalData.Categories,
			Cols:           additionalData.Cols,
			Rows:           additionalData.Rows,
			Fingerprint:    issue.GetFingerprint(),
			LocationsCount: additionalData.LocationsCount,
		},
	}

	if scanIssue.IsIgnored && issue.GetIgnoreDetails() != nil {
		scanIssue.IgnoreDetails = types.IgnoreDetails{
			Category:   issue.GetIgnoreDetails().Category,
			Reason:     issue.GetIgnoreDetails().Reason,
			Expiration: issue.GetIgnoreDetails().Expiration,
			IgnoredOn:  issue.GetIgnoreDetails().IgnoredOn,
			IgnoredBy:  issue.GetIgnoreDetails().IgnoredBy,
		}
	}

	return scanIssue
}

func ToHoversDocument(engine workflow.Engine, configResolver types.ConfigResolverInterface, p product.Product, path types.FilePath, issues []types.Issue, folderConfig *types.FolderConfig) hover.DocumentHovers {
	return hover.DocumentHovers{
		Path:    path,
		Hover:   ToHovers(engine, configResolver, issues, folderConfig),
		Product: p,
	}
}

func ToHovers(engine workflow.Engine, configResolver types.ConfigResolverInterface, issues []types.Issue, folderConfig *types.FolderConfig) (hovers []hover.Hover[hover.Context]) {
	if configResolver.GetInt(types.SettingHoverVerbosity, folderConfig) == 0 {
		return hovers
	}

	for _, i := range issues {
		var message string
		if len(i.GetFormattedMessage()) > 0 {
			message = i.GetFormattedMessage()
		} else {
			message = i.GetMessage()
		}

		hoverOutputFormat := configResolver.GetString(types.SettingFormat, folderConfig)
		switch hoverOutputFormat {
		case config.FormatHtml:
			message = string(markdown.ToHTML([]byte(message), nil, nil))
		case config.FormatMd:
			// sanitize the message, substitute <br> with line break
			message = htmlEndingRegExp.ReplaceAllString(message, "\n\n")
		default:
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
