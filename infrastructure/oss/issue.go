/*
 * 2022-2023 Snyk Limited
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

package oss

import (
	_ "embed"
	"fmt"
	"strings"

	"github.com/rs/zerolog"

	"github.com/snyk/snyk-ls/ast"
	"github.com/snyk/snyk-ls/infrastructure/utils"

	"github.com/gomarkdown/markdown"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

var issuesSeverity = map[string]types.Severity{
	"critical": types.Critical,
	"high":     types.High,
	"low":      types.Low,
	"medium":   types.Medium,
}

func toIssue(workDir types.FilePath, affectedFilePath types.FilePath, issue ossIssue, scanResult *scanResult, issueDepNode *ast.Node, learnService learn.Service, ep error_reporting.ErrorReporter, format string) *snyk.Issue {
	// this needs to be first so that the lesson from Snyk Learn is added
	codeActions := issue.AddCodeActions(learnService, ep, affectedFilePath, issueDepNode)

	// If no code actions were added (e.g., no AST node), but we have a learn service,
	// try to get the lesson directly for the MCP use case
	if len(codeActions) == 0 && learnService != nil && issue.lesson == nil && !issue.isLicenseIssue() && !issue.IsIgnored {
		lesson, err := learnService.GetLesson(issue.PackageManager, issue.Id, issue.Identifiers.CWE, issue.Identifiers.CVE, types.DependencyVulnerability)
		if err == nil && lesson != nil && lesson.Url != "" {
			issue.lesson = lesson
		}
	}

	var codelensCommands []types.CommandData
	for _, codeAction := range codeActions {
		if strings.Contains(codeAction.GetTitle(), "Upgrade to") {
			codelensCommands = append(codelensCommands, types.CommandData{
				Title:     codeAction.GetTitle(),
				CommandId: types.CodeFixCommand,
				Arguments: []any{
					codeAction.GetUuid(),
					affectedFilePath,
					getRangeFromNode(issueDepNode),
				},
				GroupingKey:   codeAction.GetGroupingKey(),
				GroupingType:  codeAction.GetGroupingType(),
				GroupingValue: codeAction.GetGroupingValue(),
			})
		}
	}
	// find all issues with the same id
	matchingIssues := []snyk.OssIssueData{}
	for _, otherIssue := range scanResult.Vulnerabilities {
		if otherIssue.Id == issue.Id {
			matchingIssues = append(matchingIssues, otherIssue.toAdditionalData(scanResult,
				[]snyk.OssIssueData{}, affectedFilePath))
		}
	}

	additionalData := issue.toAdditionalData(scanResult, matchingIssues, affectedFilePath)

	title := issue.Title
	if format == config.FormatHtml {
		title = string(markdown.ToHTML([]byte(title), nil, nil))
	}

	message := fmt.Sprintf(
		"%s affecting package %s. %s",
		title,
		issue.PackageName,
		additionalData.Remediation,
	)

	const maxLength = 200
	if len(message) > maxLength {
		message = message[:maxLength] + "... (Snyk)"
	}

	d := &snyk.Issue{
		ID:                  issue.Id,
		Message:             message,
		FormattedMessage:    issue.GetExtendedMessage(issue),
		Range:               getRangeFromNode(issueDepNode),
		Severity:            issue.ToIssueSeverity(),
		ContentRoot:         workDir,
		AffectedFilePath:    affectedFilePath,
		Product:             product.ProductOpenSource,
		IssueDescriptionURL: issue.CreateIssueURL(),
		IssueType:           types.DependencyVulnerability,
		CodeActions:         codeActions,
		CodelensCommands:    codelensCommands,
		Ecosystem:           issue.PackageManager,
		CWEs:                issue.Identifiers.CWE,
		CVEs:                issue.Identifiers.CVE,
		AdditionalData:      additionalData,
	}
	d.AdditionalData = additionalData
	fingerprint := utils.CalculateFingerprintFromAdditionalData(d)
	d.SetFingerPrint(fingerprint)

	return d
}

func getRangeFromNode(issueDepNode *ast.Node) types.Range {
	if issueDepNode == nil {
		return types.Range{}
	}
	r := types.Range{
		Start: types.Position{Line: issueDepNode.Line, Character: issueDepNode.StartChar},
		End:   types.Position{Line: issueDepNode.Line, Character: issueDepNode.EndChar},
	}
	return r
}

func convertScanResultToIssues(logger *zerolog.Logger, res *scanResult, workDir types.FilePath, targetFilePath types.FilePath, fileContent []byte, ls learn.Service, ep error_reporting.ErrorReporter, packageIssueCache map[string][]types.Issue, format string) []types.Issue {
	var issues []types.Issue

	duplicateCheckMap := map[string]bool{}

	for _, issue := range res.Vulnerabilities {
		if issue.IsIgnored {
			logger.Debug().Msgf("skipping ignored issue %s", issue.Id)
			continue
		}
		packageKey := issue.PackageName + "@" + issue.Version
		duplicateKey := string(targetFilePath) + "|" + issue.Id + "|" + issue.PackageName
		if duplicateCheckMap[duplicateKey] {
			continue
		}
		node := getDependencyNode(logger, targetFilePath, issue, fileContent)
		snykIssue := toIssue(workDir, targetFilePath, issue, res, node, ls, ep, format)
		packageIssueCache[packageKey] = append(packageIssueCache[packageKey], snykIssue)
		issues = append(issues, snykIssue)
		duplicateCheckMap[duplicateKey] = true
	}
	return issues
}
