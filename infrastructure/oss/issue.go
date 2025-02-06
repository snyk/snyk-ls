/*
 * © 2022-2023 Snyk Limited
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

var issuesSeverity = map[string]snyk.Severity{
	"critical": snyk.Critical,
	"high":     snyk.High,
	"low":      snyk.Low,
	"medium":   snyk.Medium,
}

func toIssue(affectedFilePath string, issue ossIssue, scanResult *scanResult, issueDepNode *ast.Node, learnService learn.Service, ep error_reporting.ErrorReporter) snyk.Issue {
	// this needs to be first so that the lesson from Snyk Learn is added
	codeActions := issue.AddCodeActions(learnService, ep, affectedFilePath, issueDepNode)

	var codelensCommands []types.CommandData
	for _, codeAction := range codeActions {
		if strings.Contains(codeAction.Title, "Upgrade to") {
			codelensCommands = append(codelensCommands, types.CommandData{
				Title:     codeAction.Title,
				CommandId: types.CodeFixCommand,
				Arguments: []any{
					codeAction.Uuid,
					affectedFilePath,
					getRangeFromNode(issueDepNode),
				},
				GroupingKey:   codeAction.GroupingKey,
				GroupingType:  codeAction.GroupingType,
				GroupingValue: codeAction.GroupingValue,
			})
		}
	}
	// find all issues with the same id
	matchingIssues := []snyk.OssIssueData{}
	for _, otherIssue := range scanResult.Vulnerabilities {
		if otherIssue.Id == issue.Id {
			matchingIssues = append(matchingIssues, otherIssue.toAdditionalData(scanResult,
				[]snyk.OssIssueData{}))
		}
	}

	additionalData := issue.toAdditionalData(scanResult, matchingIssues)

	title := issue.Title
	if config.CurrentConfig().Format() == config.FormatHtml {
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

	d := snyk.Issue{
		ID:                  issue.Id,
		Message:             message,
		FormattedMessage:    issue.GetExtendedMessage(issue),
		Range:               getRangeFromNode(issueDepNode),
		Severity:            issue.ToIssueSeverity(),
		AffectedFilePath:    affectedFilePath,
		Product:             product.ProductOpenSource,
		IssueDescriptionURL: issue.CreateIssueURL(),
		IssueType:           snyk.DependencyVulnerability,
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

func getRangeFromNode(issueDepNode *ast.Node) snyk.Range {
	if issueDepNode == nil {
		return snyk.Range{}
	}
	r := snyk.Range{
		Start: snyk.Position{Line: issueDepNode.Line, Character: issueDepNode.StartChar},
		End:   snyk.Position{Line: issueDepNode.Line, Character: issueDepNode.EndChar},
	}
	return r
}

func convertScanResultToIssues(c *config.Config, res *scanResult, targetFilePath string, fileContent []byte, ls learn.Service, ep error_reporting.ErrorReporter, packageIssueCache map[string][]snyk.Issue) []snyk.Issue {
	var issues []snyk.Issue

	duplicateCheckMap := map[string]bool{}

	for _, issue := range res.Vulnerabilities {
		packageKey := issue.PackageName + "@" + issue.Version
		duplicateKey := targetFilePath + "|" + issue.Id + "|" + issue.PackageName
		if duplicateCheckMap[duplicateKey] {
			continue
		}
		node := getDependencyNode(c, targetFilePath, issue, fileContent)
		snykIssue := toIssue(targetFilePath, issue, res, node, ls, ep)
		packageIssueCache[packageKey] = append(packageIssueCache[packageKey], snykIssue)
		issues = append(issues, snykIssue)
		duplicateCheckMap[duplicateKey] = true
	}
	return issues
}
