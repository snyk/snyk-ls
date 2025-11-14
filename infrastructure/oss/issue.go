/*
 * © 2025 Snyk Limited
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
	"sync"

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

func toIssue(c *config.Config, workDir types.FilePath, affectedFilePath types.FilePath, issue ossIssue, scanResult *scanResult, issueDepNode *ast.Node, learnService learn.Service, ep error_reporting.ErrorReporter, format string) *snyk.Issue {
	rangeFromNode := getRangeFromNode(issueDepNode)

	// find all issues with the same id
	matchingIssues := []snyk.OssIssueData{}
	for _, otherIssue := range scanResult.Vulnerabilities {
		if otherIssue.Id == issue.Id {
			matchingIssues = append(matchingIssues, otherIssue.toAdditionalData(
				scanResult,
				[]snyk.OssIssueData{},
				affectedFilePath,
				rangeFromNode,
			))
		}
	}

	additionalData := issue.toAdditionalData(scanResult, matchingIssues, affectedFilePath, rangeFromNode)

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

	if learnService != nil && issue.lesson == nil && !issue.isLicenseIssue() && !issue.IsIgnored {
		lesson, err := learnService.GetLesson(issue.PackageManager, issue.Id, issue.Identifiers.CWE, issue.Identifiers.CVE, types.DependencyVulnerability)
		if err == nil && lesson != nil && lesson.Url != "" {
			additionalData.Lesson = lesson.Url
		}
	}

	snykIssue := &snyk.Issue{
		ID:                  issue.Id,
		Message:             message,
		FormattedMessage:    issue.GetExtendedMessage(issue),
		Range:               rangeFromNode,
		Severity:            issue.ToIssueSeverity(),
		ContentRoot:         workDir,
		AffectedFilePath:    affectedFilePath,
		Product:             product.ProductOpenSource,
		IssueDescriptionURL: CreateIssueURL(issue.Id),
		IssueType:           types.DependencyVulnerability,
		Ecosystem:           issue.PackageManager,
		CWEs:                issue.Identifiers.CWE,
		CVEs:                issue.Identifiers.CVE,
		LessonUrl:           additionalData.Lesson,
		AdditionalData:      additionalData,
	}
	fingerprint := utils.CalculateFingerprintFromAdditionalData(snykIssue)
	snykIssue.SetFingerPrint(fingerprint)

	addCodeActionsAndLenses(c, learnService, ep, affectedFilePath, issueDepNode, snykIssue)

	return snykIssue
}

func addCodeActionsAndLenses(
	c *config.Config,
	learnService learn.Service,
	ep error_reporting.ErrorReporter,
	affectedFilePath types.FilePath,
	issueDepNode *ast.Node,
	issue *snyk.Issue,
) {
	// this needs to be first so that the lesson from Snyk Learn is added
	codeActions := GetCodeActions(c, learnService, ep, affectedFilePath, issueDepNode, issue)

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
	issue.CodeActions = codeActions
	issue.CodelensCommands = codelensCommands
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

// as issue cache can be updated outside of context, and it's not
// supporting concurrent operations, let's only do additions to any
// cache using this mutex.
//
// currently convertScanResultToIssues is the only place where a
// packageIssueCache is changed at all, so the mutex is defined here
// to keep it close to the code that needs it.
var packageIssueCacheMutex sync.Mutex

func convertScanResultToIssues(c *config.Config, res *scanResult, workDir types.FilePath, targetFilePath types.FilePath, fileContent []byte, learnService learn.Service, ep error_reporting.ErrorReporter, packageIssueCache map[string][]types.Issue, format string) []types.Issue {
	logger := c.Logger().With().Str("method", "convertScanResultToIssues").Logger()
	var issues []types.Issue

	duplicateCheckMap := map[string]bool{}

	for _, ossLegacyIssue := range res.Vulnerabilities {
		if ossLegacyIssue.IsIgnored {
			logger.Debug().Msgf("skipping ignored issue %s", ossLegacyIssue.Id)
			continue
		}
		packageKey := ossLegacyIssue.PackageName + "@" + ossLegacyIssue.Version
		duplicateKey := string(targetFilePath) + "|" + ossLegacyIssue.Id + "|" + ossLegacyIssue.PackageName
		if duplicateCheckMap[duplicateKey] {
			continue
		}
		node := getDependencyNode(&logger, targetFilePath, ossLegacyIssue.PackageManager, ossLegacyIssue.From, fileContent)
		snykIssue := toIssue(c, workDir, targetFilePath, ossLegacyIssue, res, node, learnService, ep, format)
		packageIssueCacheMutex.Lock()
		packageIssueCache[packageKey] = append(packageIssueCache[packageKey], snykIssue)
		packageIssueCacheMutex.Unlock()
		issues = append(issues, snykIssue)
		duplicateCheckMap[duplicateKey] = true
	}
	return issues
}
