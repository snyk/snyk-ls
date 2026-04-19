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

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/gomarkdown/markdown"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/ast"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/infrastructure/utils"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

// vulnIndicesByID maps each vulnerability id to indices into scanResult.Vulnerabilities (scan order).
func vulnIndicesByID(res *scanResult) map[string][]int {
	if res == nil || len(res.Vulnerabilities) == 0 {
		return nil
	}
	out := make(map[string][]int)
	for i := range res.Vulnerabilities {
		id := res.Vulnerabilities[i].Id
		out[id] = append(out[id], i)
	}
	return out
}

// matchingIssueKeysForGroup returns the stable issue key for each vulnerability row sharing the same
// public id (same scan order as legacy MatchingIssues, without copying full OssIssueData).
func matchingIssueKeysForGroup(
	logger *zerolog.Logger,
	res *scanResult,
	sameIDIndices []int,
	targetFilePath types.FilePath,
	fileContent []byte,
) []string {
	keys := make([]string, 0, len(sameIDIndices))
	for _, idx := range sameIDIndices {
		other := &res.Vulnerabilities[idx]
		node := getDependencyNode(logger, targetFilePath, other.PackageManager, other.From, fileContent)
		r := getRangeFromNode(node)
		k := util.GetIssueKey(other.Id, string(targetFilePath), r.Start.Line, r.End.Line, r.Start.Character, r.End.Character)
		keys = append(keys, k)
	}
	return keys
}

func toIssue(engine workflow.Engine, configResolver types.ConfigResolverInterface, workDir types.FilePath, affectedFilePath types.FilePath, issue ossIssue, scanResult *scanResult, sameIDIndices []int, issueDepNode *ast.Node, learnService learn.Service, ep error_reporting.ErrorReporter, format string, folderConfig *types.FolderConfig, fileContent []byte) *snyk.Issue {
	rangeFromNode := getRangeFromNode(issueDepNode)
	logger := engine.GetLogger().With().Str("method", "toIssue").Logger()
	matchingKeys := matchingIssueKeysForGroup(&logger, scanResult, sameIDIndices, affectedFilePath, fileContent)

	additionalData := issue.toAdditionalData(engine, scanResult, matchingKeys, affectedFilePath, rangeFromNode)

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
		ID:      issue.Id,
		Message: message,
		FormattedMessage: GetExtendedMessage(
			configResolver,
			engine,
			issue.Id,
			issue.Title,
			issue.Description,
			issue.Severity,
			issue.PackageName,
			issue.Identifiers.CVE,
			issue.Identifiers.CWE,
			issue.FixedIn,
			folderConfig,
		),
		Range:               rangeFromNode,
		Severity:            issue.ToIssueSeverity(),
		ContentRoot:         workDir,
		AffectedFilePath:    affectedFilePath,
		Product:             product.ProductOpenSource,
		IssueDescriptionURL: CreateIssueURL(engine, issue.Id),
		IssueType:           types.DependencyVulnerability,
		Ecosystem:           issue.PackageManager,
		CWEs:                issue.Identifiers.CWE,
		CVEs:                issue.Identifiers.CVE,
		LessonUrl:           additionalData.Lesson,
		AdditionalData:      additionalData,
	}
	fingerprint := utils.CalculateFingerprintFromAdditionalData(snykIssue)
	snykIssue.SetFingerPrint(fingerprint)

	addCodeActionsAndLenses(engine, configResolver, learnService, ep, affectedFilePath, issueDepNode, snykIssue, folderConfig)

	return snykIssue
}

func addCodeActionsAndLenses(
	engine workflow.Engine,
	configResolver types.ConfigResolverInterface,
	learnService learn.Service,
	ep error_reporting.ErrorReporter,
	affectedFilePath types.FilePath,
	issueDepNode *ast.Node,
	issue *snyk.Issue,
	folderConfig *types.FolderConfig,
) {
	// this needs to be first so that the lesson from Snyk Learn is added
	codeActions := GetCodeActions(engine, configResolver, learnService, ep, affectedFilePath, issueDepNode, issue, folderConfig)

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

func convertScanResultToIssues(engine workflow.Engine, configResolver types.ConfigResolverInterface, res *scanResult, workDir types.FilePath, targetFilePath types.FilePath, fileContent []byte, learnService learn.Service, ep error_reporting.ErrorReporter, format string, folderConfig *types.FolderConfig) []types.Issue {
	logger := engine.GetLogger().With().Str("method", "convertScanResultToIssues").Logger()
	var issues []types.Issue

	duplicateCheckMap := map[string]bool{}
	byID := vulnIndicesByID(res)

	for _, ossLegacyIssue := range res.Vulnerabilities {
		if ossLegacyIssue.IsIgnored {
			logger.Debug().Msgf("skipping ignored issue %s", ossLegacyIssue.Id)
			continue
		}
		duplicateKey := string(targetFilePath) + "|" + ossLegacyIssue.Id + "|" + ossLegacyIssue.PackageName
		if duplicateCheckMap[duplicateKey] {
			continue
		}
		node := getDependencyNode(&logger, targetFilePath, ossLegacyIssue.PackageManager, ossLegacyIssue.From, fileContent)
		sameID := byID[ossLegacyIssue.Id]
		snykIssue := toIssue(engine, configResolver, workDir, targetFilePath, ossLegacyIssue, res, sameID, node, learnService, ep, format, folderConfig, fileContent)
		issues = append(issues, snykIssue)
		duplicateCheckMap[duplicateKey] = true
	}
	return issues
}
