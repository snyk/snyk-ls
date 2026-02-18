/*
 * © 2026 Snyk Limited
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

package secrets

import (
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	codeClientSarif "github.com/snyk/code-client-go/sarif"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

// FindingsConverter converts unified API findings into internal Issue types.
type FindingsConverter struct {
	logger *zerolog.Logger
}

// NewFindingsConverter creates a new FindingsConverter.
func NewFindingsConverter(logger *zerolog.Logger) *FindingsConverter {
	return &FindingsConverter{logger: logger}
}

// ToIssues converts a slice of testapi.FindingData into a slice of types.Issue.
// Findings with multiple locations produce one issue per location.
func (c *FindingsConverter) ToIssues(findings []testapi.FindingData, scanPath types.FilePath, folderPath types.FilePath) []types.Issue {
	var issues []types.Issue
	for i := range findings {
		issues = append(issues, c.findingToIssues(&findings[i], scanPath, folderPath)...)
	}
	c.logger.Debug().Int("count", len(issues)).Msg("converted findings to issues")
	return issues
}

// findingToIssues converts a single testapi.FindingData into one issue per location.
// Returns an empty slice when the finding cannot be converted (e.g. missing attributes or locations).
func (c *FindingsConverter) findingToIssues(finding *testapi.FindingData, scanPath types.FilePath, folderPath types.FilePath) []types.Issue {
	if finding.Attributes == nil {
		return nil
	}
	attrs := finding.Attributes

	if len(attrs.Locations) == 0 {
		c.logger.Warn().Str("key", attrs.Key).Msg("finding has no locations, skipping")
		return nil
	}

	severity := toSeverity(string(attrs.Rating.Severity))
	cwes, ruleID, ruleName, categories := extractProblems(attrs.Problems)
	if ruleID == "" {
		ruleID = attrs.Key
	}

	isIgnored, ignoreDetails := suppressionToIgnoreDetails(finding.GetIgnoreDetails())

	var issues []types.Issue
	for _, loc := range attrs.Locations {
		sourceLocation, err := loc.AsSourceLocation()
		if err != nil {
			c.logger.Warn().Err(err).Str("key", attrs.Key).Msg("failed to parse source location")
			continue
		}

		issueRange := toRange(sourceLocation)
		affectedFilePath := types.FilePath(filepath.Join(string(scanPath), sourceLocation.FilePath))

		key := util.GetIssueKey(attrs.Key, string(affectedFilePath), issueRange.Start.Line, issueRange.End.Line, issueRange.Start.Character, issueRange.End.Character)
		additionalData := snyk.SecretIssueData{
			Key:        key,
			Title:      attrs.Title,
			Message:    attrs.Description,
			RuleId:     ruleID,
			RuleName:   ruleName,
			CWE:        cwes,
			Categories: categories,
			Cols:       snyk.CodePoint{issueRange.Start.Character, issueRange.End.Character},
			Rows:       snyk.CodePoint{issueRange.Start.Line, issueRange.End.Line},
		}

		issues = append(issues, &snyk.Issue{
			ID:               uuid.New().String(),
			Severity:         severity,
			IssueType:        types.SecretsIssue,
			IsIgnored:        isIgnored,
			IgnoreDetails:    ignoreDetails,
			Range:            issueRange,
			Message:          attrs.Title,
			AffectedFilePath: affectedFilePath,
			ContentRoot:      folderPath,
			Product:          product.ProductSecrets,
			CWEs:             cwes,
			FindingId:        attrs.Key,
			Fingerprint:      key,
			AdditionalData:   additionalData,
		})
	}
	return issues
}

// toRange converts a 1-based SourceLocation into a 0-based types.Range.
func toRange(loc testapi.SourceLocation) types.Range {
	startLine := loc.FromLine - 1
	startCol := 0
	if loc.FromColumn != nil {
		startCol = *loc.FromColumn - 1
	}
	endLine := startLine
	if loc.ToLine != nil {
		endLine = util.Max(*loc.ToLine-1, startLine)
	}
	endCol := 0
	if loc.ToColumn != nil {
		endCol = util.Max(*loc.ToColumn-1, 0)
	}

	return types.Range{
		Start: types.Position{Line: startLine, Character: startCol},
		End:   types.Position{Line: endLine, Character: endCol},
	}
}

// extractProblems iterates over finding problems and extracts CWE ids,
// rule id, rule name and categories from the appropriate problem types.
func extractProblems(problems []testapi.Problem) (cwes []string, ruleID string, ruleName string, categories []string) {
	for _, problem := range problems {
		discriminator, discErr := problem.Discriminator()
		if discErr != nil {
			continue
		}
		switch discriminator {
		case "cwe":
			cweProblem, cwErr := problem.AsCweProblem()
			if cwErr == nil {
				cwes = append(cwes, cweProblem.Id)
			}
		case "secret":
			secretsRule, secErr := problem.AsSecretsRuleProblem()
			if secErr == nil {
				ruleID = secretsRule.Id
				ruleName = secretsRule.Name
				categories = secretsRule.Categories
			}
		}
	}
	return cwes, ruleID, ruleName, categories
}

// suppressionToIgnoreDetails converts a testapi.Suppression into isIgnored flag and IgnoreDetails.
func suppressionToIgnoreDetails(ignoreDetails testapi.IssueIgnoreDetails) (bool, *types.IgnoreDetails) {
	if ignoreDetails == nil {
		return false, nil
	}

	status := mapSuppressionStatus(ignoreDetails.GetStatus())
	isIgnored := status == codeClientSarif.Accepted

	reason := "None given"
	justification := ignoreDetails.GetJustification()
	if justification != nil && *justification != "" {
		reason = *justification
	}

	expiration := ""
	if ignoreDetails.GetExpiresAt() != nil {
		expiration = ignoreDetails.GetExpiresAt().String()
	}
	ignoredAt := time.Time{}
	if ignoreDetails.GetCreatedAt() != nil {
		ignoredAt = *ignoreDetails.GetCreatedAt()
	}

	ignoredBy := ""
	if ignoreDetails.GetIgnoredBy() != nil && ignoreDetails.GetIgnoredBy().Email != nil {
		ignoredBy = *ignoreDetails.GetIgnoredBy().Email
	}
	ignoreId := ""
	if ignoreDetails.GetPolicyID() != nil {
		ignoreId = *ignoreDetails.GetPolicyID()
	}

	return isIgnored, &types.IgnoreDetails{
		Reason:     reason,
		Expiration: expiration,
		IgnoredOn:  ignoredAt,
		IgnoredBy:  ignoredBy,
		Status:     status,
		IgnoreId:   ignoreId,
	}
}

// mapSuppressionStatus maps testapi.SuppressionStatus to codeClientSarif.SuppresionStatus.
func mapSuppressionStatus(status testapi.SuppressionStatus) codeClientSarif.SuppresionStatus {
	switch status {
	case testapi.SuppressionStatusIgnored:
		return codeClientSarif.Accepted
	case testapi.SuppressionStatusPendingIgnoreApproval:
		return codeClientSarif.UnderReview
	default:
		return ""
	}
}

// toSeverity maps a severity string to the internal types.Severity.
func toSeverity(severity string) types.Severity {
	s, ok := types.IssuesSeverity[strings.ToLower(severity)]
	if !ok {
		return types.Low
	}
	return s
}
