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
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
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
//
// When ctx carries a learn.Service via ctx2.DepLearnService, each produced issue is
// additionally enriched with a Snyk Learn LessonUrl. A missing service, a learn
// lookup error, or a nil/empty lesson all leave LessonUrl empty — the scan never
// fails because of Learn cache misses.
func (c *FindingsConverter) ToIssues(ctx context.Context, findings []testapi.FindingData, scanPath types.FilePath, folderPath types.FilePath) []types.Issue {
	learnService := learnServiceFromContext(ctx)
	var issues []types.Issue
	for i := range findings {
		issues = append(issues, c.findingToIssues(&findings[i], scanPath, folderPath, learnService)...)
	}
	c.logger.Debug().Int("count", len(issues)).Msg("converted findings to issues")
	return issues
}

// learnServiceFromContext returns the Snyk Learn service stored in the request
// context dependencies map, or nil when absent. Mirrors the read pattern used by
// infrastructure/oss/unified_converter.go.
func learnServiceFromContext(ctx context.Context) learn.Service {
	deps, ok := ctx2.DependenciesFromContext(ctx)
	if !ok {
		return nil
	}
	ls, _ := deps[ctx2.DepLearnService].(learn.Service)
	return ls
}

// findingToIssues converts a single testapi.FindingData into one issue per location.
// Returns an empty slice when the finding cannot be converted (e.g. missing attributes or locations).
// When learnService is non-nil, each emitted issue's LessonUrl is populated in-place
// from the Snyk Learn cache; lookup errors or empty lessons leave LessonUrl untouched.
//
// Sentry-reporter parity with the SAST scanner is intentionally omitted here:
// secrets.Scanner currently has no errorReporter dependency and the rest of the
// package logs transient errors via the scanner's zerolog logger only. Adding a
// non-actionable Learn-cache-miss Sentry event would be disproportionate; revisit
// alongside any future Sentry pass on the secrets package.
func (c *FindingsConverter) findingToIssues(finding *testapi.FindingData, scanPath types.FilePath, folderPath types.FilePath, learnService learn.Service) []types.Issue {
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

		isFullScan := scanPath == "" || scanPath == folderPath
		var affectedFilePath types.FilePath
		if isFullScan {
			affectedFilePath = types.FilePath(filepath.Join(string(folderPath), sourceLocation.FilePath))
		} else {
			affectedFilePath = scanPath
		}

		compositeKey := util.GetIssueKey(attrs.Key, sourceLocation.FilePath, issueRange.Start.Line, issueRange.End.Line, issueRange.Start.Character, issueRange.End.Character)
		riskScore := 0
		if attrs.Risk.RiskScore != nil {
			riskScore = int(attrs.Risk.RiskScore.Value)
		}
		additionalData := snyk.SecretsIssueData{
			Key:            compositeKey,
			Title:          attrs.Title,
			Message:        attrs.Description,
			RuleId:         ruleID,
			RuleName:       ruleName,
			CWE:            cwes,
			Categories:     categories,
			Cols:           snyk.CodePoint{issueRange.Start.Character, issueRange.End.Character},
			Rows:           snyk.CodePoint{issueRange.Start.Line, issueRange.End.Line},
			LocationsCount: len(attrs.Locations),
			RiskScore:      riskScore,
		}

		message := c.getMessage(attrs.Title, attrs.Description)
		formattedMessage := c.formattedMessageMarkdown(severity, attrs.Title, attrs.Description, cwes)

		issue := &snyk.Issue{
			ID:               ruleID,
			Severity:         severity,
			IssueType:        types.SecretsIssue,
			IsIgnored:        isIgnored,
			IgnoreDetails:    ignoreDetails,
			Range:            issueRange,
			Message:          message,
			FormattedMessage: formattedMessage,
			AffectedFilePath: affectedFilePath,
			ContentRoot:      folderPath,
			Product:          product.ProductSecrets,
			CWEs:             cwes,
			FindingId:        attrs.Key,
			Fingerprint:      attrs.Key,
			AdditionalData:   additionalData,
		}
		c.enrichWithLearnLesson(issue, learnService)
		issues = append(issues, issue)
	}
	return issues
}

// enrichWithLearnLesson looks up the Snyk Learn lesson for an issue and writes
// lesson.Url into LessonUrl on success. A nil learnService, a lookup error, or
// a nil/empty lesson all leave LessonUrl untouched — Learn cache misses must
// never fail the scan.
func (c *FindingsConverter) enrichWithLearnLesson(issue *snyk.Issue, learnService learn.Service) {
	if learnService == nil {
		return
	}
	lesson, err := learnService.GetLesson(
		issue.GetEcosystem(), issue.GetID(),
		issue.GetCWEs(), issue.GetCVEs(),
		issue.GetIssueType(),
	)
	if err != nil {
		c.logger.Warn().Err(err).Str("issueId", issue.GetID()).Msg("Failed to get learn lesson")
		return
	}
	if lesson != nil && lesson.Url != "" {
		issue.SetLessonUrl(lesson.Url)
	}
}

func (c *FindingsConverter) getMessage(title, description string) string {
	text := description
	if title != "" {
		text = fmt.Sprintf("%s: %s", title, description)
	}
	const maxLength = 100
	if len(text) > maxLength {
		text = text[:maxLength] + "..."
	}
	return text
}

func severityToMarkdown(severity types.Severity) string {
	switch severity {
	case types.Critical:
		return "🔥 Critical Severity"
	case types.High:
		return "🚨 High Severity"
	case types.Medium:
		return "⚠️ Medium Severity"
	case types.Low:
		return "⬇️ Low Severity"
	default:
		return "❔️ Unknown Severity"
	}
}

func cweToMarkdown(cwes []string) string {
	if len(cwes) == 0 {
		return ""
	}
	var builder strings.Builder
	ending := "y"
	if len(cwes) > 1 {
		ending = "ies"
	}
	fmt.Fprintf(&builder, "Vulnerabilit%s: ", ending)
	for i, cwe := range cwes {
		if i > 0 {
			builder.WriteString(" | ")
		}
		parts := strings.Split(cwe, "-")
		if len(parts) == 2 {
			fmt.Fprintf(&builder, "[%s](https://cwe.mitre.org/data/definitions/%s.html)", cwe, parts[1])
		} else {
			builder.WriteString(cwe)
		}
	}
	builder.WriteString("\n\n\n")
	return builder.String()
}

func (c *FindingsConverter) formattedMessageMarkdown(severity types.Severity, title, description string, cwes []string) string {
	var builder strings.Builder
	const separator = "\n\n\n\n"

	builder.Grow(500)
	fmt.Fprintf(&builder, "## %s", severityToMarkdown(severity))
	if title != "" {
		fmt.Fprintf(&builder, " | %s", title)
	}
	cwe := cweToMarkdown(cwes)
	if cwe != "" {
		builder.WriteString(" | ")
	}
	builder.WriteString(cwe)
	builder.WriteString(separator)
	builder.WriteString(description)

	return builder.String()
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

	status := ignoreDetails.GetStatus()
	isIgnored := status == testapi.SuppressionStatusIgnored

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

	category := ignoreDetails.GetIgnoreReasonType()
	return isIgnored, &types.IgnoreDetails{
		Reason:     reason,
		Expiration: expiration,
		IgnoredOn:  ignoredAt,
		IgnoredBy:  ignoredBy,
		Status:     status,
		IgnoreId:   ignoreId,
		Category:   category,
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
