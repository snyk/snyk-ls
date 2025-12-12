// Package filter provides centralized issue filtering logic for severity, risk score, and issue view options
package filter

import (
	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/types"
)

// FilterIssues applies severity, risk score, and issue view option filters to a list of issues
func FilterIssues(issues []types.Issue, c *config.Config, folderPath types.FilePath) []types.Issue {
	if len(issues) == 0 {
		return issues
	}

	var filteredIssues []types.Issue
	folderConfig := c.FolderConfig(folderPath)
	riskScoreEnabled := folderConfig.FeatureFlags[featureflag.UseExperimentalRiskScoreInCLI]
	codeConsistentIgnoresEnabled := folderConfig.FeatureFlags[featureflag.SnykCodeConsistentIgnores]

	for _, issue := range issues {
		if !IsVisibleSeverity(issue, c) {
			continue
		}

		if riskScoreEnabled && !IsVisibleRiskScore(issue, c) {
			continue
		}

		if codeConsistentIgnoresEnabled && !IsVisibleForIssueViewOptions(issue, c) {
			continue
		}

		filteredIssues = append(filteredIssues, issue)
	}

	return filteredIssues
}

// IsVisibleSeverity checks if the issue's severity passes the severity filter
func IsVisibleSeverity(issue types.Issue, c *config.Config) bool {
	switch issue.GetSeverity() {
	case types.Critical:
		return c.FilterSeverity().Critical
	case types.High:
		return c.FilterSeverity().High
	case types.Medium:
		return c.FilterSeverity().Medium
	case types.Low:
		return c.FilterSeverity().Low
	}
	return false
}

// IsVisibleRiskScore checks if the issue's risk score passes the risk score threshold
func IsVisibleRiskScore(issue types.Issue, c *config.Config) bool {
	riskScoreThreshold := c.RiskScoreThreshold()
	switch {
	case riskScoreThreshold == 0:
		return true
	case riskScoreThreshold < 0:
		return true
	case riskScoreThreshold > 1000:
		return false
	}

	// Get risk score from issue's additional data
	additionalData := issue.GetAdditionalData()
	ossIssueData, ok := additionalData.(snyk.OssIssueData)
	if !ok {
		// If it's not an OSS issue, don't filter by risk score
		return true
	}

	issueRiskScore := ossIssueData.RiskScore

	// If issue has no risk score (0 means not set for legacy scans), show all issues
	if issueRiskScore == 0 {
		return true
	}

	// Issue is visible if its risk score meets or exceeds the filter threshold
	return issueRiskScore >= uint16(riskScoreThreshold)
}

// IsVisibleForIssueViewOptions checks if the issue matches the current view options (open/ignored)
func IsVisibleForIssueViewOptions(issue types.Issue, c *config.Config) bool {
	issueViewOptions := c.IssueViewOptions()
	if issue.GetIsIgnored() {
		return issueViewOptions.IgnoredIssues
	}
	return issueViewOptions.OpenIssues
}
