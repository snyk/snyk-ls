package ux

import (
	"github.com/snyk/snyk-ls/domain/snyk/issues"
)

func NewIssueHoverIsDisplayedProperties(issue issues.Issue) IssueHoverIsDisplayedProperties {
	return IssueHoverIsDisplayedProperties{
		IssueId:   issue.ID,
		IssueType: types[issue.IssueType],
		Severity:  severities[issue.Severity],
	}
}

var (
	types = map[issues.Type]IssueType{
		issues.PackageHealth:             AdvisorIssue,
		issues.CodeQualityIssue:          CodeQualityIssue,
		issues.CodeSecurityVulnerability: CodeSecurityVulnerability,
		issues.LicenceIssue:              LicenceIssue,
		issues.DependencyVulnerability:   OpenSourceVulnerability,
		issues.InfrastructureIssue:       InfrastructureAsCodeIssue,
		issues.ContainerVulnerability:    ContainerVulnerability,
	}
	severities = map[issues.Severity]Severity{
		issues.Critical: Critical,
		issues.High:     High,
		issues.Medium:   Medium,
		issues.Low:      Low,
	}
)
