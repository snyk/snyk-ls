package converters

import (
	"github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
)

func NewIssueHoverIsDisplayedProperties(issue snyk.Issue) ux.IssueHoverIsDisplayedProperties {
	return ux.IssueHoverIsDisplayedProperties{
		IssueId:   issue.ID,
		IssueType: types[issue.IssueType],
		Severity:  severities[issue.Severity],
	}
}

var (
	types = map[snyk.Type]ux.IssueType{
		snyk.PackageHealth:             ux.AdvisorIssue,
		snyk.CodeQualityIssue:          ux.CodeQualityIssue,
		snyk.CodeSecurityVulnerability: ux.CodeSecurityVulnerability,
		snyk.LicenceIssue:              ux.LicenceIssue,
		snyk.DependencyVulnerability:   ux.OpenSourceVulnerability,
		snyk.InfrastructureIssue:       ux.InfrastructureAsCodeIssue,
		snyk.ContainerVulnerability:    ux.ContainerVulnerability,
	}
	severities = map[snyk.Severity]ux.Severity{
		snyk.Critical: ux.Critical,
		snyk.High:     ux.High,
		snyk.Medium:   ux.Medium,
		snyk.Low:      ux.Low,
	}
)
