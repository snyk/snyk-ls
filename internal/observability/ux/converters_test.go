package ux

import (
	"reflect"
	"testing"

	"github.com/snyk/snyk-ls/domain/snyk/issues"
)

func TestNewIssueHoverIsDisplayedProperties(t *testing.T) {
	tests := []struct {
		name   string
		input  issues.Issue
		output IssueHoverIsDisplayedProperties
	}{
		{
			name: "critical issues",
			input: issues.Issue{
				ID:        "id",
				Severity:  issues.Critical,
				IssueType: issues.PackageHealth,
			},
			output: IssueHoverIsDisplayedProperties{
				IssueId:   "id",
				Severity:  Critical,
				IssueType: AdvisorIssue,
			},
		},
		{
			name: "high severity issues",
			input: issues.Issue{
				ID:        "id",
				Severity:  issues.High,
				IssueType: issues.PackageHealth,
			},
			output: IssueHoverIsDisplayedProperties{
				IssueId:   "id",
				Severity:  High,
				IssueType: AdvisorIssue,
			},
		},
		{
			name: "medium severity issues",
			input: issues.Issue{
				ID:        "id",
				Severity:  issues.Medium,
				IssueType: issues.PackageHealth,
			},
			output: IssueHoverIsDisplayedProperties{
				IssueId:   "id",
				Severity:  Medium,
				IssueType: AdvisorIssue,
			},
		},
		{
			name: "low severity issues",
			input: issues.Issue{
				ID:        "id",
				Severity:  issues.Low,
				IssueType: issues.PackageHealth,
			},
			output: IssueHoverIsDisplayedProperties{
				IssueId:   "id",
				Severity:  Low,
				IssueType: AdvisorIssue,
			},
		},
		{
			name: "oss issues",
			input: issues.Issue{
				ID:        "id",
				Severity:  issues.Critical,
				IssueType: issues.DependencyVulnerability,
			},
			output: IssueHoverIsDisplayedProperties{
				IssueId:   "id",
				Severity:  Critical,
				IssueType: OpenSourceVulnerability,
			},
		},
		{
			name: "iac issues",
			input: issues.Issue{
				ID:        "id",
				Severity:  issues.Critical,
				IssueType: issues.InfrastructureIssue,
			},
			output: IssueHoverIsDisplayedProperties{
				IssueId:   "id",
				Severity:  Critical,
				IssueType: InfrastructureAsCodeIssue,
			},
		},
		{
			name: "code security issues",
			input: issues.Issue{
				ID:        "id",
				Severity:  issues.Critical,
				IssueType: issues.CodeSecurityVulnerability,
			},
			output: IssueHoverIsDisplayedProperties{
				IssueId:   "id",
				Severity:  Critical,
				IssueType: CodeSecurityVulnerability,
			},
		},
		{
			name: "code quality issues",
			input: issues.Issue{
				ID:        "id",
				Severity:  issues.Critical,
				IssueType: issues.CodeQualityIssue,
			},
			output: IssueHoverIsDisplayedProperties{
				IssueId:   "id",
				Severity:  Critical,
				IssueType: CodeQualityIssue,
			},
		},
		{
			name: "code quality issues",
			input: issues.Issue{
				ID:        "id",
				Severity:  issues.Critical,
				IssueType: issues.LicenceIssue,
			},
			output: IssueHoverIsDisplayedProperties{
				IssueId:   "id",
				Severity:  Critical,
				IssueType: LicenceIssue,
			},
		},
		{
			name: "code quality issues",
			input: issues.Issue{
				ID:        "id",
				Severity:  issues.Critical,
				IssueType: issues.ContainerVulnerability,
			},
			output: IssueHoverIsDisplayedProperties{
				IssueId:   "id",
				Severity:  Critical,
				IssueType: ContainerVulnerability,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewIssueHoverIsDisplayedProperties(tt.input); !reflect.DeepEqual(got, tt.output) {
				t.Errorf("NewIssueHoverIsDisplayedProperties() = %v, want %v", got, tt.output)
			}
		})
	}
}
