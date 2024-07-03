/*
 * © 2023 Snyk Limited
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

package hover

import (
	"reflect"
	"testing"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/observability/ux"
)

func TestNewIssueHoverIsDisplayedProperties(t *testing.T) {
	tests := []struct {
		name   string
		input  snyk.Issue
		output ux.IssueHoverIsDisplayedProperties
	}{
		{
			name: "critical issues",
			input: snyk.Issue{
				ID:        "id",
				Severity:  snyk.Critical,
				IssueType: snyk.PackageHealth,
			},
			output: ux.IssueHoverIsDisplayedProperties{
				IssueId:   "id",
				Severity:  ux.Critical,
				IssueType: ux.AdvisorIssue,
			},
		},
		{
			name: "high severity issues",
			input: snyk.Issue{
				ID:        "id",
				Severity:  snyk.High,
				IssueType: snyk.PackageHealth,
			},
			output: ux.IssueHoverIsDisplayedProperties{
				IssueId:   "id",
				Severity:  ux.High,
				IssueType: ux.AdvisorIssue,
			},
		},
		{
			name: "medium severity issues",
			input: snyk.Issue{
				ID:        "id",
				Severity:  snyk.Medium,
				IssueType: snyk.PackageHealth,
			},
			output: ux.IssueHoverIsDisplayedProperties{
				IssueId:   "id",
				Severity:  ux.Medium,
				IssueType: ux.AdvisorIssue,
			},
		},
		{
			name: "low severity issues",
			input: snyk.Issue{
				ID:        "id",
				Severity:  snyk.Low,
				IssueType: snyk.PackageHealth,
			},
			output: ux.IssueHoverIsDisplayedProperties{
				IssueId:   "id",
				Severity:  ux.Low,
				IssueType: ux.AdvisorIssue,
			},
		},
		{
			name: "oss issues",
			input: snyk.Issue{
				ID:        "id",
				Severity:  snyk.Critical,
				IssueType: snyk.DependencyVulnerability,
			},
			output: ux.IssueHoverIsDisplayedProperties{
				IssueId:   "id",
				Severity:  ux.Critical,
				IssueType: ux.OpenSourceVulnerability,
			},
		},
		{
			name: "iac issues",
			input: snyk.Issue{
				ID:        "id",
				Severity:  snyk.Critical,
				IssueType: snyk.InfrastructureIssue,
			},
			output: ux.IssueHoverIsDisplayedProperties{
				IssueId:   "id",
				Severity:  ux.Critical,
				IssueType: ux.InfrastructureAsCodeIssue,
			},
		},
		{
			name: "code security issues",
			input: snyk.Issue{
				ID:        "id",
				Severity:  snyk.Critical,
				IssueType: snyk.CodeSecurityVulnerability,
			},
			output: ux.IssueHoverIsDisplayedProperties{
				IssueId:   "id",
				Severity:  ux.Critical,
				IssueType: ux.CodeSecurityVulnerability,
			},
		},
		{
			name: "code quality issues",
			input: snyk.Issue{
				ID:        "id",
				Severity:  snyk.Critical,
				IssueType: snyk.CodeQualityIssue,
			},
			output: ux.IssueHoverIsDisplayedProperties{
				IssueId:   "id",
				Severity:  ux.Critical,
				IssueType: ux.CodeQualityIssue,
			},
		},
		{
			name: "code quality issues",
			input: snyk.Issue{
				ID:        "id",
				Severity:  snyk.Critical,
				IssueType: snyk.LicenceIssue,
			},
			output: ux.IssueHoverIsDisplayedProperties{
				IssueId:   "id",
				Severity:  ux.Critical,
				IssueType: ux.LicenceIssue,
			},
		},
		{
			name: "code quality issues",
			input: snyk.Issue{
				ID:        "id",
				Severity:  snyk.Critical,
				IssueType: snyk.ContainerVulnerability,
			},
			output: ux.IssueHoverIsDisplayedProperties{
				IssueId:   "id",
				Severity:  ux.Critical,
				IssueType: ux.ContainerVulnerability,
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
