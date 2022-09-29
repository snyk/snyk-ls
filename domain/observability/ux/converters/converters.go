/*
 * Copyright 2022 Snyk Ltd.
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
