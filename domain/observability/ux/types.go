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

package ux

type AnalysisIsReadyProperties struct {
	AnalysisType      AnalysisType `json:"analysisType"`
	Result            Result       `json:"result"`
	FileCount         int          `json:"fileCount,omitempty"`
	DurationInSeconds float64      `json:"durationInSeconds,omitempty"`
}

type AnalysisIsTriggeredProperties struct {
	AnalysisType    []AnalysisType `json:"analysisType"`
	TriggeredByUser bool           `json:"triggeredByUser"`
}

type IssueHoverIsDisplayedProperties struct {
	IssueId   string    `json:"issueId"`
	IssueType IssueType `json:"issueType"`
	Severity  Severity  `json:"severity"`
}

type PluginIsInstalledProperties struct {
}

type Result string
type AnalysisType string
type IDE string
type Severity string
type IssueType string

const (
	Advisor              AnalysisType = "Snyk Advisor"
	CodeQuality          AnalysisType = "Snyk Code Quality"
	CodeSecurity         AnalysisType = "Snyk Code Security"
	OpenSource           AnalysisType = "Snyk Open Source"
	Container            AnalysisType = "Snyk Container"
	InfrastructureAsCode AnalysisType = "Snyk Infrastructure as Code"
)

const (
	VisualStudioCode IDE = "Visual Studio Code"
	VisualStudio     IDE = "Visual Studio"
	Eclipse          IDE = "Eclipse"
	JetBrains        IDE = "JetBrains"
)

const (
	High     Severity = "High"
	Medium   Severity = "Medium"
	Low      Severity = "Low"
	Critical Severity = "Critical"
)

const (
	Success Result = "Success"
	Error   Result = "Error"
)

const (
	AdvisorIssue              IssueType = "Advisor"
	CodeQualityIssue          IssueType = "Code Quality Issue"
	CodeSecurityVulnerability IssueType = "Code Security Vulnerability"
	LicenceIssue              IssueType = "Licence Issue"
	OpenSourceVulnerability   IssueType = "Open Source Vulnerability"
	InfrastructureAsCodeIssue IssueType = "Infrastructure as Code Issue"
	ContainerVulnerability    IssueType = "Container Vulnerability"
)
