/*
 * © 2024 Snyk Limited
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

package mcp_extension

import (
	"encoding/json"

	"github.com/rs/zerolog"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/infrastructure/oss"
	"github.com/snyk/snyk-ls/internal/types"
)

// IssueData contains extracted issue information for serialization
type IssueData struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Severity    string                 `json:"severity"`
	RuleID      string                 `json:"ruleId,omitempty"`
	Dataflow    []snyk.DataFlowElement `json:"dataflow,omitempty"`
	CWEs        []string               `json:"cwes,omitempty"`
	CVEs        []string               `json:"cves,omitempty"`
	PackageName string                 `json:"packageName,omitempty"`
	Version     string                 `json:"version,omitempty"`
	Ecosystem   string                 `json:"ecosystem,omitempty"`
	FixedIn     []string               `json:"fixedIn,omitempty"`
	Remediation string                 `json:"remediation,omitempty"`
	FilePath    string                 `json:"filePath,omitempty"`
	Line        int                    `json:"line,omitempty"`
	Column      int                    `json:"column,omitempty"`
	Message     string                 `json:"message,omitempty"`
	LearnURL    string                 `json:"learnUrl,omitempty"`
	FingerPrint string                 `json:"fingerPrint,omitempty"`
}

const (
	CodeOutputMapper = "CodeOutputMapper"
	ScaOutputMapper  = "ScaOutputMapper"
)

// EnhancedScanResult contains the original scan output and extracted issues
type EnhancedScanResult struct {
	OriginalOutput string      `json:"-"`
	Success        bool        `json:"success"`
	IssueCount     int         `json:"issueCount"`
	Issues         []IssueData `json:"issues"`
}

// mapScanResponse maps the scan output to an enhanced format for LLMs
func mapScanResponse(logger *zerolog.Logger, toolDef SnykMcpToolsDefinition, output string, success bool, workDir string, learnService learn.Service) string {
	mapperFunc, ok := outputMapperMap[toolDef.OutputMapper]
	if !ok || !IsJSON(output) {
		return output
	}

	result := EnhancedScanResult{
		OriginalOutput: output,
		Success:        success,
		Issues:         []IssueData{},
	}

	mapperFunc(logger, &result, learnService, workDir)

	enhancedJSON, err := json.Marshal(result)
	if err != nil {
		return output
	}

	return string(enhancedJSON)
}

// extractSCAIssues extracts structured issue data from SCA JSON output
func extractSCAIssues(logger *zerolog.Logger, result *EnhancedScanResult, learnService learn.Service, workDir string) {
	issues, err := oss.ConvertJSONToIssues(logger, []byte(result.OriginalOutput), learnService, workDir)
	if err != nil {
		return
	}

	for _, issue := range issues {
		result.Issues = append(result.Issues, convertIssueToData(issue))
	}
	result.IssueCount = len(result.Issues)
}

// extractSASTIssues extracts issues from SAST scan output
func extractSASTIssues(logger *zerolog.Logger, result *EnhancedScanResult, _ learn.Service, workDir string) {
	issues, err := code.ConvertSARIFJSONToIssues(logger, 0, []byte(result.OriginalOutput), workDir)
	if err != nil {
		return
	}

	for _, issue := range issues {
		result.Issues = append(result.Issues, convertIssueToData(issue))
	}
	result.IssueCount = len(result.Issues)
}

// convertIssueToData converts a types.Issue to IssueData for serialization
func convertIssueToData(issue types.Issue) IssueData {
	title := ""
	learnURL := issue.GetLessonUrl()

	if additionalData := issue.GetAdditionalData(); additionalData != nil {
		title = additionalData.GetTitle()
	}

	data := IssueData{
		ID:       issue.GetID(),
		Title:    title,
		Severity: issue.GetSeverity().String(),
		Message:  issue.GetMessage(),
		LearnURL: learnURL,
	}

	// Handle different issue types
	if additionalData := issue.GetAdditionalData(); additionalData != nil {
		switch ad := additionalData.(type) {
		case snyk.OssIssueData:
			data.PackageName = ad.PackageName
			data.Version = ad.Version
			data.Ecosystem = ad.PackageManager
			data.FixedIn = ad.FixedIn
			data.Remediation = ad.Remediation
			data.CVEs = ad.Identifiers.CVE
			data.CWEs = ad.Identifiers.CWE
			data.RuleID = issue.GetRuleID()
			// OSS stores lesson URL in additional data
			if ad.Lesson != "" {
				data.LearnURL = ad.Lesson
			}

		case snyk.CodeIssueData:
			data.RuleID = ad.RuleId
			data.CWEs = ad.CWE
			data.Dataflow = ad.DataFlow
			data.FingerPrint = issue.GetFingerprint()
		}
	}

	// Add file location if available
	if affectedFile := issue.GetAffectedFilePath(); affectedFile != "" {
		data.FilePath = string(affectedFile)
		r := issue.GetRange()
		if r.Start.Line >= 0 && r.Start.Character >= 0 {
			data.Line = r.Start.Line + 1 // Convert 0-based to 1-based
			data.Column = r.Start.Character + 1
		}
	}

	return data
}
