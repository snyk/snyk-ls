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

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/infrastructure/oss"
	"github.com/snyk/snyk-ls/internal/types"
)

// IssueData contains extracted issue information for serialization
type IssueData struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	RuleID      string   `json:"ruleId,omitempty"`
	CWEs        []string `json:"cwes,omitempty"`
	CVEs        []string `json:"cves,omitempty"`
	PackageName string   `json:"packageName,omitempty"`
	Version     string   `json:"version,omitempty"`
	Ecosystem   string   `json:"ecosystem,omitempty"`
	FixedIn     []string `json:"fixedIn,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	FilePath    string   `json:"filePath,omitempty"`
	Line        int      `json:"line,omitempty"`
	Column      int      `json:"column,omitempty"`
	Message     string   `json:"message,omitempty"` // Added for SAST issues
}

// EnhancedScanResult contains the original scan output and extracted issues
type EnhancedScanResult struct {
	OriginalOutput string      `json:"originalOutput"`
	Success        bool        `json:"success"`
	ScanType       string      `json:"scanType"`
	IssueCount     int         `json:"issueCount"`
	Issues         []IssueData `json:"issues"`
}

// mapScanResponse maps the scan output to an enhanced format for LLMs
func mapScanResponse(toolName string, output string, success bool, scanPath string) string {
	result := EnhancedScanResult{
		OriginalOutput: output,
		Success:        success,
		Issues:         []IssueData{},
	}

	// Extract scan type and handle response
	if isSCATool(toolName) {
		result.ScanType = "sca"
		extractSCAIssues(&result)
	} else if isSASTTool(toolName) {
		result.ScanType = "sast"
		extractSASTIssues(&result, scanPath)
	} else {
		// For other tools, just return the original output
		return output
	}

	// Marshal enhanced result
	enhancedJSON, err := json.Marshal(result)
	if err != nil {
		// Fallback to original output if marshaling fails
		return output
	}

	return string(enhancedJSON)
}

// isSCATool checks if the tool is an SCA scanner
func isSCATool(toolName string) bool {
	return toolName == "snyk_sca_scan"
}

// isSASTTool checks if the tool is a SAST scanner
func isSASTTool(toolName string) bool {
	return toolName == "snyk_code_scan"
}

// extractSCAIssues extracts issues from SCA scan output
func extractSCAIssues(result *EnhancedScanResult) {
	// Try to parse JSON output
	issues, err := oss.ConvertJSONToIssues([]byte(result.OriginalOutput))
	if err != nil {
		// If parsing fails, just keep the original output
		return
	}

	// Convert to IssueData format
	for _, issue := range issues {
		result.Issues = append(result.Issues, convertIssueToData(issue))
	}
	result.IssueCount = len(result.Issues)
}

// extractSASTIssues extracts issues from SAST scan output
func extractSASTIssues(result *EnhancedScanResult, scanPath string) {
	// Try to parse SARIF JSON output
	issues, err := code.ConvertSARIFJSONToIssues([]byte(result.OriginalOutput), scanPath)
	if err != nil {
		// If parsing fails, just keep the original output
		return
	}

	// Convert to IssueData format
	for _, issue := range issues {
		result.Issues = append(result.Issues, convertIssueToData(issue))
	}
	result.IssueCount = len(result.Issues)
}

// convertIssueToData converts a types.Issue to IssueData
func convertIssueToData(issue types.Issue) IssueData {
	issueData := IssueData{
		ID:       issue.GetID(),
		Title:    issue.GetAdditionalData().GetTitle(),
		Severity: issue.GetSeverity().String(),
		RuleID:   issue.GetID(), // For Snyk, ID is often the rule ID
		CWEs:     issue.GetCWEs(),
		CVEs:     issue.GetCVEs(),
	}

	// Extract additional data based on issue type
	if additionalData, ok := issue.GetAdditionalData().(snyk.OssIssueData); ok {
		issueData.PackageName = additionalData.PackageName
		issueData.Version = additionalData.Version
		issueData.Ecosystem = additionalData.PackageManager
		issueData.FixedIn = additionalData.FixedIn
		issueData.Remediation = additionalData.Remediation
		issueData.FilePath = string(additionalData.DisplayTargetFile)
		issueData.Line = additionalData.LineNumber
	}

	if additionalData, ok := issue.GetAdditionalData().(snyk.CodeIssueData); ok {
		issueData.FilePath = string(issue.GetAffectedFilePath())
		issueData.Line = issue.GetRange().Start.Line
		issueData.Column = issue.GetRange().Start.Character
		issueData.Message = additionalData.Message
	}

	return issueData
}
