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
	"strings"

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
}

// EnhancedScanResult contains the original scan output and extracted issues
type EnhancedScanResult struct {
	OriginalOutput string      `json:"originalOutput"`
	Success        bool        `json:"success"`
	ScanType       string      `json:"scanType"`
	IssueCount     int         `json:"issueCount"`
	Issues         []IssueData `json:"issues"`
}

// mapScanResponse maps the scan response based on the tool name
func mapScanResponse(toolName string, output string, success bool) string {
	if !strings.HasPrefix(toolName, "snyk_") || (!strings.Contains(toolName, "_scan") && toolName != "snyk_sca_scan") {
		return output
	}

	var scanType string
	switch toolName {
	case "snyk_sca_scan":
		scanType = "SCA"
	case "snyk_code_scan":
		scanType = "SAST"
	default:
		return output
	}

	var issues []types.Issue
	var err error

	if scanType == "SCA" {
		issues, err = oss.ConvertJSONToIssues([]byte(output))
	} else if scanType == "SAST" {
		issues, err = code.ConvertSARIFJSONToIssues([]byte(output))
	}

	if err != nil {
		// Return original output if parsing fails
		return output
	}

	// Convert issues to IssueData for serialization
	issueDataList := make([]IssueData, 0, len(issues))
	for _, issue := range issues {
		issueData := IssueData{
			ID:       issue.GetID(),
			Title:    issue.GetAdditionalData().GetTitle(),
			Severity: strings.ToLower(issue.GetSeverity().String()),
			CWEs:     issue.GetCWEs(),
			CVEs:     issue.GetCVEs(),
		}

		// Add type-specific fields
		if scanType == "SCA" {
			if additionalData, ok := issue.GetAdditionalData().(snyk.OssIssueData); ok {
				issueData.PackageName = additionalData.PackageName
				issueData.Version = additionalData.Version
				issueData.Ecosystem = additionalData.PackageManager
				issueData.FixedIn = additionalData.FixedIn
				issueData.Remediation = additionalData.Remediation
			}
		} else if scanType == "SAST" {
			if additionalData, ok := issue.GetAdditionalData().(snyk.CodeIssueData); ok {
				issueData.RuleID = additionalData.RuleId
				issueData.FilePath = string(issue.GetAffectedFilePath())
				if len(additionalData.Rows) > 0 {
					issueData.Line = additionalData.Rows[0] + 1 // Convert to 1-based
				}
				if len(additionalData.Cols) > 0 {
					issueData.Column = additionalData.Cols[0] + 1
				}
			}
		}

		issueDataList = append(issueDataList, issueData)
	}

	result := EnhancedScanResult{
		OriginalOutput: output,
		Success:        success,
		ScanType:       strings.ToLower(scanType),
		IssueCount:     len(issueDataList),
		Issues:         issueDataList,
	}

	enhancedOutput, err := json.Marshal(result)
	if err != nil {
		return output
	}

	return string(enhancedOutput)
}
