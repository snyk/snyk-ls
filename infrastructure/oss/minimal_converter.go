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

package oss

import (
	"encoding/json"
	"fmt"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/utils"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

// ConvertJSONToIssuesWithoutDependencies converts OSS JSON output to Issues without requiring external dependencies
// This is a minimal version for use by MCP and other tools that need conversion without a full scanner
// It reuses existing methods from ossIssue but skips features that require external services
func ConvertJSONToIssuesWithoutDependencies(jsonOutput []byte) ([]types.Issue, error) {
	var scanResults []scanResult
	var issues []types.Issue

	// Try parsing as array first
	if err := json.Unmarshal(jsonOutput, &scanResults); err != nil {
		// Try parsing as single object
		var singleResult scanResult
		if err := json.Unmarshal(jsonOutput, &singleResult); err != nil {
			return nil, fmt.Errorf("failed to parse OSS JSON: %w", err)
		}
		scanResults = append(scanResults, singleResult)
	}

	for _, scanResult := range scanResults {
		// Determine target file path
		targetFilePath := types.FilePath(scanResult.DisplayTargetFile)
		if targetFilePath == "" {
			targetFilePath = types.FilePath(scanResult.Path)
		}

		for _, vuln := range scanResult.Vulnerabilities {
			if vuln.IsIgnored {
				continue
			}

			// Find all matching issues with the same ID for the additional data
			matchingIssues := []snyk.OssIssueData{}
			for _, otherIssue := range scanResult.Vulnerabilities {
				if otherIssue.Id == vuln.Id {
					matchingIssues = append(matchingIssues, otherIssue.toAdditionalData(&scanResult,
						[]snyk.OssIssueData{}, targetFilePath))
				}
			}

			// Use the existing toAdditionalData method to create additional data
			additionalData := vuln.toAdditionalData(&scanResult, matchingIssues, targetFilePath)

			// Create message using existing remediation
			message := fmt.Sprintf(
				"%s affecting package %s. %s",
				vuln.Title,
				vuln.PackageName,
				additionalData.Remediation,
			)

			const maxLength = 200
			if len(message) > maxLength {
				message = message[:maxLength] + "... (Snyk)"
			}

			// Create the issue using existing methods
			issue := &snyk.Issue{
				ID:                  vuln.Id,
				Message:             message,
				FormattedMessage:    vuln.GetExtendedMessage(vuln),
				Range:               types.Range{}, // No range info without file parsing
				Severity:            vuln.ToIssueSeverity(),
				Product:             product.ProductOpenSource,
				IssueDescriptionURL: vuln.CreateIssueURL(),
				IssueType:           types.DependencyVulnerability,
				Ecosystem:           vuln.PackageManager,
				CWEs:                vuln.Identifiers.CWE,
				CVEs:                vuln.Identifiers.CVE,
				AdditionalData:      additionalData,
			}

			// Set fingerprint using existing utility
			fingerprint := utils.CalculateFingerprintFromAdditionalData(issue)
			issue.SetFingerPrint(fingerprint)

			issues = append(issues, issue)
		}
	}

	return issues, nil
}
