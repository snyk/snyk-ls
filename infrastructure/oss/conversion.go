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

// ConvertJSONToIssues converts OSS JSON output to Issues without requiring a full scanner instance
// This is a simplified version for use by MCP and other tools that need conversion without full scanner
func ConvertJSONToIssues(jsonOutput []byte) ([]types.Issue, error) {
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
		for _, vulnerability := range scanResult.Vulnerabilities {
			if vulnerability.IsIgnored {
				continue
			}

			issue := convertVulnerabilityToIssue(vulnerability, &scanResult)
			issues = append(issues, issue)
		}
	}

	return issues, nil
}

// convertVulnerabilityToIssue converts a single vulnerability to an Issue
// This is a simplified version without external dependencies like learn service
func convertVulnerabilityToIssue(vuln ossIssue, scanResult *scanResult) *snyk.Issue {
	// Use the existing toAdditionalData method with empty matching issues
	additionalData := vuln.toAdditionalData(scanResult, []snyk.OssIssueData{}, types.FilePath(scanResult.DisplayTargetFile))

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

	d := &snyk.Issue{
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

	fingerprint := utils.CalculateFingerprintFromAdditionalData(d)
	d.SetFingerPrint(fingerprint)

	return d
}

// Export type for use in conversion
type ScanResult = scanResult
