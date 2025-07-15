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
	"net/url"

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
	// Use safe version that doesn't call potentially panicking methods
	safeAdditionalData := GetSafeAdditionalData(vuln, scanResult, types.FilePath(scanResult.DisplayTargetFile))

	message := fmt.Sprintf(
		"%s affecting package %s. %s",
		vuln.Title,
		vuln.PackageName,
		safeAdditionalData.Remediation,
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
		AdditionalData:      safeAdditionalData,
	}

	fingerprint := utils.CalculateFingerprintFromAdditionalData(d)
	d.SetFingerPrint(fingerprint)

	return d
}

// Export type for use in conversion
type ScanResult = scanResult

// GetSafeAdditionalData creates OssIssueData with safe remediation handling
func GetSafeAdditionalData(vuln ossIssue, scanResult *scanResult, affectedFilePath types.FilePath) snyk.OssIssueData {
	additionalData := snyk.OssIssueData{
		Key:               fmt.Sprintf("%s-%s-%d", vuln.Id, affectedFilePath, 0), // Simplified key without util package
		Title:             vuln.Title,
		Name:              vuln.Name,
		Identifiers:       snyk.Identifiers{CWE: vuln.Identifiers.CWE, CVE: vuln.Identifiers.CVE},
		LineNumber:        vuln.LineNumber,
		Description:       vuln.Description,
		Version:           vuln.Version,
		License:           vuln.License,
		PackageManager:    vuln.PackageManager,
		PackageName:       vuln.PackageName,
		From:              vuln.From,
		FixedIn:           vuln.FixedIn,
		UpgradePath:       vuln.UpgradePath,
		IsUpgradable:      vuln.IsUpgradable,
		CVSSv3:            vuln.CVSSv3,
		CvssScore:         vuln.CvssScore,
		Exploit:           vuln.Exploit,
		IsPatchable:       vuln.IsPatchable,
		ProjectName:       scanResult.ProjectName,
		DisplayTargetFile: affectedFilePath,
		Language:          vuln.Language,
		Remediation:       getSafeRemediation(vuln),
	}

	// Add references
	for _, ref := range vuln.References {
		u, _ := url.Parse(string(ref.Url))
		additionalData.References = append(additionalData.References, types.Reference{
			Url:   u,
			Title: ref.Title,
		})
	}

	return additionalData
}

// getSafeRemediation provides remediation advice with safe bounds checking
func getSafeRemediation(vuln ossIssue) string {
	// Check if we have a valid upgrade path
	hasUpgradePath := len(vuln.UpgradePath) > 1

	if vuln.IsUpgradable || vuln.IsPatchable {
		if hasUpgradePath {
			// Safe access to upgrade path
			upgradePath, ok := vuln.UpgradePath[1].(string)
			if ok && upgradePath != "" {
				upgradeMessage := "Upgrade to " + upgradePath

				// Check if it's outdated (safe bounds checking)
				if len(vuln.From) > 1 && vuln.UpgradePath[1] == vuln.From[1] {
					if vuln.IsPatchable {
						return upgradeMessage
					} else {
						return getOutdatedMessage(vuln)
					}
				}
				return upgradeMessage
			}
		}
	}

	return "No remediation advice available"
}

// getOutdatedMessage returns message for outdated dependencies
func getOutdatedMessage(vuln ossIssue) string {
	remediationAdvice := fmt.Sprintf("Your dependencies are out of date, "+
		"otherwise you would be using a newer %s than %s@%s. ", vuln.Name, vuln.Name, vuln.Version)

	if vuln.PackageManager == "npm" || vuln.PackageManager == "yarn" || vuln.PackageManager == "yarn-workspace" {
		remediationAdvice += "Try relocking your lockfile or deleting node_modules and reinstalling" +
			" your dependencies. If the problem persists, one of your dependencies may be bundling outdated modules."
	} else {
		remediationAdvice += "Try reinstalling your dependencies. If the problem persists, one of your dependencies may be bundling outdated modules."
	}
	return remediationAdvice
}
