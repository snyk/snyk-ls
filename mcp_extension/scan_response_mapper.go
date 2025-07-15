/*
 * © 2025 Snyk Limited
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
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/rs/zerolog"
)

// EnhancedScanResult contains both the original CLI output and additional structured data
type EnhancedScanResult struct {
	// OriginalOutput is the human-readable CLI output
	OriginalOutput string `json:"originalOutput"`
	// StructuredData contains the parsed JSON/SARIF data with additional fields
	StructuredData *StructuredScanData `json:"structuredData,omitempty"`
	// Success indicates if the scan was successful
	Success bool `json:"success"`
}

// StructuredScanData contains the additional fields needed by LLMs
type StructuredScanData struct {
	// Common fields
	IssueCount int    `json:"issueCount"`
	ScanType   string `json:"scanType"` // "sca" or "sast"

	// SCA specific fields
	Ecosystem       string        `json:"ecosystem,omitempty"` // package manager
	DependencyCount int           `json:"dependencyCount,omitempty"`
	Vulnerabilities []ScaVulnInfo `json:"vulnerabilities,omitempty"`

	// SAST specific fields
	FilesAnalyzed int             `json:"filesAnalyzed,omitempty"`
	CodeIssues    []SastIssueInfo `json:"codeIssues,omitempty"`
}

// ScaVulnInfo contains vulnerability information for SCA
type ScaVulnInfo struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	PackageName string   `json:"packageName"`
	Version     string   `json:"version"`
	CVEs        []string `json:"cves,omitempty"`
	CWEs        []string `json:"cwes,omitempty"`
	FixedIn     []string `json:"fixedIn,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
}

// SastIssueInfo contains issue information for SAST
type SastIssueInfo struct {
	RuleID   string   `json:"ruleId"`
	Title    string   `json:"title"`
	Severity string   `json:"severity"`
	FilePath string   `json:"filePath"`
	Line     int      `json:"line"`
	Column   int      `json:"column"`
	CWEs     []string `json:"cwes,omitempty"`
}

// ScanResponseMapper handles mapping of scan results
type ScanResponseMapper struct {
	logger *zerolog.Logger
}

// NewScanResponseMapper creates a new mapper instance
func NewScanResponseMapper(logger *zerolog.Logger) *ScanResponseMapper {
	return &ScanResponseMapper{logger: logger}
}

// MapScanResponse maps the CLI output to an enhanced result based on the tool name
func (m *ScanResponseMapper) MapScanResponse(toolName string, cliOutput string) (*mcp.CallToolResult, error) {
	m.logger.Debug().Str("toolName", toolName).Msg("Mapping scan response")

	// For non-scan tools, return the output as-is
	if toolName != SnykScaTest && toolName != SnykCodeTest {
		return mcp.NewToolResultText(cliOutput), nil
	}

	// Create enhanced result
	enhanced := &EnhancedScanResult{
		OriginalOutput: cliOutput,
		Success:        true,
	}

	// Try to parse structured data based on tool type
	switch toolName {
	case SnykScaTest:
		structuredData, err := m.parseScaOutput(cliOutput)
		if err != nil {
			m.logger.Warn().Err(err).Msg("Failed to parse SCA JSON, returning original output only")
			// Still return the original output even if parsing fails
			enhanced.Success = false
		} else {
			enhanced.StructuredData = structuredData
		}

	case SnykCodeTest:
		structuredData, err := m.parseSastOutput(cliOutput)
		if err != nil {
			m.logger.Warn().Err(err).Msg("Failed to parse SAST SARIF, returning original output only")
			// Still return the original output even if parsing fails
			enhanced.Success = false
		} else {
			enhanced.StructuredData = structuredData
		}
	}

	// Convert to JSON for structured response
	jsonBytes, err := json.Marshal(enhanced)
	if err != nil {
		m.logger.Error().Err(err).Msg("Failed to marshal enhanced result")
		return mcp.NewToolResultText(cliOutput), nil
	}

	return mcp.NewToolResultText(string(jsonBytes)), nil
}

// parseScaOutput parses SCA JSON output
func (m *ScanResponseMapper) parseScaOutput(output string) (*StructuredScanData, error) {
	// SCA output structure based on infrastructure/oss/types.go
	type scaResult struct {
		Vulnerabilities []struct {
			ID           string   `json:"id"`
			Title        string   `json:"title"`
			Severity     string   `json:"severity"`
			PackageName  string   `json:"packageName"`
			Version      string   `json:"version"`
			CVE          []string `json:"CVE,omitempty"`
			CWE          []string `json:"CWE,omitempty"`
			FixedIn      []string `json:"fixedIn,omitempty"`
			IsUpgradable bool     `json:"isUpgradable,omitempty"`
			IsPatchable  bool     `json:"isPatchable,omitempty"`
			UpgradePath  []any    `json:"upgradePath,omitempty"`
			From         []string `json:"from,omitempty"`
		} `json:"vulnerabilities"`
		Ok              bool   `json:"ok"`
		DependencyCount int    `json:"dependencyCount"`
		PackageManager  string `json:"packageManager"`
	}

	var results []scaResult

	// Try to parse as array first (multiple projects)
	if err := json.Unmarshal([]byte(output), &results); err != nil {
		// Try single result
		var singleResult scaResult
		if err := json.Unmarshal([]byte(output), &singleResult); err != nil {
			return nil, fmt.Errorf("failed to parse SCA JSON: %w", err)
		}
		results = []scaResult{singleResult}
	}

	// Aggregate results
	data := &StructuredScanData{
		ScanType:        "sca",
		Vulnerabilities: []ScaVulnInfo{},
	}

	for _, result := range results {
		if data.Ecosystem == "" && result.PackageManager != "" {
			data.Ecosystem = result.PackageManager
		}
		data.DependencyCount += result.DependencyCount

		for _, vuln := range result.Vulnerabilities {
			data.Vulnerabilities = append(data.Vulnerabilities, ScaVulnInfo{
				ID:          vuln.ID,
				Title:       vuln.Title,
				Severity:    vuln.Severity,
				PackageName: vuln.PackageName,
				Version:     vuln.Version,
				CVEs:        vuln.CVE,
				CWEs:        vuln.CWE,
				FixedIn:     vuln.FixedIn,
				Remediation: m.getRemediationAdvice(vuln, result.PackageManager),
			})
			data.IssueCount++
		}
	}

	return data, nil
}

// parseSastOutput parses SAST SARIF output
func (m *ScanResponseMapper) parseSastOutput(output string) (*StructuredScanData, error) {
	// SARIF structure based on infrastructure/code/convert.go
	type sarifResponse struct {
		Type     string  `json:"type"`
		Progress float64 `json:"progress"`
		Status   string  `json:"status"`
		Sarif    struct {
			Runs []struct {
				Tool struct {
					Driver struct {
						Rules []struct {
							ID               string `json:"id"`
							ShortDescription struct {
								Text string `json:"text"`
							} `json:"shortDescription"`
							Properties struct {
								Cwe []string `json:"cwe"`
							} `json:"properties"`
						} `json:"rules"`
					} `json:"driver"`
				} `json:"tool"`
				Results []struct {
					RuleID    string `json:"ruleId"`
					Level     string `json:"level"`
					Locations []struct {
						PhysicalLocation struct {
							ArtifactLocation struct {
								URI string `json:"uri"`
							} `json:"artifactLocation"`
							Region struct {
								StartLine   int `json:"startLine"`
								StartColumn int `json:"startColumn"`
							} `json:"region"`
						} `json:"physicalLocation"`
					} `json:"locations"`
				} `json:"results"`
			} `json:"runs"`
		} `json:"sarif"`
		Coverage []struct {
			Files int `json:"files"`
		} `json:"coverage"`
	}

	var sarif sarifResponse
	if err := json.Unmarshal([]byte(output), &sarif); err != nil {
		return nil, fmt.Errorf("failed to parse SARIF JSON: %w", err)
	}

	data := &StructuredScanData{
		ScanType:   "sast",
		CodeIssues: []SastIssueInfo{},
	}

	// Count analyzed files
	for _, cov := range sarif.Coverage {
		data.FilesAnalyzed += cov.Files
	}

	if len(sarif.Sarif.Runs) > 0 {
		run := sarif.Sarif.Runs[0]

		// Build a map of rule ID to rule info
		ruleMap := make(map[string]struct {
			title string
			cwes  []string
		})

		for _, rule := range run.Tool.Driver.Rules {
			ruleMap[rule.ID] = struct {
				title string
				cwes  []string
			}{
				title: rule.ShortDescription.Text,
				cwes:  rule.Properties.Cwe,
			}
		}

		// Process results
		for _, result := range run.Results {
			ruleInfo := ruleMap[result.RuleID]

			for _, loc := range result.Locations {
				issue := SastIssueInfo{
					RuleID:   result.RuleID,
					Title:    ruleInfo.title,
					Severity: m.mapSarifLevel(result.Level),
					FilePath: loc.PhysicalLocation.ArtifactLocation.URI,
					Line:     loc.PhysicalLocation.Region.StartLine,
					Column:   loc.PhysicalLocation.Region.StartColumn,
					CWEs:     ruleInfo.cwes,
				}
				data.CodeIssues = append(data.CodeIssues, issue)
				data.IssueCount++
			}
		}
	}

	return data, nil
}

// mapSarifLevel maps SARIF severity levels to standard severity strings
func (m *ScanResponseMapper) mapSarifLevel(level string) string {
	switch strings.ToLower(level) {
	case "error":
		return "high"
	case "warning":
		return "medium"
	case "note", "information":
		return "low"
	default:
		return "low"
	}
}

// getRemediationAdvice generates remediation advice based on Snyk's logic
func (m *ScanResponseMapper) getRemediationAdvice(vuln struct {
	ID           string   `json:"id"`
	Title        string   `json:"title"`
	Severity     string   `json:"severity"`
	PackageName  string   `json:"packageName"`
	Version      string   `json:"version"`
	CVE          []string `json:"CVE,omitempty"`
	CWE          []string `json:"CWE,omitempty"`
	FixedIn      []string `json:"fixedIn,omitempty"`
	IsUpgradable bool     `json:"isUpgradable,omitempty"`
	IsPatchable  bool     `json:"isPatchable,omitempty"`
	UpgradePath  []any    `json:"upgradePath,omitempty"`
	From         []string `json:"from,omitempty"`
}, packageManager string) string {
	// Get upgrade message
	upgradeMessage := ""
	hasUpgradePath := len(vuln.UpgradePath) > 1
	if hasUpgradePath {
		upgradePath, ok := vuln.UpgradePath[1].(string)
		if ok {
			upgradeMessage = "Upgrade to " + upgradePath
		}
	}

	// Check if outdated
	isOutdated := hasUpgradePath && len(vuln.From) > 1 && vuln.UpgradePath[1] == vuln.From[1]

	if vuln.IsUpgradable || vuln.IsPatchable {
		if isOutdated {
			if vuln.IsPatchable {
				return upgradeMessage
			} else {
				return m.getOutdatedDependencyMessage(vuln.PackageName, vuln.Version, packageManager)
			}
		} else if upgradeMessage != "" {
			return upgradeMessage
		}
	}

	return "No remediation advice available"
}

// getOutdatedDependencyMessage generates message for outdated dependencies
func (m *ScanResponseMapper) getOutdatedDependencyMessage(packageName, version, packageManager string) string {
	remediationAdvice := fmt.Sprintf("Your dependencies are out of date, "+
		"otherwise you would be using a newer %s than %s@%s. ", packageName, packageName, version)

	if packageManager == "npm" || packageManager == "yarn" || packageManager == "yarn-workspace" {
		remediationAdvice += "Try relocking your lockfile or deleting node_modules and reinstalling" +
			" your dependencies. If the problem persists, one of your dependencies may be bundling outdated modules."
	} else {
		remediationAdvice += "Try reinstalling your dependencies. If the problem persists, one of your dependencies may be bundling outdated modules."
	}

	return remediationAdvice
}
