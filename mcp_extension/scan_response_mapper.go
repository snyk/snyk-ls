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

// EnhancedScanResult contains both the original CLI output and extracted issue information
type EnhancedScanResult struct {
	OriginalOutput string      `json:"originalOutput"`
	Success        bool        `json:"success"`
	ScanType       string      `json:"scanType"`
	IssueCount     int         `json:"issueCount"`
	Issues         []IssueData `json:"issues,omitempty"`
}

// IssueData contains the essential fields needed by LLMs
type IssueData struct {
	// Common fields
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Severity string   `json:"severity"`
	RuleID   string   `json:"ruleId,omitempty"`
	CWEs     []string `json:"cwes,omitempty"`
	CVEs     []string `json:"cves,omitempty"`

	// SCA specific
	PackageName string   `json:"packageName,omitempty"`
	Version     string   `json:"version,omitempty"`
	Ecosystem   string   `json:"ecosystem,omitempty"`
	FixedIn     []string `json:"fixedIn,omitempty"`
	Remediation string   `json:"remediation,omitempty"`

	// SAST specific
	FilePath string `json:"filePath,omitempty"`
	Line     int    `json:"line,omitempty"`
	Column   int    `json:"column,omitempty"`
}

// ScanResponseMapper handles parsing of scan JSON/SARIF responses
type ScanResponseMapper struct {
	logger zerolog.Logger
}

// NewScanResponseMapper creates a new instance of ScanResponseMapper
func NewScanResponseMapper(logger zerolog.Logger) *ScanResponseMapper {
	return &ScanResponseMapper{
		logger: logger,
	}
}

// MapResponse processes JSON output from scanners and returns enhanced response
func (m *ScanResponseMapper) MapResponse(toolName string, jsonOutput string) (*mcp.CallToolResult, error) {
	m.logger.Debug().
		Str("tool", toolName).
		Msg("Mapping scan response")

	// Parse based on scanner type
	var enhanced EnhancedScanResult
	switch toolName {
	case "snyk_sca_scan":
		enhanced = m.mapSCAResponse(jsonOutput)
	case "snyk_code_scan":
		enhanced = m.mapSASTResponse(jsonOutput)
	default:
		// Return original output for non-scanner tools
		return &mcp.CallToolResult{
			Content: []mcp.Content{mcp.TextContent{Type: "text", Text: jsonOutput}},
		}, nil
	}

	// Serialize the enhanced result to JSON
	resultJSON, err := json.MarshalIndent(enhanced, "", "  ")
	if err != nil {
		m.logger.Err(err).Msg("Failed to serialize enhanced result")
		return nil, fmt.Errorf("failed to serialize result: %w", err)
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{mcp.TextContent{Type: "text", Text: string(resultJSON)}},
	}, nil
}

// mapSCAResponse handles SCA (Open Source) scan output
func (m *ScanResponseMapper) mapSCAResponse(jsonOutput string) EnhancedScanResult {
	result := EnhancedScanResult{
		OriginalOutput: jsonOutput,
		Success:        true,
		ScanType:       "sca",
		Issues:         []IssueData{},
	}

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
	if err := json.Unmarshal([]byte(jsonOutput), &results); err != nil {
		// Try single result
		var singleResult scaResult
		if err := json.Unmarshal([]byte(jsonOutput), &singleResult); err != nil {
			m.logger.Err(err).Msg("Failed to parse SCA JSON")
			result.Success = false
			return result
		}
		results = []scaResult{singleResult}
	}

	// Extract issues
	ecosystem := ""
	for _, scanResult := range results {
		if ecosystem == "" && scanResult.PackageManager != "" {
			ecosystem = scanResult.PackageManager
		}

		for _, vuln := range scanResult.Vulnerabilities {
			issue := IssueData{
				ID:          vuln.ID,
				Title:       vuln.Title,
				Severity:    vuln.Severity,
				PackageName: vuln.PackageName,
				Version:     vuln.Version,
				CVEs:        vuln.CVE,
				CWEs:        vuln.CWE,
				FixedIn:     vuln.FixedIn,
				Ecosystem:   scanResult.PackageManager,
				Remediation: m.getRemediationAdvice(vuln, scanResult.PackageManager),
			}
			result.Issues = append(result.Issues, issue)
		}
	}

	result.IssueCount = len(result.Issues)
	return result
}

// mapSASTResponse handles SAST (Code) scan output
func (m *ScanResponseMapper) mapSASTResponse(jsonOutput string) EnhancedScanResult {
	result := EnhancedScanResult{
		OriginalOutput: jsonOutput,
		Success:        true,
		ScanType:       "sast",
		Issues:         []IssueData{},
	}

	// Parse the SARIF response structure
	var sarifResp struct {
		Type   string `json:"type"`
		Status string `json:"status"`
		Sarif  struct {
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
	}

	err := json.Unmarshal([]byte(jsonOutput), &sarifResp)
	if err != nil {
		m.logger.Err(err).Msg("Failed to parse SAST JSON")
		result.Success = false
		return result
	}

	if len(sarifResp.Sarif.Runs) > 0 {
		run := sarifResp.Sarif.Runs[0]

		// Build rule map
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
		for _, res := range run.Results {
			ruleInfo := ruleMap[res.RuleID]

			for _, loc := range res.Locations {
				issue := IssueData{
					ID:       res.RuleID,
					RuleID:   res.RuleID,
					Title:    ruleInfo.title,
					Severity: m.mapSarifLevel(res.Level),
					CWEs:     ruleInfo.cwes,
					FilePath: loc.PhysicalLocation.ArtifactLocation.URI,
					Line:     loc.PhysicalLocation.Region.StartLine,
					Column:   loc.PhysicalLocation.Region.StartColumn,
				}
				result.Issues = append(result.Issues, issue)
			}
		}
	}

	result.IssueCount = len(result.Issues)
	return result
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

// getRemediationAdvice generates remediation advice for SCA vulnerabilities
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
