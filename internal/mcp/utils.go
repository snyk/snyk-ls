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

package mcp

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
)

// summarizeSnykOutput summarizes JSON output from Snyk
//
//nolint:gocyclo // this will be deleted
func summarizeSnykOutput(jsonOutput string) (map[string]interface{}, error) {
	var rawData map[string]interface{}
	if err := json.Unmarshal([]byte(jsonOutput), &rawData); err != nil {
		return nil, err
	}

	summary := map[string]interface{}{
		"status":                "success",
		"total_vulnerabilities": 0,
		"severity_counts": map[string]int{
			"critical": 0,
			"high":     0,
			"medium":   0,
			"low":      0,
		},
		"top_vulnerable_packages": []interface{}{},
		"upgrade_recommendations": []interface{}{},
		"error":                   nil,
	}

	// Check for vulnerabilities
	vulnerabilitiesRaw, hasVulns := rawData["vulnerabilities"]
	if !hasVulns {
		summary["status"] = "no vulnerabilities"
		return summary, nil
	}

	// Convert vulnerabilities to a slice of interface{}
	vulnsSlice, err := toInterfaceSlice(vulnerabilitiesRaw)
	if err != nil {
		summary["status"] = "error"
		summary["error"] = err.Error()
		return summary, nil
	}

	if len(vulnsSlice) == 0 {
		summary["status"] = "no vulnerabilities"
		return summary, nil
	}

	// We have vulnerabilities; fill summary data
	summary["total_vulnerabilities"] = len(vulnsSlice)

	// For severity counts and top packages
	//nolint:forcetypeassert // this will be deleted
	severityCounts := summary["severity_counts"].(map[string]int)
	packageCounter := make(map[string]int)

	for _, v := range vulnsSlice {
		vulnMap, ok := v.(map[string]interface{})
		if !ok {
			continue // skip if it's not in the expected shape
		}

		// Handle severity
		severity, _ := vulnMap["severity"].(string)
		severity = strings.ToLower(severity)
		if _, exists := severityCounts[severity]; exists {
			severityCounts[severity]++
		}

		// Count package occurrences
		packageName, _ := vulnMap["packageName"].(string)
		if packageName != "" {
			packageCounter[packageName]++
		}
	}

	// Build "top_vulnerable_packages" (top 5)
	summary["top_vulnerable_packages"] = topPackageCounts(packageCounter, 5)

	// Build "upgrade_recommendations" from the first 5 vulnerabilities
	upgradeRecs := make([]interface{}, 0, 5)
	for i, v := range vulnsSlice {
		if i >= 5 {
			break
		}
		vulnMap, _ := v.(map[string]interface{})
		if vulnMap == nil {
			continue
		}

		upgradePath, _ := toInterfaceSlice(vulnMap["upgradePath"])
		if len(upgradePath) == 0 {
			continue
		}

		// Find the first non-nil or non-empty upgrade path element
		var upgradedTo string
		for _, up := range upgradePath {
			str, ok := up.(string)
			if ok && str != "" {
				upgradedTo = str
				break
			}
		}

		if upgradedTo != "" {
			packageName, _ := vulnMap["packageName"].(string)
			currentVersion, _ := vulnMap["version"].(string)
			severity, _ := vulnMap["severity"].(string)
			rec := map[string]interface{}{
				"package":             packageName,
				"current_version":     currentVersion,
				"recommended_version": upgradedTo,
				"severity":            severity,
			}
			upgradeRecs = append(upgradeRecs, rec)
		}
	}
	summary["upgrade_recommendations"] = upgradeRecs

	return summary, nil
}

// helper: convert arbitrary interface{} to []interface{}
func toInterfaceSlice(val interface{}) ([]interface{}, error) {
	if val == nil {
		return nil, nil
	}
	sl, ok := val.([]interface{})
	if !ok {
		return nil, errors.New("expected a list/array for vulnerabilities")
	}
	return sl, nil
}

// helper: produce a top-N list of package counts
func topPackageCounts(pkgMap map[string]int, n int) []interface{} {
	// Convert map to slice of (name, count) pairs
	type pkgCount struct {
		Name  string
		Count int
	}
	pcList := make([]pkgCount, 0, len(pkgMap))
	for name, count := range pkgMap {
		pcList = append(pcList, pkgCount{name, count})
	}

	// Sort by descending count
	sort.Slice(pcList, func(i, j int) bool {
		return pcList[i].Count > pcList[j].Count
	})

	// Take top N
	limit := n
	if len(pcList) < n {
		limit = len(pcList)
	}
	pcList = pcList[:limit]

	// Convert back to []interface{}
	result := make([]interface{}, 0, limit)
	for _, p := range pcList {
		result = append(result, map[string]interface{}{
			"name":  p.Name,
			"count": p.Count,
		})
	}
	return result
}

// buildArgs builds command-line arguments for Snyk CLI based on parameters
func buildArgs(cliPath string, command string, params map[string]interface{}) []string {
	args := []string{cliPath, command}

	// Add params as command-line flags
	for key, value := range params {
		switch v := value.(type) {
		case bool:
			if v {
				args = append(args, "--"+key)
			}
		case string:
			if v != "" {
				args = append(args, "--"+key+"="+v)
			}
		}
	}

	return args
}
