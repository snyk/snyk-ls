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

package oss

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/learn/mock_learn"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

// Test_buildUpgradePath tests the buildUpgradePath function
func Test_buildUpgradePath(t *testing.T) {
	testutil.UnitTest(t)

	tests := []struct {
		name            string
		dependencyPath  []string
		finding         *testapi.FindingData
		expectedUpgrade []any
		description     string
	}{
		{
			name:            "No upgrade path when no fix relationships exist - returns empty",
			dependencyPath:  []string{"root@1.0.0", "test-package@1.0.0"},
			finding:         createFindingWithoutUpgradePath(t),
			expectedUpgrade: []any{false},
			description:     "Should return [false] when no upgrade information is available.",
		},
		{
			name:            "Direct dependency with single upgrade path",
			dependencyPath:  []string{"goof@1.0.0", "lodash@4.2.3"},
			finding:         createFindingWithUpgradePaths(t, "lodash", [][]string{{"goof@1.0.0", "lodash@4.17.21"}}),
			expectedUpgrade: []any{false, "lodash@4.17.21"},
			description:     "Should extract upgrade path from fix relationships.",
		},
		{
			name:            "Transitive dependency with upgrade path",
			dependencyPath:  []string{"root@1.0.0", "direct-dependency@1.7.1", "lodash@4.2.3"},
			finding:         createFindingWithUpgradePaths(t, "lodash", [][]string{{"root@1.0.0", "direct-dependency@2.0.0", "lodash@4.17.21"}}),
			expectedUpgrade: []any{false, "direct-dependency@2.0.0", "lodash@4.17.21"},
			description:     "Should handle multi-level transitive dependencies.",
		},
		{
			name:            "Multiple upgrade paths via different direct dependencies - filters to requested one",
			dependencyPath:  []string{"goof@1.0.0", "direct-dependency@1.7.1", "lodash@4.2.3"},
			finding:         createFindingWithUpgradePaths(t, "lodash", [][]string{{"goof@1.0.0", "another-direct-dependency@2.0.0", "lodash@4.17.22"}, {"goof@1.0.0", "direct-dependency@2.0.0", "lodash@4.17.21"}}),
			expectedUpgrade: []any{false, "direct-dependency@2.0.0", "lodash@4.17.21"},
			description:     "Should filter finding's multiple upgrade paths and return the one matching the input dependency path's direct dependency (position [1]). Tests scenario where vuln is reached through different direct dependencies.",
		},
		{
			name:            "Multiple upgrade paths via same direct dependency - returns first matching",
			dependencyPath:  []string{"root@1.0.0", "dep-a@1.0.0", "dep-a1@1.0.0", "vuln-pkg@1.0.0"},
			finding:         createFindingWithUpgradePaths(t, "vuln-pkg", [][]string{{"root@1.0.0", "dep-a@2.0.0", "dep-a1@2.0.0", "vuln-pkg@1.0.1"}, {"root@1.0.0", "dep-a@2.0.0", "dep-a2@2.0.0", "vuln-pkg@1.0.1"}}),
			expectedUpgrade: []any{false, "dep-a@2.0.0", "dep-a1@2.0.0", "vuln-pkg@1.0.1"},
			description:     "Should return first matching upgrade path when multiple paths exist through same direct dependency but different transitive paths. Tests scenario where vuln is reached through same direct dep via different transitive routes.",
		},
		{
			name:            "Returns empty when the only upgrade path is for a dependency path other than the one we are focused on",
			dependencyPath:  []string{"root@1.0.0", "lodash@4.2.3", "vuln-pkg@0.0.4"},
			finding:         createFindingWithUpgradePaths(t, "vuln-pkg", [][]string{{"root@1.0.0", "other-pkg@2.0.0", "vuln-pkg@0.2.8"}}),
			expectedUpgrade: []any{false},
			description:     "Should return [false] when finding has upgrade paths but none match the input dependency path's direct dependency. Represents partial fix scenario where fix exists via different route (e.g., via other-pkg) but not via the route in question (lodash).",
		},
		{
			name:            "Defensive: empty dependency path",
			dependencyPath:  []string{},
			finding:         createFindingWithUpgradePaths(t, "lodash", [][]string{{"goof@1.0.0", "lodash@4.17.21"}}),
			expectedUpgrade: []any{false},
			description:     "Should return [false] when dependency path is empty.",
		},
		{
			name:            "Malformed data: single element dependency path - handles gracefully",
			dependencyPath:  []string{"root@1.0.0"},
			finding:         createFindingWithUpgradePaths(t, "lodash", [][]string{{"goof@1.0.0", "lodash@4.17.21"}}),
			expectedUpgrade: []any{false},
			description:     "Should return [false] when dependency path has only root (length 1, malformed) to avoid panic.",
		},
		{
			name:            "Malformed data: UpgradePackageAdvice is for a different package - handles gracefully",
			dependencyPath:  []string{"root@1.0.0", "lodash@4.2.3"},
			finding:         createFindingWithUpgradePaths(t, "other-pkg", [][]string{{"root@1.0.0", "other-pkg@2.0.0"}}),
			expectedUpgrade: []any{false},
			description:     "Should return [false] when UpgradePackageAdvice exists but targets a different package than the vulnerable one (malformed API data).",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildUpgradePath(tt.dependencyPath, tt.finding)
			assert.Equal(t, tt.expectedUpgrade, result, tt.description)
		})
	}
}

// Test_buildRemediationAdvice tests the buildRemediationAdvice function
func Test_buildRemediationAdvice(t *testing.T) {
	testutil.UnitTest(t)

	tests := []struct {
		name            string
		finding         *testapi.FindingData
		problem         *testapi.SnykVulnProblem
		ecosystem       string
		dependencyPath  []string
		upgradePath     []any
		expectedMessage string
		description     string
	}{
		{
			name:    "No remediation when no fixed versions",
			finding: createFindingWithoutUpgradePath(t),
			problem: &testapi.SnykVulnProblem{
				PackageName:              "test-package",
				PackageVersion:           "1.0.0",
				InitiallyFixedInVersions: []string{},
			},
			ecosystem:       "npm",
			dependencyPath:  []string{"root@1.0.0", "test-package@1.0.0"},
			upgradePath:     []any{false},
			expectedMessage: "No remediation advice available",
			description:     "Should return no remediation message when no fix available.",
		},
		{
			name:    "Direct dependency with fix available",
			finding: createFindingWithoutUpgradePath(t),
			problem: &testapi.SnykVulnProblem{
				PackageName:              "test-package",
				PackageVersion:           "1.0.0",
				InitiallyFixedInVersions: []string{"1.0.1"},
			},
			ecosystem:       "npm",
			dependencyPath:  []string{"root@1.0.0", "test-package@1.0.0"},
			upgradePath:     []any{false, "test-package@1.0.1"},
			expectedMessage: "Upgrade to test-package@1.0.1",
			description:     "Should return upgrade message for direct dependency when fix is available.",
		},
		{
			name:    "Transitive dependency with fix and upgrade path available",
			finding: createFindingWithoutUpgradePath(t),
			problem: &testapi.SnykVulnProblem{
				PackageName:              "vuln-pkg",
				PackageVersion:           "1.0.0",
				InitiallyFixedInVersions: []string{"1.0.1"},
			},
			ecosystem:       "maven",
			dependencyPath:  []string{"root@1.0.0", "intermediate@1.0.0", "vuln-pkg@1.0.0"},
			upgradePath:     []any{false, "intermediate@2.0.0", "vuln-pkg@1.0.1"},
			expectedMessage: "Upgrade to intermediate@2.0.0",
			description:     "Should return upgrade message showing intermediate package to upgrade for transitive dependency fixes.",
		},
		{
			name:    "Deep transitive dependency with fix available but no upgrade path",
			finding: createFindingWithoutUpgradePath(t),
			problem: &testapi.SnykVulnProblem{
				PackageName:              "vuln-pkg",
				PackageVersion:           "1.0.0",
				InitiallyFixedInVersions: []string{"1.0.1"}, // Fix exists in vuln-pkg@1.0.1
			},
			ecosystem:       "pip",
			dependencyPath:  []string{"root@1.0.0", "pkg-a@1.0.0", "pkg-b@1.0.0", "vuln-pkg@1.0.0"}, // Deep transitive
			upgradePath:     []any{false},                                                           // No upgrade path because intermediate deps haven't updated to consume the fix
			expectedMessage: "",                                                                     // Returns empty when fix exists but no upgrade path available through dependency chain
			description:     "Should return empty when fix exists but intermediate dependencies haven't consumed it yet (common with deep transitive dependencies).",
		},
		{
			name:    "Malformed data: upgrade path suggests same vulnerable version - npm",
			finding: createFindingWithoutUpgradePath(t),
			problem: &testapi.SnykVulnProblem{
				PackageName:              "test-package",
				PackageVersion:           "1.0.0",
				InitiallyFixedInVersions: []string{"1.0.1"},
			},
			ecosystem:       "npm",
			dependencyPath:  []string{"root@1.0.0", "test-package@1.0.0"},
			upgradePath:     []any{false, "test-package@1.0.0"}, // Same as dependencyPath[1] - unrealistic but handled defensively
			expectedMessage: "Your dependencies are out of date, otherwise you would be using a newer test-package than test-package@1.0.0. Try relocking your lockfile or deleting node_modules and reinstalling your dependencies. If the problem persists, one of your dependencies may be bundling outdated modules.",
			description:     "Should return outdated dependency message when upgradePath[1] == dependencyPath[1] (defensive handling - shouldn't occur with real API data).",
		},
		{
			name:    "Malformed data: upgrade path suggests same vulnerable version - yarn",
			finding: createFindingWithoutUpgradePath(t),
			problem: &testapi.SnykVulnProblem{
				PackageName:              "test-package",
				PackageVersion:           "1.0.0",
				InitiallyFixedInVersions: []string{"1.0.1"},
			},
			ecosystem:       "yarn",
			dependencyPath:  []string{"root@1.0.0", "test-package@1.0.0"},
			upgradePath:     []any{false, "test-package@1.0.0"}, // Same as dependencyPath[1] - unrealistic but handled defensively
			expectedMessage: "Your dependencies are out of date, otherwise you would be using a newer test-package than test-package@1.0.0. Try relocking your lockfile or deleting node_modules and reinstalling your dependencies. If the problem persists, one of your dependencies may be bundling outdated modules.",
			description:     "Should return outdated dependency message for yarn (same behavior as npm for this edge case).",
		},
		{
			name:    "Malformed data: upgrade path suggests same vulnerable version - maven",
			finding: createFindingWithoutUpgradePath(t),
			problem: &testapi.SnykVulnProblem{
				PackageName:              "test-package",
				PackageVersion:           "1.0.0",
				InitiallyFixedInVersions: []string{"1.0.1"},
			},
			ecosystem:       "maven",
			dependencyPath:  []string{"root@1.0.0", "test-package@1.0.0"},
			upgradePath:     []any{false, "test-package@1.0.0"}, // Same as dependencyPath[1] - unrealistic but handled defensively
			expectedMessage: "Your dependencies are out of date, otherwise you would be using a newer test-package than test-package@1.0.0. Try reinstalling your dependencies. If the problem persists, one of your dependencies may be bundling outdated modules.",
			description:     "Should return outdated dependency message for maven (different remediation steps than npm/yarn).",
		},
		{
			name:    "Malformed data: upgrade path suggests same vulnerable version - pip",
			finding: createFindingWithoutUpgradePath(t),
			problem: &testapi.SnykVulnProblem{
				PackageName:              "test-package",
				PackageVersion:           "1.0.0",
				InitiallyFixedInVersions: []string{"1.0.1"},
			},
			ecosystem:       "pip",
			dependencyPath:  []string{"root@1.0.0", "test-package@1.0.0"},
			upgradePath:     []any{false, "test-package@1.0.0"}, // Same as dependencyPath[1] - unrealistic but handled defensively
			expectedMessage: "Your dependencies are out of date, otherwise you would be using a newer test-package than test-package@1.0.0. Try reinstalling your dependencies. If the problem persists, one of your dependencies may be bundling outdated modules.",
			description:     "Should return outdated dependency message for pip (different remediation steps than npm/yarn).",
		},
		{
			name:    "Malformed data: upgrade path for different package than vulnerable one",
			finding: createFindingWithUpgradePaths(t, "other-pkg", [][]string{{"root@1.0.0", "other-pkg@2.0.0"}}),
			problem: &testapi.SnykVulnProblem{
				PackageName:              "test-package",
				PackageVersion:           "1.0.0",
				InitiallyFixedInVersions: []string{"1.0.1"},
			},
			ecosystem:       "npm",
			dependencyPath:  []string{"root@1.0.0", "test-package@1.0.0"},
			upgradePath:     []any{false, "other-pkg@2.0.0"}, // Wrong package - unrealistic but handled defensively
			expectedMessage: "Upgrade to other-pkg@2.0.0",    // Still returns upgrade message for defensive handling
			description:     "Should return upgrade message even when upgrade path targets wrong package (defensive handling of malformed API data).",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildRemediationAdvice(tt.finding, tt.problem, tt.ecosystem, tt.dependencyPath, tt.upgradePath)
			assert.Equal(t, tt.expectedMessage, result, tt.description)
		})
	}
}

// Test_extractDependencyPath tests the extractDependencyPath function
func Test_extractDependencyPath(t *testing.T) {
	testutil.UnitTest(t)

	tests := []struct {
		name           string
		finding        *testapi.FindingData
		expected       []string
		description    string
		skipTestReason string
	}{
		{
			name:        "Extract path from finding with dependency evidence",
			finding:     createFindingWithDependencyPath(t, "goof@1.0.0", []string{"lodash@4.17.20"}),
			expected:    []string{"goof@1.0.0", "lodash@4.17.20"},
			description: "Should extract dependency path from finding with valid dependency_path evidence.",
		},
		{
			name:        "Defensive: non-dependency_path evidence - returns empty slice",
			finding:     createFindingWithNonDependencyPathEvidence(t),
			expected:    []string{},
			description: "Should return empty slice when evidence exists but none is of the dependency_path type.",
		},
		{
			name:           "TODO: multiple dependency paths - should return all paths",
			finding:        createFindingWithMultipleDependencyPaths(t, "goof@1.0.0", []string{"lodash@4.17.20"}, []string{"other-pkg@1.0.0"}),
			expected:       []string{"goof@1.0.0", "lodash@4.17.20" /* path 1 */, "goof@1.0.0", "other-pkg@1.0.0" /* path 2 */}, // I would expect the output to be a 2D slice.
			description:    "Should return all dependency paths when multiple exist.",
			skipTestReason: "Prod code needs to be updated to return all dependency paths, not just the first one (FIXME in prod code first).",
		},
		{
			name:           "TODO: vuln-pkg as both direct and transitive dependency - should return all paths",
			finding:        createFindingWithMultipleDependencyPaths(t, "goof@1.0.0", []string{"vuln-pkg@1.0.0"}, []string{"other-pkg@1.0.0", "vuln-pkg@1.0.0"}, []string{"another-pkg@1.0.0", "vuln-pkg@1.0.0"}),
			expected:       []string{"goof@1.0.0", "vuln-pkg@1.0.0" /* direct */, "goof@1.0.0", "other-pkg@1.0.0", "vuln-pkg@1.0.0" /* transitive via other-pkg */, "goof@1.0.0", "another-pkg@1.0.0", "vuln-pkg@1.0.0" /* transitive via another-pkg */}, // I would expect the output to be a 2D slice.
			description:    "Should return all paths including when vulnerable package appears as BOTH a direct dependency AND transitive dependencies via other routes. All paths must be preserved independently.",
			skipTestReason: "Prod code needs to be updated to return all dependency paths, not just the first one (FIXME in prod code first).",
		},
		{
			name: "Wrong behavior: multiple dependency paths - returns first one only (FIXME in prod code)",
			// TODO: Delete this test and enable the test above when the fix has been implemented in the prod code.
			finding:     createFindingWithMultipleDependencyPaths(t, "goof@1.0.0", []string{"lodash@4.17.20"}, []string{"other-pkg@1.0.0"}),
			expected:    []string{"goof@1.0.0", "lodash@4.17.20"}, // Wrong: should return both paths, but currently only returns first
			description: "With the current incorrect behavior, should return only the first path when multiple exist. If this bug has been fixed, please delete this test and enable the tests above.",
		},
		{
			name:        "Malformed data: finding with empty evidence array",
			finding:     &testapi.FindingData{Attributes: &testapi.FindingAttributes{}},
			expected:    []string{},
			description: "Should return empty slice when finding has attributes but no evidence.",
		},
		{
			name:        "Malformed data: finding with nil attributes",
			finding:     &testapi.FindingData{},
			expected:    nil,
			description: "Should return nil when finding has nil attributes.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipTestReason != "" {
				t.Skip(tt.skipTestReason)
			}

			result := extractDependencyPath(tt.finding)
			assert.Equal(t, tt.expected, result, tt.description)
		})
	}
}

// Test_buildMessage tests the buildMessage function
func Test_buildMessage(t *testing.T) {
	testutil.UnitTest(t)

	tests := []struct {
		name        string
		title       string
		packageName string
		remediation string
		expected    string
		description string
	}{
		{
			name:        "Short message",
			title:       "Prototype Pollution",
			packageName: "lodash",
			remediation: "Upgrade to lodash@4.17.21",
			expected:    "Prototype Pollution affecting package lodash. Upgrade to lodash@4.17.21",
			description: "Should build message with title, package name, and remediation advice.",
		},
		{
			name:        "No remediation available",
			title:       "ReDoS",
			packageName: "regex-pkg",
			remediation: "No remediation advice available",
			expected:    "ReDoS affecting package regex-pkg. No remediation advice available",
			description: "Should build message with title, package name, and include the 'No remediation advice available' text.",
		},
		{
			name:        "Long remediation message gets truncated",
			title:       "Vuln",
			packageName: "pkg",
			remediation: strings.Repeat("A", 300), // 300 chars
			expected:    "Vuln affecting package pkg. " + strings.Repeat("A", 172) + "... (Snyk)",
			description: "Should truncate message at 200 characters and append '... (Snyk)' suffix.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildMessage(tt.title, tt.packageName, tt.remediation)
			assert.Equal(t, tt.expected, result, tt.description)
		})
	}
}

// Test_getIntroducingFinding tests finding the dependency that introduces a vulnerability
func Test_getIntroducingFinding(t *testing.T) {
	testutil.UnitTest(t)

	tests := []struct {
		name           string
		findings       []*testapi.FindingData
		problemPkgName string
		expectedIndex  int
		description    string
		skipTestReason string
	}{
		{
			name: "Direct dependency introduces vulnerability",
			findings: []*testapi.FindingData{
				createFindingWithDependencyPath(t, "goof@1.0.0", []string{"lodash@4.17.4"}),
			},
			problemPkgName: "lodash",
			expectedIndex:  0,
			description:    "Should return the finding (which happens to be a direct dependency, but would also be returned by fallback logic if it wasn't).",
		},
		{
			name: "Multiple findings - first direct dependency wins",
			findings: []*testapi.FindingData{
				createFindingWithDependencyPath(t, "goof@1.0.0", []string{"other-pkg@1.0.0", "lodash@4.17.4"}), // indirect
				createFindingWithDependencyPath(t, "goof@1.0.0", []string{"lodash@4.17.4"}),                    // direct - should win
			},
			problemPkgName: "lodash",
			expectedIndex:  1,
			description:    "Should return first finding with vulnerable package as direct dependency when multiple findings exist.",
		},
		{
			name: "TODO: multiple findings with different direct dependencies - should return one per direct dep",
			findings: []*testapi.FindingData{
				createFindingWithDependencyPath(t, "goof@1.0.0", []string{"other-pkg@1.0.0", "lodash@4.17.4"}),
				createFindingWithDependencyPath(t, "goof@1.0.0", []string{"other-pkg@1.0.0", "sub-pkg@1.2.3", "lodash@4.17.0"}),
				createFindingWithDependencyPath(t, "goof@1.0.0", []string{"another-pkg@1.0.0", "lodash@4.17.4"}),
				createFindingWithDependencyPath(t, "goof@1.0.0", []string{"another-pkg@1.0.0", "another-sub-pkg@2.6.5", "lodash@4.17.2"}),
			},
			problemPkgName: "lodash",
			expectedIndex:  0, // TODO: Change to expectedIndexes []int{0, 2} when function signature changes to return []*testapi.FindingData
			description:    "Should return one finding for each unique direct dependency (other-pkg and another-pkg) that transitively leads to vulnerable package.",
			skipTestReason: "Prod code needs to be updated to return multiple findings (one per unique direct dependency), not just the first one (FIXME in prod code first).",
		},
		{
			name: "TODO: vuln-pkg as both direct and transitive dependency - should return findings for all unique direct deps",
			findings: []*testapi.FindingData{
				createFindingWithDependencyPath(t, "goof@1.0.0", []string{"vuln-pkg@1.0.0"}),                                     // vuln-pkg is direct
				createFindingWithDependencyPath(t, "goof@1.0.0", []string{"other-pkg@1.0.0", "vuln-pkg@1.0.0"}),                  // vuln-pkg via other-pkg
				createFindingWithDependencyPath(t, "goof@1.0.0", []string{"other-pkg@1.0.0", "sub-pkg@1.0.0", "vuln-pkg@1.0.0"}), // another path via other-pkg
				createFindingWithDependencyPath(t, "goof@1.0.0", []string{"another-pkg@1.0.0", "vuln-pkg@1.0.0"}),                // vuln-pkg via another-pkg
			},
			problemPkgName: "vuln-pkg",
			expectedIndex:  0, // TODO: Change to expectedIndexes []int{0, 1, 3} when function signature changes - includes vuln-pkg as direct dep AND other-pkg AND another-pkg
			description:    "Should return findings for all unique direct dependencies including when vulnerable package is BOTH a direct dependency AND a transitive dependency via other routes. All Issues should exist independently.",
			skipTestReason: "Prod code needs to be updated to return multiple findings (one per unique direct dependency), not just the first one (FIXME in prod code first).",
		},
		{
			name: "Wrong behavior: multiple transitive paths through different direct deps - returns first finding only",
			// TODO: Delete this test and enable the test above when the fix has been implemented in the prod code.
			findings: []*testapi.FindingData{
				createFindingWithDependencyPath(t, "goof@1.0.0", []string{"other-pkg@1.0.0", "lodash@4.17.4"}),
				createFindingWithDependencyPath(t, "goof@1.0.0", []string{"another-pkg@1.0.0", "lodash@4.17.4"}),
			},
			problemPkgName: "lodash",
			expectedIndex:  0,
			description:    "With the current incorrect behavior, should return only first finding when multiple direct dependencies transitively lead to vulnerable package. If this bug has been fixed, please delete this test and enable the tests above.",
		},
		{
			name: "Malformed data: dependency path with only root - returns first finding gracefully",
			findings: []*testapi.FindingData{
				createFindingWithDependencyPath(t, "goof@1.0.0", []string{}), // Only root, no actual dependency (malformed)
			},
			problemPkgName: "lodash",
			expectedIndex:  0,
			description:    "Should return first finding when dependency path has insufficient length (malformed API data).",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipTestReason != "" {
				t.Skip(tt.skipTestReason)
			}

			// Create issue with findings
			problem := &testapi.SnykVulnProblem{
				PackageName: tt.problemPkgName,
			}
			issue := createMockIssueWithFindings(t, tt.findings)

			result, err := getIntroducingFinding(issue, problem)

			assert.NoError(t, err, "getIntroducingFinding should not return an error")
			assert.Equal(t, tt.findings[tt.expectedIndex], result, tt.description)
		})
	}
}

// Test_extractUpgradePackage tests extraction of upgrade paths from fix relationships
func Test_extractUpgradePackage(t *testing.T) {
	testutil.UnitTest(t)

	tests := []struct {
		name           string
		dependencyPath []string
		finding        *testapi.FindingData
		expected       []string
		description    string
	}{
		{
			name:           "Fix relationship with upgrade path",
			dependencyPath: []string{"goof@1.0.0", "lodash@4.17.4"},
			finding:        createFindingWithUpgradePaths(t, "lodash", [][]string{{"goof@1.0.0", "lodash@4.17.21"}}),
			expected:       []string{"goof@1.0.0", "lodash@4.17.21"},
			description:    "Should extract upgrade path from fix relationships.",
		},
		{
			name:           "Multiple upgrade paths via different direct dependencies - returns the one for the direct dependency in question",
			dependencyPath: []string{"goof@1.0.0", "express@4.12.4", "debug@2.2.0"},
			finding:        createFindingWithUpgradePaths(t, "debug", [][]string{{"goof@1.0.0", "express@4.15.2", "debug@2.6.9"}, {"goof@1.0.0", "mongoose@5.0.0", "debug@2.6.9"}}),
			expected:       []string{"goof@1.0.0", "express@4.15.2", "debug@2.6.9"},
			description:    "Should filter finding's multiple upgrade paths and return the first one where direct dependency (position [1]) matches the input dependency path. Tests scenario where vulnerable package is reached through different direct dependencies.",
		},
		{
			name:           "Multiple upgrade paths via same direct dependency - returns first matching",
			dependencyPath: []string{"root@1.0.0", "dep-a@1.0.0", "dep-a1@1.0.0", "vuln-pkg@1.0.0"},
			finding:        createFindingWithUpgradePaths(t, "vuln-pkg", [][]string{{"root@1.0.0", "dep-a@2.0.0", "dep-a1@2.0.0", "vuln-pkg@1.0.1"}, {"root@1.0.0", "dep-a@2.0.0", "dep-a2@2.0.0", "vuln-pkg@1.0.1"}}),
			expected:       []string{"root@1.0.0", "dep-a@2.0.0", "dep-a1@2.0.0", "vuln-pkg@1.0.1"},
			description:    "Should return first matching upgrade path when multiple paths exist through same direct dependency but different transitive paths. Tests scenario where vuln is reached through same direct dep via different transitive routes.",
		},
		{
			name:           "No fix relationships",
			dependencyPath: []string{"goof@1.0.0", "lodash@4.17.4"},
			finding: &testapi.FindingData{
				Relationships: nil,
			},
			expected:    nil,
			description: "Should return nil when no fix relationships exist.",
		},
		{
			name:           "Returns empty when the only upgrade path is for a dependency path other than the one we are focused on",
			dependencyPath: []string{"goof@1.0.0", "lodash@4.17.4"},
			finding:        createFindingWithUpgradePaths(t, "other-pkg", [][]string{{"goof@1.0.0", "other-pkg@2.0.0"}}),
			expected:       []string{},
			description:    "Should return empty slice when finding has upgrade paths but none match the input dependency path's direct dependency. Represents partial fix scenario where fix exists via different route (other-pkg) but not via the route in question (lodash).",
		},
		{
			name:           "Defensive: Empty dependency path",
			dependencyPath: []string{},
			finding:        createFindingWithUpgradePaths(t, "lodash", [][]string{{"goof@1.0.0", "lodash@4.17.21"}}),
			expected:       nil,
			description:    "Should return nil when dependency path is empty.",
		},
		{
			name:           "Defensive: Empty upgrade paths array",
			dependencyPath: []string{"goof@1.0.0", "lodash@4.17.4"},
			finding:        createFindingWithUpgradePaths(t, "lodash", [][]string{}),
			expected:       nil,
			description:    "Should return nil when UpgradePaths array is empty.",
		},
		{
			name:           "Defensive: nil Action attribute - handles gracefully",
			dependencyPath: []string{"goof@1.0.0", "lodash@4.17.4"},
			finding:        createFindingWithNilAction(t),
			expected:       nil,
			description:    "Should return nil when Fix.Data.Attributes.Action is nil.",
		},
		{
			name:           "Malformed data: single element dependency path - handles gracefully",
			dependencyPath: []string{"root@1.0.0"},
			finding:        createFindingWithUpgradePaths(t, "lodash", [][]string{{"goof@1.0.0", "lodash@4.17.21"}}),
			expected:       nil,
			description:    "Should return nil when dependency path has only root (length 1, malformed) to avoid panic.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractUpgradePackage(tt.dependencyPath, tt.finding)
			assert.Equal(t, tt.expected, result, tt.description)
		})
	}
}

// Test_processIssue_CodeActionGeneration verifies code action and code lens generation
// based on fix availability and feature flag state
func Test_processIssue_CodeActionGeneration(t *testing.T) {
	tests := []struct {
		name                string
		quickFixEnabled     bool
		fixVersions         []string
		expectedRemediation string
		expectCodeActions   bool
	}{
		{
			name:                "WithFix_FFEnabled_HasCodeActions",
			quickFixEnabled:     true,
			fixVersions:         []string{"4.17.21"}, // fixed version available
			expectedRemediation: "Upgrade to lodash@4.17.21",
			expectCodeActions:   true,
		},
		{
			name:                "WithFix_FFDisabled_NoCodeActions",
			quickFixEnabled:     false,
			fixVersions:         []string{"4.17.21"}, // fixed version available
			expectedRemediation: "Upgrade to lodash@4.17.21",
			expectCodeActions:   false,
		},
		{
			name:                "NoFix_NoCodeActions",
			quickFixEnabled:     true,       // FF enabled to prove no quick-fix even then
			fixVersions:         []string{}, // no fix available
			expectedRemediation: "No remediation advice available",
			expectCodeActions:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupProcessIssueTest(t, util.Ptr(tt.quickFixEnabled), "package.json")

			// Create a finding with lodash matching testdata/package.json
			finding := createCompleteUnifiedFinding(
				t,
				"npm",
				"goof@1.0.1",
				[]string{"lodash@4.17.4"}, // matches testdata/package.json
				tt.fixVersions,
				"lodash",
				"4.17.4",
				"Prototype Pollution",
			)

			trIssue, err := testapi.NewIssueFromFindings([]*testapi.FindingData{&finding})
			require.NoError(t, err)

			// Act
			result := processIssue(
				setup.ctx,
				trIssue,
				zerolog.Nop(),
				types.FilePath(setup.filePath),
				types.FilePath(setup.workDir),
			)

			// Verify basic issue data
			require.NotNil(t, result, "processIssue should return an issue")
			assert.Equal(t, "lodash-id", result.ID)
			assert.Equal(t, types.High, result.Severity)

			additionalData, ok := result.AdditionalData.(snyk.OssIssueData)
			require.True(t, ok)
			assert.Equal(t, "lodash", additionalData.PackageName)
			assert.Equal(t, "4.17.4", additionalData.Version)
			assert.Equal(t, tt.expectedRemediation, additionalData.Remediation)

			if !tt.expectCodeActions {
				// Verify no code actions or code lenses are generated
				assert.Empty(t, result.GetCodeActions(), "Code actions should not be generated")
				assert.Empty(t, result.GetCodelensCommands(), "Code lenses should not be generated")
			} else {
				// Verify code actions are generated
				codeActions := result.GetCodeActions()
				assert.NotEmpty(t, codeActions, "Code actions should be generated")

				// Verify the quick-fix actions
				var hasQuickFix bool
				for _, action := range codeActions {
					title := action.GetTitle()
					if strings.Contains(title, "Upgrade to") && strings.Contains(title, "⚡️") {
						hasQuickFix = true
						assert.Contains(t, title, "lodash")
						assert.Contains(t, title, "4.17.21")
						break
					}
				}
				assert.True(t, hasQuickFix, "Should have a quick-fix upgrade code action")

				// Verify code lens commands are generated
				codelensCommands := result.GetCodelensCommands()
				assert.NotEmpty(t, codelensCommands, "Code lens commands should be generated")

				var hasUpgradeCodeLens bool
				for _, cmd := range codelensCommands {
					if strings.Contains(cmd.Title, "Upgrade to") && strings.Contains(cmd.Title, "⚡️") {
						hasUpgradeCodeLens = true
						assert.Contains(t, cmd.Title, "lodash")
						assert.Contains(t, cmd.Title, "4.17.21")
						break
					}
				}
				assert.True(t, hasUpgradeCodeLens, "Should have an upgrade code lens command")
			}
		})
	}
}

// Test_processIssue_Defensive_WrongTypeInContextDeps verifies graceful handling when context deps have wrong types
func Test_processIssue_Defensive_WrongTypeInContextDeps(t *testing.T) {
	testutil.UnitTest(t)

	ctx := t.Context()

	workDir, err := filepath.Abs("testdata")
	require.NoError(t, err)

	filePath := filepath.Join(workDir, "package.json")
	ctx = ctx2.NewContextWithWorkDirAndFilePath(ctx, types.FilePath(workDir), types.FilePath(filePath))

	// Create deps with WRONG types (strings instead of proper types)
	deps := map[string]any{
		ctx2.DepConfig:        "not-a-config",    // Should be *config.Config
		ctx2.DepLearnService:  "not-a-service",   // Should be learn.Service
		ctx2.DepErrorReporter: "not-an-reporter", // Should be error_reporting.ErrorReporter
	}
	ctx = ctx2.NewContextWithDependencies(ctx, deps)

	finding := createCompleteUnifiedFinding(
		t,
		"npm",
		"goof@1.0.1",
		[]string{"lodash@4.17.4"},
		[]string{"4.17.21"},
		"lodash",
		"4.17.4",
		"Prototype Pollution",
	)

	trIssue, err := testapi.NewIssueFromFindings([]*testapi.FindingData{&finding})
	require.NoError(t, err)

	logger := zerolog.Nop()

	result := processIssue(
		ctx,
		trIssue,
		logger,
		types.FilePath(filePath),
		types.FilePath(workDir),
	)

	assertProcessIssueGracefulDegradation(t, result, "lodash", types.High)
}

// Test_processIssue_Defensive_MissingContextDeps verifies graceful handling when context dependencies are missing
func Test_processIssue_Defensive_MissingContextDeps(t *testing.T) {
	testutil.UnitTest(t)

	// Create a context WITHOUT dependencies to test error handling
	ctx := t.Context()

	workDir, err := filepath.Abs("testdata")
	require.NoError(t, err)

	filePath := filepath.Join(workDir, "package.json")
	ctx = ctx2.NewContextWithWorkDirAndFilePath(ctx, types.FilePath(workDir), types.FilePath(filePath))

	// Note: NOT calling NewContextWithDependencies, so deps will be missing

	finding := createCompleteUnifiedFinding(
		t,
		"npm",
		"goof@1.0.1",
		[]string{"lodash@4.17.4"},
		[]string{"4.17.21"},
		"lodash",
		"4.17.4",
		"Prototype Pollution",
	)

	trIssue, err := testapi.NewIssueFromFindings([]*testapi.FindingData{&finding})
	require.NoError(t, err)

	logger := zerolog.Nop()

	result := processIssue(
		ctx,
		trIssue,
		logger,
		types.FilePath(filePath),
		types.FilePath(workDir),
	)

	assertProcessIssueGracefulDegradation(t, result, "lodash", types.High)
}

// Test_processIssue_Defensive_NilDependencyNode verifies graceful handling when dependency node can't be found
func Test_processIssue_Defensive_NilDependencyNode(t *testing.T) {
	// Use a non-existent file path so getDependencyNode returns nil
	setup := setupProcessIssueTest(t, util.Ptr(true), "nonexistent.json")

	finding := createCompleteUnifiedFinding(
		t,
		"npm",
		"my-app@1.0.0",
		[]string{"vulnerable-pkg@1.0.0"},
		[]string{"1.0.1"},
		"vulnerable-pkg",
		"1.0.0",
		"Security Vulnerability",
	)

	trIssue, err := testapi.NewIssueFromFindings([]*testapi.FindingData{&finding})
	require.NoError(t, err)

	// Act
	result := processIssue(
		setup.ctx,
		trIssue,
		zerolog.Nop(),
		types.FilePath(setup.filePath),
		types.FilePath(setup.workDir),
	)

	// Verify graceful degradation
	assertProcessIssueGracefulDegradation(t, result, "vulnerable-pkg", types.High)

	// Verify range should be empty
	assert.Equal(t, types.Range{}, result.Range, "Range should be empty when dependency node is nil")
}

// processIssueTestSetup holds the common setup for processIssue tests
type processIssueTestSetup struct {
	ctx      context.Context
	config   *config.Config
	workDir  string
	filePath string
}

// setupProcessIssueTest creates common test setup for processIssue tests.
// Parameters:
//   - quickFixEnabled: nil=don't set (use default), util.Ptr(true)=enable, util.Ptr(false)=disable
//   - manifestFile: the manifest file name (e.g., "package.json")
func setupProcessIssueTest(t *testing.T, quickFixEnabled *bool, manifestFile string) processIssueTestSetup {
	t.Helper()

	c, ctx := testutil.UnitTestWithCtx(t)

	if quickFixEnabled != nil {
		c.SetSnykOSSQuickFixCodeActionsEnabled(*quickFixEnabled)
	}

	workDir, err := filepath.Abs("testdata")
	require.NoError(t, err)

	filePath := filepath.Join(workDir, manifestFile)
	ctx = ctx2.NewContextWithWorkDirAndFilePath(ctx, types.FilePath(workDir), types.FilePath(filePath))

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	learnService := mock_learn.NewMockService(ctrl)
	errorReporter := error_reporting.NewTestErrorReporter()

	learnService.EXPECT().
		GetLesson(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), types.DependencyVulnerability).
		Return(nil, nil).
		AnyTimes()

	deps := map[string]any{
		ctx2.DepConfig:        c,
		ctx2.DepLearnService:  learnService,
		ctx2.DepErrorReporter: errorReporter,
	}
	ctx = ctx2.NewContextWithDependencies(ctx, deps)

	return processIssueTestSetup{
		ctx:      ctx,
		config:   c,
		workDir:  workDir,
		filePath: filePath,
	}
}

// assertProcessIssueGracefulDegradation verifies that processIssue handles edge cases gracefully:
// - Issue is created with basic data
// - No code actions or code lenses are generated
// - Core vulnerability data (package name, upgrade path) is preserved
func assertProcessIssueGracefulDegradation(t *testing.T, result *snyk.Issue, expectedPkgName string, expectedSeverity types.Severity) {
	t.Helper()

	require.NotNil(t, result, "processIssue should return an issue")
	// ID format matches createCompleteUnifiedFinding: pkgName + "-id"
	assert.Equal(t, expectedPkgName+"-id", result.ID)
	assert.Equal(t, expectedSeverity, result.Severity)

	assert.Empty(t, result.GetCodeActions(), "Code actions should not be generated")
	assert.Empty(t, result.GetCodelensCommands(), "Code lens commands should not be generated")

	additionalData, ok := result.AdditionalData.(snyk.OssIssueData)
	require.True(t, ok, "AdditionalData should be OssIssueData")
	assert.Equal(t, expectedPkgName, additionalData.PackageName)
	assert.NotEmpty(t, additionalData.UpgradePath, "Upgrade path should still be built")
}

// createCompleteUnifiedFinding builds a FindingData with all key fields populated so that
// unified conversion can yield actionable issues (UpgradePath/From/FixedIn etc.).
func createCompleteUnifiedFinding(
	t *testing.T,
	packageManager string,
	root string,
	path []string,
	fixedIn []string,
	pkgName string,
	version string,
	title string,
) testapi.FindingData {
	t.Helper()
	id := uuid.New()
	high := testapi.Severity("high")
	finding := testapi.FindingData{
		Id:   &id,
		Type: nil,
		Attributes: &testapi.FindingAttributes{
			Key:         pkgName + "-vuln-id",
			Title:       title,
			Description: title + " description",
			FindingType: testapi.FindingTypeSca,
			Rating: testapi.Rating{
				Severity: high,
			},
			Problems:  nil,
			Locations: []testapi.FindingLocation{},
			Evidence:  []testapi.Evidence{},
		},
	}

	var ecosystem testapi.SnykvulndbPackageEcosystem
	err := ecosystem.FromSnykvulndbBuildPackageEcosystem(testapi.SnykvulndbBuildPackageEcosystem{
		PackageManager: packageManager,
		Language:       "",
	})
	require.NoError(t, err)

	var problem testapi.Problem
	err = problem.FromSnykVulnProblem(testapi.SnykVulnProblem{
		Id:                       pkgName + "-id",
		PackageName:              pkgName,
		PackageVersion:           version,
		Ecosystem:                ecosystem,
		InitiallyFixedInVersions: fixedIn,
	})
	require.NoError(t, err)
	finding.Attributes.Problems = []testapi.Problem{problem}

	// Build dependency path evidence
	dependencyPkgs := make([]testapi.Package, len(path)+1)
	rootParts := strings.Split(root, "@")
	dependencyPkgs[0] = testapi.Package{Name: rootParts[0], Version: rootParts[1]}
	for i, pkgStr := range path {
		parts := strings.Split(pkgStr, "@")
		dependencyPkgs[i+1] = testapi.Package{Name: parts[0], Version: parts[1]}
	}
	var depEv testapi.Evidence
	err = depEv.FromDependencyPathEvidence(testapi.DependencyPathEvidence{Path: dependencyPkgs})
	require.NoError(t, err)
	finding.Attributes.Evidence = append(finding.Attributes.Evidence, depEv)

	// Add package location
	var loc testapi.FindingLocation
	err = loc.FromPackageLocation(testapi.PackageLocation{
		Package: testapi.Package{Name: pkgName, Version: version},
	})
	require.NoError(t, err)
	finding.Attributes.Locations = append(finding.Attributes.Locations, loc)

	// Add fix relationships if fixedIn versions are provided
	if len(fixedIn) > 0 {
		// Build upgrade path with root and fixed version
		upgradePkgs := make([]testapi.Package, len(path)+1)
		upgradePkgs[0] = dependencyPkgs[0] // root package stays the same
		for i, pkgStr := range path {
			parts := strings.Split(pkgStr, "@")
			// Use fixed version for the vulnerable package
			if parts[0] == pkgName {
				upgradePkgs[i+1] = testapi.Package{Name: parts[0], Version: fixedIn[0]}
			} else {
				upgradePkgs[i+1] = testapi.Package{Name: parts[0], Version: parts[1]}
			}
		}

		var fixAction testapi.FixAction
		err = fixAction.FromUpgradePackageAdvice(testapi.UpgradePackageAdvice{
			Format:      testapi.UpgradePackageAdviceFormatUpgradePackageAdvice,
			PackageName: pkgName,
			UpgradePaths: []testapi.UpgradePath{
				{
					DependencyPath: upgradePkgs,
					IsDrop:         false,
				},
			},
		})
		require.NoError(t, err)

		finding.Relationships = &struct {
			Asset *struct {
				Data *struct {
					Id   uuid.UUID `json:"id"`
					Type string    `json:"type"`
				} `json:"data,omitempty"`
				Links testapi.IoSnykApiCommonRelatedLink `json:"links"`
				Meta  *testapi.IoSnykApiCommonMeta       `json:"meta,omitempty"`
			} `json:"asset,omitempty"`
			Fix *struct {
				Data *struct {
					Attributes *testapi.FixAttributes `json:"attributes,omitempty"`
					Id         uuid.UUID              `json:"id"`
					Type       string                 `json:"type"`
				} `json:"data,omitempty"`
			} `json:"fix,omitempty"`
			Org *struct {
				Data *struct {
					Id   uuid.UUID `json:"id"`
					Type string    `json:"type"`
				} `json:"data,omitempty"`
			} `json:"org,omitempty"`
			Policy *struct {
				Data *struct {
					Attributes *testapi.PolicyAttributes `json:"attributes,omitempty"`
					Id         uuid.UUID                 `json:"id"`
					Type       string                    `json:"type"`
				} `json:"data,omitempty"`
				Links testapi.IoSnykApiCommonRelatedLink `json:"links"`
				Meta  *testapi.IoSnykApiCommonMeta       `json:"meta,omitempty"`
			} `json:"policy,omitempty"`
			Test *struct {
				Data *struct {
					Id   uuid.UUID `json:"id"`
					Type string    `json:"type"`
				} `json:"data,omitempty"`
				Links testapi.IoSnykApiCommonRelatedLink `json:"links"`
				Meta  *testapi.IoSnykApiCommonMeta       `json:"meta,omitempty"`
			} `json:"test,omitempty"`
		}{
			Fix: &struct {
				Data *struct {
					Attributes *testapi.FixAttributes `json:"attributes,omitempty"`
					Id         uuid.UUID              `json:"id"`
					Type       string                 `json:"type"`
				} `json:"data,omitempty"`
			}{
				Data: &struct {
					Attributes *testapi.FixAttributes `json:"attributes,omitempty"`
					Id         uuid.UUID              `json:"id"`
					Type       string                 `json:"type"`
				}{
					Attributes: &testapi.FixAttributes{
						Action:  &fixAction,
						Outcome: "resolved",
					},
					Id:   uuid.New(),
					Type: "fix",
				},
			},
		}
	}

	return finding
}

// createFindingWithNilAction creates a FindingData with Fix relationships but Action is nil
func createFindingWithNilAction(t *testing.T) *testapi.FindingData {
	t.Helper()
	finding := createBaseFindingWithRelationshipsStruct(t)

	fixID := uuid.New()
	finding.Relationships.Fix = &struct {
		Data *struct {
			Attributes *testapi.FixAttributes `json:"attributes,omitempty"`
			Id         uuid.UUID              `json:"id"`
			Type       string                 `json:"type"`
		} `json:"data,omitempty"`
	}{
		Data: &struct {
			Attributes *testapi.FixAttributes `json:"attributes,omitempty"`
			Id         uuid.UUID              `json:"id"`
			Type       string                 `json:"type"`
		}{
			Attributes: &testapi.FixAttributes{
				Action:  nil, // Explicitly nil Action
				Outcome: "resolved",
			},
			Id:   fixID,
			Type: "fix",
		},
	}

	return finding
}

// createFindingWithNonDependencyPathEvidence creates a FindingData with evidence that isn't dependency_path
func createFindingWithNonDependencyPathEvidence(t *testing.T) *testapi.FindingData {
	t.Helper()
	finding := &testapi.FindingData{
		Attributes: &testapi.FindingAttributes{
			Evidence: []testapi.Evidence{},
		},
	}

	// Add "other" evidence to the Evidence array (not dependency_path type)
	var evidence testapi.Evidence
	err := evidence.FromOtherEvidence(testapi.OtherEvidence{
		Source: "other",
	})
	require.NoError(t, err)
	finding.Attributes.Evidence = append(finding.Attributes.Evidence, evidence)

	return finding
}

// createFindingWithDependencyPath creates a FindingData with only dependency path evidence
func createFindingWithDependencyPath(t *testing.T, root string, path []string) *testapi.FindingData {
	t.Helper()
	finding := &testapi.FindingData{
		Attributes: &testapi.FindingAttributes{
			Evidence: []testapi.Evidence{},
		},
	}

	// Build dependency path evidence
	dependencyPkgs := make([]testapi.Package, len(path)+1)
	rootParts := strings.Split(root, "@")
	dependencyPkgs[0] = testapi.Package{Name: rootParts[0], Version: rootParts[1]}

	for i, pkgStr := range path {
		parts := strings.Split(pkgStr, "@")
		dependencyPkgs[i+1] = testapi.Package{Name: parts[0], Version: parts[1]}
	}

	var depEv testapi.Evidence
	err := depEv.FromDependencyPathEvidence(testapi.DependencyPathEvidence{
		Path: dependencyPkgs,
	})
	require.NoError(t, err)
	finding.Attributes.Evidence = append(finding.Attributes.Evidence, depEv)

	return finding
}

// createFindingWithMultipleDependencyPaths creates a FindingData with multiple dependency path evidences
func createFindingWithMultipleDependencyPaths(t *testing.T, root string, paths ...[]string) *testapi.FindingData {
	t.Helper()
	finding := &testapi.FindingData{
		Attributes: &testapi.FindingAttributes{
			Evidence: []testapi.Evidence{},
		},
	}

	rootParts := strings.Split(root, "@")

	// Build dependency path evidence for each path
	for _, path := range paths {
		dependencyPkgs := make([]testapi.Package, len(path)+1)
		dependencyPkgs[0] = testapi.Package{Name: rootParts[0], Version: rootParts[1]}
		for i, pkgStr := range path {
			parts := strings.Split(pkgStr, "@")
			dependencyPkgs[i+1] = testapi.Package{Name: parts[0], Version: parts[1]}
		}
		var depEv testapi.Evidence
		err := depEv.FromDependencyPathEvidence(testapi.DependencyPathEvidence{Path: dependencyPkgs})
		require.NoError(t, err)
		finding.Attributes.Evidence = append(finding.Attributes.Evidence, depEv)
	}

	return finding
}

func createFindingWithoutUpgradePath(t *testing.T) *testapi.FindingData {
	t.Helper()
	finding := &testapi.FindingData{
		Attributes: &testapi.FindingAttributes{
			Evidence: []testapi.Evidence{},
		},
	}

	var depEv testapi.Evidence
	err := depEv.FromDependencyPathEvidence(testapi.DependencyPathEvidence{
		Path: []testapi.Package{
			{Name: "root", Version: "1.0.0"},
			{Name: "test-package", Version: "1.0.0"},
		},
	})
	require.NoError(t, err)

	finding.Attributes.Evidence = append(finding.Attributes.Evidence, depEv)

	return finding
}

// createBaseFindingWithRelationshipsStruct creates a base FindingData with the Relationships structure initialized
func createBaseFindingWithRelationshipsStruct(t *testing.T) *testapi.FindingData {
	t.Helper()
	id := uuid.New()
	return &testapi.FindingData{
		Id: &id,
		Attributes: &testapi.FindingAttributes{
			Evidence: []testapi.Evidence{},
		},
		Relationships: &struct {
			Asset *struct {
				Data *struct {
					Id   uuid.UUID `json:"id"`
					Type string    `json:"type"`
				} `json:"data,omitempty"`
				Links testapi.IoSnykApiCommonRelatedLink `json:"links"`
				Meta  *testapi.IoSnykApiCommonMeta       `json:"meta,omitempty"`
			} `json:"asset,omitempty"`
			Fix *struct {
				Data *struct {
					Attributes *testapi.FixAttributes `json:"attributes,omitempty"`
					Id         uuid.UUID              `json:"id"`
					Type       string                 `json:"type"`
				} `json:"data,omitempty"`
			} `json:"fix,omitempty"`
			Org *struct {
				Data *struct {
					Id   uuid.UUID `json:"id"`
					Type string    `json:"type"`
				} `json:"data,omitempty"`
			} `json:"org,omitempty"`
			Policy *struct {
				Data *struct {
					Attributes *testapi.PolicyAttributes `json:"attributes,omitempty"`
					Id         uuid.UUID                 `json:"id"`
					Type       string                    `json:"type"`
				} `json:"data,omitempty"`
				Links testapi.IoSnykApiCommonRelatedLink `json:"links"`
				Meta  *testapi.IoSnykApiCommonMeta       `json:"meta,omitempty"`
			} `json:"policy,omitempty"`
			Test *struct {
				Data *struct {
					Id   uuid.UUID `json:"id"`
					Type string    `json:"type"`
				} `json:"data,omitempty"`
				Links testapi.IoSnykApiCommonRelatedLink `json:"links"`
				Meta  *testapi.IoSnykApiCommonMeta       `json:"meta,omitempty"`
			} `json:"test,omitempty"`
		}{},
	}
}

// createFindingWithUpgradePaths creates a FindingData with fix relationships for one or more upgrade paths
func createFindingWithUpgradePaths(t *testing.T, packageName string, upgradePaths [][]string) *testapi.FindingData {
	t.Helper()
	finding := createBaseFindingWithRelationshipsStruct(t)

	// Convert each upgrade path to UpgradePath structs
	apiUpgradePaths := make([]testapi.UpgradePath, len(upgradePaths))
	for i, path := range upgradePaths {
		packages := make([]testapi.Package, len(path))
		for j, pkgStr := range path {
			parts := strings.Split(pkgStr, "@")
			packages[j] = testapi.Package{Name: parts[0], Version: parts[1]}
		}
		apiUpgradePaths[i] = testapi.UpgradePath{
			DependencyPath: packages,
			IsDrop:         false,
		}
	}

	// Create fix action with all upgrade paths
	var fixAction testapi.FixAction
	upgradeAdvice := testapi.UpgradePackageAdvice{
		Format:       testapi.UpgradePackageAdviceFormatUpgradePackageAdvice,
		PackageName:  packageName,
		UpgradePaths: apiUpgradePaths,
	}
	err := fixAction.FromUpgradePackageAdvice(upgradeAdvice)
	require.NoError(t, err)

	fixID := uuid.New()
	finding.Relationships.Fix = &struct {
		Data *struct {
			Attributes *testapi.FixAttributes `json:"attributes,omitempty"`
			Id         uuid.UUID              `json:"id"`
			Type       string                 `json:"type"`
		} `json:"data,omitempty"`
	}{
		Data: &struct {
			Attributes *testapi.FixAttributes `json:"attributes,omitempty"`
			Id         uuid.UUID              `json:"id"`
			Type       string                 `json:"type"`
		}{
			Attributes: &testapi.FixAttributes{
				Action:  &fixAction,
				Outcome: "resolved",
			},
			Id:   fixID,
			Type: "fix",
		},
	}

	return finding
}

// createMockIssueWithFindings creates a testapi.Issue with the given findings
// Note: testapi.NewIssueFromFindings returns an error if findings slice is empty,
// so len(findings) should always be > 0 when calling this helper
func createMockIssueWithFindings(t *testing.T, findings []*testapi.FindingData) testapi.Issue {
	t.Helper()
	issue, err := testapi.NewIssueFromFindings(findings)
	require.NoError(t, err, "failed to create issue from findings in test helper")
	return issue
}
