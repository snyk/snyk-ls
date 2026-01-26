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
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/learn/mock_learn"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
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
			name:            "Empty when no upgrade path and no fix relationships",
			dependencyPath:  []string{"root@1.0.0", "test-package@1.0.0"},
			finding:         createFindingWithoutUpgradePath(t),
			expectedUpgrade: []any{false},
			description:     "Should return [false] when no upgrade information available",
		},
		{
			name:            "Upgrade path with fix relationships",
			dependencyPath:  []string{"goof@1.0.0", "lodash@4.17.20"},
			finding:         createFindingWithFixRelationship(t, "lodash", []string{"goof@1.0.0", "lodash@4.17.21"}),
			expectedUpgrade: []any{false, "lodash@4.17.21"},
			description:     "Should extract upgrade path from fix relationships",
		},
		{
			name:            "Multiple upgrade paths - filters by package name",
			dependencyPath:  []string{"goof@1.0.0", "lodash@4.17.20"},
			finding:         createFindingWithMultipleUpgradePaths(t, "lodash", []string{"goof@1.0.0", "lodash@4.17.21"}, []string{"goof@1.0.0", "other-pkg@2.0.0"}),
			expectedUpgrade: []any{false, "lodash@4.17.21"},
			description:     "Should filter and return the upgrade path matching the dependency package name",
		},
		{
			name:            "Transitive dependency with multi-level path",
			dependencyPath:  []string{"root@1.0.0", "intermediate@2.0.0", "lodash@4.17.20"},
			finding:         createFindingWithFixRelationship(t, "lodash", []string{"root@1.0.0", "intermediate@2.0.0", "lodash@4.17.21"}),
			expectedUpgrade: []any{false, "intermediate@2.0.0", "lodash@4.17.21"},
			description:     "Should handle multi-level transitive dependencies",
		},
		{
			name:            "Empty dependency path",
			dependencyPath:  []string{},
			finding:         createFindingWithFixRelationship(t, "lodash", []string{"goof@1.0.0", "lodash@4.17.21"}),
			expectedUpgrade: []any{false},
			description:     "Should return [false] when dependency path is empty",
		},
		{
			name:            "Malformed data: single element dependency path - handles gracefully",
			dependencyPath:  []string{"root@1.0.0"},
			finding:         createFindingWithFixRelationship(t, "lodash", []string{"goof@1.0.0", "lodash@4.17.21"}),
			expectedUpgrade: []any{false},
			description:     "Should return [false] when dependency path has only root (length 1, malformed) to avoid panic",
		},
		{
			name:            "Malformed data: fix relationships for different package - handles gracefully",
			dependencyPath:  []string{"root@1.0.0", "lodash@4.17.20"},
			finding:         createFindingWithFixRelationship(t, "other-pkg", []string{"root@1.0.0", "other-pkg@2.0.0"}),
			expectedUpgrade: []any{false},
			description:     "Should return [false] when fix relationships exist but target a different package than the vulnerable one (malformed API data)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildUpgradePath(tt.dependencyPath, tt.finding)
			assert.Equal(t, tt.expectedUpgrade, result)
		})
	}
}

// Test_buildRemediationAdvice tests the buildRemediationAdvice function
func Test_buildRemediationAdvice(t *testing.T) {
	testutil.UnitTest(t)

	tests := []struct {
		name            string
		dependencyPath  []string
		finding         *testapi.FindingData
		vuln            *testapi.SnykVulnProblem
		upgradePath     []any
		ecosystem       string
		expectedMessage string
		description     string
	}{
		{
			name:           "No remediation when no fixed versions",
			dependencyPath: []string{"root@1.0.0", "test-package@1.0.0"},
			finding:        createFindingWithoutUpgradePath(t),
			vuln: &testapi.SnykVulnProblem{
				PackageName:              "test-package",
				PackageVersion:           "1.0.0",
				InitiallyFixedInVersions: []string{},
			},
			upgradePath:     []any{false},
			ecosystem:       "npm",
			expectedMessage: "No remediation advice available",
			description:     "Should return no remediation message when no fix available",
		},
		{
			name:           "Has upgrade message when fix is available",
			dependencyPath: []string{"root@1.0.0", "test-package@1.0.0"},
			finding:        createFindingWithoutUpgradePath(t),
			vuln: &testapi.SnykVulnProblem{
				PackageName:              "test-package",
				PackageVersion:           "1.0.0",
				InitiallyFixedInVersions: []string{"1.0.1"},
			},
			upgradePath:     []any{false, "test-package@1.0.1"},
			ecosystem:       "npm",
			expectedMessage: "Upgrade to test-package@1.0.1",
			description:     "Should return upgrade message when fix is available",
		},
		{
			name:           "Outdated dependency message when upgrade path equals dependency path - npm",
			dependencyPath: []string{"root@1.0.0", "test-package@1.0.0"},
			finding:        createFindingWithoutUpgradePath(t),
			vuln: &testapi.SnykVulnProblem{
				PackageName:              "test-package",
				PackageVersion:           "1.0.0",
				InitiallyFixedInVersions: []string{"1.0.1"},
			},
			upgradePath:     []any{false, "test-package@1.0.0"}, // Same as dependencyPath[1]
			ecosystem:       "npm",
			expectedMessage: "Your dependencies are out of date, otherwise you would be using a newer test-package than test-package@1.0.0. Try relocking your lockfile or deleting node_modules and reinstalling your dependencies. If the problem persists, one of your dependencies may be bundling outdated modules.",
			description:     "Should return npm-specific outdated dependency message",
		},
		{
			name:           "Outdated dependency message - yarn ecosystem",
			dependencyPath: []string{"root@1.0.0", "test-package@1.0.0"},
			finding:        createFindingWithoutUpgradePath(t),
			vuln: &testapi.SnykVulnProblem{
				PackageName:              "test-package",
				PackageVersion:           "1.0.0",
				InitiallyFixedInVersions: []string{"1.0.1"},
			},
			upgradePath:     []any{false, "test-package@1.0.0"},
			ecosystem:       "yarn",
			expectedMessage: "Your dependencies are out of date, otherwise you would be using a newer test-package than test-package@1.0.0. Try relocking your lockfile or deleting node_modules and reinstalling your dependencies. If the problem persists, one of your dependencies may be bundling outdated modules.",
			description:     "Should return yarn-specific outdated dependency message (same as npm)",
		},
		{
			name:           "Outdated dependency message - maven ecosystem",
			dependencyPath: []string{"root@1.0.0", "test-package@1.0.0"},
			finding:        createFindingWithoutUpgradePath(t),
			vuln: &testapi.SnykVulnProblem{
				PackageName:              "test-package",
				PackageVersion:           "1.0.0",
				InitiallyFixedInVersions: []string{"1.0.1"},
			},
			upgradePath:     []any{false, "test-package@1.0.0"},
			ecosystem:       "maven",
			expectedMessage: "Your dependencies are out of date, otherwise you would be using a newer test-package than test-package@1.0.0. Try reinstalling your dependencies. If the problem persists, one of your dependencies may be bundling outdated modules.",
			description:     "Should return maven-specific outdated dependency message (different from npm)",
		},
		{
			name:           "Outdated dependency message - pip ecosystem",
			dependencyPath: []string{"root@1.0.0", "test-package@1.0.0"},
			finding:        createFindingWithoutUpgradePath(t),
			vuln: &testapi.SnykVulnProblem{
				PackageName:              "test-package",
				PackageVersion:           "1.0.0",
				InitiallyFixedInVersions: []string{"1.0.1"},
			},
			upgradePath:     []any{false, "test-package@1.0.0"},
			ecosystem:       "pip",
			expectedMessage: "Your dependencies are out of date, otherwise you would be using a newer test-package than test-package@1.0.0. Try reinstalling your dependencies. If the problem persists, one of your dependencies may be bundling outdated modules.",
			description:     "Should return pip-specific outdated dependency message (different from npm)",
		},
		{
			name:           "Edge case: upgradable but no upgrade path built",
			dependencyPath: []string{"root@1.0.0", "test-package@1.0.0"},
			finding:        createFindingWithoutUpgradePath(t),
			vuln: &testapi.SnykVulnProblem{
				PackageName:              "test-package",
				PackageVersion:           "1.0.0",
				InitiallyFixedInVersions: []string{"1.0.1"}, // Has fixed versions
			},
			upgradePath:     []any{false}, // But upgrade path is empty (only [false])
			ecosystem:       "npm",
			expectedMessage: "", // Current behavior: returns empty when isUpgradable but no upgrade path (rare edge case per prod code)
			description:     "Should return empty string when isUpgradable=true but upgradePath is empty (rare scenario where path construction fails)",
		},
		{
			name:           "Edge case: upgrade path for different package than vulnerable one",
			dependencyPath: []string{"root@1.0.0", "test-package@1.0.0"},
			finding:        createFindingWithFixRelationship(t, "other-pkg", []string{"root@1.0.0", "other-pkg@2.0.0"}),
			vuln: &testapi.SnykVulnProblem{
				PackageName:              "test-package",
				PackageVersion:           "1.0.0",
				InitiallyFixedInVersions: []string{"1.0.1"},
			},
			upgradePath:     []any{false, "other-pkg@2.0.0"}, // Upgrade path is for wrong package (unexpected/malformed)
			ecosystem:       "npm",
			expectedMessage: "Upgrade to other-pkg@2.0.0", // Should still return the upgrade message even if mismatch
			description:     "Should return upgrade message even when upgrade path mismatches vulnerable package (malformed data tolerance)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildRemediationAdvice(tt.finding, tt.vuln, tt.ecosystem, tt.dependencyPath, tt.upgradePath)

			assert.Equal(t, tt.expectedMessage, result)
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
		skipTestReason string
	}{
		{
			name:     "Extract path from finding with dependency evidence",
			finding:  createFindingWithDependencyPath(t, "goof@1.0.0", []string{"lodash@4.17.20"}),
			expected: []string{"goof@1.0.0", "lodash@4.17.20"},
		},
		{
			name:     "Empty path for finding without evidence",
			finding:  &testapi.FindingData{Attributes: &testapi.FindingAttributes{}},
			expected: []string{},
		},
		{
			name:     "Empty path for nil attributes",
			finding:  &testapi.FindingData{},
			expected: nil,
		},
		{
			name:     "Defensive: non-dependency_path evidence - returns empty slice",
			finding:  createFindingWithNonDependencyPathEvidence(t),
			expected: []string{},
		},
		{
			name:           "TODO: multiple dependency paths - should return all paths",
			finding:        createFindingWithMultipleDependencyPaths(t, "goof@1.0.0", []string{"lodash@4.17.20"}, []string{"other-pkg@1.0.0"}),
			expected:       []string{"goof@1.0.0", "lodash@4.17.20", "goof@1.0.0", "other-pkg@1.0.0"},
			skipTestReason: "Prod code needs to be updated to return all dependency paths, not just the first one (FIXME in prod code first)",
		},
		{
			name: "Wrong behavior: multiple dependency paths - returns first one only (FIXME in prod code)",
			// TODO: Delete this test and enable the test above when the fix has been implemented in the prod code.
			finding:  createFindingWithMultipleDependencyPaths(t, "goof@1.0.0", []string{"lodash@4.17.20"}, []string{"other-pkg@1.0.0"}),
			expected: []string{"goof@1.0.0", "lodash@4.17.20"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipTestReason != "" {
				t.Skip(tt.skipTestReason)
			}
			result := extractDependencyPath(tt.finding)
			assert.Equal(t, tt.expected, result)
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
	}{
		{
			name:        "Short message",
			title:       "Prototype Pollution",
			packageName: "lodash",
			remediation: "Upgrade to lodash@4.17.21",
			expected:    "Prototype Pollution affecting package lodash. Upgrade to lodash@4.17.21",
		},
		{
			name:        "No remediation available",
			title:       "ReDoS",
			packageName: "regex-pkg",
			remediation: "No remediation advice available",
			expected:    "ReDoS affecting package regex-pkg. No remediation advice available",
		},
		{
			name:        "Empty title",
			title:       "",
			packageName: "test-pkg",
			remediation: "Upgrade to test-pkg@2.0.0",
			expected:    " affecting package test-pkg. Upgrade to test-pkg@2.0.0",
		},
		{
			name:        "Empty package name",
			title:       "Vulnerability",
			packageName: "",
			remediation: "No fix available",
			expected:    "Vulnerability affecting package . No fix available",
		},
		{
			name:        "Empty remediation",
			title:       "Security Issue",
			packageName: "vulnerable-pkg",
			remediation: "",
			expected:    "Security Issue affecting package vulnerable-pkg. ",
		},
		{
			name:        "Special characters in title",
			title:       "XSS <script>alert('test')</script>",
			packageName: "web-pkg",
			remediation: "Update required",
			expected:    "XSS <script>alert('test')</script> affecting package web-pkg. Update required",
		},
		{
			name:        "Special characters in package name",
			title:       "Vulnerability",
			packageName: "@scope/package-name",
			remediation: "Upgrade to @scope/package-name@2.0.0",
			expected:    "Vulnerability affecting package @scope/package-name. Upgrade to @scope/package-name@2.0.0",
		},
		{
			name:        "Long remediation message gets truncated",
			title:       "Vuln",
			packageName: "pkg",
			remediation: strings.Repeat("A", 300), // 300 chars
			expected:    "Vuln affecting package pkg. " + strings.Repeat("A", 172) + "... (Snyk)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildMessage(tt.title, tt.packageName, tt.remediation)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test_buildMessage_TruncatesLongMessages verifies that long messages are properly truncated
func Test_buildMessage_TruncatesLongMessages(t *testing.T) {
	testutil.UnitTest(t)

	// Message format: "{title} affecting package {pkg}. {remediation}"
	// Truncation happens when message length > 200
	// Need title long enough that total message exceeds 200 chars
	longTitle := strings.Repeat("A", 200)
	packageName := "package-name"
	remediation := "remediation advice"

	result := buildMessage(longTitle, packageName, remediation)

	// Expected: first 200 chars of full message + "... (Snyk)"
	fullMessage := longTitle + " affecting package " + packageName + ". " + remediation
	expectedTruncated := fullMessage[:200] + "... (Snyk)"

	assert.Equal(t, expectedTruncated, result, "Truncated message should match expected format")
	assert.Equal(t, 210, len(result), "Truncated message should be exactly 210 chars (200 + '... (Snyk)')")
}

// Test_getIntroducingFinding tests finding the dependency that introduces a vulnerability
func Test_getIntroducingFinding(t *testing.T) {
	testutil.UnitTest(t)

	tests := []struct {
		name           string
		findings       []*testapi.FindingData
		problemPkgName string
		expectedIndex  int
		expectError    bool
	}{
		{
			name: "Direct dependency introduces vulnerability",
			findings: []*testapi.FindingData{
				createFindingWithDependencyPath(t, "goof@1.0.0", []string{"lodash@4.17.4"}),
			},
			problemPkgName: "lodash",
			expectedIndex:  0,
			expectError:    false,
		},
		{
			name: "Multiple findings - first direct dependency wins",
			findings: []*testapi.FindingData{
				createFindingWithDependencyPath(t, "goof@1.0.0", []string{"other-pkg@1.0.0", "lodash@4.17.4"}), // indirect
				createFindingWithDependencyPath(t, "goof@1.0.0", []string{"lodash@4.17.4"}),                    // direct - should win
			},
			problemPkgName: "lodash",
			expectedIndex:  1,
			expectError:    false,
		},
		{
			name: "No direct dependency - returns first finding",
			findings: []*testapi.FindingData{
				createFindingWithDependencyPath(t, "goof@1.0.0", []string{"other-pkg@1.0.0", "lodash@4.17.4"}),
				createFindingWithDependencyPath(t, "goof@1.0.0", []string{"another-pkg@1.0.0", "lodash@4.17.4"}),
			},
			problemPkgName: "lodash",
			expectedIndex:  0,
			expectError:    false,
		},
		{
			name: "Malformed data: dependency path with only root - returns first finding gracefully",
			findings: []*testapi.FindingData{
				createFindingWithDependencyPath(t, "goof@1.0.0", []string{}), // Only root, no actual dependency (malformed)
			},
			problemPkgName: "lodash",
			expectedIndex:  0,
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create issue with findings
			problem := &testapi.SnykVulnProblem{
				PackageName: tt.problemPkgName,
			}

			issue := createMockIssueWithFindings(t, tt.findings)
			result, err := getIntroducingFinding(issue, problem)

			if tt.expectError {
				require.Error(t, err)
				require.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				// Verify we got the expected finding
				assert.Equal(t, tt.findings[tt.expectedIndex], result)
			}
		})
	}
}

// Test_getIntroducingFinding_NoFindings tests error handling when there are no findings
func Test_getIntroducingFinding_NoFindings(t *testing.T) {
	testutil.UnitTest(t)

	// Note: testapi.NewIssueFromFindings returns an error if the findings slice is empty,
	// so we can't test the "len(findings) == 0" error path in getIntroducingFinding.
	// That check is defensive but unreachable since GAF prevents empty findings.

	// This test documents that the function works with minimal findings (one finding with empty evidence)
	problem := &testapi.SnykVulnProblem{
		PackageName: "test-package",
	}

	// Create a finding without any dependency path (edge case)
	finding := &testapi.FindingData{
		Attributes: &testapi.FindingAttributes{
			Evidence: []testapi.Evidence{},
		},
	}

	issue, err := testapi.NewIssueFromFindings([]*testapi.FindingData{finding})
	require.NoError(t, err, "Should be able to create issue with one finding")

	// This should still work - it will return the first finding even if path is empty
	result, err := getIntroducingFinding(issue, problem)
	require.NoError(t, err)
	require.NotNil(t, result)
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
			name:           "No fix relationships",
			dependencyPath: []string{"goof@1.0.0", "lodash@4.17.4"},
			finding: &testapi.FindingData{
				Relationships: nil,
			},
			expected:    nil,
			description: "Should return nil when no fix relationships exist",
		},
		{
			name:           "Defensive: nil Action attribute - handles gracefully",
			dependencyPath: []string{"goof@1.0.0", "lodash@4.17.4"},
			finding:        createFindingWithNilAction(t),
			expected:       nil,
			description:    "Should return nil when Fix.Data.Attributes.Action is nil",
		},
		{
			name:           "Fix relationship with upgrade path",
			dependencyPath: []string{"goof@1.0.0", "lodash@4.17.4"},
			finding:        createFindingWithFixRelationship(t, "lodash", []string{"goof@1.0.0", "lodash@4.17.21"}),
			expected:       []string{"goof@1.0.0", "lodash@4.17.21"},
			description:    "Should extract upgrade path from fix relationships",
		},
		{
			name:           "Multiple upgrade paths - returns matching package",
			dependencyPath: []string{"goof@1.0.0", "lodash@4.17.4"},
			finding:        createFindingWithMultipleUpgradePaths(t, "lodash", []string{"goof@1.0.0", "lodash@4.17.21"}, []string{"goof@1.0.0", "other-pkg@2.0.0"}),
			expected:       []string{"goof@1.0.0", "lodash@4.17.21"},
			description:    "Should return the upgrade path matching the dependency package name",
		},
		{
			name:           "Empty dependency path",
			dependencyPath: []string{},
			finding:        createFindingWithFixRelationship(t, "lodash", []string{"goof@1.0.0", "lodash@4.17.21"}),
			expected:       nil,
			description:    "Should return nil when dependency path is empty",
		},
		{
			name:           "Wrong package name in upgrade path",
			dependencyPath: []string{"goof@1.0.0", "lodash@4.17.4"},
			finding:        createFindingWithFixRelationship(t, "other-pkg", []string{"goof@1.0.0", "other-pkg@2.0.0"}),
			expected:       []string{},
			description:    "Should return empty when upgrade path doesn't match dependency package",
		},
		{
			name:           "Malformed data: single element dependency path - handles gracefully",
			dependencyPath: []string{"root@1.0.0"},
			finding:        createFindingWithFixRelationship(t, "lodash", []string{"goof@1.0.0", "lodash@4.17.21"}),
			expected:       nil,
			description:    "Should return nil when dependency path has only root (length 1, malformed) to avoid panic",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractUpgradePackage(tt.dependencyPath, tt.finding)
			assert.Equal(t, tt.expected, result, tt.description)
		})
	}
}

// Test_processIssue_WithUpgradePath_HasCodeActions verifies that issues with an upgrade path
// have quick-fix code actions generated
func Test_processIssue_WithUpgradePath_HasCodeActions(t *testing.T) {
	c, ctx := testutil.UnitTestWithCtx(t)

	// Enable OSS quick-fix code actions for this test
	c.SetSnykOSSQuickFixCodeActionsEnabled(true)

	workDir, err := filepath.Abs("testdata")
	require.NoError(t, err)

	filePath := filepath.Join(workDir, "package.json")
	ctx = ctx2.NewContextWithWorkDirAndFilePath(ctx, types.FilePath(workDir), types.FilePath(filePath))

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	learnService := mock_learn.NewMockService(ctrl)
	errorReporter := error_reporting.NewTestErrorReporter()

	// Expect GetLesson to be called for the vulnerability
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

	// Create a finding with an upgrade path matching real package.json
	finding := createCompleteUnifiedFinding(
		t,
		"npm",
		"goof@1.0.1",
		[]string{"lodash@4.17.4"}, // matches testdata/package.json
		[]string{"4.17.21"},       // fixed version available
		"lodash",
		"4.17.4", // matches testdata/package.json
		"Prototype Pollution",
	)

	// Convert to Issue using GAF's helper
	trIssue, err := testapi.NewIssueFromFindings([]*testapi.FindingData{&finding})
	require.NoError(t, err)

	logger := zerolog.Nop()

	// Process the issue through the unified converter
	result := processIssue(
		ctx,
		trIssue,
		logger,
		types.FilePath(filePath),
		types.FilePath(workDir),
	)

	require.NotNil(t, result, "processIssue should return an issue")
	assert.Equal(t, "lodash-id", result.ID, "Issue ID should match the problem ID")
	assert.Equal(t, types.High, result.Severity, "Severity should be High")

	// Verify basic issue properties
	assert.Contains(t, result.Message, "lodash", "Message should mention the affected package")

	// Verify upgrade path is available in additional data (prerequisite for code actions)
	additionalData, ok := result.AdditionalData.(snyk.OssIssueData)
	require.True(t, ok, "AdditionalData should be OssIssueData")
	assert.NotEmpty(t, additionalData.UpgradePath, "Should have an upgrade path")
	assert.True(t, additionalData.IsUpgradable, "Should be marked as upgradable")

	// Verify code actions are generated
	codeActions := result.GetCodeActions()
	assert.NotEmpty(t, codeActions, "Code actions should be generated with fix relationships")

	// Check for quick-fix action
	var hasQuickFix bool
	for _, action := range codeActions {
		title := action.GetTitle()
		if strings.Contains(title, "Upgrade to") && strings.Contains(title, "⚡️") {
			hasQuickFix = true
			assert.Contains(t, title, "lodash", "Quick-fix title should mention the package")
			assert.Contains(t, title, "4.17.21", "Quick-fix title should mention the target version")
			break
		}
	}
	assert.True(t, hasQuickFix, "Should have a quick-fix upgrade code action")
}

// Test_processIssue_FeatureFlagDisabled verifies that code actions are not generated when feature flag is disabled
func Test_processIssue_FeatureFlagDisabled(t *testing.T) {
	c, ctx := testutil.UnitTestWithCtx(t)

	// Explicitly disable OSS quick-fix code actions for this test
	c.SetSnykOSSQuickFixCodeActionsEnabled(false)

	workDir, err := filepath.Abs("testdata")
	require.NoError(t, err)

	filePath := filepath.Join(workDir, "package.json")
	ctx = ctx2.NewContextWithWorkDirAndFilePath(ctx, types.FilePath(workDir), types.FilePath(filePath))

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	learnService := mock_learn.NewMockService(ctrl)
	errorReporter := error_reporting.NewTestErrorReporter()

	learnService.EXPECT().
		GetLesson(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), types.DependencyVulnerability).
		Return(nil, nil).
		AnyTimes()

	// All dependencies are properly set up
	deps := map[string]any{
		ctx2.DepConfig:        c,
		ctx2.DepLearnService:  learnService,
		ctx2.DepErrorReporter: errorReporter,
	}
	ctx = ctx2.NewContextWithDependencies(ctx, deps)

	// Create a finding with an upgrade path
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

	require.NotNil(t, result, "processIssue should return an issue")
	assert.Equal(t, "lodash-id", result.ID)
	assert.Equal(t, types.High, result.Severity)

	// Verify the issue has upgrade path data
	additionalData, ok := result.AdditionalData.(snyk.OssIssueData)
	require.True(t, ok)
	assert.NotEmpty(t, additionalData.UpgradePath, "Should have an upgrade path")
	assert.True(t, additionalData.IsUpgradable, "Should be marked as upgradable")

	// Verify code actions and codelenses are NOT generated when feature flag is disabled
	assert.Empty(t, result.GetCodeActions(), "Code actions should not be generated when feature flag is disabled")
	assert.Empty(t, result.GetCodelensCommands(), "Codelens commands should not be generated when feature flag is disabled")
}

// Test_processIssue_WithUpgradePath_HasCodeLens verifies that issues with upgrade code actions
// also have corresponding code lens commands
func Test_processIssue_WithUpgradePath_HasCodeLens(t *testing.T) {
	c, ctx := testutil.UnitTestWithCtx(t)

	// Enable OSS quick-fix code actions for this test
	c.SetSnykOSSQuickFixCodeActionsEnabled(true)

	workDir, err := filepath.Abs("testdata")
	require.NoError(t, err)

	filePath := filepath.Join(workDir, "package.json")
	ctx = ctx2.NewContextWithWorkDirAndFilePath(ctx, types.FilePath(workDir), types.FilePath(filePath))

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

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

	// Create a finding with an upgrade path matching real package.json
	finding := createCompleteUnifiedFinding(
		t,
		"npm",
		"goof@1.0.1",
		[]string{"lodash@4.17.4"}, // matches testdata/package.json
		[]string{"4.17.21"},
		"lodash",
		"4.17.4", // matches testdata/package.json
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

	require.NotNil(t, result, "processIssue should return an issue")

	// Verify the issue has the expected additional data
	additionalData, ok := result.AdditionalData.(snyk.OssIssueData)
	require.True(t, ok, "AdditionalData should be OssIssueData")
	assert.Equal(t, "lodash", additionalData.PackageName)
	assert.Equal(t, "4.17.4", additionalData.Version)

	// Verify there's a remediation path available
	assert.NotEmpty(t, additionalData.UpgradePath, "Should have an upgrade path")
	assert.True(t, additionalData.IsUpgradable, "Should be marked as upgradable")

	// Verify codelens commands are generated
	codelensCommands := result.GetCodelensCommands()
	assert.NotEmpty(t, codelensCommands, "Codelens commands should be generated with fix relationships")

	// Check that codelens command is derived from upgrade action
	var hasUpgradeCodeLens bool
	for _, cmd := range codelensCommands {
		if strings.Contains(cmd.Title, "Upgrade to") && strings.Contains(cmd.Title, "⚡️") {
			hasUpgradeCodeLens = true
			assert.Contains(t, cmd.Title, "lodash", "Codelens title should mention the package")
			assert.Contains(t, cmd.Title, "4.17.21", "Codelens title should mention the target version")
			assert.Equal(t, types.CodeFixCommand, cmd.CommandId, "Should use CodeFixCommand")
			break
		}
	}
	assert.True(t, hasUpgradeCodeLens, "Should have an upgrade codelens command")
}

// Test_processIssue_WrongTypeInContextDeps verifies behavior when context deps have wrong types
func Test_processIssue_WrongTypeInContextDeps(t *testing.T) {
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

	// Issue should still be created even with wrong types in dependencies
	require.NotNil(t, result, "processIssue should return an issue even with wrong type dependencies")
	assert.Equal(t, "lodash-id", result.ID)
	assert.Equal(t, types.High, result.Severity)

	// Verify code actions are NOT generated when dependencies have wrong types
	assert.Empty(t, result.GetCodeActions(), "Code actions should not be generated with wrong type dependencies")
	assert.Empty(t, result.GetCodelensCommands(), "Codelens commands should not be generated with wrong type dependencies")

	// But the issue should still have all the core data
	additionalData, ok := result.AdditionalData.(snyk.OssIssueData)
	require.True(t, ok)
	assert.Equal(t, "lodash", additionalData.PackageName)
	assert.NotEmpty(t, additionalData.UpgradePath, "Upgrade path should still be built")
}

// Test_processIssue_MissingContextDeps verifies that processIssue handles missing context dependencies gracefully
func Test_processIssue_MissingContextDeps(t *testing.T) {
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

	// Issue should still be created even without context dependencies
	require.NotNil(t, result, "processIssue should return an issue even without context dependencies")
	assert.Equal(t, "lodash-id", result.ID)
	assert.Equal(t, types.High, result.Severity)

	// Verify code actions are NOT generated when dependencies are missing
	assert.Empty(t, result.GetCodeActions(), "Code actions should not be generated without context dependencies")
	assert.Empty(t, result.GetCodelensCommands(), "Codelens commands should not be generated without context dependencies")

	// But the issue should still have all the core data
	additionalData, ok := result.AdditionalData.(snyk.OssIssueData)
	require.True(t, ok)
	assert.Equal(t, "lodash", additionalData.PackageName)
	assert.NotEmpty(t, additionalData.UpgradePath, "Upgrade path should still be built")
}

// Test_processIssue_NilDependencyNode verifies behavior when dependency node can't be found
func Test_processIssue_NilDependencyNode(t *testing.T) {
	c, ctx := testutil.UnitTestWithCtx(t)

	// Use a non-existent file path so getDependencyNode returns nil
	workDir, err := filepath.Abs("testdata")
	require.NoError(t, err)

	// Use a file path that doesn't exist or has no matching dependency
	filePath := filepath.Join(workDir, "nonexistent.json")
	ctx = ctx2.NewContextWithWorkDirAndFilePath(ctx, types.FilePath(workDir), types.FilePath(filePath))

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

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

	logger := zerolog.Nop()

	result := processIssue(
		ctx,
		trIssue,
		logger,
		types.FilePath(filePath),
		types.FilePath(workDir),
	)

	require.NotNil(t, result, "processIssue should return an issue even with nil dependency node")

	// Verify issue was created with basic data
	assert.Equal(t, "vulnerable-pkg-id", result.ID)
	assert.Equal(t, types.High, result.Severity)

	// Verify range is empty when node is nil
	assert.Equal(t, types.Range{}, result.Range, "Range should be empty when dependency node is nil")

	// Verify code actions and codelenses are NOT generated when node is nil
	// The production code skips adding actions when issueDepNode is empty
	assert.Empty(t, result.GetCodeActions(), "Code actions should not be generated when dependency node is nil")
	assert.Empty(t, result.GetCodelensCommands(), "Codelens commands should not be generated when dependency node is nil")

	// But the issue should still have all the core vulnerability data
	additionalData, ok := result.AdditionalData.(snyk.OssIssueData)
	require.True(t, ok)
	assert.Equal(t, "vulnerable-pkg", additionalData.PackageName)
	assert.NotEmpty(t, additionalData.UpgradePath, "Upgrade path should still be built")
}

// Test_processIssue_SingleVulnerability verifies basic issue conversion
func Test_processIssue_SingleVulnerability(t *testing.T) {
	c, ctx := testutil.UnitTestWithCtx(t)
	workDir, err := filepath.Abs("testdata")
	require.NoError(t, err)

	filePath := filepath.Join(workDir, "package.json")
	ctx = ctx2.NewContextWithWorkDirAndFilePath(ctx, types.FilePath(workDir), types.FilePath(filePath))

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

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

	finding := createCompleteUnifiedFinding(
		t,
		"npm",
		"my-app@1.0.0",
		[]string{"vulnerable-pkg@1.0.0"},
		[]string{}, // no fix available
		"vulnerable-pkg",
		"1.0.0",
		"Security Vulnerability",
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

	require.NotNil(t, result, "processIssue should return an issue")
	assert.Equal(t, "vulnerable-pkg-id", result.ID)
	assert.Equal(t, types.High, result.Severity)
	assert.Contains(t, result.Message, "vulnerable-pkg")
	assert.Contains(t, result.Message, "Security Vulnerability")

	additionalData, ok := result.AdditionalData.(snyk.OssIssueData)
	require.True(t, ok)
	assert.Equal(t, "vulnerable-pkg", additionalData.PackageName)
	assert.Equal(t, "1.0.0", additionalData.Version)
	assert.Equal(t, "No remediation advice available", additionalData.Remediation, "Remediation field should indicate no fix available")
}

// Test_processIssue_NoFixRelationships_DepsCorrect verifies that quick-fix actions are not generated
// when there are no fix relationships, even when deps are correct and feature flag is enabled
func Test_processIssue_NoFixRelationships_DepsCorrect(t *testing.T) {
	c, ctx := testutil.UnitTestWithCtx(t)

	// Enable OSS quick-fix code actions
	c.SetSnykOSSQuickFixCodeActionsEnabled(true)

	workDir, err := filepath.Abs("testdata")
	require.NoError(t, err)

	filePath := filepath.Join(workDir, "package.json")
	ctx = ctx2.NewContextWithWorkDirAndFilePath(ctx, types.FilePath(workDir), types.FilePath(filePath))

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	learnService := mock_learn.NewMockService(ctrl)
	errorReporter := error_reporting.NewTestErrorReporter()

	learnService.EXPECT().
		GetLesson(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), types.DependencyVulnerability).
		Return(nil, nil).
		AnyTimes()

	// All dependencies are properly set up
	deps := map[string]any{
		ctx2.DepConfig:        c,
		ctx2.DepLearnService:  learnService,
		ctx2.DepErrorReporter: errorReporter,
	}
	ctx = ctx2.NewContextWithDependencies(ctx, deps)

	// Create a finding WITHOUT fix relationships (no fixedIn versions)
	finding := createCompleteUnifiedFinding(
		t,
		"npm",
		"my-app@1.0.0",
		[]string{"vulnerable-pkg@1.0.0"},
		[]string{}, // no fix available - no fix relationships will be created
		"vulnerable-pkg",
		"1.0.0",
		"Security Vulnerability",
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

	require.NotNil(t, result, "processIssue should return an issue")
	assert.Equal(t, "vulnerable-pkg-id", result.ID)
	assert.Equal(t, types.High, result.Severity)

	// Verify the issue has NO upgrade path (only [false])
	additionalData, ok := result.AdditionalData.(snyk.OssIssueData)
	require.True(t, ok)
	assert.Equal(t, []any{false}, additionalData.UpgradePath, "Should have empty upgrade path [false]")
	// Note: IsUpgradable is based on len(upgradePath) > 0, so [false] makes it true
	// This is a quirk of the current implementation - might want to change to len(upgradePath) > 1
	assert.True(t, additionalData.IsUpgradable, "Current behavior: marked as upgradable when upgradePath=[false]")

	// Verify quick-fix code actions are NOT generated when no fix relationships exist
	// (Snyk Learn actions might still be present, but no quick-fix)
	codeActions := result.GetCodeActions()
	for _, action := range codeActions {
		title := action.GetTitle()
		assert.NotContains(t, title, "Upgrade to", "Should not have upgrade quick-fix action")
		assert.NotContains(t, title, "⚡️", "Should not have quick-fix lightning bolt emoji")
	}

	// Verify no upgrade codelens command
	codelensCommands := result.GetCodelensCommands()
	for _, cmd := range codelensCommands {
		assert.NotContains(t, cmd.Title, "Upgrade to", "Should not have upgrade codelens")
		assert.NotContains(t, cmd.Title, "⚡️", "Should not have quick-fix lightning bolt emoji in codelens")
	}
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

	// Add package location evidence (not dependency_path)
	var pkgLoc testapi.FindingLocation
	err := pkgLoc.FromPackageLocation(testapi.PackageLocation{
		Package: testapi.Package{Name: "test-pkg", Version: "1.0.0"},
	})
	require.NoError(t, err)
	finding.Attributes.Locations = append(finding.Attributes.Locations, pkgLoc)

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
func createFindingWithMultipleDependencyPaths(t *testing.T, root string, path1 []string, path2 []string) *testapi.FindingData {
	t.Helper()
	finding := &testapi.FindingData{
		Attributes: &testapi.FindingAttributes{
			Evidence: []testapi.Evidence{},
		},
	}

	// Build first dependency path evidence
	dependencyPkgs1 := make([]testapi.Package, len(path1)+1)
	rootParts := strings.Split(root, "@")
	dependencyPkgs1[0] = testapi.Package{Name: rootParts[0], Version: rootParts[1]}
	for i, pkgStr := range path1 {
		parts := strings.Split(pkgStr, "@")
		dependencyPkgs1[i+1] = testapi.Package{Name: parts[0], Version: parts[1]}
	}
	var depEv1 testapi.Evidence
	err := depEv1.FromDependencyPathEvidence(testapi.DependencyPathEvidence{Path: dependencyPkgs1})
	require.NoError(t, err)
	finding.Attributes.Evidence = append(finding.Attributes.Evidence, depEv1)

	// Build second dependency path evidence
	dependencyPkgs2 := make([]testapi.Package, len(path2)+1)
	dependencyPkgs2[0] = testapi.Package{Name: rootParts[0], Version: rootParts[1]}
	for i, pkgStr := range path2 {
		parts := strings.Split(pkgStr, "@")
		dependencyPkgs2[i+1] = testapi.Package{Name: parts[0], Version: parts[1]}
	}
	var depEv2 testapi.Evidence
	err = depEv2.FromDependencyPathEvidence(testapi.DependencyPathEvidence{Path: dependencyPkgs2})
	require.NoError(t, err)
	finding.Attributes.Evidence = append(finding.Attributes.Evidence, depEv2)

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

// createFindingWithFixRelationship creates a FindingData with fix relationships
func createFindingWithFixRelationship(t *testing.T, packageName string, upgradePath []string) *testapi.FindingData {
	t.Helper()
	finding := createBaseFindingWithRelationshipsStruct(t)

	// Build upgrade path packages
	packages := make([]testapi.Package, len(upgradePath))
	for i, pkgStr := range upgradePath {
		parts := strings.Split(pkgStr, "@")
		packages[i] = testapi.Package{Name: parts[0], Version: parts[1]}
	}

	// Create fix action
	var fixAction testapi.FixAction
	upgradeAdvice := testapi.UpgradePackageAdvice{
		Format:      testapi.UpgradePackageAdviceFormatUpgradePackageAdvice,
		PackageName: packageName,
		UpgradePaths: []testapi.UpgradePath{
			{
				DependencyPath: packages,
				IsDrop:         false,
			},
		},
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

// createFindingWithMultipleUpgradePaths creates a FindingData with multiple upgrade paths in fix relationships
func createFindingWithMultipleUpgradePaths(t *testing.T, packageName string, path1 []string, path2 []string) *testapi.FindingData {
	t.Helper()
	finding := createBaseFindingWithRelationshipsStruct(t)

	// Convert path1 to packages
	packages1 := make([]testapi.Package, len(path1))
	for i, pkgStr := range path1 {
		parts := strings.Split(pkgStr, "@")
		packages1[i] = testapi.Package{Name: parts[0], Version: parts[1]}
	}

	// Convert path2 to packages
	packages2 := make([]testapi.Package, len(path2))
	for i, pkgStr := range path2 {
		parts := strings.Split(pkgStr, "@")
		packages2[i] = testapi.Package{Name: parts[0], Version: parts[1]}
	}

	// Create fix action with multiple paths
	var fixAction testapi.FixAction
	upgradeAdvice := testapi.UpgradePackageAdvice{
		Format:      testapi.UpgradePackageAdviceFormatUpgradePackageAdvice,
		PackageName: packageName,
		UpgradePaths: []testapi.UpgradePath{
			{
				DependencyPath: packages1,
				IsDrop:         false,
			},
			{
				DependencyPath: packages2,
				IsDrop:         false,
			},
		},
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
