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
	"github.com/snyk/go-application-framework/pkg/apiclients/mocks"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_convertFindingDataToIssues_EmptyFindings(t *testing.T) {
	_, ctx := testutil.UnitTestWithCtx(t)
	workDir, err := filepath.Abs("testdata")
	require.NoError(t, err)

	path := filepath.Join(workDir, "package.json")
	ctx = ctx2.NewContextWithWorkDirAndFilePath(ctx, types.FilePath(workDir), types.FilePath(path))
	packageIssueCache := make(map[string][]types.Issue)

	mockResult := createMockResult(t, path)
	mockResult.EXPECT().Findings(gomock.Any()).Return(nil, true, nil).AnyTimes()

	// Act
	issues, err := convertTestResultToIssues(
		ctx,
		mockResult,
		packageIssueCache,
	)

	// require
	require.NoError(t, err)
	require.NotNil(t, issues)
	require.Empty(t, issues)
}

func Test_convertFindingDataToIssues_SingleVulnerability(t *testing.T) {
	_, ctx := testutil.UnitTestWithCtx(t)
	// Arrange
	workDir, err := filepath.Abs("testdata")
	require.NoError(t, err)
	path := filepath.Join(workDir, "package.json")
	ctx = ctx2.NewContextWithWorkDirAndFilePath(ctx, types.FilePath(workDir), types.FilePath(path))
	packageIssueCache := make(map[string][]types.Issue)

	// Create a test finding
	finding := createTestFinding()
	findings := []testapi.FindingData{finding}

	mockResult := createMockResult(t, path)
	mockResult.EXPECT().Findings(ctx).Return(findings, true, nil).AnyTimes()

	// Act
	issues, err := convertTestResultToIssues(
		ctx,
		mockResult,
		packageIssueCache,
	)

	// require
	require.NoError(t, err)
	require.NotNil(t, issues)
	require.Len(t, issues, 1)

	issue := issues[0]
	require.NotEmpty(t, issue.GetID())
	require.NotEmpty(t, issue.GetMessage())
	require.NotNil(t, issue.GetAdditionalData())
}

func createMockResult(t *testing.T, path string) *mocks.MockTestResult {
	t.Helper()
	ctrl := gomock.NewController(t)
	mockResult := mocks.NewMockTestResult(ctrl)

	subject := testapi.DepGraphSubject{Type: testapi.DepGraphSubjectTypeDepGraph, Locator: testapi.LocalPathLocator{
		Paths: []string{path},
		Type:  testapi.LocalPath,
	}}

	testSubject := testapi.TestSubject{}
	err := testSubject.FromDepGraphSubject(subject)
	require.NoError(t, err)

	mockResult.EXPECT().GetTestSubject().Return(testSubject).AnyTimes()
	return mockResult
}

// New tests to validate that unified issues produce upgrade-related quick-fix actions and code lenses.
// NOTE: These tests currently express the desired behavior and may fail until the unified
// conversion flow adds OSS quick-fix code actions and corresponding codelens commands.

func Test_UnifiedIssue_HasUpgradeQuickFixAction(t *testing.T) {
	// Arrange: create a unified finding with an upgrade path suggesting a newer version
	finding := createCompleteUnifiedFinding(
		"npm",
		"goof@1.0.0",
		[]string{"lodash@4.17.20"}, // dependency path ending with vulnerable package current version
		[]string{"4.17.21"},        // fixed version available
		"lodash",
		"4.17.20",
		"Prototype Pollution",
	)

	// convert to Problems map and then to issues
	c, ctx := testutil.UnitTestWithCtx(t)
	workDir, err := filepath.Abs("testdata")
	require.NoError(t, err)
	path := filepath.Join(workDir, "package.json")
	ctx = ctx2.NewContextWithWorkDirAndFilePath(ctx, types.FilePath(workDir), types.FilePath(path))
	problems := asProblemsMap(ctx, []testapi.FindingData{finding})
	require.NotEmpty(t, problems)
	// Enable OSS quick-fix actions (deps already injected by UnitTestWithCtx)
	c.SetSnykOSSQuickFixCodeActionsEnabled(true)

	// Pick first problem group
	for _, group := range problems {
		issue, err := convertProblemToIssue(ctx, group.Problem, group.Findings, types.FilePath(path))
		require.NoError(t, err)
		require.NotNil(t, issue)

		// deps already injected above
		enriched := addUnifiedOssQuickFixesAndLenses(ctx, []types.Issue{issue})
		require.Len(t, enriched, 1)
		enrichedIssue := enriched[0]

		// Act: inspect code actions collected on the unified issue
		actions := enrichedIssue.GetCodeActions()

		// Assert: expect an upgrade quick-fix to be present (title contains "Upgrade to")
		// This will start failing until the unified flow adds OSS quick-fix actions.
		hasUpgrade := false
		for _, a := range actions {
			if strings.Contains(a.GetTitle(), "Upgrade to") {
				hasUpgrade = true
				break
			}
		}
		assert.True(t, hasUpgrade, "expected unified issue to include an 'Upgrade to' quick-fix action")
		break
	}
}

func Test_UnifiedIssue_ProducesUpgradeCodeLens(t *testing.T) {
	// Arrange: create a unified finding with an upgrade path
	finding := createCompleteUnifiedFinding(
		"npm",
		"goof@1.0.0",
		[]string{"lodash@4.17.20"},
		[]string{"4.17.21"},
		"lodash",
		"4.17.20",
		"Prototype Pollution",
	)

	// convert to Problems map and then to issues
	c, ctx := testutil.UnitTestWithCtx(t)
	workDir, err := filepath.Abs("testdata")
	require.NoError(t, err)
	path := filepath.Join(workDir, "package.json")
	ctx = ctx2.NewContextWithWorkDirAndFilePath(ctx, types.FilePath(workDir), types.FilePath(path))
	problems := asProblemsMap(ctx, []testapi.FindingData{finding})
	require.NotEmpty(t, problems)
	// Enable OSS quick-fix actions
	c.SetSnykOSSQuickFixCodeActionsEnabled(true)

	for _, group := range problems {
		issue, err := convertProblemToIssue(ctx, group.Problem, group.Findings, types.FilePath(path))
		require.NoError(t, err)
		require.NotNil(t, issue)

		// deps already injected by UnitTestWithCtx
		enriched := addUnifiedOssQuickFixesAndLenses(ctx, []types.Issue{issue})
		require.Len(t, enriched, 1)
		enrichedIssue := enriched[0]

		// Act: inspect codelens commands on the unified issue
		lenses := enrichedIssue.GetCodelensCommands()

		// Assert: expect at least one lens with title containing "Upgrade to"
		// This will start failing until codelenses are added for unified issues.
		hasUpgradeLens := false
		for _, l := range lenses {
			if strings.Contains(l.Title, "Upgrade to") {
				hasUpgradeLens = true
				break
			}
		}
		assert.True(t, hasUpgradeLens, "expected unified issue to include an 'Upgrade to' code lens")
		break
	}
}

// createTestFinding creates a sample FindingData for testing
func createTestFinding() testapi.FindingData {
	high := testapi.Severity("high")
	return testapi.FindingData{
		Id:   nil, // UUID will be nil for simplicity in tests
		Type: nil, // Type will be nil for simplicity in tests
		Attributes: &testapi.FindingAttributes{
			Key:         "SNYK-JS-TEST-123456",
			Title:       "Test Vulnerability",
			Description: "Test vulnerability description",
			FindingType: "vulnerability",
			Rating: testapi.Rating{
				Severity: high,
			},
			Problems:  createTestProblems(),
			Locations: []testapi.FindingLocation{}, // Simplified for testing
			Evidence:  []testapi.Evidence{},        // Simplified for testing
		},
	}
}

// createTestProblems creates test problems for the finding
func createTestProblems() []testapi.Problem {
	var problem testapi.Problem
	var ecosystem testapi.SnykvulndbPackageEcosystem

	// Create ecosystem
	buildEco := testapi.SnykvulndbBuildPackageEcosystem{
		PackageManager: "npm",
		Language:       "javascript",
	}
	_ = ecosystem.FromSnykvulndbBuildPackageEcosystem(buildEco)

	// Create a SnykVulnProblem
	vulnProblem := testapi.SnykVulnProblem{
		Id:                       "SNYK-JS-TEST-123456",
		PackageName:              "test-package",
		PackageVersion:           "1.0.0",
		Ecosystem:                ecosystem,
		CvssBaseScore:            7.5,
		InitiallyFixedInVersions: []string{"1.0.1"},
		CvssSources:              []testapi.SnykvulndbCvssSource{},
	}

	// Use FromSnykVulnProblem to set it
	_ = problem.FromSnykVulnProblem(vulnProblem)

	return []testapi.Problem{problem}
}

// Test_buildUpgradePath tests the buildUpgradePath function
func Test_buildUpgradePath(t *testing.T) {
	tests := []struct {
		name            string
		finding         testapi.FindingData
		vuln            *testapi.SnykVulnProblem
		expectedUpgrade []any
		description     string
	}{
		{
			name:    "Fallback when no upgrade path in API",
			finding: createFindingWithoutUpgradePath(),
			vuln: &testapi.SnykVulnProblem{
				PackageName:              "test-package",
				PackageVersion:           "1.0.0",
				InitiallyFixedInVersions: []string{"1.0.1"},
			},
			expectedUpgrade: []any{false, "test-package@1.0.1"},
			description:     "Should fallback to InitiallyFixedInVersions when no upgrade path",
		},
		{
			name:    "Empty when no upgrade path and no fixed versions",
			finding: createFindingWithoutUpgradePath(),
			vuln: &testapi.SnykVulnProblem{
				PackageName:              "test-package",
				PackageVersion:           "1.0.0",
				InitiallyFixedInVersions: []string{},
			},
			expectedUpgrade: []any{false},
			description:     "Should return [false] when no upgrade information but has dependency path",
		},
		{
			name:    "Upgrade path with dependency path",
			finding: createFindingWithUpgradePath("goof@1.0.1", []string{"hbs@4.0.4", "handlebars@4.0.14", "uglify-js@3.13.9"}),
			vuln: &testapi.SnykVulnProblem{
				PackageName:              "uglify-js",
				PackageVersion:           "3.13.9",
				InitiallyFixedInVersions: []string{"3.19.3"},
			},
			expectedUpgrade: []any{false, "hbs@4.0.4", "handlebars@4.0.14", "uglify-js@3.19.3"},
			description:     "Should use dependency path with upgraded version for target",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			result := buildUpgradePath(tt.finding, tt.vuln)

			// Assert
			require.Equal(t, len(tt.expectedUpgrade), len(result), "Length mismatch")
			for i, expected := range tt.expectedUpgrade {
				require.Equal(t, expected, result[i], "Upgrade path element %d mismatch", i)
			}
		})
	}
}

// Helper functions for creating test findings
func createFindingWithUpgradePath(root string, path []string) testapi.FindingData {
	finding := createTestFinding()

	// Add dependency path evidence
	if finding.Attributes == nil {
		finding.Attributes = &testapi.FindingAttributes{}
	}
	if finding.Attributes.Evidence == nil {
		finding.Attributes.Evidence = []testapi.Evidence{}
	}

	// Create dependency packages
	dependencyPkgs := make([]testapi.Package, len(path)+1)
	rootParts := strings.Split(root, "@")
	dependencyPkgs[0] = testapi.Package{Name: rootParts[0], Version: rootParts[1]}

	for i, pkgStr := range path {
		parts := strings.Split(pkgStr, "@")
		dependencyPkgs[i+1] = testapi.Package{Name: parts[0], Version: parts[1]}
	}

	// Add dependency path evidence
	var depEv testapi.Evidence
	_ = depEv.FromDependencyPathEvidence(testapi.DependencyPathEvidence{
		Path: dependencyPkgs,
	})

	finding.Attributes.Evidence = append(finding.Attributes.Evidence, depEv)

	return finding
}

func createFindingWithoutUpgradePath() testapi.FindingData {
	finding := createTestFinding()

	// Add dependency path evidence but no upgrade path
	if finding.Attributes == nil {
		finding.Attributes = &testapi.FindingAttributes{}
	}

	if finding.Attributes.Evidence == nil {
		finding.Attributes.Evidence = []testapi.Evidence{}
	}

	var depEv testapi.Evidence
	_ = depEv.FromDependencyPathEvidence(testapi.DependencyPathEvidence{
		Path: []testapi.Package{
			{Name: "root", Version: "1.0.0"},
			{Name: "test-package", Version: "1.0.0"},
		},
	})

	finding.Attributes.Evidence = append(finding.Attributes.Evidence, depEv)

	return finding
}

// createCompleteUnifiedFinding builds a FindingData with all key fields populated so that
// unified conversion can yield actionable issues (UpgradePath/From/FixedIn etc.).
func createCompleteUnifiedFinding(
	packageManager string,
	root string,
	path []string,
	fixedIn []string,
	pkgName string,
	version string,
	title string,
) testapi.FindingData {
	finding := createTestFinding()

	// Override attributes as requested
	if finding.Attributes == nil {
		finding.Attributes = &testapi.FindingAttributes{}
	}
	finding.Attributes.Title = title
	finding.Attributes.Description = title + " description"

	// Build ecosystem from packageManager
	var ecosystem testapi.SnykvulndbPackageEcosystem
	_ = ecosystem.FromSnykvulndbBuildPackageEcosystem(testapi.SnykvulndbBuildPackageEcosystem{
		PackageManager: packageManager,
		Language:       "",
	})

	// Inject SnykVulnProblem with desired fields
	var problem testapi.Problem
	_ = problem.FromSnykVulnProblem(testapi.SnykVulnProblem{
		Id:                       pkgName + "-id",
		PackageName:              pkgName,
		PackageVersion:           version,
		Ecosystem:                ecosystem,
		InitiallyFixedInVersions: fixedIn,
	})
	finding.Attributes.Problems = []testapi.Problem{problem}

	// Dependency path evidence (root + path...)
	if finding.Attributes.Evidence == nil {
		finding.Attributes.Evidence = []testapi.Evidence{}
	}
	dependencyPkgs := make([]testapi.Package, len(path)+1)
	rootParts := strings.Split(root, "@")
	dependencyPkgs[0] = testapi.Package{Name: rootParts[0], Version: rootParts[1]}
	for i, pkgStr := range path {
		parts := strings.Split(pkgStr, "@")
		dependencyPkgs[i+1] = testapi.Package{Name: parts[0], Version: parts[1]}
	}
	var depEv testapi.Evidence
	_ = depEv.FromDependencyPathEvidence(testapi.DependencyPathEvidence{Path: dependencyPkgs})
	finding.Attributes.Evidence = append(finding.Attributes.Evidence, depEv)

	// Add a package location to help extractVersion logic
	finding.Attributes.Locations = append(finding.Attributes.Locations, func() testapi.FindingLocation {
		var loc testapi.FindingLocation
		_ = loc.FromPackageLocation(testapi.PackageLocation{
			Package: testapi.Package{Name: pkgName, Version: version},
		})
		return loc
	}())

	return finding
}

// Test_buildRemediationAdvice tests the buildRemediationAdvice function
func Test_buildRemediationAdvice(t *testing.T) {
	tests := []struct {
		name            string
		finding         testapi.FindingData
		vuln            *testapi.SnykVulnProblem
		expectedMessage string
		description     string
	}{
		{
			name:    "No remediation when no fixed versions",
			finding: createFindingWithoutUpgradePath(),
			vuln: &testapi.SnykVulnProblem{
				PackageName:              "test-package",
				PackageVersion:           "1.0.0",
				InitiallyFixedInVersions: []string{},
			},
			expectedMessage: "No remediation advice available",
			description:     "Should return no remediation message when no fix available",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			result := buildRemediationAdvice(tt.finding, tt.vuln)

			// Assert
			require.NotEmpty(t, result, "Message should not be empty")
			require.Contains(t, result, tt.expectedMessage)
		})
	}
}
