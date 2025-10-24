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
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/apiclients/mocks"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
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
