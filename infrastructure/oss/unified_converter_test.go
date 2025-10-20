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
	"testing"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_ConvertFindingDataToIssues_EmptyFindings(t *testing.T) {
	// Arrange
	ctx := t.Context()
	workDir := types.FilePath("/test/workdir")
	path := types.FilePath("/test/workdir/package.json")
	logger := zerolog.Nop()
	errorReporter := error_reporting.NewTestErrorReporter()
	var learnService learn.Service
	packageIssueCache := make(map[string][]types.Issue)
	format := config.FormatMd
	metadata := &WorkflowMetadata{
		ProjectName:    "test-project",
		PackageManager: "npm",
	}

	var findings []testapi.FindingData

	// Act
	issues := ConvertFindingDataToIssues(
		ctx,
		findings,
		workDir,
		path,
		&logger,
		errorReporter,
		learnService,
		packageIssueCache,
		format,
		metadata,
	)

	// Assert
	assert.NotNil(t, issues)
	assert.Empty(t, issues)
}

func Test_ConvertFindingDataToIssues_SingleVulnerability(t *testing.T) {
	// Arrange
	ctx := t.Context()
	workDir := types.FilePath("/test/workdir")
	path := types.FilePath("/test/workdir/package.json")
	logger := zerolog.Nop()
	errorReporter := error_reporting.NewTestErrorReporter()
	var learnService learn.Service
	packageIssueCache := make(map[string][]types.Issue)
	format := config.FormatMd
	metadata := &WorkflowMetadata{
		ProjectName:    "test-project",
		PackageManager: "npm",
	}

	// Create a test finding
	finding := createTestFinding()
	findings := []testapi.FindingData{finding}

	// Act
	issues := ConvertFindingDataToIssues(
		ctx,
		findings,
		workDir,
		path,
		&logger,
		errorReporter,
		learnService,
		packageIssueCache,
		format,
		metadata,
	)

	// Assert
	require.NotNil(t, issues)
	require.Len(t, issues, 1)

	issue := issues[0]
	assert.NotEmpty(t, issue.GetID())
	assert.NotEmpty(t, issue.GetMessage())
	assert.NotNil(t, issue.GetAdditionalData())
}

func Test_convertFindingToIssue_GetID(t *testing.T) {
	// Arrange
	finding := createTestFinding()
	workDir := types.FilePath("/test/workdir")
	affectedFilePath := types.FilePath("/test/workdir/package.json")
	logger := zerolog.Nop()
	var learnService learn.Service
	errorReporter := error_reporting.NewTestErrorReporter()
	format := config.FormatMd
	metadata := &WorkflowMetadata{
		ProjectName:    "test-project",
		PackageManager: "npm",
	}

	// Act
	issue, err := convertFindingToIssue(
		finding,
		workDir,
		affectedFilePath,
		&logger,
		learnService,
		errorReporter,
		format,
		metadata,
	)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, issue)
	assert.Equal(t, "SNYK-JS-TEST-123456", issue.GetID())
}

func Test_convertFindingToIssue_GetSeverity(t *testing.T) {
	// Arrange
	finding := createTestFinding()
	workDir := types.FilePath("/test/workdir")
	affectedFilePath := types.FilePath("/test/workdir/package.json")
	logger := zerolog.Nop()
	var learnService learn.Service
	errorReporter := error_reporting.NewTestErrorReporter()
	format := config.FormatMd
	metadata := &WorkflowMetadata{
		ProjectName:    "test-project",
		PackageManager: "npm",
	}

	// Act
	issue, err := convertFindingToIssue(
		finding,
		workDir,
		affectedFilePath,
		&logger,
		learnService,
		errorReporter,
		format,
		metadata,
	)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, issue)
	assert.Equal(t, types.High, issue.GetSeverity())
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
