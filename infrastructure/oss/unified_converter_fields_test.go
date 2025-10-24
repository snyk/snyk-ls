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
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

// Test helper to create a complete issue for field testing
func createCompleteTestIssue(t *testing.T) *snyk.Issue {
	t.Helper()
	finding := createCompleteTestFinding()
	workDir := types.FilePath("/test/workdir")
	affectedFilePath := types.FilePath("/test/workdir/package.json")
	var learnService learn.Service
	format := config.FormatMd
	metadata := &WorkflowMetadata{
		ProjectName:       "test-project",
		PackageManager:    "npm",
		DisplayTargetFile: "package.json",
	}

	issue, err := convertFindingToIssue(finding, workDir, affectedFilePath, learnService, format, metadata)

	require.NoError(t, err)
	require.NotNil(t, issue)
	return issue
}

// createCompleteTestFinding creates a comprehensive test finding with all fields
func createCompleteTestFinding() testapi.FindingData {
	high := testapi.Severity("high")

	// Create CWE problem
	var cweProblem testapi.Problem
	_ = cweProblem.FromCweProblem(testapi.CweProblem{
		Id: "CWE-79",
	})

	// Create CVE problem
	var cveProblem testapi.Problem
	_ = cveProblem.FromCveProblem(testapi.CveProblem{
		Id: "CVE-2021-1234",
	})

	// Create SnykVuln problem
	var vulnProblem testapi.Problem
	var ecosystem testapi.SnykvulndbPackageEcosystem
	buildEco := testapi.SnykvulndbBuildPackageEcosystem{
		PackageManager: "npm",
		Language:       "javascript",
	}
	_ = ecosystem.FromSnykvulndbBuildPackageEcosystem(buildEco)

	vuln := testapi.SnykVulnProblem{
		Id:                       "SNYK-JS-LODASH-590103",
		PackageName:              "lodash",
		PackageVersion:           "4.17.19",
		Ecosystem:                ecosystem,
		CvssBaseScore:            7.5,
		InitiallyFixedInVersions: []string{"4.17.21"},
		CvssSources:              []testapi.SnykvulndbCvssSource{},
		References: []testapi.SnykvulndbReferenceLinks{
			{
				Title: "GitHub Issue",
				Url:   "https://github.com/lodash/lodash/issues/1234",
			},
			{
				Title: "Snyk Advisory",
				Url:   "https://security.snyk.io/vuln/SNYK-JS-LODASH-590103",
			},
		},
	}
	_ = vulnProblem.FromSnykVulnProblem(vuln)

	return testapi.FindingData{
		Id:   nil,
		Type: nil,
		Attributes: &testapi.FindingAttributes{
			Key:         "SNYK-JS-LODASH-590103",
			Title:       "Prototype Pollution",
			Description: "lodash versions prior to 4.17.21 are vulnerable to Prototype Pollution",
			FindingType: "vulnerability",
			Rating: testapi.Rating{
				Severity: high,
			},
			Problems:  []testapi.Problem{vulnProblem, cweProblem, cveProblem},
			Locations: []testapi.FindingLocation{},
			Evidence:  []testapi.Evidence{},
		},
	}
}

// ============================================================================
// Issue Interface Method Tests
// ============================================================================

func Test_Issue_GetID(t *testing.T) {
	issue := createCompleteTestIssue(t)
	assert.Equal(t, "SNYK-JS-LODASH-590103", issue.GetID())
}

func Test_Issue_GetRange(t *testing.T) {
	issue := createCompleteTestIssue(t)
	r := issue.GetRange()
	// Default range should be empty when no location info available
	assert.NotNil(t, r)
}

func Test_Issue_GetMessage(t *testing.T) {
	issue := createCompleteTestIssue(t)
	message := issue.GetMessage()
	assert.NotEmpty(t, message)
	assert.Contains(t, message, "Prototype Pollution")
	assert.Contains(t, message, "lodash")
}

func Test_Issue_GetFormattedMessage(t *testing.T) {
	issue := createCompleteTestIssue(t)
	formatted := issue.GetFormattedMessage()
	assert.NotEmpty(t, formatted)
	assert.Contains(t, formatted, "vulnerable")
}

func Test_Issue_GetAffectedFilePath(t *testing.T) {
	issue := createCompleteTestIssue(t)
	assert.Equal(t, types.FilePath("/test/workdir/package.json"), issue.GetAffectedFilePath())
}

func Test_Issue_GetContentRoot(t *testing.T) {
	issue := createCompleteTestIssue(t)
	assert.Equal(t, types.FilePath("/test/workdir"), issue.GetContentRoot())
}

func Test_Issue_GetIsNew(t *testing.T) {
	issue := createCompleteTestIssue(t)
	// New issues should default to false
	assert.False(t, issue.GetIsNew())
}

func Test_Issue_GetIsIgnored(t *testing.T) {
	issue := createCompleteTestIssue(t)
	// No suppression in test data
	assert.False(t, issue.GetIsIgnored())
}

func Test_Issue_GetSeverity(t *testing.T) {
	issue := createCompleteTestIssue(t)
	assert.Equal(t, types.High, issue.GetSeverity())
}

func Test_Issue_GetIgnoreDetails(t *testing.T) {
	issue := createCompleteTestIssue(t)
	// No suppression in test data
	assert.Nil(t, issue.GetIgnoreDetails())
}

func Test_Issue_GetProduct(t *testing.T) {
	issue := createCompleteTestIssue(t)
	assert.Equal(t, product.ProductOpenSource, issue.GetProduct())
}

func Test_Issue_GetFingerprint(t *testing.T) {
	issue := createCompleteTestIssue(t)
	fingerprint := issue.GetFingerprint()
	assert.NotEmpty(t, fingerprint)
}

func Test_Issue_GetAdditionalData(t *testing.T) {
	issue := createCompleteTestIssue(t)
	additionalData := issue.GetAdditionalData()
	assert.NotNil(t, additionalData)

	ossData, ok := additionalData.(snyk.OssIssueData)
	assert.True(t, ok, "AdditionalData should be OssIssueData")
	assert.NotEmpty(t, ossData.Key)
}

func Test_Issue_GetEcosystem(t *testing.T) {
	issue := createCompleteTestIssue(t)
	assert.Equal(t, "npm", issue.GetEcosystem())
}

func Test_Issue_GetCWEs(t *testing.T) {
	issue := createCompleteTestIssue(t)
	cwes := issue.GetCWEs()
	require.Len(t, cwes, 1)
	assert.Equal(t, "CWE-79", cwes[0])
}

func Test_Issue_GetCVEs(t *testing.T) {
	issue := createCompleteTestIssue(t)
	cves := issue.GetCVEs()
	require.Len(t, cves, 1)
	assert.Equal(t, "CVE-2021-1234", cves[0])
}

func Test_Issue_GetIssueType(t *testing.T) {
	issue := createCompleteTestIssue(t)
	assert.Equal(t, types.DependencyVulnerability, issue.GetIssueType())
}

func Test_Issue_GetLessonUrl(t *testing.T) {
	issue := createCompleteTestIssue(t)
	// LearnService is nil in tests, so URL should be empty
	assert.Empty(t, issue.GetLessonUrl())
}

func Test_Issue_GetIssueDescriptionURL(t *testing.T) {
	issue := createCompleteTestIssue(t)
	url := issue.GetIssueDescriptionURL()
	assert.NotNil(t, url)
	assert.Contains(t, url.String(), "snyk.io/vuln/SNYK-JS-LODASH-590103")
}

func Test_Issue_GetCodeActions(t *testing.T) {
	issue := createCompleteTestIssue(t)
	actions := issue.GetCodeActions()
	// Code actions are not generated yet (marked as TODO)
	assert.NotNil(t, actions)
}

func Test_Issue_GetCodelensCommands(t *testing.T) {
	issue := createCompleteTestIssue(t)
	commands := issue.GetCodelensCommands()
	// Codelens commands are not generated yet (marked as TODO)
	assert.NotNil(t, commands)
}

func Test_Issue_GetFilterableIssueType(t *testing.T) {
	issue := createCompleteTestIssue(t)
	assert.Equal(t, product.FilterableIssueTypeOpenSource, issue.GetFilterableIssueType())
}

func Test_Issue_GetRuleID(t *testing.T) {
	issue := createCompleteTestIssue(t)
	// RuleID should be same as ID
	assert.Equal(t, "SNYK-JS-LODASH-590103", issue.GetRuleID())
}

func Test_Issue_GetReferences(t *testing.T) {
	issue := createCompleteTestIssue(t)
	refs := issue.GetReferences()
	assert.NotNil(t, refs)
	require.Len(t, refs, 2, "Should extract 2 references from test data")

	// Verify first reference
	assert.Equal(t, "GitHub Issue", refs[0].Title)
	assert.NotNil(t, refs[0].Url)
	assert.Equal(t, "https://github.com/lodash/lodash/issues/1234", refs[0].Url.String())

	// Verify second reference
	assert.Equal(t, "Snyk Advisory", refs[1].Title)
	assert.NotNil(t, refs[1].Url)
	assert.Equal(t, "https://security.snyk.io/vuln/SNYK-JS-LODASH-590103", refs[1].Url.String())
}

func Test_Issue_GetFindingId(t *testing.T) {
	issue := createCompleteTestIssue(t)
	// Finding ID is nil in our test data
	assert.Empty(t, issue.GetFindingId())
}

// ============================================================================
// OssIssueData Field Tests
// ============================================================================

func Test_OssIssueData_Key(t *testing.T) {
	issue := createCompleteTestIssue(t)
	ossData := issue.GetAdditionalData().(snyk.OssIssueData)
	assert.NotEmpty(t, ossData.Key)
	// Key is a computed hash, not the ID itself
}

func Test_OssIssueData_Title(t *testing.T) {
	issue := createCompleteTestIssue(t)
	ossData := issue.GetAdditionalData().(snyk.OssIssueData)
	assert.Equal(t, "Prototype Pollution", ossData.Title)
}

func Test_OssIssueData_Name(t *testing.T) {
	issue := createCompleteTestIssue(t)
	ossData := issue.GetAdditionalData().(snyk.OssIssueData)
	assert.Equal(t, "lodash", ossData.Name)
}

func Test_OssIssueData_LineNumber(t *testing.T) {
	issue := createCompleteTestIssue(t)
	ossData := issue.GetAdditionalData().(snyk.OssIssueData)
	// Line number defaults to 0 when no location info
	assert.Equal(t, 0, ossData.LineNumber)
}

func Test_OssIssueData_Identifiers(t *testing.T) {
	issue := createCompleteTestIssue(t)
	ossData := issue.GetAdditionalData().(snyk.OssIssueData)
	assert.Len(t, ossData.Identifiers.CWE, 1)
	assert.Equal(t, "CWE-79", ossData.Identifiers.CWE[0])
	assert.Len(t, ossData.Identifiers.CVE, 1)
	assert.Equal(t, "CVE-2021-1234", ossData.Identifiers.CVE[0])
}

func Test_OssIssueData_Description(t *testing.T) {
	issue := createCompleteTestIssue(t)
	ossData := issue.GetAdditionalData().(snyk.OssIssueData)
	assert.NotEmpty(t, ossData.Description)
	assert.Contains(t, ossData.Description, "vulnerable")
}

func Test_OssIssueData_References(t *testing.T) {
	issue := createCompleteTestIssue(t)
	ossData := issue.GetAdditionalData().(snyk.OssIssueData)
	assert.NotNil(t, ossData.References)
	require.Len(t, ossData.References, 2, "Should have 2 references")

	// Verify references are properly mapped
	assert.Equal(t, "GitHub Issue", ossData.References[0].Title)
	assert.Equal(t, "https://github.com/lodash/lodash/issues/1234", ossData.References[0].Url.String())
}

func Test_OssIssueData_Version(t *testing.T) {
	issue := createCompleteTestIssue(t)
	ossData := issue.GetAdditionalData().(snyk.OssIssueData)
	assert.Equal(t, "4.17.19", ossData.Version)
}

func Test_OssIssueData_License(t *testing.T) {
	issue := createCompleteTestIssue(t)
	ossData := issue.GetAdditionalData().(snyk.OssIssueData)
	// No license issue in test data
	assert.Empty(t, ossData.License)
}

func Test_OssIssueData_PackageManager(t *testing.T) {
	issue := createCompleteTestIssue(t)
	ossData := issue.GetAdditionalData().(snyk.OssIssueData)
	assert.Equal(t, "npm", ossData.PackageManager)
}

func Test_OssIssueData_PackageName(t *testing.T) {
	issue := createCompleteTestIssue(t)
	ossData := issue.GetAdditionalData().(snyk.OssIssueData)
	assert.Equal(t, "lodash", ossData.PackageName)
}

func Test_OssIssueData_From(t *testing.T) {
	issue := createCompleteTestIssue(t)
	ossData := issue.GetAdditionalData().(snyk.OssIssueData)
	// No dependency path in test data
	assert.Empty(t, ossData.From)
}

func Test_OssIssueData_FixedIn(t *testing.T) {
	issue := createCompleteTestIssue(t)
	ossData := issue.GetAdditionalData().(snyk.OssIssueData)
	require.Len(t, ossData.FixedIn, 1)
	assert.Equal(t, "4.17.21", ossData.FixedIn[0])
}

func Test_OssIssueData_UpgradePath(t *testing.T) {
	issue := createCompleteTestIssue(t)
	ossData := issue.GetAdditionalData().(snyk.OssIssueData)
	// Upgrade path is empty when no dependency path evidence
	assert.Empty(t, ossData.UpgradePath)
}

func Test_OssIssueData_IsUpgradable(t *testing.T) {
	issue := createCompleteTestIssue(t)
	ossData := issue.GetAdditionalData().(snyk.OssIssueData)
	// Should be true because FixedIn is not empty
	assert.True(t, ossData.IsUpgradable)
}

func Test_OssIssueData_CVSSv3(t *testing.T) {
	issue := createCompleteTestIssue(t)
	ossData := issue.GetAdditionalData().(snyk.OssIssueData)
	// No CVSS sources in test data
	assert.Empty(t, ossData.CVSSv3)
}

func Test_OssIssueData_CvssScore(t *testing.T) {
	issue := createCompleteTestIssue(t)
	ossData := issue.GetAdditionalData().(snyk.OssIssueData)
	assert.Equal(t, 7.5, ossData.CvssScore)
}

func Test_OssIssueData_CvssSources(t *testing.T) {
	issue := createCompleteTestIssue(t)
	ossData := issue.GetAdditionalData().(snyk.OssIssueData)
	// No CVSS sources in test data
	assert.Empty(t, ossData.CvssSources)
}

func Test_OssIssueData_Exploit(t *testing.T) {
	issue := createCompleteTestIssue(t)
	ossData := issue.GetAdditionalData().(snyk.OssIssueData)
	// No exploit details in test data
	assert.Empty(t, ossData.Exploit)
}

func Test_OssIssueData_IsPatchable(t *testing.T) {
	issue := createCompleteTestIssue(t)
	ossData := issue.GetAdditionalData().(snyk.OssIssueData)
	// Patches not supported in unified workflow
	assert.False(t, ossData.IsPatchable)
}

func Test_OssIssueData_ProjectName(t *testing.T) {
	issue := createCompleteTestIssue(t)
	ossData := issue.GetAdditionalData().(snyk.OssIssueData)
	assert.Equal(t, "test-project", ossData.ProjectName)
}

func Test_OssIssueData_DisplayTargetFile(t *testing.T) {
	issue := createCompleteTestIssue(t)
	ossData := issue.GetAdditionalData().(snyk.OssIssueData)
	assert.Equal(t, types.FilePath("/test/workdir/package.json"), ossData.DisplayTargetFile)
}

func Test_OssIssueData_Language(t *testing.T) {
	issue := createCompleteTestIssue(t)
	ossData := issue.GetAdditionalData().(snyk.OssIssueData)
	assert.Equal(t, "javascript", ossData.Language)
}

func Test_OssIssueData_Details(t *testing.T) {
	issue := createCompleteTestIssue(t)
	ossData := issue.GetAdditionalData().(snyk.OssIssueData)
	assert.NotEmpty(t, ossData.Details)
	assert.Contains(t, ossData.Details, "vulnerable")
}

func Test_OssIssueData_MatchingIssues(t *testing.T) {
	issue := createCompleteTestIssue(t)
	ossData := issue.GetAdditionalData().(snyk.OssIssueData)
	// Matching issues are computed by delta processing
	assert.Empty(t, ossData.MatchingIssues)
}

func Test_OssIssueData_Lesson(t *testing.T) {
	issue := createCompleteTestIssue(t)
	ossData := issue.GetAdditionalData().(snyk.OssIssueData)
	// Learn service is nil in tests
	assert.Empty(t, ossData.Lesson)
}

func Test_OssIssueData_Remediation(t *testing.T) {
	issue := createCompleteTestIssue(t)
	ossData := issue.GetAdditionalData().(snyk.OssIssueData)
	assert.NotEmpty(t, ossData.Remediation)
	assert.Contains(t, ossData.Remediation, "Upgrade")
	assert.Contains(t, ossData.Remediation, "4.17.21")
}

func Test_OssIssueData_AppliedPolicyRules(t *testing.T) {
	issue := createCompleteTestIssue(t)
	ossData := issue.GetAdditionalData().(snyk.OssIssueData)
	// No policy modifications in test data
	assert.Empty(t, ossData.AppliedPolicyRules.Annotation.Value)
	assert.Empty(t, ossData.AppliedPolicyRules.SeverityChange.NewSeverity)
}

func Test_OssIssueData_GetFilterableIssueType(t *testing.T) {
	issue := createCompleteTestIssue(t)
	ossData := issue.GetAdditionalData().(snyk.OssIssueData)
	assert.Equal(t, product.FilterableIssueTypeOpenSource, ossData.GetFilterableIssueType())
}

func Test_OssIssueData_IsFixable(t *testing.T) {
	issue := createCompleteTestIssue(t)
	ossData := issue.GetAdditionalData().(snyk.OssIssueData)
	// IsFixable requires IsUpgradable AND IsPatchable AND valid upgrade path
	// In our test, IsPatchable is false, so IsFixable should be false
	assert.False(t, ossData.IsFixable())
}

// ============================================================================
// Edge Case and Integration Tests
// ============================================================================

func Test_ConvertFindingDataToIssues_WithReferences(t *testing.T) {
	// Arrange
	ctx := t.Context()
	finding := createCompleteTestFinding()
	workDir := types.FilePath("/test/workdir")
	path := types.FilePath("/test/workdir/package.json")
	logger := zerolog.Nop()
	errorReporter := error_reporting.NewTestErrorReporter()
	var learnService learn.Service
	packageIssueCache := make(map[string][]types.Issue)
	format := config.FormatMd
	metadata := &WorkflowMetadata{ProjectName: "test-project"}

	// Act
	issues := ConvertFindingDataToIssues(
		ctx,
		[]testapi.FindingData{finding},
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
	require.Len(t, issues, 1)
	refs := issues[0].GetReferences()
	assert.Len(t, refs, 2)
	assert.Equal(t, "GitHub Issue", refs[0].Title)
	assert.Equal(t, "Snyk Advisory", refs[1].Title)
}

func Test_ConvertFindingDataToIssues_NoReferences(t *testing.T) {
	// Arrange
	ctx := t.Context()
	workDir := types.FilePath("/test/workdir")
	path := types.FilePath("/test/workdir/package.json")
	logger := zerolog.Nop()
	errorReporter := error_reporting.NewTestErrorReporter()
	var learnService learn.Service
	packageIssueCache := make(map[string][]types.Issue)
	format := config.FormatMd
	metadata := &WorkflowMetadata{}

	// Create finding without references
	high := testapi.Severity("high")
	var ecosystem testapi.SnykvulndbPackageEcosystem
	_ = ecosystem.FromSnykvulndbBuildPackageEcosystem(testapi.SnykvulndbBuildPackageEcosystem{
		PackageManager: "npm",
		Language:       "javascript",
	})

	var vulnProblem testapi.Problem
	_ = vulnProblem.FromSnykVulnProblem(testapi.SnykVulnProblem{
		Id:                       "SNYK-TEST-NO-REFS",
		PackageName:              "test-pkg",
		PackageVersion:           "1.0.0",
		Ecosystem:                ecosystem,
		CvssBaseScore:            5.0,
		InitiallyFixedInVersions: []string{},
		References:               []testapi.SnykvulndbReferenceLinks{}, // Empty references
	})

	finding := testapi.FindingData{
		Attributes: &testapi.FindingAttributes{
			Key:         "SNYK-TEST-NO-REFS",
			Title:       "Test Vulnerability",
			Description: "Test",
			FindingType: "vulnerability",
			Rating:      testapi.Rating{Severity: high},
			Problems:    []testapi.Problem{vulnProblem},
		},
	}

	// Act
	issues := ConvertFindingDataToIssues(
		ctx,
		[]testapi.FindingData{finding},
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
	require.Len(t, issues, 1)
	refs := issues[0].GetReferences()
	assert.NotNil(t, refs, "References should not be nil")
	assert.Empty(t, refs, "References should be empty slice, not nil")
}

func Test_ConvertFindingDataToIssues_InvalidReferenceURL(t *testing.T) {
	// Arrange
	ctx := t.Context()
	workDir := types.FilePath("/test/workdir")
	path := types.FilePath("/test/workdir/package.json")
	logger := zerolog.Nop()
	errorReporter := error_reporting.NewTestErrorReporter()
	var learnService learn.Service
	packageIssueCache := make(map[string][]types.Issue)
	format := config.FormatMd
	metadata := &WorkflowMetadata{}

	// Create finding with invalid URL
	high := testapi.Severity("high")
	var ecosystem testapi.SnykvulndbPackageEcosystem
	_ = ecosystem.FromSnykvulndbBuildPackageEcosystem(testapi.SnykvulndbBuildPackageEcosystem{
		PackageManager: "npm",
		Language:       "javascript",
	})

	var vulnProblem testapi.Problem
	_ = vulnProblem.FromSnykVulnProblem(testapi.SnykVulnProblem{
		Id:                       "SNYK-TEST-INVALID-URL",
		PackageName:              "test-pkg",
		PackageVersion:           "1.0.0",
		Ecosystem:                ecosystem,
		CvssBaseScore:            5.0,
		InitiallyFixedInVersions: []string{},
		References: []testapi.SnykvulndbReferenceLinks{
			{
				Title: "Valid Reference",
				Url:   "https://example.com/valid",
			},
			{
				Title: "Invalid Reference",
				Url:   "://invalid-url", // Invalid URL
			},
			{
				Title: "Another Valid Reference",
				Url:   "https://example.com/another",
			},
		},
	})

	finding := testapi.FindingData{
		Attributes: &testapi.FindingAttributes{
			Key:         "SNYK-TEST-INVALID-URL",
			Title:       "Test Vulnerability",
			Description: "Test",
			FindingType: "vulnerability",
			Rating:      testapi.Rating{Severity: high},
			Problems:    []testapi.Problem{vulnProblem},
		},
	}

	// Act
	issues := ConvertFindingDataToIssues(
		ctx,
		[]testapi.FindingData{finding},
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
	require.Len(t, issues, 1)
	refs := issues[0].GetReferences()
	assert.Len(t, refs, 2, "Should skip invalid URL and include only valid ones")
	assert.Equal(t, "Valid Reference", refs[0].Title)
	assert.Equal(t, "Another Valid Reference", refs[1].Title)
}

func Test_ConvertFindingDataToIssues_MultipleSeverities(t *testing.T) {
	// Test that different severity levels are correctly converted
	testCases := []struct {
		name             string
		severity         testapi.Severity
		expectedSeverity types.Severity
	}{
		{"Critical", "critical", types.Critical},
		{"High", "high", types.High},
		{"Medium", "medium", types.Medium},
		{"Low", "low", types.Low},
		{"Unknown", "unknown", types.Low}, // Default fallback
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange
			ctx := t.Context()
			workDir := types.FilePath("/test/workdir")
			path := types.FilePath("/test/workdir/package.json")
			logger := zerolog.Nop()
			errorReporter := error_reporting.NewTestErrorReporter()
			var learnService learn.Service
			packageIssueCache := make(map[string][]types.Issue)
			format := config.FormatMd
			metadata := &WorkflowMetadata{}

			var ecosystem testapi.SnykvulndbPackageEcosystem
			_ = ecosystem.FromSnykvulndbBuildPackageEcosystem(testapi.SnykvulndbBuildPackageEcosystem{
				PackageManager: "npm",
				Language:       "javascript",
			})

			var vulnProblem testapi.Problem
			_ = vulnProblem.FromSnykVulnProblem(testapi.SnykVulnProblem{
				Id:             "SNYK-TEST-" + tc.name,
				PackageName:    "test-pkg",
				PackageVersion: "1.0.0",
				Ecosystem:      ecosystem,
				CvssBaseScore:  5.0,
			})

			finding := testapi.FindingData{
				Attributes: &testapi.FindingAttributes{
					Key:         "SNYK-TEST-" + tc.name,
					Title:       "Test",
					Description: "Test",
					FindingType: "vulnerability",
					Rating:      testapi.Rating{Severity: tc.severity},
					Problems:    []testapi.Problem{vulnProblem},
				},
			}

			// Act
			issues := ConvertFindingDataToIssues(
				ctx,
				[]testapi.FindingData{finding},
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
			require.Len(t, issues, 1)
			assert.Equal(t, tc.expectedSeverity, issues[0].GetSeverity())
		})
	}
}
