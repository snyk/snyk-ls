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

package code

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/local_workflows/code_workflow/sast_contract"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/infrastructure/learn/mock_learn"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/testutil/workspaceutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// testCodeConfigUsesFolderOrg is a shared helper function that tests CodeConfig creation
// uses the correct folder-specific org for a single folder scenario.
// This focuses on the core CodeConfig creation flow: FolderOrganization -> createCodeConfig -> CreateCodeScanner
func testCodeConfigUsesFolderOrg(
	t *testing.T,
	c *config.Config,
	scanner *Scanner,
	folderPath types.FilePath,
	expectedOrg string,
) {
	t.Helper()

	// Verify FolderOrganization() returns the expected org
	folderOrg := c.FolderOrganization(folderPath)
	assert.Equal(t, expectedOrg, folderOrg, "FolderOrganization should return folder's org")

	// Get FolderConfig for the folder
	folderConfig := c.FolderConfig(folderPath)
	require.NotNil(t, folderConfig, "FolderConfig should not be nil")

	// Verify the CodeConfig has the correct org
	// This is what CreateCodeScanner uses internally, so we verify it first
	codeConfig, err := scanner.createCodeConfig(folderConfig)
	require.NoError(t, err, "createCodeConfig should succeed with folder's org")
	require.NotNil(t, codeConfig, "CodeConfig should not be nil")

	// Verify the org is correctly set in the config
	configOrg := codeConfig.Organization()

	// The org should be resolved to UUID (code-client-go expects UUID, not slug)
	expectedOrgUUID, err := c.ResolveOrgToUUID(expectedOrg)
	require.NoError(t, err, "Should be able to resolve folder's org to UUID")
	assert.Equal(t, expectedOrgUUID, configOrg, "CodeConfig should use folder's org (as UUID)")

	// Verify CreateCodeScanner() creates a scanner with folder's org
	// This is the actual function used in the scanning flow (via codeScanner method in UploadAndAnalyze)
	codeScanner, err := CreateCodeScanner(scanner, folderConfig)
	require.NoError(t, err, "CreateCodeScanner should succeed with folder's org")
	require.NotNil(t, codeScanner, "CodeScanner should not be nil")
}

// Test_CodeConfig_UsesFolderOrganization is an INTEGRATION TEST that verifies
// CodeConfig creation uses the correct folder-specific organization for different folders.
func Test_CodeConfig_UsesFolderOrganization(t *testing.T) {
	c := testutil.IntegTest(t)
	c.SetSnykCodeEnabled(true)

	// Set up two folders with different orgs
	folderPath1, folderPath2, _, folderOrg1, folderOrg2 := testutil.SetupFoldersWithOrgs(t, c)

	// Set up workspace with the folders
	// This is required for FolderOrganizationForSubPath to work (used by GetCodeApiUrlForFolder)
	_, _ = workspaceutil.SetupWorkspace(t, c, folderPath1, folderPath2)

	// Create a scanner to test CreateCodeScanner (the actual function used in scanning)
	// This is called via sc.codeScanner() in UploadAndAnalyze during actual scans
	scanner := &Scanner{
		C: c,
	}

	// Test folder 1
	t.Run("folder 1", func(t *testing.T) {
		testCodeConfigUsesFolderOrg(t, c, scanner, folderPath1, folderOrg1)
	})

	// Test folder 2
	t.Run("folder 2", func(t *testing.T) {
		testCodeConfigUsesFolderOrg(t, c, scanner, folderPath2, folderOrg2)
	})

	// Verify the orgs are different
	assert.NotEqual(t, folderOrg1, folderOrg2, "Folder orgs should be different")
}

// Test_CodeConfig_FallsBackToGlobalOrg is an INTEGRATION TEST that verifies
// CodeConfig creation falls back to global org when no folder-specific org is configured.
func Test_CodeConfig_FallsBackToGlobalOrg(t *testing.T) {
	c := testutil.IntegTest(t)
	c.SetSnykCodeEnabled(true)

	folderPath, globalOrg := testutil.SetupGlobalOrgOnly(t, c)

	// Set up workspace with the folder
	// This is required for FolderOrganizationForSubPath to work (used by GetCodeApiUrlForFolder)
	_, _ = workspaceutil.SetupWorkspace(t, c, folderPath)

	// Verify FolderOrganization() returns the global org (fallback behavior)
	folderOrg := c.FolderOrganization(folderPath)
	assert.Equal(t, globalOrg, folderOrg, "FolderOrganization should fall back to global org when no folder org is configured")

	// Get FolderConfig for the folder
	folderConfig := c.FolderConfig(folderPath)
	require.NotNil(t, folderConfig, "FolderConfig should not be nil")

	// Create a scanner to test CreateCodeScanner (the actual function used in scanning)
	// This is called via sc.codeScanner() in UploadAndAnalyze during actual scans
	scanner := &Scanner{
		C: c,
	}

	// Test: verify CreateCodeScanner() creates a scanner with global org as fallback
	// This is the actual function used in the scanning flow (via codeScanner method in UploadAndAnalyze)
	codeScanner, err := CreateCodeScanner(scanner, folderConfig)
	require.NoError(t, err, "CreateCodeScanner should succeed with global org fallback")
	require.NotNil(t, codeScanner, "CodeScanner should not be nil")

	// Verify the CodeConfig used by the scanner has the correct org
	// CreateCodeScanner internally calls createCodeConfig, so we verify that path
	codeConfig, err := scanner.createCodeConfig(folderConfig)
	require.NoError(t, err, "createCodeConfig should succeed with global org fallback")
	require.NotNil(t, codeConfig, "CodeConfig should not be nil")

	// Verify the org is correctly set in the config
	configOrg := codeConfig.Organization()

	// The org should be resolved to UUID (code-client-go expects UUID, not slug)
	globalOrgUUID, err := c.ResolveOrgToUUID(globalOrg)
	require.NoError(t, err, "Should be able to resolve global org to UUID")
	assert.Equal(t, globalOrgUUID, configOrg, "CodeConfig should fall back to global org (as UUID) when no folder org is set")

}

// Test_EnrichWithExplain_UsesFolderOrganization is an INTEGRATION TEST that verifies
// getExplainEndpoint() uses the correct folder-specific organization when called for issues
// from different folders.
func Test_EnrichWithExplain_UsesFolderOrganization(t *testing.T) {
	c := testutil.IntegTest(t)
	c.SetSnykCodeEnabled(true)

	// Set up two folders with different orgs
	folderPath1, folderPath2, _, folderOrg1, folderOrg2 := testutil.SetupFoldersWithOrgs(t, c)

	// Set up workspace with the folders
	// This is required for FolderOrganizationForSubPath to work (used by getExplainEndpoint)
	_, _ = workspaceutil.SetupWorkspace(t, c, folderPath1, folderPath2)

	// Create issues with ContentRoot set to different folders
	issue1 := &snyk.Issue{
		ID:               "issue1",
		AffectedFilePath: types.FilePath("file1.js"),
		ContentRoot:      folderPath1,
		Product:          product.ProductCode,
		AdditionalData:   snyk.CodeIssueData{Key: "key1", RuleId: "javascript/sqli"},
		Range:            types.Range{Start: types.Position{Line: 0}, End: types.Position{Line: 1}},
	}

	issue2 := &snyk.Issue{
		ID:               "issue2",
		AffectedFilePath: types.FilePath("file2.js"),
		ContentRoot:      folderPath2,
		Product:          product.ProductCode,
		AdditionalData:   snyk.CodeIssueData{Key: "key2", RuleId: "javascript/sqli"},
		Range:            types.Range{Start: types.Position{Line: 0}, End: types.Position{Line: 1}},
	}

	// Test folder 1
	t.Run("folder 1", func(t *testing.T) {
		endpoint, err := getExplainEndpoint(c, issue1.GetContentRoot())
		require.NoError(t, err, "getExplainEndpoint should succeed for folder 1")
		require.NotNil(t, endpoint, "Endpoint should not be nil")

		// Verify the endpoint URL contains the correct org
		// The endpoint format is: {apiUrl}/rest/orgs/{org}/explain-fix
		assert.Contains(t, endpoint.Path, folderOrg1, "Endpoint should contain folder 1's org")
		assert.NotContains(t, endpoint.Path, folderOrg2, "Endpoint should not contain folder 2's org")
	})

	// Test folder 2
	t.Run("folder 2", func(t *testing.T) {
		endpoint, err := getExplainEndpoint(c, issue2.GetContentRoot())
		require.NoError(t, err, "getExplainEndpoint should succeed for folder 2")
		require.NotNil(t, endpoint, "Endpoint should not be nil")

		// Verify the endpoint URL contains the correct org
		assert.Contains(t, endpoint.Path, folderOrg2, "Endpoint should contain folder 2's org")
		assert.NotContains(t, endpoint.Path, folderOrg1, "Endpoint should not contain folder 1's org")
	})

	// Verify the orgs are different
	assert.NotEqual(t, folderOrg1, folderOrg2, "Folder orgs should be different")
}

// Test_GetAutofixDiffs_UsesFolderOrganization is an INTEGRATION TEST that verifies
// NewAutofixCodeRequestContext() uses the correct folder-specific organization when called
// for issues from different folders.
func Test_GetAutofixDiffs_UsesFolderOrganization(t *testing.T) {
	c := testutil.IntegTest(t)
	c.SetSnykCodeEnabled(true)

	// Set up two folders with different orgs
	folderPath1, folderPath2, _, folderOrg1, folderOrg2 := testutil.SetupFoldersWithOrgs(t, c)

	// Set up workspace with the folders
	// This is required for FolderOrganization to work (used by NewAutofixCodeRequestContext)
	_, _ = workspaceutil.SetupWorkspace(t, c, folderPath1, folderPath2)

	// Test folder 1
	t.Run("folder 1", func(t *testing.T) {
		requestContext := NewAutofixCodeRequestContext(folderPath1)
		require.NotNil(t, requestContext, "RequestContext should not be nil")

		// Verify the request context uses the correct org
		// newCodeRequestContext calls FolderOrganization() which should return folderOrg1
		assert.Equal(t, folderOrg1, requestContext.Org.PublicId, "RequestContext should use folder 1's org")
		assert.NotEqual(t, folderOrg2, requestContext.Org.PublicId, "RequestContext should not use folder 2's org")
	})

	// Test folder 2
	t.Run("folder 2", func(t *testing.T) {
		requestContext := NewAutofixCodeRequestContext(folderPath2)
		require.NotNil(t, requestContext, "RequestContext should not be nil")

		// Verify the request context uses the correct org
		assert.Equal(t, folderOrg2, requestContext.Org.PublicId, "RequestContext should use folder 2's org")
		assert.NotEqual(t, folderOrg1, requestContext.Org.PublicId, "RequestContext should not use folder 1's org")
	})

	// Verify the orgs are different
	assert.NotEqual(t, folderOrg1, folderOrg2, "Folder orgs should be different")
}

// Test_Scan_SetsContentRootCorrectly is an INTEGRATION TEST that verifies
// ContentRoot is set correctly on issues returned from scanning files in different folders.
func Test_Scan_SetsContentRootCorrectly(t *testing.T) {
	c := testutil.IntegTest(t)
	c.SetSnykCodeEnabled(true)
	// Set a fake token so Scan() passes the authentication check
	// We're using FakeCodeScannerClient, so we don't need a real token
	c.SetToken("00000000-0000-0000-0000-000000000001")

	// Set up two folders with different orgs
	folderPath1, folderPath2, _, folderOrg1, folderOrg2 := testutil.SetupFoldersWithOrgs(t, c)

	// Set up workspace with the folders
	// This is required for FolderOrganization to work
	_, _ = workspaceutil.SetupWorkspace(t, c, folderPath1, folderPath2)

	// Set up feature flag service with SAST settings
	fakeFeatureFlagService := featureflag.NewFakeService()
	fakeFeatureFlagService.SastSettings = &sast_contract.SastResponse{SastEnabled: true}

	// Create scanner with FakeCodeScannerClient to avoid real API calls
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	learnMock := mock_learn.NewMockService(ctrl)
	// Set up learn service mock to return empty lessons (needed by issue enhancer)
	learnMock.EXPECT().
		GetLesson(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&learn.Lesson{}, nil).AnyTimes()

	scanner := New(
		c,
		performance.NewInstrumentor(),
		&snyk_api.FakeApiClient{CodeEnabled: true},
		newTestCodeErrorReporter(),
		learnMock,
		fakeFeatureFlagService,
		notification.NewNotifier(),
		NewCodeInstrumentor(),
		newTestCodeErrorReporter(),
		NewFakeCodeScannerClient,
	)

	// Create folder configs with SAST enabled
	folderConfig1 := &types.FolderConfig{
		FolderPath: folderPath1,
		SastSettings: &sast_contract.SastResponse{
			SastEnabled: true,
		},
	}

	folderConfig2 := &types.FolderConfig{
		FolderPath: folderPath2,
		SastSettings: &sast_contract.SastResponse{
			SastEnabled: true,
		},
	}

	// Test folder 1
	t.Run("folder 1", func(t *testing.T) {
		// Scan a file in folder 1
		// The FakeCodeScannerClient will return SARIF that gets converted to issues
		issues, err := scanner.Scan(context.Background(), types.FilePath("test1.js"), folderPath1, folderConfig1)
		require.NoError(t, err, "Scan should succeed for folder 1")
		require.NotEmpty(t, issues, "Should return issues from scan")

		// Verify all issues have ContentRoot set to folderPath1
		for _, issue := range issues {
			assert.Equal(t, folderPath1, issue.GetContentRoot(), "Issue ContentRoot should be set to folder 1")
			// Verify FolderOrganization returns the correct org for this issue's ContentRoot
			issueOrg := c.FolderOrganization(issue.GetContentRoot())
			assert.Equal(t, folderOrg1, issueOrg, "FolderOrganization should return folder 1's org for issue's ContentRoot")
		}
	})

	// Test folder 2
	t.Run("folder 2", func(t *testing.T) {
		// Scan a file in folder 2
		issues, err := scanner.Scan(context.Background(), types.FilePath("test2.js"), folderPath2, folderConfig2)
		require.NoError(t, err, "Scan should succeed for folder 2")
		require.NotEmpty(t, issues, "Should return issues from scan")

		// Verify all issues have ContentRoot set to folderPath2
		for _, issue := range issues {
			assert.Equal(t, folderPath2, issue.GetContentRoot(), "Issue ContentRoot should be set to folder 2")
			// Verify FolderOrganization returns the correct org for this issue's ContentRoot
			issueOrg := c.FolderOrganization(issue.GetContentRoot())
			assert.Equal(t, folderOrg2, issueOrg, "FolderOrganization should return folder 2's org for issue's ContentRoot")
		}
	})

	// Verify the orgs are different
	assert.NotEqual(t, folderOrg1, folderOrg2, "Folder orgs should be different")
}
