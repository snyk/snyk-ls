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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/testutil/workspaceutil"
)

// Test_CodeConfig_UsesFolderOrganization is an INTEGRATION TEST that verifies
// createCodeConfig() sets the correct organization in CodeConfig based on FolderOrganization()
// for different folders. This test uses testutil.IntegTest() to run in the integration test suite.
func Test_CodeConfig_UsesFolderOrganization(t *testing.T) {
	c := testutil.IntegTest(t)
	c.SetSnykCodeEnabled(true)

	// Set up two folders with different orgs
	folderPath1, folderPath2, _, folderOrg1, folderOrg2 := testutil.SetupFoldersWithOrgs(t, c)

	// Set up workspace with the folders
	// This is required for FolderOrganizationForSubPath to work
	_, _ = workspaceutil.SetupWorkspace(t, c, folderPath1, folderPath2)

	// Create a scanner to test createCodeConfig
	scanner := &Scanner{
		C: c,
	}

	// Get FolderConfig for folder 1
	folderConfig1 := c.FolderConfig(folderPath1)
	require.NotNil(t, folderConfig1, "FolderConfig for folder1 should not be nil")

	// Test folder 1: verify createCodeConfig() sets org in CodeConfig
	codeConfig1, err := scanner.createCodeConfig(folderConfig1)
	require.NoError(t, err)
	require.NotNil(t, codeConfig1)
	configOrg1 := codeConfig1.Organization()
	assert.Equal(t, folderOrg1, configOrg1, "CodeConfig for folder1 should use folder1's org")

	// Get FolderConfig for folder 2
	folderConfig2 := c.FolderConfig(folderPath2)
	require.NotNil(t, folderConfig2, "FolderConfig for folder2 should not be nil")

	// Test folder 2: verify createCodeConfig() sets different org in CodeConfig
	codeConfig2, err := scanner.createCodeConfig(folderConfig2)
	require.NoError(t, err)
	require.NotNil(t, codeConfig2)
	configOrg2 := codeConfig2.Organization()
	assert.Equal(t, folderOrg2, configOrg2, "CodeConfig for folder2 should use folder2's org")

	// Verify the orgs are different
	assert.NotEqual(t, folderOrg1, folderOrg2, "Folder orgs should be different")
}

func Test_CodeConfig_FallsBackToGlobalOrg(t *testing.T) {
	c := testutil.IntegTest(t)
	c.SetSnykCodeEnabled(true)

	folderPath, globalOrg := testutil.SetupGlobalOrgOnly(t, c)

	// Set up workspace with the folder
	// This is required for FolderOrganizationForSubPath to work (used by GetCodeApiUrlForFolder)
	_, _ = workspaceutil.SetupWorkspace(t, c, folderPath)

	// Create a scanner to test createCodeConfig
	scanner := &Scanner{
		C: c,
	}

	// Get FolderConfig for the folder
	folderConfig := c.FolderConfig(folderPath)
	require.NotNil(t, folderConfig, "FolderConfig should not be nil")

	// Test: verify createCodeConfig() uses global org as fallback
	codeConfig, err := scanner.createCodeConfig(folderConfig)
	require.NoError(t, err)
	require.NotNil(t, codeConfig)
	configOrg := codeConfig.Organization()
	assert.Equal(t, globalOrg, configOrg, "CodeConfig should fall back to global org when no folder org is set")
}

func Test_GetCodeApiUrlForFolder_UsesFolderOrganization(t *testing.T) {
	c := testutil.IntegTest(t)

	// Set up FedRAMP environment
	c.UpdateApiEndpoints("https://api.snykgov.io")

	// Set up two folders with different orgs
	folderPath1, folderPath2, _, folderOrg1, folderOrg2 := testutil.SetupFoldersWithOrgs(t, c)

	// Set up workspace with the folders
	// This is required for FolderOrganizationForSubPath to work
	_, _ = workspaceutil.SetupWorkspace(t, c, folderPath1, folderPath2)

	// Test folder 1: verify GetCodeApiUrlForFolder() includes folder1's org in FedRAMP URL
	apiUrl1, err := GetCodeApiUrlForFolder(c, folderPath1)
	require.NoError(t, err)
	assert.Contains(t, apiUrl1, "/hidden/orgs/"+folderOrg1+"/code", "FedRAMP API URL for folder1 should include folder1's org")

	// Test folder 2: verify GetCodeApiUrlForFolder() includes folder2's org in FedRAMP URL
	apiUrl2, err := GetCodeApiUrlForFolder(c, folderPath2)
	require.NoError(t, err)
	assert.Contains(t, apiUrl2, "/hidden/orgs/"+folderOrg2+"/code", "FedRAMP API URL for folder2 should include folder2's org")

	// Verify the URLs are different
	assert.NotEqual(t, apiUrl1, apiUrl2, "API URLs for different folders should be different")
}

func Test_GetExplainEndpoint_UsesFolderOrganization(t *testing.T) {
	c := testutil.IntegTest(t)

	// Set up two folders with different orgs
	folderPath1, folderPath2, _, folderOrg1, folderOrg2 := testutil.SetupFoldersWithOrgs(t, c)

	// Set up workspace with the folders
	// This is required for FolderOrganizationForSubPath to work
	_, _ = workspaceutil.SetupWorkspace(t, c, folderPath1, folderPath2)

	// Test folder 1: verify getExplainEndpoint() includes folder1's org
	endpoint1, err := getExplainEndpoint(c, folderPath1)
	require.NoError(t, err)
	endpoint1Str := endpoint1.String()
	assert.Contains(t, endpoint1Str, "/rest/orgs/"+folderOrg1+"/explain-fix", "Explain endpoint for folder1 should include folder1's org")

	// Test folder 2: verify getExplainEndpoint() includes folder2's org
	endpoint2, err := getExplainEndpoint(c, folderPath2)
	require.NoError(t, err)
	endpoint2Str := endpoint2.String()
	assert.Contains(t, endpoint2Str, "/rest/orgs/"+folderOrg2+"/explain-fix", "Explain endpoint for folder2 should include folder2's org")

	// Verify the endpoints are different
	assert.NotEqual(t, endpoint1Str, endpoint2Str, "Explain endpoints for different folders should be different")
}

func Test_GetExplainEndpoint_FallsBackToGlobalOrg(t *testing.T) {
	c := testutil.IntegTest(t)

	folderPath, globalOrg := testutil.SetupGlobalOrgOnly(t, c)

	// Set up workspace with the folder
	// This is required for FolderOrganizationForSubPath to work
	_, _ = workspaceutil.SetupWorkspace(t, c, folderPath)

	// Test: verify getExplainEndpoint() uses global org as fallback
	endpoint, err := getExplainEndpoint(c, folderPath)
	require.NoError(t, err)
	endpointStr := endpoint.String()
	assert.Contains(t, endpointStr, "/rest/orgs/"+globalOrg+"/explain-fix", "Explain endpoint should fall back to global org when no folder org is set")
}

func Test_NewAutofixCodeRequestContext_UsesFolderOrganization(t *testing.T) {
	c := testutil.IntegTest(t)

	// Set up two folders with different orgs
	folderPath1, folderPath2, _, folderOrg1, folderOrg2 := testutil.SetupFoldersWithOrgs(t, c)

	// Set up workspace with the folders
	// This is required for FolderOrganizationForSubPath to work
	_, _ = workspaceutil.SetupWorkspace(t, c, folderPath1, folderPath2)

	// Test folder 1: verify NewAutofixCodeRequestContext() uses folder1's org
	requestContext1 := NewAutofixCodeRequestContext(folderPath1)
	require.NotNil(t, requestContext1)
	assert.Equal(t, folderOrg1, requestContext1.Org.PublicId, "Request context for folder1 should use folder1's org")
	assert.Equal(t, "IDE", requestContext1.Initiator, "Request context should have correct initiator")
	assert.Equal(t, "language-server", requestContext1.Flow, "Request context should have correct flow")

	// Test folder 2: verify NewAutofixCodeRequestContext() uses folder2's org
	requestContext2 := NewAutofixCodeRequestContext(folderPath2)
	require.NotNil(t, requestContext2)
	assert.Equal(t, folderOrg2, requestContext2.Org.PublicId, "Request context for folder2 should use folder2's org")
	assert.Equal(t, "IDE", requestContext2.Initiator, "Request context should have correct initiator")
	assert.Equal(t, "language-server", requestContext2.Flow, "Request context should have correct flow")

	// Verify different folders get different orgs
	assert.NotEqual(t, requestContext1.Org.PublicId, requestContext2.Org.PublicId, "Different folders should have different orgs in request context")
}

func Test_NewAutofixCodeRequestContext_FallsBackToGlobalOrg(t *testing.T) {
	c := testutil.IntegTest(t)

	// Set up a global org but no folder orgs
	folderPath, globalOrg := testutil.SetupGlobalOrgOnly(t, c)

	// Verify FolderOrganization() returns the global org (fallback)
	folderOrg := c.FolderOrganization(folderPath)
	assert.Equal(t, globalOrg, folderOrg, "FolderOrganization() should fall back to global org when no folder org is configured")

	// Verify NewAutofixCodeRequestContext() uses the global org
	requestContext := NewAutofixCodeRequestContext(folderPath)
	require.NotNil(t, requestContext)
	assert.Equal(t, globalOrg, requestContext.Org.PublicId, "Request context should fall back to global org when no folder org is configured")
	assert.Equal(t, "IDE", requestContext.Initiator, "Request context should have correct initiator")
	assert.Equal(t, "language-server", requestContext.Flow, "Request context should have correct flow")
}

// Test_SarifConverter_UsesFolderOrganization verifies
// SarifConverter.toIssues() sets ContentRoot correctly for different folders, ensuring
// issues are associated with the correct folder (and thus the correct org via FolderOrganization()).
func Test_SarifConverter_UsesFolderOrganization(t *testing.T) {
	c := testutil.IntegTest(t)
	c.SetSnykCodeEnabled(true)

	// Set up two folders with different orgs
	folderPath1, folderPath2, _, folderOrg1, folderOrg2 := testutil.SetupFoldersWithOrgs(t, c)

	// Create a minimal SARIF response for testing
	sarifJSON := `{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": [{
			"tool": {
				"driver": {
					"name": "SnykCode",
					"rules": [{
						"id": "test-rule",
						"properties": {
							"categories": ["Security"]
						}
					}]
				}
			},
			"results": [{
				"ruleId": "test-rule",
				"level": "error",
				"message": {
					"text": "Test issue"
				},
				"locations": [{
					"physicalLocation": {
						"artifactLocation": {
							"uri": "test.java"
						},
						"region": {
							"startLine": 1,
							"startColumn": 1,
							"endLine": 1,
							"endColumn": 10
						}
					}
				}]
			}]
		}]
	}`

	// Convert SARIF to issues for folder 1
	issues1, err := ConvertSARIFJSONToIssues(c.Logger(), c.HoverVerbosity(), []byte(sarifJSON), string(folderPath1))
	require.NoError(t, err)
	require.NotEmpty(t, issues1, "Should have at least one issue")

	// Verify ContentRoot is set to folder1's path
	for _, issue := range issues1 {
		assert.Equal(t, folderPath1, issue.GetContentRoot(), "Issue ContentRoot should be set to folder1's path")
		// Verify we can get the correct org from the ContentRoot
		orgFromContentRoot := c.FolderOrganization(issue.GetContentRoot())
		assert.Equal(t, folderOrg1, orgFromContentRoot, "FolderOrganization() should return folder1's org from ContentRoot")
	}

	// Convert SARIF to issues for folder 2
	issues2, err := ConvertSARIFJSONToIssues(c.Logger(), c.HoverVerbosity(), []byte(sarifJSON), string(folderPath2))
	require.NoError(t, err)
	require.NotEmpty(t, issues2, "Should have at least one issue")

	// Verify ContentRoot is set to folder2's path
	for _, issue := range issues2 {
		assert.Equal(t, folderPath2, issue.GetContentRoot(), "Issue ContentRoot should be set to folder2's path")
		// Verify we can get the correct org from the ContentRoot
		orgFromContentRoot := c.FolderOrganization(issue.GetContentRoot())
		assert.Equal(t, folderOrg2, orgFromContentRoot, "FolderOrganization() should return folder2's org from ContentRoot")
	}

	// Verify different folders produce issues with different ContentRoots
	assert.NotEqual(t, issues1[0].GetContentRoot(), issues2[0].GetContentRoot(), "Issues from different folders should have different ContentRoots")
}

// Test_SarifConverter_FallsBackToGlobalOrg verifies that when converting SARIF to issues
// for a folder without a folder-specific org, the ContentRoot is still set correctly,
// allowing FolderOrganization() to fall back to the global org.
func Test_SarifConverter_FallsBackToGlobalOrg(t *testing.T) {
	c := testutil.IntegTest(t)
	c.SetSnykCodeEnabled(true)

	// Set up a global org but no folder orgs
	folderPath, globalOrg := testutil.SetupGlobalOrgOnly(t, c)

	// Create a minimal SARIF response for testing
	sarifJSON := `{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": [{
			"tool": {
				"driver": {
					"name": "SnykCode",
					"rules": [{
						"id": "test-rule",
						"properties": {
							"categories": ["Security"]
						}
					}]
				}
			},
			"results": [{
				"ruleId": "test-rule",
				"level": "error",
				"message": {
					"text": "Test issue"
				},
				"locations": [{
					"physicalLocation": {
						"artifactLocation": {
							"uri": "test.java"
						},
						"region": {
							"startLine": 1,
							"startColumn": 1,
							"endLine": 1,
							"endColumn": 10
						}
					}
				}]
			}]
		}]
	}`

	// Convert SARIF to issues
	issues, err := ConvertSARIFJSONToIssues(c.Logger(), c.HoverVerbosity(), []byte(sarifJSON), string(folderPath))
	require.NoError(t, err)
	require.NotEmpty(t, issues, "Should have at least one issue")

	// Verify ContentRoot is set to the folder path
	for _, issue := range issues {
		assert.Equal(t, folderPath, issue.GetContentRoot(), "Issue ContentRoot should be set to folder path")
		// Verify FolderOrganization() falls back to global org
		orgFromContentRoot := c.FolderOrganization(issue.GetContentRoot())
		assert.Equal(t, globalOrg, orgFromContentRoot, "FolderOrganization() should fall back to global org when no folder org is configured")
	}
}
