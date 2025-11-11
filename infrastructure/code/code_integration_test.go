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
)

// Test_CodeConfig_UsesFolderOrganization is an INTEGRATION TEST that verifies
// createCodeConfig() sets the correct organization in CodeConfig based on FolderOrganization()
// for different folders. This test uses testutil.UnitTest() to avoid making actual API calls,
// as it only tests configuration initialization methods, not the full workflow execution.
func Test_CodeConfig_UsesFolderOrganization(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetSnykCodeEnabled(true)

	// Set up two folders with different orgs
	folderPath1, folderPath2, _, folderOrg1, folderOrg2 := testutil.SetupFoldersWithOrgs(t, c)

	// Create a scanner to test createCodeConfig
	scanner := &Scanner{
		C: c,
	}

	// Test folder 1: verify createCodeConfig() sets org in CodeConfig
	codeConfig1, err := scanner.createCodeConfig(folderPath1)
	require.NoError(t, err)
	require.NotNil(t, codeConfig1)
	configOrg1 := codeConfig1.Organization()
	assert.Equal(t, folderOrg1, configOrg1, "CodeConfig for folder1 should use folder1's org")

	// Test folder 2: verify createCodeConfig() sets different org in CodeConfig
	codeConfig2, err := scanner.createCodeConfig(folderPath2)
	require.NoError(t, err)
	require.NotNil(t, codeConfig2)
	configOrg2 := codeConfig2.Organization()
	assert.Equal(t, folderOrg2, configOrg2, "CodeConfig for folder2 should use folder2's org")

	// Verify the orgs are different
	assert.NotEqual(t, folderOrg1, folderOrg2, "Folder orgs should be different")
}

func Test_CodeConfig_FallsBackToGlobalOrg(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetSnykCodeEnabled(true)

	folderPath, globalOrg := testutil.SetupGlobalOrgOnly(t, c)

	// Create a scanner to test createCodeConfig
	scanner := &Scanner{
		C: c,
	}

	// Test: verify createCodeConfig() uses global org as fallback
	codeConfig, err := scanner.createCodeConfig(folderPath)
	require.NoError(t, err)
	require.NotNil(t, codeConfig)
	configOrg := codeConfig.Organization()
	assert.Equal(t, globalOrg, configOrg, "CodeConfig should fall back to global org when no folder org is set")
}

func Test_GetCodeApiUrlForFolder_UsesFolderOrganization(t *testing.T) {
	c := testutil.UnitTest(t)

	// Set up FedRAMP environment
	c.UpdateApiEndpoints("https://api.snykgov.io")

	// Set up two folders with different orgs
	folderPath1, folderPath2, _, folderOrg1, folderOrg2 := testutil.SetupFoldersWithOrgs(t, c)

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
	c := testutil.UnitTest(t)

	// Set up two folders with different orgs
	folderPath1, folderPath2, _, folderOrg1, folderOrg2 := testutil.SetupFoldersWithOrgs(t, c)

	// Test folder 1: verify getExplainEndpoint() includes folder1's org
	endpoint1 := getExplainEndpoint(c, folderPath1)
	endpoint1Str := endpoint1.String()
	assert.Contains(t, endpoint1Str, "/rest/orgs/"+folderOrg1+"/explain-fix", "Explain endpoint for folder1 should include folder1's org")

	// Test folder 2: verify getExplainEndpoint() includes folder2's org
	endpoint2 := getExplainEndpoint(c, folderPath2)
	endpoint2Str := endpoint2.String()
	assert.Contains(t, endpoint2Str, "/rest/orgs/"+folderOrg2+"/explain-fix", "Explain endpoint for folder2 should include folder2's org")

	// Verify the endpoints are different
	assert.NotEqual(t, endpoint1Str, endpoint2Str, "Explain endpoints for different folders should be different")
}

func Test_GetExplainEndpoint_FallsBackToGlobalOrg(t *testing.T) {
	c := testutil.UnitTest(t)

	folderPath, globalOrg := testutil.SetupGlobalOrgOnly(t, c)

	// Test: verify getExplainEndpoint() uses global org as fallback
	endpoint := getExplainEndpoint(c, folderPath)
	endpointStr := endpoint.String()
	assert.Contains(t, endpointStr, "/rest/orgs/"+globalOrg+"/explain-fix", "Explain endpoint should fall back to global org when no folder org is set")
}

func Test_NewAutofixCodeRequestContext_UsesFolderOrganization(t *testing.T) {
	c := testutil.UnitTest(t)

	// Set up two folders with different orgs
	folderPath1, folderPath2, _, folderOrg1, folderOrg2 := testutil.SetupFoldersWithOrgs(t, c)

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
	c := testutil.UnitTest(t)

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
