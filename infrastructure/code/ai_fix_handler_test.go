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

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/testutil/workspaceutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_getExplainEndpoint(t *testing.T) {
	t.Run("should return default explain endpoint", func(t *testing.T) {
		c := testutil.UnitTest(t)
		random, _ := uuid.NewRandom()
		orgUUID := random.String()

		// Setup fake workspace with the folder
		folderPaths := []types.FilePath{types.FilePath("/fake/test-folder-0")}
		_, _ = workspaceutil.SetupWorkspace(t, c, folderPaths...)
		folder := folderPaths[0]

		err := storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), &types.FolderConfig{
			FolderPath:                  folder,
			PreferredOrg:                orgUUID,
			OrgSetByUser:                true,
			OrgMigratedFromGlobalConfig: true,
		}, c.Logger())
		require.NoError(t, err)

		actualEndpoint, err := getExplainEndpoint(c, folder)
		require.NoError(t, err)
		expectedEndpoint := "https://api.snyk.io/rest/orgs/" + orgUUID + "/explain-fix?version=2024-10-15"
		assert.Equal(t, expectedEndpoint, actualEndpoint.String())
	})

	t.Run("should return correct explain endpoint for non-default API endpoint", func(t *testing.T) {
		c := testutil.UnitTest(t)
		random, _ := uuid.NewRandom()
		orgUUID := random.String()
		c.UpdateApiEndpoints("https://test.snyk.io")

		// Setup fake workspace with the folder
		folderPaths := []types.FilePath{types.FilePath("/fake/test-folder-0")}
		_, _ = workspaceutil.SetupWorkspace(t, c, folderPaths...)
		folder := folderPaths[0]

		err := storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), &types.FolderConfig{
			FolderPath:                  folder,
			PreferredOrg:                orgUUID,
			OrgSetByUser:                true,
			OrgMigratedFromGlobalConfig: true,
		}, c.Logger())
		require.NoError(t, err)

		actualEndpoint, err := getExplainEndpoint(c, folder)
		require.NoError(t, err)
		expectedEndpoint := "https://test.snyk.io/rest/orgs/" + orgUUID + "/explain-fix?version=2024-10-15"
		assert.Equal(t, expectedEndpoint, actualEndpoint.String())
	})

	t.Run("should find correct folder when passing subdirectory in multi-folder workspace", func(t *testing.T) {
		c := testutil.UnitTest(t)

		// Setup fake workspace with 3 folders
		folderPaths := []types.FilePath{
			types.FilePath("/fake/test-folder-0"),
			types.FilePath("/fake/test-folder-1"),
			types.FilePath("/fake/test-folder-2"),
		}
		_, _ = workspaceutil.SetupWorkspace(t, c, folderPaths...)

		// Configure each folder with different orgs
		folder1UUID, _ := uuid.NewRandom()
		folder2UUID, _ := uuid.NewRandom()
		folder3UUID, _ := uuid.NewRandom()

		err := storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), &types.FolderConfig{
			FolderPath:                  folderPaths[0],
			PreferredOrg:                folder1UUID.String(),
			OrgSetByUser:                true,
			OrgMigratedFromGlobalConfig: true,
		}, c.Logger())
		require.NoError(t, err)

		err = storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), &types.FolderConfig{
			FolderPath:                  folderPaths[1],
			PreferredOrg:                folder2UUID.String(),
			OrgSetByUser:                true,
			OrgMigratedFromGlobalConfig: true,
		}, c.Logger())
		require.NoError(t, err)

		err = storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), &types.FolderConfig{
			FolderPath:                  folderPaths[2],
			PreferredOrg:                folder3UUID.String(),
			OrgSetByUser:                true,
			OrgMigratedFromGlobalConfig: true,
		}, c.Logger())
		require.NoError(t, err)

		// Pass a subdirectory of the second folder
		subdirectory := types.FilePath(string(folderPaths[1]) + "/src/main/java")

		actualEndpoint, err := getExplainEndpoint(c, subdirectory)
		require.NoError(t, err)

		// Should use the second folder's organization
		expectedEndpoint := "https://api.snyk.io/rest/orgs/" + folder2UUID.String() + "/explain-fix?version=2024-10-15"
		assert.Equal(t, expectedEndpoint, actualEndpoint.String())
	})
}

func Test_getExplainEndpoint_UsesFolderOrganization(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetSnykCodeEnabled(true)

	// Set up two folders with different orgs
	folderPath1 := types.FilePath("/fake/test-folder-1")
	folderPath2 := types.FilePath("/fake/test-folder-2")
	folderOrg1, _ := uuid.NewRandom()
	folderOrg2, _ := uuid.NewRandom()

	// Set up workspace with the folders
	// This is required for FolderOrganizationForSubPath to work (used by getExplainEndpoint)
	_, _ = workspaceutil.SetupWorkspace(t, c, folderPath1, folderPath2)

	// Configure folder 1 with org1
	err := storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), &types.FolderConfig{
		FolderPath:                  folderPath1,
		PreferredOrg:                folderOrg1.String(),
		OrgSetByUser:                true,
		OrgMigratedFromGlobalConfig: true,
	}, c.Logger())
	require.NoError(t, err)

	// Configure folder 2 with org2
	err = storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), &types.FolderConfig{
		FolderPath:                  folderPath2,
		PreferredOrg:                folderOrg2.String(),
		OrgSetByUser:                true,
		OrgMigratedFromGlobalConfig: true,
	}, c.Logger())
	require.NoError(t, err)

	// Test folder 1
	t.Run("folder 1", func(t *testing.T) {
		endpoint, err := getExplainEndpoint(c, folderPath1)
		require.NoError(t, err, "getExplainEndpoint should succeed for folder 1")
		require.NotNil(t, endpoint, "Endpoint should not be nil")

		// Verify the endpoint URL contains the correct org
		// The endpoint format is: {apiUrl}/rest/orgs/{org}/explain-fix
		assert.Contains(t, endpoint.Path, folderOrg1.String(), "Endpoint should contain folder 1's org")
		assert.NotContains(t, endpoint.Path, folderOrg2.String(), "Endpoint should not contain folder 2's org")
	})

	// Test folder 2
	t.Run("folder 2", func(t *testing.T) {
		endpoint, err := getExplainEndpoint(c, folderPath2)
		require.NoError(t, err, "getExplainEndpoint should succeed for folder 2")
		require.NotNil(t, endpoint, "Endpoint should not be nil")

		// Verify the endpoint URL contains the correct org
		assert.Contains(t, endpoint.Path, folderOrg2.String(), "Endpoint should contain folder 2's org")
		assert.NotContains(t, endpoint.Path, folderOrg1.String(), "Endpoint should not contain folder 1's org")
	})

	// Verify the orgs are different
	assert.NotEqual(t, folderOrg1.String(), folderOrg2.String(), "Folder orgs should be different")
}
