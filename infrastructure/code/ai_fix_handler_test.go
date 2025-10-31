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

	"github.com/snyk/snyk-ls/domain/ide/command/testutils"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_getExplainEndpoint(t *testing.T) {
	t.Run("should return default explain endpoint", func(t *testing.T) {
		c := testutil.UnitTest(t)
		random, _ := uuid.NewRandom()
		orgUUID := random.String()

		// Setup fake workspace with the folder
		_, folderPaths := testutils.SetupFakeWorkspace(t, c, 1)
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
		_, folderPaths := testutils.SetupFakeWorkspace(t, c, 1)
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
		_, folderPaths := testutils.SetupFakeWorkspace(t, c, 3)

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
