/*
 * © 2022-2024 Snyk Limited
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

func TestGetCodeApiUrlForFolder(t *testing.T) {
	t.Run("should return Snyk Code API URL for non-FedRAMP", func(t *testing.T) {
		c := testutil.UnitTest(t)
		c.UpdateApiEndpoints("https://api.snyk.io")

		// Any folder should work for non-FedRAMP
		actual, err := GetCodeApiUrlForFolder(c, "/some/path")
		assert.NoError(t, err)
		assert.Equal(t, c.SnykCodeApi(), actual)
	})

	t.Run("should return error when folder path argument is the empty string in FedRAMP", func(t *testing.T) {
		c := testutil.UnitTest(t)
		c.UpdateApiEndpoints("https://api.snykgov.io")
		c.SetOrganization("test-org")

		_, err := GetCodeApiUrlForFolder(c, "")
		assert.ErrorContains(t, err, "specifying a folder is required in a fedramp environment")
	})

	t.Run("should return error when workspace folder not found in FedRAMP", func(t *testing.T) {
		c := testutil.UnitTest(t)
		c.UpdateApiEndpoints("https://api.snykgov.io")
		c.SetOrganization("test-org")

		// Setup workspace with a folder, but try to access a different path
		_, folderPaths := testutils.SetupFakeWorkspace(t, c, 1)

		err := storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), &types.FolderConfig{
			FolderPath:                  folderPaths[0],
			PreferredOrg:                "test-org",
			OrgSetByUser:                true,
			OrgMigratedFromGlobalConfig: true,
		}, c.Logger())
		require.NoError(t, err)

		// Path that doesn't exist in any workspace folder
		_, err = GetCodeApiUrlForFolder(c, "/nonexistent/path")
		assert.ErrorContains(t, err, "no workspace folder found for path")
	})

	t.Run("should return error when organization not configured in FedRAMP", func(t *testing.T) {
		c := testutil.UnitTest(t)
		c.UpdateApiEndpoints("https://api.snykgov.io")

		// Setup workspace but configure folder without org
		_, folderPaths := testutils.SetupFakeWorkspace(t, c, 1)

		err := storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), &types.FolderConfig{
			FolderPath:                  folderPaths[0],
			PreferredOrg:                "",
			OrgSetByUser:                false,
			OrgMigratedFromGlobalConfig: true,
		}, c.Logger())
		require.NoError(t, err)

		_, err = GetCodeApiUrlForFolder(c, folderPaths[0])
		assert.ErrorContains(t, err, "organization is required in a fedramp environment")
	})

	t.Run("should use correct folder org when passing subdirectory in FedRAMP", func(t *testing.T) {
		c := testutil.UnitTest(t)
		c.UpdateApiEndpoints("https://api.snykgov.io")

		// Setup workspace with 2 folders
		_, folderPaths := testutils.SetupFakeWorkspace(t, c, 2)

		folder1UUID, _ := uuid.NewRandom()
		folder2UUID, _ := uuid.NewRandom()

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

		// Pass subdirectory of second folder
		subdirectory := types.FilePath(string(folderPaths[1]) + "/src/java")

		actual, err := GetCodeApiUrlForFolder(c, subdirectory)
		assert.NoError(t, err)

		// Should use second folder's org
		expected := "https://api.snykgov.io/hidden/orgs/" + folder2UUID.String() + "/code"
		assert.Equal(t, expected, actual)
	})

	t.Run("Snykgov instances code api url generation with various URL formats", func(t *testing.T) {
		var snykgovInstances = []string{
			"snykgov",
			"fedramp-alpha.snykgov",
		}

		for _, instance := range snykgovInstances {
			inputList := []string{
				"https://" + instance + ".io/api/v1",
				"https://" + instance + ".io/api",
				"https://app." + instance + ".io/api",
				"https://app." + instance + ".io/api/v1",
				"https://api." + instance + ".io/api/v1",
				"https://api." + instance + ".io/v1",
				"https://api." + instance + ".io",
				"https://api." + instance + ".io?something=here",
			}

			for _, input := range inputList {
				t.Run(instance+" with "+input, func(t *testing.T) {
					c := testutil.UnitTest(t)

					t.Setenv("DEEPROXY_API_URL", "")

					random, _ := uuid.NewRandom()
					orgUUID := random.String()

					c.UpdateApiEndpoints(input)

					// Setup workspace with folder for FedRAMP testing
					_, folderPaths := testutils.SetupFakeWorkspace(t, c, 1)
					folderPath := folderPaths[0]

					err := storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), &types.FolderConfig{
						FolderPath:                  folderPath,
						PreferredOrg:                orgUUID,
						OrgMigratedFromGlobalConfig: true,
						OrgSetByUser:                true,
					}, c.Logger())
					require.NoError(t, err)

					expected := "https://api." + instance + ".io/hidden/orgs/" + orgUUID + "/code"

					actual, err := GetCodeApiUrlForFolder(c, folderPath)
					require.NoError(t, err)
					assert.Contains(t, actual, expected)
				})
			}
		}
	})

	t.Run("Deeproxy instances code api url generation", func(t *testing.T) {
		var deeproxyInstances = []string{
			"snyk",
			"au.snyk",
		}

		for _, instance := range deeproxyInstances {
			inputList := []string{
				"https://" + instance + ".io/api/v1",
				"https://" + instance + ".io/api",
				"https://app." + instance + ".io/api",
				"https://app." + instance + ".io/api/v1",
				"https://api." + instance + ".io/api/v1",
				"https://api." + instance + ".io/v1",
				"https://api." + instance + ".io",
				"https://api." + instance + ".io?something=here",
			}

			expected := "https://deeproxy." + instance + ".io"

			for _, input := range inputList {
				t.Run(instance+" with "+input, func(t *testing.T) {
					c := testutil.UnitTest(t)

					t.Setenv("DEEPROXY_API_URL", "")

					c.UpdateApiEndpoints(input)

					// For non-FedRAMP, any folder works
					actual, err := GetCodeApiUrlForFolder(c, "/some/path")
					require.NoError(t, err)
					assert.Contains(t, actual, expected)
				})
			}
		}
	})

	t.Run("Default deeproxy url for code api", func(t *testing.T) {
		c := testutil.UnitTest(t)

		// For non-FedRAMP, any folder works
		url, err := GetCodeApiUrlForFolder(c, "/some/path")
		require.NoError(t, err)
		assert.Equal(t, c.SnykCodeApi(), url)
	})
}
