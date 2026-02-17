/*
 * © 2022-2026 Snyk Limited
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

	"github.com/snyk/code-client-go/pkg/code/sast_contract"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/testutil/workspaceutil"
	"github.com/snyk/snyk-ls/internal/types"
)

const testOrgUUID = "00000000-0000-0000-0000-000000000001"

func TestGetCodeApiUrlForFolder(t *testing.T) {
	t.Run("should return an error when folder path argument is an empty string", func(t *testing.T) {
		c := testutil.UnitTest(t)

		_, err := GetCodeApiUrlForFolder(c, "")
		assert.ErrorContains(t, err, "no folder specified when trying to determine Snyk Code API URL")
	})

	t.Run("should return an error when workspace folder not found", func(t *testing.T) {
		c := testutil.UnitTest(t)

		// Setup workspace with a folder, but try to access a different path
		folderPaths := []types.FilePath{types.FilePath("/fake/test-folder-0")}
		_, _ = workspaceutil.SetupWorkspace(t, c, folderPaths...)

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

		// Clear env since it takes priority over the config.
		t.Setenv(config.DeeproxyApiUrlKey, "")

		// Clear the default org set by UnitTest to test the error case
		c.SetOrganization("")

		// Set up the API URL to use for the test.
		c.UpdateApiEndpoints("https://api.snykgov.io")

		// Setup workspace but configure folder without org
		folderPaths := []types.FilePath{types.FilePath("/fake/test-folder-0")}
		_, _ = workspaceutil.SetupWorkspace(t, c, folderPaths...)

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

		// Clear env since it takes priority over the config.
		t.Setenv(config.DeeproxyApiUrlKey, "")

		// Set up the API URL to use for the test.
		c.UpdateApiEndpoints("https://api.snykgov.io")

		// Setup workspace with 2 folders
		folderPaths := []types.FilePath{
			types.FilePath("/fake/test-folder-0"),
			types.FilePath("/fake/test-folder-1"),
		}
		_, _ = workspaceutil.SetupWorkspace(t, c, folderPaths...)

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

	t.Run("should return SCLE URL as-is in non-FedRAMP when local engine is enabled", func(t *testing.T) {
		c := testutil.UnitTest(t)

		// Clear env since it takes priority over local engine.
		t.Setenv(config.DeeproxyApiUrlKey, "")

		// Set up the API URL to use for the test.
		c.UpdateApiEndpoints("https://api.snyk.io")

		const localEngineURL = "http://localhost:8080"
		folder, err := setupFakeWorkspaceFolderWithSAST(t, c, localEngineURL)
		require.NoError(t, err)

		actual, err := GetCodeApiUrlForFolder(c, folder)
		require.NoError(t, err)

		// In non-FedRAMP, SCLE URL should be returned as-is
		assert.Equal(t, localEngineURL, actual)
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

					// Clear env since it takes priority over the config.
					t.Setenv(config.DeeproxyApiUrlKey, "")

					folder, err := setupFakeWorkspaceFolderWithSAST(t, c, "")
					require.NoError(t, err)
					c.UpdateApiEndpoints(input)

					expected := "https://api." + instance + ".io/hidden/orgs/" + testOrgUUID + "/code"

					actual, err := GetCodeApiUrlForFolder(c, folder)
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

					// Clear env since it takes priority over the config.
					t.Setenv(config.DeeproxyApiUrlKey, "")

					folder, err := setupFakeWorkspaceFolderWithSAST(t, c, "")
					require.NoError(t, err)
					c.UpdateApiEndpoints(input)

					actual, err := GetCodeApiUrlForFolder(c, folder)
					require.NoError(t, err)
					assert.Contains(t, actual, expected)
				})
			}
		}
	})

	t.Run("Default deeproxy url for code api", func(t *testing.T) {
		c := testutil.UnitTest(t)

		// Clear env since it takes priority over default deeproxy url.
		t.Setenv(config.DeeproxyApiUrlKey, "")

		folder, err := setupFakeWorkspaceFolderWithSAST(t, c, "")
		require.NoError(t, err)

		url, err := GetCodeApiUrlForFolder(c, folder)
		require.NoError(t, err)
		assert.Equal(t, config.DefaultDeeproxyApiUrl, url)
	})
}

func setupFakeWorkspaceFolderWithSAST(t *testing.T, c *config.Config, localEngineURL string) (types.FilePath, error) {
	t.Helper()

	folderPaths := []types.FilePath{types.FilePath("/fake/test-folder-0")}
	_, _ = workspaceutil.SetupWorkspace(t, c, folderPaths...)
	folderPath := folderPaths[0]

	sastResponse := sast_contract.SastResponse{
		SastEnabled: true,
		LocalCodeEngine: sast_contract.LocalCodeEngine{
			AllowCloudUpload: false,
			Url:              localEngineURL,
			Enabled:          localEngineURL != "",
		},
		Org:                         testOrgUUID,
		SupportedLanguages:          nil,
		ReportFalsePositivesEnabled: false,
		AutofixEnabled:              false,
	}

	folderConfig := &types.FolderConfig{
		FolderPath:                  folderPath,
		PreferredOrg:                testOrgUUID,
		AutoDeterminedOrg:           testOrgUUID,
		OrgSetByUser:                true,
		OrgMigratedFromGlobalConfig: true,
		SastSettings:                &sastResponse,
	}

	err := storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), folderConfig, c.Logger())

	return folderPath, err
}
