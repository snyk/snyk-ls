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

	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/folderconfig"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/testutil/workspaceutil"
	"github.com/snyk/snyk-ls/internal/types"
)

const testOrgUUID = "00000000-0000-0000-0000-000000000001"

func TestGetCodeApiUrlForFolder(t *testing.T) {
	t.Run("should return an error when folder path argument is an empty string", func(t *testing.T) {
		engine := testutil.UnitTest(t)

		_, err := GetCodeApiUrlForFolder(engine, testutil.DefaultConfigResolver(engine), "")
		assert.ErrorContains(t, err, "no folder specified when trying to determine Snyk Code API URL")
	})

	t.Run("should return an error when workspace folder not found", func(t *testing.T) {
		engine := testutil.UnitTest(t)

		// Setup workspace with a folder, but try to access a different path
		folderPaths := []types.FilePath{types.FilePath("/fake/test-folder-0")}
		_, _ = workspaceutil.SetupWorkspace(t, engine, folderPaths...)

		engineConfig := engine.GetConfiguration()
		types.SetPreferredOrgAndOrgSetByUser(engineConfig, folderPaths[0], "test-org", true)
		err := folderconfig.UpdateFolderConfig(engineConfig, &types.FolderConfig{FolderPath: folderPaths[0]}, engine.GetLogger())
		require.NoError(t, err)

		// Path that doesn't exist in any workspace folder
		_, err = GetCodeApiUrlForFolder(engine, testutil.DefaultConfigResolver(engine), "/nonexistent/path")
		assert.ErrorContains(t, err, "no workspace folder found for path")
	})

	t.Run("should return error when organization not configured in FedRAMP", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		config.SetOrganization(engine.GetConfiguration(), "")

		// Clear env since it takes priority over the config.
		t.Setenv(config.DeeproxyApiUrlKey, "")
		// Clear the default org set by UnitTest so this scenario exercises missing-org behavior.
		config.SetOrganization(engine.GetConfiguration(), "")

		// Set up the API URL to use for the test.
		config.UpdateApiEndpointsOnConfig(engine.GetConfiguration(), "https://api.snykgov.io")

		// Setup workspace but configure folder without org
		folderPaths := []types.FilePath{types.FilePath("/fake/test-folder-0")}
		_, _ = workspaceutil.SetupWorkspace(t, engine, folderPaths...)

		engineConfig := engine.GetConfiguration()
		types.SetPreferredOrgAndOrgSetByUser(engineConfig, folderPaths[0], "", false)
		err := folderconfig.UpdateFolderConfig(engineConfig, &types.FolderConfig{FolderPath: folderPaths[0]}, engine.GetLogger())
		require.NoError(t, err)

		_, err = GetCodeApiUrlForFolder(engine, testutil.DefaultConfigResolver(engine), folderPaths[0])
		assert.ErrorContains(t, err, "organization is required in a fedramp environment")
	})

	t.Run("should use correct folder org when passing subdirectory in FedRAMP", func(t *testing.T) {
		engine := testutil.UnitTest(t)

		// Clear env since it takes priority over the config.
		t.Setenv(config.DeeproxyApiUrlKey, "")

		// Set up the API URL to use for the test.
		config.UpdateApiEndpointsOnConfig(engine.GetConfiguration(), "https://api.snykgov.io")

		// Setup workspace with 2 folders
		folderPaths := []types.FilePath{
			types.FilePath("/fake/test-folder-0"),
			types.FilePath("/fake/test-folder-1"),
		}
		_, _ = workspaceutil.SetupWorkspace(t, engine, folderPaths...)

		folder1UUID, _ := uuid.NewRandom()
		folder2UUID, _ := uuid.NewRandom()

		engineConfig := engine.GetConfiguration()
		types.SetPreferredOrgAndOrgSetByUser(engineConfig, folderPaths[0], folder1UUID.String(), true)
		err := folderconfig.UpdateFolderConfig(engineConfig, &types.FolderConfig{FolderPath: folderPaths[0]}, engine.GetLogger())
		require.NoError(t, err)

		types.SetPreferredOrgAndOrgSetByUser(engineConfig, folderPaths[1], folder2UUID.String(), true)
		err = folderconfig.UpdateFolderConfig(engineConfig, &types.FolderConfig{FolderPath: folderPaths[1]}, engine.GetLogger())
		require.NoError(t, err)

		// Pass subdirectory of second folder
		subdirectory := types.FilePath(string(folderPaths[1]) + "/src/java")

		actual, err := GetCodeApiUrlForFolder(engine, testutil.DefaultConfigResolver(engine), subdirectory)
		assert.NoError(t, err)

		// Should use second folder's org
		expected := "https://api.snykgov.io/hidden/orgs/" + folder2UUID.String() + "/code"
		assert.Equal(t, expected, actual)
	})

	t.Run("should return SCLE URL as-is in non-FedRAMP when local engine is enabled", func(t *testing.T) {
		engine := testutil.UnitTest(t)

		// Clear env since it takes priority over local engine.
		t.Setenv(config.DeeproxyApiUrlKey, "")

		// Set up the API URL to use for the test.
		config.UpdateApiEndpointsOnConfig(engine.GetConfiguration(), "https://api.snyk.io")

		const localEngineURL = "http://localhost:8080"
		folder, err := setupFakeWorkspaceFolderWithSAST(t, engine, localEngineURL)
		require.NoError(t, err)

		actual, err := GetCodeApiUrlForFolder(engine, testutil.DefaultConfigResolver(engine), folder)
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
					engine := testutil.UnitTest(t)

					// Clear env since it takes priority over the config.
					t.Setenv(config.DeeproxyApiUrlKey, "")

					folder, err := setupFakeWorkspaceFolderWithSAST(t, engine, "")
					require.NoError(t, err)
					config.UpdateApiEndpointsOnConfig(engine.GetConfiguration(), input)

					expected := "https://api." + instance + ".io/hidden/orgs/" + testOrgUUID + "/code"

					actual, err := GetCodeApiUrlForFolder(engine, testutil.DefaultConfigResolver(engine), folder)
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
					engine := testutil.UnitTest(t)

					// Clear env since it takes priority over the config.
					t.Setenv(config.DeeproxyApiUrlKey, "")

					folder, err := setupFakeWorkspaceFolderWithSAST(t, engine, "")
					require.NoError(t, err)
					config.UpdateApiEndpointsOnConfig(engine.GetConfiguration(), input)

					actual, err := GetCodeApiUrlForFolder(engine, testutil.DefaultConfigResolver(engine), folder)
					require.NoError(t, err)
					assert.Contains(t, actual, expected)
				})
			}
		}
	})

	t.Run("Default deeproxy url for code api", func(t *testing.T) {
		engine := testutil.UnitTest(t)

		// Clear env since it takes priority over default deeproxy url.
		t.Setenv(config.DeeproxyApiUrlKey, "")

		folder, err := setupFakeWorkspaceFolderWithSAST(t, engine, "")
		require.NoError(t, err)

		url, err := GetCodeApiUrlForFolder(engine, testutil.DefaultConfigResolver(engine), folder)
		require.NoError(t, err)
		assert.Equal(t, config.DefaultDeeproxyApiUrl, url)
	})
}

func setupFakeWorkspaceFolderWithSAST(t *testing.T, engine workflow.Engine, localEngineURL string) (types.FilePath, error) {
	t.Helper()

	folderPaths := []types.FilePath{types.FilePath("/fake/test-folder-0")}
	_, _ = workspaceutil.SetupWorkspace(t, engine, folderPaths...)
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

	engineConfig := engine.GetConfiguration()
	types.SetPreferredOrgAndOrgSetByUser(engineConfig, folderPath, testOrgUUID, true)
	types.SetAutoDeterminedOrg(engineConfig, folderPath, testOrgUUID)
	types.SetSastSettings(engineConfig, folderPath, &sastResponse)

	folderConfig := &types.FolderConfig{
		FolderPath:     folderPath,
		ConfigResolver: testutil.DefaultConfigResolver(engine),
	}

	err := folderconfig.UpdateFolderConfig(engineConfig, folderConfig, engine.GetLogger())

	return folderPath, err
}
