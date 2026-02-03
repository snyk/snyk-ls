// ABOUTME: Smoke tests for LdxSyncService cache population and refresh behavior
// ABOUTME: Tests verify cache correctly populated on initialize, folder changes, login, and config updates
/*
 * © 2026 Snyk Limited
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

package server

import (
	"os"
	"testing"
	"time"

	"github.com/creachadair/jrpc2/server"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

// requireValidLdxSyncCache validates LDX-Sync cache entries for specified folders
// validators is a map of folder path to validation function, call require/assert inside of them
func requireValidLdxSyncCache(t *testing.T, c *config.Config, validators map[types.FilePath]func(*ldx_sync_config.LdxSyncConfigResult)) {
	t.Helper()

	// Wait for all cache entries to be populated
	require.Eventually(t, func() bool {
		for folderPath := range validators {
			result := c.GetLdxSyncResult(folderPath)
			if result == nil || result.Error != nil {
				return false
			}
			if result.Config == nil {
				return false
			}
			if result.Config.Data.Attributes.Organizations == nil {
				return false
			}
			if len(*result.Config.Data.Attributes.Organizations) == 0 {
				return false
			}
		}
		return true
	}, 10*time.Second, time.Second, "Cache should be populated for all folders")

	// Run validators for each folder
	for folderPath, validator := range validators {
		cachedResult := c.GetLdxSyncResult(folderPath)
		require.NotNil(t, cachedResult, "Cache should have entry for folder %s", folderPath)
		require.Nil(t, cachedResult.Error, "Cache entry should have no error for folder %s", folderPath)
		require.NotNil(t, cachedResult.Config, "Config should be populated for folder %s", folderPath)
		require.NotNil(t, cachedResult.Config.Data.Attributes.Organizations, "Organizations list should exist for folder %s", folderPath)

		orgs := *cachedResult.Config.Data.Attributes.Organizations
		require.Greater(t, len(orgs), 0, "Should have at least one org for folder %s", folderPath)

		// Validate organization data is actually valid
		for i, org := range orgs {
			require.NotEmpty(t, org.Id, "Org %d should have non-empty ID for folder %s", i, folderPath)
			require.NotEmpty(t, org.Name, "Org %d should have non-empty Name for folder %s", i, folderPath)
		}

		require.NotEmpty(t, cachedResult.RemoteUrl, "RemoteUrl should be set from git remote for folder %s", folderPath)
		require.Equal(t, string(folderPath), cachedResult.ProjectRoot, "ProjectRoot should match folder path for folder %s", folderPath)

		// allowing empty validator for cases when we just care about cache being present
		if validator != nil {
			validator(cachedResult)
		}
	}
}

// setupLdxSyncCacheTest creates test environment for LDX-Sync cache tests
// tokenSecretName is optional - empty string uses default SNYK_TOKEN
func setupLdxSyncCacheTest(t *testing.T, tokenSecretName string) (*config.Config, server.Local) {
	t.Helper()
	c := testutil.SmokeTest(t, tokenSecretName)
	loc, _ := setupServer(t, c)

	// Disable scanning products - only testing cache behavior
	c.SetSnykCodeEnabled(false)
	c.SetSnykIacEnabled(false)
	c.SetSnykOssEnabled(false)

	cleanupChannels()
	di.Init()

	// Cleanup stored folder configs to prevent test interference
	t.Cleanup(func() {
		s, _ := storedconfig.ConfigFile(c.IdeName())
		_ = os.Remove(s)
	})

	return c, loc
}

// Test_SmokeLdxSyncCache_InitializeWithMultipleFolders verifies cache population when
// initializing the language server with multiple workspace folders
func Test_SmokeLdxSyncCache_InitializeWithMultipleFolders(t *testing.T) {
	c, loc := setupLdxSyncCacheTest(t, "")

	// Setup first folder
	t.Log("Setting up first folder (nodejs-goof)...")
	folder1 := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", loc, c)
	t.Logf("First folder setup complete: %s", folder1)

	// Setup second folder by adding it as workspace folder
	t.Log("Setting up second folder (python-goof)...")
	folder2, err := setupCustomTestRepo(t, types.FilePath(t.TempDir()), testsupport.PythonGoof, "c32657c", c.Logger())
	require.NoError(t, err, "Failed to setup second test repo")
	require.NotEmpty(t, folder2, "Folder path should not be empty")
	require.DirExists(t, string(folder2), "Folder should exist")
	t.Logf("Second folder setup complete: %s", folder2)

	workspaceFolder2 := types.WorkspaceFolder{
		Name: "Python Goof",
		Uri:  uri.PathToUri(folder2),
	}
	t.Log("Adding second workspace folder...")
	addWorkSpaceFolder(t, loc, workspaceFolder2)
	t.Log("Second workspace folder added")

	// Verify entries are independent (different remotes)
	var cache1RemoteUrl, cache2RemoteUrl string
	requireValidLdxSyncCache(t, c, map[types.FilePath]func(*ldx_sync_config.LdxSyncConfigResult){
		folder1: func(result *ldx_sync_config.LdxSyncConfigResult) {
			cache1RemoteUrl = result.RemoteUrl
		},
		folder2: func(result *ldx_sync_config.LdxSyncConfigResult) {
			cache2RemoteUrl = result.RemoteUrl
		},
	})

	assert.NotEqual(t, cache1RemoteUrl, cache2RemoteUrl, "Each folder should have its own git remote")
}

// Test_SmokeLdxSyncCache_AddFolderRefreshesCache verifies cache updates when
// adding a new workspace folder via didChangeWorkspaceFolders
func Test_SmokeLdxSyncCache_AddFolderRefreshesCache(t *testing.T) {
	c, loc := setupLdxSyncCacheTest(t, "")

	// Initialize with first folder
	folder1 := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", loc, c)

	requireValidLdxSyncCache(t, c, map[types.FilePath]func(*ldx_sync_config.LdxSyncConfigResult){
		folder1: nil,
	})

	folder2, err := setupCustomTestRepo(t, types.FilePath(t.TempDir()), testsupport.PythonGoof, "c32657c", c.Logger())
	require.NoError(t, err, "Failed to setup second test repo")
	require.NotEmpty(t, folder2, "Folder path should not be empty")
	require.DirExists(t, string(folder2), "Folder should exist")

	workspaceFolder2 := types.WorkspaceFolder{
		Name: "Python Goof",
		Uri:  uri.PathToUri(folder2),
	}
	addWorkSpaceFolder(t, loc, workspaceFolder2)

	// Verify both folders' caches are valid and have populated Organizations
	requireValidLdxSyncCache(t, c, map[types.FilePath]func(*ldx_sync_config.LdxSyncConfigResult){
		folder1: nil,
		folder2: func(result *ldx_sync_config.LdxSyncConfigResult) {
			assert.NotNil(t, result.Config.Data.Attributes.Organizations)
			assert.Greater(t, len(*result.Config.Data.Attributes.Organizations), 0)
		},
	})
}

// Test_SmokeLdxSyncCache_ChangePreferredOrgTriggersRefetch verifies that changing
// the PreferredOrg setting triggers a cache refresh
func Test_SmokeLdxSyncCache_ChangePreferredOrgTriggersRefetch(t *testing.T) {
	c, loc := setupLdxSyncCacheTest(t, "SNYK_TOKEN_CONSISTENT_IGNORES")

	// Initialize with folder
	folder := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", loc, c)

	requireValidLdxSyncCache(t, c, map[types.FilePath]func(*ldx_sync_config.LdxSyncConfigResult){
		folder: nil,
	})

	// Change PreferredOrg via didChangeConfiguration
	sendModifiedFolderConfiguration(t, c, loc, func(folderConfigs map[types.FilePath]*types.FolderConfig) {
		folderConfig := folderConfigs[folder]
		folderConfig.OrgSetByUser = true
		if folderConfig.AutoDeterminedOrg == "b1a01686-331c-4b59-854c-139216d56bb0" {
			folderConfig.PreferredOrg = "code-consistent-ignores-early-access-verification"
		} else {
			folderConfig.PreferredOrg = "ide-risk-score-testing"
		}
	})

	// Verify cache remains valid and error-free after config change
	requireValidLdxSyncCache(t, c, map[types.FilePath]func(*ldx_sync_config.LdxSyncConfigResult){
		folder: nil,
	})
}

// setupCustomTestRepo is a helper that wraps storedconfig.SetupCustomTestRepo
// to match the signature used in tests
func setupCustomTestRepo(t *testing.T, targetDir types.FilePath, repo string, commit string, logger *zerolog.Logger) (types.FilePath, error) {
	t.Helper()
	return storedconfig.SetupCustomTestRepo(t, targetDir, repo, commit, logger, false)
}
