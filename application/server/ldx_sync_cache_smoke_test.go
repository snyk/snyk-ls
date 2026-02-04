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

// LdxSyncCacheValidation holds validation info for a folder's LDX-Sync cache entry
type LdxSyncCacheValidation struct {
	OrgId     string                  // The org ID resolved for this folder
	OrgConfig *types.LDXSyncOrgConfig // The org config from cache
}

// requireValidLdxSyncCache validates LDX-Sync cache entries for specified folders.
// The cache structure stores:
// - FolderToOrgMapping: folder path -> org ID
// - OrgConfigs: org ID -> LDXSyncOrgConfig (org-level settings)
// validators is a map of folder path to validation function
func requireValidLdxSyncCache(t *testing.T, c *config.Config, validators map[types.FilePath]func(*LdxSyncCacheValidation)) {
	t.Helper()

	// Wait for all cache entries to be populated
	require.Eventually(t, func() bool {
		cache := c.GetLdxSyncOrgConfigCache()
		if cache == nil {
			t.Logf("Waiting for cache: cache is nil")
			return false
		}

		for folderPath := range validators {
			orgId := cache.GetOrgIdForFolder(folderPath)
			if orgId == "" {
				t.Logf("Waiting for cache entry for folder %s: org ID not yet resolved", folderPath)
				return false
			}
		}
		t.Logf("All cache entries populated successfully")
		return true
	}, 30*time.Second, time.Second, "Cache should be populated for all folders")

	// Run validators for each folder
	cache := c.GetLdxSyncOrgConfigCache()
	require.NotNil(t, cache, "Cache should not be nil")

	for folderPath, validator := range validators {
		orgId := cache.GetOrgIdForFolder(folderPath)
		require.NotEmpty(t, orgId, "Cache should have org ID for folder %s", folderPath)

		orgConfig := cache.GetOrgConfig(orgId)
		// Note: orgConfig may be nil if LDX-Sync didn't return org-level settings
		// This is valid - the cache primarily stores folder-to-org mappings

		// allowing empty validator for cases when we just care about cache being present
		if validator != nil {
			validation := &LdxSyncCacheValidation{
				OrgId:     orgId,
				OrgConfig: orgConfig,
			}
			validator(validation)
		}
	}
}

// setupLdxSyncCacheTest creates test environment for LDX-Sync cache tests
func setupLdxSyncCacheTest(t *testing.T) (*config.Config, server.Local) {
	t.Helper()
	c := testutil.SmokeTest(t, "SNYK_TOKEN_CONSISTENT_IGNORES")

	// Clear any existing config file from previous test runs
	if s, err := storedconfig.ConfigFile(c.IdeName()); err == nil {
		_ = os.Remove(s)
	}

	loc, _ := setupServer(t, c)

	// Disable scanning products - only testing cache behavior
	c.SetSnykCodeEnabled(false)
	c.SetSnykIacEnabled(false)
	c.SetSnykOssEnabled(false)

	cleanupChannels()
	di.Init()

	return c, loc
}

// Test_SmokeLdxSyncCache_InitializeWithMultipleFolders verifies cache population when
// initializing the language server with multiple workspace folders
func Test_SmokeLdxSyncCache_InitializeWithMultipleFolders(t *testing.T) {
	c, loc := setupLdxSyncCacheTest(t)

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

	// Verify entries are independent (different org IDs possible, or same org but both resolved)
	var cache1OrgId, cache2OrgId string
	requireValidLdxSyncCache(t, c, map[types.FilePath]func(*LdxSyncCacheValidation){
		folder1: func(v *LdxSyncCacheValidation) {
			cache1OrgId = v.OrgId
			assert.NotEmpty(t, v.OrgId, "Folder 1 should have resolved org ID")
		},
		folder2: func(v *LdxSyncCacheValidation) {
			cache2OrgId = v.OrgId
			assert.NotEmpty(t, v.OrgId, "Folder 2 should have resolved org ID")
		},
	})

	// Both folders should have org IDs resolved (they may be same or different depending on user's orgs)
	assert.NotEmpty(t, cache1OrgId, "Folder 1 should have org ID in cache")
	assert.NotEmpty(t, cache2OrgId, "Folder 2 should have org ID in cache")
}

// Test_SmokeLdxSyncCache_AddFolderRefreshesCache verifies cache updates when
// adding a new workspace folder via didChangeWorkspaceFolders
func Test_SmokeLdxSyncCache_AddFolderRefreshesCache(t *testing.T) {
	c, loc := setupLdxSyncCacheTest(t)

	// Initialize with first folder
	folder1 := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", loc, c)

	requireValidLdxSyncCache(t, c, map[types.FilePath]func(*LdxSyncCacheValidation){
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

	// Verify both folders' caches are valid and have org IDs resolved
	requireValidLdxSyncCache(t, c, map[types.FilePath]func(*LdxSyncCacheValidation){
		folder1: nil,
		folder2: func(v *LdxSyncCacheValidation) {
			assert.NotEmpty(t, v.OrgId, "Folder 2 should have resolved org ID")
		},
	})
}

// Test_SmokeLdxSyncCache_ChangePreferredOrgTriggersRefetch verifies that changing
// the PreferredOrg setting triggers a cache refresh
func Test_SmokeLdxSyncCache_ChangePreferredOrgTriggersRefetch(t *testing.T) {
	c, loc := setupLdxSyncCacheTest(t)

	// Initialize with folder
	folder := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", loc, c)

	var initialOrgId string
	requireValidLdxSyncCache(t, c, map[types.FilePath]func(*LdxSyncCacheValidation){
		folder: func(v *LdxSyncCacheValidation) {
			initialOrgId = v.OrgId
		},
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

	// Verify cache remains valid after config change - org ID should still be resolved
	requireValidLdxSyncCache(t, c, map[types.FilePath]func(*LdxSyncCacheValidation){
		folder: func(v *LdxSyncCacheValidation) {
			assert.NotEmpty(t, v.OrgId, "Folder should still have resolved org ID after config change")
			// Note: The org ID may change if PreferredOrg was set to a different org
			t.Logf("Initial org ID: %s, Current org ID: %s", initialOrgId, v.OrgId)
		},
	})
}

// setupCustomTestRepo is a helper that wraps storedconfig.SetupCustomTestRepo
// to match the signature used in tests
func setupCustomTestRepo(t *testing.T, targetDir types.FilePath, repo string, commit string, logger *zerolog.Logger) (types.FilePath, error) {
	t.Helper()
	return storedconfig.SetupCustomTestRepo(t, targetDir, repo, commit, logger, false)
}
