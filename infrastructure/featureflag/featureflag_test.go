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

package featureflag

import (
	"testing"

	"github.com/snyk/go-application-framework/pkg/local_workflows/code_workflow/sast_contract"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_Fetch_cachesFlags(t *testing.T) {
	c := testutil.UnitTest(t)
	service := New(c).(*serviceImpl)
	org := "test-org-123"

	// First fetch populates cache
	flags1 := service.fetch(org)
	require.NotNil(t, flags1)
	assert.Contains(t, flags1, SnykCodeConsistentIgnores)
	assert.Contains(t, flags1, SnykCodeInlineIgnore)

	// Second fetch returns cached flags
	flags2 := service.fetch(org)
	assert.Equal(t, flags1, flags2)

	// Cache should contain the org
	assert.Contains(t, service.orgToFlag, org)
}

func Test_Fetch_differentOrgsSeparateCaches(t *testing.T) {
	c := testutil.UnitTest(t)
	service := New(c).(*serviceImpl)

	org1 := "org-1"
	org2 := "org-2"

	flags1 := service.fetch(org1)
	assert.NotNil(t, flags1)

	flags2 := service.fetch(org2)
	assert.NotNil(t, flags2)

	// Cache should have both orgs
	assert.Contains(t, service.orgToFlag, org1)
	assert.Contains(t, service.orgToFlag, org2)
	assert.Len(t, service.orgToFlag, 2)
}

func Test_FlushCache_clearsAllOrgs(t *testing.T) {
	c := testutil.UnitTest(t)
	service := New(c).(*serviceImpl)

	org := "test-org"
	_ = service.fetch(org)
	assert.NotEmpty(t, service.orgToFlag)

	service.FlushCache()

	assert.Empty(t, service.orgToFlag)
}

func Test_GetFromFolderConfig_returnsCorrectFlag(t *testing.T) {
	c := testutil.UnitTest(t)
	service := New(c)

	folderPath := types.FilePath("/test/folder")

	// Setup folder config with specific feature flags
	folderConfig := &types.FolderConfig{
		FolderPath: folderPath,
		FeatureFlags: map[string]bool{
			SnykCodeConsistentIgnores: true,
			SnykCodeInlineIgnore:      false,
		},
	}
	c.UpdateFolderConfig(folderConfig)

	// Test existing flags
	value1 := service.GetFromFolderConfig(folderPath, SnykCodeConsistentIgnores)
	assert.True(t, value1)

	value2 := service.GetFromFolderConfig(folderPath, SnykCodeInlineIgnore)
	assert.False(t, value2)

	// Test non-existent flag
	value3 := service.GetFromFolderConfig(folderPath, "nonExistentFlag")
	assert.False(t, value3)
}

func Test_GetFromFolderConfig_multipleFolders(t *testing.T) {
	c := testutil.UnitTest(t)
	service := New(c)

	folder1 := types.FilePath("/folder1")
	folder2 := types.FilePath("/folder2")

	// Setup different flags for each folder
	config1 := &types.FolderConfig{
		FolderPath: folder1,
		FeatureFlags: map[string]bool{
			SnykCodeConsistentIgnores: true,
		},
	}
	config2 := &types.FolderConfig{
		FolderPath: folder2,
		FeatureFlags: map[string]bool{
			SnykCodeConsistentIgnores: false,
		},
	}
	c.UpdateFolderConfig(config1)
	c.UpdateFolderConfig(config2)

	// Each folder should have its own flags
	val1 := service.GetFromFolderConfig(folder1, SnykCodeConsistentIgnores)
	assert.True(t, val1)

	val2 := service.GetFromFolderConfig(folder2, SnykCodeConsistentIgnores)
	assert.False(t, val2)
}

func Test_PopulateFolderConfig_setsFlags(t *testing.T) {
	c := testutil.UnitTest(t)
	service := New(c)

	folderPath := types.FilePath("/test/folder")
	folderConfig := &types.FolderConfig{
		FolderPath: folderPath,
	}

	service.PopulateFolderConfig(folderConfig)

	assert.NotNil(t, folderConfig.FeatureFlags)
	assert.Contains(t, folderConfig.FeatureFlags, SnykCodeConsistentIgnores)
	assert.Contains(t, folderConfig.FeatureFlags, SnykCodeInlineIgnore)
}

func Test_PopulateFolderConfig_multipleFolders(t *testing.T) {
	c := testutil.UnitTest(t)
	service := New(c)

	folder1 := &types.FolderConfig{FolderPath: "/folder1"}
	folder2 := &types.FolderConfig{FolderPath: "/folder2"}

	// Populate both folders
	service.PopulateFolderConfig(folder1)
	service.PopulateFolderConfig(folder2)

	assert.NotNil(t, folder1.FeatureFlags)
	assert.NotNil(t, folder2.FeatureFlags)
}

func Test_FetchSastSettings_cachesSettings(t *testing.T) {
	c := testutil.UnitTest(t)
	service := New(c).(*serviceImpl)
	org := "test-org-sast"

	// First fetch populates cache
	settings1, err1 := service.fetchSastSettings(org)
	require.NoError(t, err1)
	require.NotNil(t, settings1)

	// Second fetch returns cached settings
	settings2, err2 := service.fetchSastSettings(org)
	require.NoError(t, err2)
	assert.Equal(t, settings1, settings2)

	// Cache should contain the org
	assert.Contains(t, service.orgToSastSettings, org)
}

func Test_FetchSastSettings_differentOrgsSeparateCaches(t *testing.T) {
	c := testutil.UnitTest(t)
	service := New(c).(*serviceImpl)

	org1 := "org-sast-1"
	org2 := "org-sast-2"

	settings1, err1 := service.fetchSastSettings(org1)
	require.NoError(t, err1)
	assert.NotNil(t, settings1)

	settings2, err2 := service.fetchSastSettings(org2)
	require.NoError(t, err2)
	assert.NotNil(t, settings2)

	// Cache should have both orgs
	assert.Contains(t, service.orgToSastSettings, org1)
	assert.Contains(t, service.orgToSastSettings, org2)
	assert.Len(t, service.orgToSastSettings, 2)
}

func Test_FlushCache_clearsSastSettings(t *testing.T) {
	c := testutil.UnitTest(t)
	service := New(c).(*serviceImpl)

	org := "test-org-sast"
	_, _ = service.fetchSastSettings(org)
	assert.NotEmpty(t, service.orgToSastSettings)

	service.FlushCache()

	assert.Empty(t, service.orgToSastSettings)
}

func Test_GetSastSettings_returnsSettings(t *testing.T) {
	c := testutil.UnitTest(t)
	service := New(c)

	folderPath := types.FilePath("/test/folder")

	// First populate folder config
	folderConfig := &types.FolderConfig{
		FolderPath: folderPath,
	}
	service.PopulateFolderConfig(folderConfig)
	c.UpdateFolderConfig(folderConfig)

	// Then get SAST settings
	settings := service.GetSastSettingsFromFolderConfig(folderPath)
	assert.NotNil(t, settings)
}

func Test_GetSastSettings_returnsDefaultWhenNotFound(t *testing.T) {
	c := testutil.UnitTest(t)
	service := New(c)

	folderPath := types.FilePath("/nonexistent/folder")

	settings := service.GetSastSettingsFromFolderConfig(folderPath)
	assert.NotNil(t, settings)
	// Should return default struct, not nil
	assert.Equal(t, &sast_contract.SastResponse{}, settings)
}

func Test_PopulateFolderConfig_populatesSastSettings(t *testing.T) {
	c := testutil.UnitTest(t)
	service := New(c)

	folderPath := types.FilePath("/test/folder")
	folderConfig := &types.FolderConfig{
		FolderPath: folderPath,
	}

	service.PopulateFolderConfig(folderConfig)

	assert.NotNil(t, folderConfig.FeatureFlags)
	assert.NotNil(t, folderConfig.SastSettings)
}

func Test_PopulateFolderConfig_continuesOnSastSettingsError(t *testing.T) {
	c := testutil.UnitTest(t)
	service := New(c)

	folderPath := types.FilePath("/test/folder")
	folderConfig := &types.FolderConfig{
		FolderPath: folderPath,
	}

	// Even if SAST settings fetch fails, feature flags should still be populated
	service.PopulateFolderConfig(folderConfig)

	assert.NotNil(t, folderConfig.FeatureFlags)
}
