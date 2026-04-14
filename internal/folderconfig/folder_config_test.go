/*
 * © 2025-2026 Snyk Limited
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

package folderconfig

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"

	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/storage"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_GetOrCreateFolderConfig_shouldStoreEverythingInStorageFile(t *testing.T) {
	conf, storageFile := SetupConfigurationWithStorage(t)
	path := types.FilePath(t.TempDir())
	dir, err := os.UserHomeDir()
	require.NoError(t, err)

	nop := zerolog.Nop()

	// act
	_, err = GetOrCreateFolderConfig(conf, path, &nop)
	require.NoError(t, err)
	types.SetFolderUserSetting(conf, path, types.SettingReferenceFolder, dir)

	// verify - expect normalized paths
	expectedPath := types.PathKey(path)
	expectedReferencePath := types.PathKey(types.FilePath(dir))

	// Verify config is stored in configuration with normalized path
	updatedConfig, err := GetOrCreateFolderConfig(conf, path, &nop)
	require.NoError(t, err)
	require.Equal(t, expectedPath, updatedConfig.FolderPath)

	// Read reference folder directly from configuration
	snap := types.ReadFolderConfigSnapshot(conf, path)
	require.Equal(t, expectedReferencePath, snap.ReferenceFolderPath)

	// Verify folder is present in configuration
	require.True(t, isFolderPersisted(conf, expectedPath))

	// Verify storage file has content
	bytes, err := os.ReadFile(storageFile)
	require.NoError(t, err)
	require.Greater(t, len(bytes), 0)
}

func Test_GetOrCreateFolderConfig_shouldIntegrateGitBranchInformation(t *testing.T) {
	dir := types.FilePath(t.TempDir())
	logger := zerolog.New(zerolog.NewTestWriter(t))
	repo, err := SetupCustomTestRepo(t, dir, "https://github.com/snyk-labs/nodejs-goof", "", &logger, false)
	require.NoError(t, err)

	conf, _ := SetupConfigurationWithStorage(t)

	// Act
	actual, err := GetOrCreateFolderConfig(conf, repo, &logger)
	require.NoError(t, err)

	// Verify we got branches (from configuration)
	snap := types.ReadFolderConfigSnapshot(conf, actual.FolderPath)
	require.Greater(t, len(snap.LocalBranches), 0)
}

func Test_GetOrCreateFolderConfig_shouldReturnExistingFolderConfig(t *testing.T) {
	conf, _ := SetupConfigurationWithStorage(t)
	path := types.FilePath(t.TempDir())
	scanCommandConfig := types.ScanCommandConfig{
		PreScanCommand:              "/a",
		PreScanOnlyReferenceFolder:  false,
		PostScanCommand:             "/b",
		PostScanOnlyReferenceFolder: false,
	}
	referenceDir := t.TempDir()

	logger := zerolog.New(zerolog.NewTestWriter(t))
	fp := string(types.PathKey(path))
	conf.PersistInStorage(configresolver.UserFolderKey(fp, types.SettingReferenceFolder))
	conf.PersistInStorage(configresolver.UserFolderKey(fp, types.SettingAdditionalParameters))
	conf.PersistInStorage(configresolver.FolderMetadataKey(fp, types.SettingLocalBranches))
	conf.PersistInStorage(configresolver.UserFolderKey(fp, types.SettingBaseBranch))
	conf.PersistInStorage(configresolver.UserFolderKey(fp, types.SettingReferenceBranch))
	conf.PersistInStorage(configresolver.UserFolderKey(fp, types.SettingScanCommandConfig))
	conf.Set(configresolver.UserFolderKey(fp, types.SettingReferenceFolder), &configresolver.LocalConfigField{Value: referenceDir, Changed: true})
	conf.Set(configresolver.UserFolderKey(fp, types.SettingAdditionalParameters), &configresolver.LocalConfigField{Value: []string{"--additional-param=asdf", "--additional-param2=add"}, Changed: true})
	conf.Set(configresolver.FolderMetadataKey(fp, types.SettingLocalBranches), []string{"main", "dev"})
	conf.Set(configresolver.UserFolderKey(fp, types.SettingBaseBranch), &configresolver.LocalConfigField{Value: "main", Changed: true})
	conf.Set(configresolver.UserFolderKey(fp, types.SettingReferenceBranch), &configresolver.LocalConfigField{Value: "main", Changed: true})
	conf.Set(configresolver.UserFolderKey(fp, types.SettingScanCommandConfig), &configresolver.LocalConfigField{Value: map[product.Product]types.ScanCommandConfig{product.ProductOpenSource: scanCommandConfig}, Changed: true})

	// Act
	actual, err := GetOrCreateFolderConfig(conf, path, &logger)
	require.NoError(t, err)

	// Verify the folderConfig is what we tried to write.
	require.Equal(t, types.PathKey(path), actual.FolderPath)
	snap := types.ReadFolderConfigSnapshot(conf, path)
	require.Equal(t, types.PathKey(types.FilePath(referenceDir)), snap.ReferenceFolderPath)
	assert.Equal(t, []string{"--additional-param=asdf", "--additional-param2=add"}, snap.AdditionalParameters)
	assert.ElementsMatch(t, []string{"main", "dev"}, snap.LocalBranches)
	assert.Equal(t, "main", snap.BaseBranch)
	assert.Equal(t, scanCommandConfig, snap.ScanCommandConfig[product.ProductOpenSource])
}

func Test_GetOrCreateFolderConfig_shouldReturnLocalBranchesEvenWithoutBaseBranch(t *testing.T) {
	// Create a temporary test Git repository with an initial commit and branches
	branches := []string{"feature-branch", "develop"}
	tempDir := t.TempDir()
	initializeTestGitRepo(t, tempDir, branches)

	conf, _ := SetupConfigurationWithStorage(t)

	logger := zerolog.New(zerolog.NewTestWriter(t))

	// Test GetOrCreateFolderConfig
	folderConfig, err := GetOrCreateFolderConfig(conf, types.FilePath(tempDir), &logger)

	// Should not return an error
	require.NoError(t, err)
	require.NotNil(t, folderConfig)

	// Should have local branches from Git (stored in configuration)
	snap := types.ReadFolderConfigSnapshot(conf, folderConfig.FolderPath)
	assert.ElementsMatch(t, branches, snap.LocalBranches)

	// Base branch should be empty since we couldn't determine it
	assert.Empty(t, snap.BaseBranch)
}

func Test_GetOrCreateFolderConfig_GitLocalBranchesTakePriorityOverStoredConfig(t *testing.T) {
	// Create a temporary test Git repository with an initial commit and branches
	tempDir := t.TempDir()
	gitBranches := []string{"main", "git-feature", "git-develop"}
	initializeTestGitRepo(t, tempDir, gitBranches)

	// Create a folderConfig with outdated branch info
	conf, _ := SetupConfigurationWithStorage(t)
	fc := &types.FolderConfig{FolderPath: types.FilePath(tempDir)}
	fp := string(types.PathKey(fc.FolderPath))
	conf.Set(configresolver.FolderMetadataKey(fp, types.SettingLocalBranches), []string{"old-main", "old-feature"})
	conf.Set(configresolver.UserFolderKey(fp, types.SettingBaseBranch), &configresolver.LocalConfigField{Value: "old-main", Changed: true})
	logger := zerolog.New(zerolog.NewTestWriter(t))

	// Act
	folderConfig, err := GetOrCreateFolderConfig(conf, types.FilePath(tempDir), &logger)
	require.NoError(t, err)
	require.NotNil(t, folderConfig)

	// Git local branches should take priority - we should get fresh branches from Git
	snap := types.ReadFolderConfigSnapshot(conf, folderConfig.FolderPath)
	assert.ElementsMatch(t, gitBranches, snap.LocalBranches)
}

func Test_GetOrCreateFolderConfig_StoredConfigBaseBranchNotOverwrittenByGit(t *testing.T) {
	// Create a temporary test Git repository with an initial commit and main branch
	tempDir := t.TempDir()
	initializeTestGitRepo(t, tempDir, []string{"main"})

	// Set a specific default branch in Git config
	cmd := exec.Command("git", "config", "init.defaultBranch", "git-default-branch")
	cmd.Dir = tempDir
	err := cmd.Run()
	require.NoError(t, err)

	// Create folderConfig with a different base branch than Git default
	conf, _ := SetupConfigurationWithStorage(t)
	storedBaseBranch := "some-stored-base-branch"
	fc := &types.FolderConfig{FolderPath: types.FilePath(tempDir)}
	fp := string(types.PathKey(fc.FolderPath))
	conf.Set(configresolver.UserFolderKey(fp, types.SettingBaseBranch), &configresolver.LocalConfigField{Value: storedBaseBranch, Changed: true})
	conf.Set(configresolver.UserFolderKey(fp, types.SettingReferenceBranch), &configresolver.LocalConfigField{Value: storedBaseBranch, Changed: true})
	logger := zerolog.New(zerolog.NewTestWriter(t))

	// Act
	folderConfig, err := GetOrCreateFolderConfig(conf, types.FilePath(tempDir), &logger)
	require.NoError(t, err)
	require.NotNil(t, folderConfig)

	// Stored config base branch should be preserved, not overwritten by Git default
	bbSnap := types.ReadFolderConfigSnapshot(conf, types.FilePath(tempDir))
	assert.Equal(t, storedBaseBranch, bbSnap.BaseBranch)
}

func Test_GetOrCreateFolderConfig_NewFolder(t *testing.T) {
	conf, _ := SetupConfigurationWithStorage(t)
	path := types.FilePath(t.TempDir())
	logger := zerolog.New(zerolog.NewTestWriter(t))

	// Action
	actual, err := GetOrCreateFolderConfig(conf, path, &logger)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, actual)
	newSnap := types.ReadFolderConfigSnapshot(conf, path)
	assert.False(t, newSnap.OrgSetByUser, "Auto-org should be enabled")
	assert.Empty(t, newSnap.PreferredOrg, "PreferredOrg should be empty for new folders")
	assert.Empty(t, newSnap.AutoDeterminedOrg, "AutoDeterminedOrg will be set by LDX-Sync later")
}

func Test_GetOrCreateFolderConfig_ExistingFolderWithZeroValues(t *testing.T) {
	// Setup: existing folder with Go zero-values
	conf, _ := SetupConfigurationWithStorage(t)
	path := types.FilePath(t.TempDir())
	logger := zerolog.New(zerolog.NewTestWriter(t))

	// Action
	actual, err := GetOrCreateFolderConfig(conf, path, &logger)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, actual)
	zeroSnap := types.ReadFolderConfigSnapshot(conf, path)
	assert.False(t, zeroSnap.OrgSetByUser, "OrgSetByUser should be false for zero-value config")
}

func Test_GetOrCreateFolderConfig_ExistingFolder_PreservesValues(t *testing.T) {
	conf, _ := SetupConfigurationWithStorage(t)
	path := types.FilePath(t.TempDir())
	logger := zerolog.New(zerolog.NewTestWriter(t))

	types.SetPreferredOrgAndOrgSetByUser(conf, path, "some-org-id", true)

	// Action
	actual, err := GetOrCreateFolderConfig(conf, path, &logger)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, actual)
	snap := types.ReadFolderConfigSnapshot(conf, path)
	assert.True(t, snap.OrgSetByUser, "Should remain unchanged")
	assert.Equal(t, "some-org-id", snap.PreferredOrg, "PreferredOrg should be preserved")
}

func Test_BatchUpdateFolderConfigs(t *testing.T) {
	t.Run("updates multiple folders in a single load/save cycle", func(t *testing.T) {
		conf, _ := SetupConfigurationWithStorage(t)
		logger := zerolog.New(zerolog.NewTestWriter(t))

		path1 := types.FilePath(t.TempDir())
		path2 := types.FilePath(t.TempDir())

		configs := []*types.FolderConfig{
			{FolderPath: path1},
			{FolderPath: path2},
		}
		types.SetFolderUserSetting(conf, path1, types.SettingBaseBranch, "main")
		types.SetFolderUserSetting(conf, path1, types.SettingReferenceBranch, "main")
		types.SetFolderUserSetting(conf, path2, types.SettingBaseBranch, "develop")
		types.SetFolderUserSetting(conf, path2, types.SettingReferenceBranch, "develop")
		types.SetPreferredOrgAndOrgSetByUser(conf, path2, "org-1", true)

		err := BatchUpdateFolderConfigs(conf, configs, &logger)
		require.NoError(t, err)

		// Verify both were persisted
		snap1 := types.ReadFolderConfigSnapshot(conf, path1)
		assert.Equal(t, "main", snap1.BaseBranch)

		snap2 := types.ReadFolderConfigSnapshot(conf, path2)
		assert.Equal(t, "develop", snap2.BaseBranch)
		assert.Equal(t, "org-1", snap2.PreferredOrg)
	})

	t.Run("does nothing for empty slice", func(t *testing.T) {
		conf, _ := SetupConfigurationWithStorage(t)
		logger := zerolog.New(zerolog.NewTestWriter(t))

		err := BatchUpdateFolderConfigs(conf, nil, &logger)
		require.NoError(t, err)

		err = BatchUpdateFolderConfigs(conf, []*types.FolderConfig{}, &logger)
		require.NoError(t, err)
	})

	t.Run("preserves existing folder configs not in the batch", func(t *testing.T) {
		conf, _ := SetupConfigurationWithStorage(t)
		logger := zerolog.New(zerolog.NewTestWriter(t))

		// Pre-create a folder config
		existingPath := types.FilePath(t.TempDir())
		types.SetFolderUserSetting(conf, existingPath, types.SettingBaseBranch, "existing-branch")

		// Batch update a different folder
		newPath := types.FilePath(t.TempDir())
		newFc := &types.FolderConfig{FolderPath: newPath}
		types.SetFolderUserSetting(conf, newPath, types.SettingBaseBranch, "new-branch")
		err := BatchUpdateFolderConfigs(conf, []*types.FolderConfig{newFc}, &logger)
		require.NoError(t, err)

		// Verify existing config is preserved
		existingSnap := types.ReadFolderConfigSnapshot(conf, existingPath)
		assert.Equal(t, "existing-branch", existingSnap.BaseBranch)

		// Verify new config was added
		newSnap := types.ReadFolderConfigSnapshot(conf, newPath)
		assert.Equal(t, "new-branch", newSnap.BaseBranch)
	})
}

func Test_CopyFolderConfigValues_DoesNotPersistDstKeys(t *testing.T) {
	conf, storageFile := SetupConfigurationWithStorage(t)

	srcPath := types.FilePath(t.TempDir())
	dstPath := types.FilePath(t.TempDir())

	// Set source values (these get persisted)
	types.SetFolderUserSetting(conf, srcPath, types.SettingBaseBranch, "main")
	types.SetFolderUserSetting(conf, srcPath, types.SettingAdditionalParameters, []string{"-d"})
	types.SetAutoDeterminedOrg(conf, srcPath, "org-uuid")

	// Copy to destination (should NOT persist)
	types.CopyFolderConfigValues(conf, srcPath, dstPath)

	// Values should be accessible in memory
	snap := types.ReadFolderConfigSnapshot(conf, dstPath)
	assert.Equal(t, "main", snap.BaseBranch)
	assert.Equal(t, []string{"-d"}, snap.AdditionalParameters)
	assert.Equal(t, "org-uuid", snap.AutoDeterminedOrg)

	// Storage file should NOT contain destination folder keys
	data, err := os.ReadFile(storageFile)
	require.NoError(t, err)
	dstNormalized := string(types.PathKey(dstPath))
	assert.NotContains(t, string(data), dstNormalized, "destination folder keys should not be persisted to storage")
}

func Test_CopyFolderConfigValues_CopiesAllSettings(t *testing.T) {
	conf, _ := SetupConfigurationWithStorage(t)

	srcPath := types.FilePath(t.TempDir())
	dstPath := types.FilePath(t.TempDir())

	// Set all user and metadata settings on source
	types.SetFolderUserSetting(conf, srcPath, types.SettingBaseBranch, "develop")
	types.SetFolderUserSetting(conf, srcPath, types.SettingReferenceBranch, "develop")
	types.SetFolderUserSetting(conf, srcPath, types.SettingAdditionalParameters, []string{"--all-projects"})
	types.SetFolderUserSetting(conf, srcPath, types.SettingAdditionalEnvironment, "FOO=bar")
	types.SetFolderUserSetting(conf, srcPath, types.SettingReferenceFolder, "/ref/path")
	types.SetFolderUserSetting(conf, srcPath, types.SettingScanCommandConfig, map[product.Product]types.ScanCommandConfig{
		"Snyk Code": {PreScanCommand: "echo test"},
	})
	types.SetPreferredOrgAndOrgSetByUser(conf, srcPath, "my-org", true)
	types.SetAutoDeterminedOrg(conf, srcPath, "auto-org")

	// Copy
	types.CopyFolderConfigValues(conf, srcPath, dstPath)

	// Verify all values copied
	snap := types.ReadFolderConfigSnapshot(conf, dstPath)
	assert.Equal(t, "develop", snap.BaseBranch)
	assert.Equal(t, []string{"--all-projects"}, snap.AdditionalParameters)
	assert.Equal(t, "FOO=bar", snap.AdditionalEnv)
	assert.Equal(t, types.FilePath("/ref/path"), snap.ReferenceFolderPath)
	assert.Equal(t, "my-org", snap.PreferredOrg)
	assert.True(t, snap.OrgSetByUser)
	assert.Equal(t, "auto-org", snap.AutoDeterminedOrg)
}

// isFolderPersisted checks if any well-known config key exists for the folder (for test verification).
func isFolderPersisted(conf configuration.Configuration, path types.FilePath) bool {
	fp := string(types.PathKey(path))
	keys := []string{
		configresolver.UserFolderKey(fp, types.SettingBaseBranch),
		configresolver.UserFolderKey(fp, types.SettingReferenceFolder),
		configresolver.FolderMetadataKey(fp, types.SettingLocalBranches),
	}
	for _, k := range keys {
		if conf.Get(k) != nil {
			return true
		}
	}
	return false
}

func SetupConfigurationWithStorage(t *testing.T) (configuration.Configuration, string) {
	t.Helper()
	conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	storageFile := SetupStorage(t, conf)
	return conf, storageFile
}

func SetupStorage(t *testing.T, conf configuration.Configuration) string {
	t.Helper()
	conf.PersistInStorage(ConfigMainKey)
	tempDir := t.TempDir()
	storageFile := filepath.Join(tempDir, "testStorage")

	// Ensure the parent directory exists and create empty storage file
	if err := os.MkdirAll(filepath.Dir(storageFile), 0755); err != nil {
		require.NoError(t, err)
	}
	if err := os.WriteFile(storageFile, []byte("{}"), 0644); err != nil {
		require.NoError(t, err)
	}

	s, err := storage.NewStorageWithCallbacks(storage.WithStorageFile(storageFile))
	require.NoError(t, err)
	conf.SetStorage(s)
	return storageFile
}
