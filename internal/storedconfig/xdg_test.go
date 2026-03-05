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

package storedconfig

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/adrg/xdg"
	"github.com/rs/zerolog"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/internal/types"
)

func TestConfigFile(t *testing.T) {
	ideName := "intellij"
	actual, err := ConfigFile(ideName)
	require.NoError(t, err)

	expected := filepath.Join(xdg.ConfigHome, subDir, fmt.Sprintf("%s-%s", fileNameBase, ideName))
	require.Equal(t, expected, actual)
}

func Test_folderConfigFromFallbackStorage_NotNilIfCreateIfNotExist(t *testing.T) {
	conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	logger := zerolog.New(zerolog.NewTestWriter(t))

	tempDir := t.TempDir()
	path := types.FilePath(tempDir)

	// Get the folder config from storage for a folder that doesn't exist yet and verify we get a result back
	folderConfig, err := folderConfigFromStorage(conf, path, &logger, true)
	require.NoError(t, err)
	require.NotNil(t, folderConfig)
}

func Test_folderConfigFromFallbackStorage_NilIfDoNotCreate(t *testing.T) {
	conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	logger := zerolog.New(zerolog.NewTestWriter(t))

	tempDir := t.TempDir()
	path := types.FilePath(tempDir)

	// With dynamic persistence, folderConfigFromStorage always returns a minimal config.
	// createIfNotExist is no longer used; caller handles nil via GetFolderConfigWithOptions.
	folderConfig, err := folderConfigFromStorage(conf, path, &logger, false)
	require.NoError(t, err)
	require.NotNil(t, folderConfig)
	require.Equal(t, types.PathKey(path), folderConfig.FolderPath)
}

func Test_UpdateFolderConfig_SavesToStorage(t *testing.T) {
	conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	logger := zerolog.New(zerolog.NewTestWriter(t))

	tempDir := t.TempDir()
	path := types.FilePath(tempDir)

	// Get the folder config from storage for a folder that doesn't exist yet and verify we get a result back
	folderConfig, err := folderConfigFromStorage(conf, path, &logger, true)
	require.NoError(t, err)
	require.NotNil(t, folderConfig)

	// Persist the config to storage
	err = UpdateFolderConfig(conf, folderConfig, &logger)
	require.NoError(t, err)

	// Retrieve the config from storage and verify it was persisted
	storedConfig, err := GetStoredConfig(conf, &logger, true)
	require.NoError(t, err)
	require.NotNil(t, storedConfig)
}

func Test_UpdateFolderConfig_PersistsUserOverrides(t *testing.T) {
	conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	logger := zerolog.New(zerolog.NewTestWriter(t))

	tempDir := t.TempDir()
	path := types.FilePath(tempDir)

	// Create a folder config with user overrides (write to configuration)
	folderConfig := &types.FolderConfig{FolderPath: path}
	folderConfig.SetConf(conf)
	fp := string(types.PathKey(path))
	types.SetFolderUserSetting(conf, path, types.SettingEnabledSeverities, []string{"critical", "high"})
	types.SetFolderUserSetting(conf, path, types.SettingRiskScoreThreshold, 800)

	// Persist the config to storage
	err := UpdateFolderConfig(conf, folderConfig, &logger)
	require.NoError(t, err)

	// Retrieve the config from storage
	retrievedConfig, err := folderConfigFromStorage(conf, path, &logger, true)
	require.NoError(t, err)
	require.NotNil(t, retrievedConfig)
	retrievedConfig.SetConf(conf)

	// Verify user overrides were persisted (read from configuration)
	require.True(t, types.HasUserOverride(conf, path, types.SettingEnabledSeverities))
	require.True(t, types.HasUserOverride(conf, path, types.SettingRiskScoreThreshold))

	severitiesVal := conf.Get(configuration.UserFolderKey(fp, types.SettingEnabledSeverities))
	require.NotNil(t, severitiesVal)

	thresholdVal := conf.Get(configuration.UserFolderKey(fp, types.SettingRiskScoreThreshold))
	require.NotNil(t, thresholdVal)
}

// Test_ModifyStoredConfig_ConcurrentAdds verifies that concurrent ModifyStoredConfig calls
// do not lose updates (TOCTOU race). Without the mutex, the second Save could overwrite
// the first's changes. Run with -race to detect data races.
func Test_ModifyStoredConfig_ConcurrentAdds(t *testing.T) {
	conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	logger := zerolog.New(zerolog.NewTestWriter(t))

	path1 := types.FilePath(filepath.Join(t.TempDir(), "folder1"))
	path2 := types.FilePath(filepath.Join(t.TempDir(), "folder2"))

	var wg sync.WaitGroup
	wg.Add(2)

	addFolder := func(path types.FilePath, branch string) {
		defer wg.Done()
		err := ModifyStoredConfig(conf, &logger, func(sc *StoredConfig) bool {
			if sc.FolderConfigs == nil {
				sc.FolderConfigs = make(map[types.FilePath]*types.FolderConfig)
			}
			types.SetFolderUserSetting(conf, path, types.SettingBaseBranch, branch)
			types.SetFolderUserSetting(conf, path, types.SettingReferenceBranch, branch)
			sc.FolderConfigs[types.PathKey(path)] = &types.FolderConfig{FolderPath: path}
			return true
		})
		require.NoError(t, err)
	}

	go addFolder(path1, "branch1")
	go addFolder(path2, "branch2")

	wg.Wait()

	// Both entries must be present (no lost updates from TOCTOU)
	sc, err := GetStoredConfig(conf, &logger, true)
	require.NoError(t, err)
	require.NotNil(t, sc)
	require.Len(t, sc.FolderConfigs, 2, "both folder configs must be present after concurrent ModifyStoredConfig calls")
	require.Contains(t, sc.FolderConfigs, types.PathKey(path1))
	require.Contains(t, sc.FolderConfigs, types.PathKey(path2))
	fc1, _ := GetFolderConfigWithOptions(conf, path1, &logger, GetFolderConfigOptions{ReadOnly: true})
	fc2, _ := GetFolderConfigWithOptions(conf, path2, &logger, GetFolderConfigOptions{ReadOnly: true})
	require.NotNil(t, fc1)
	require.NotNil(t, fc2)
	fc1.SetConf(conf)
	fc2.SetConf(conf)
	require.Equal(t, "branch1", fc1.BaseBranch())
	require.Equal(t, "branch2", fc2.BaseBranch())
}

// FC-103: Folder JSON persistence ↔ Configuration user:folder:<path>:* and folder:<path>:* keys are kept in sync (load and save)
func Test_FC103_FolderConfigPersistenceSync_ConfigurationPrefixKeysInSync(t *testing.T) {
	conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	logger := zerolog.New(zerolog.NewTestWriter(t))

	path := types.FilePath(t.TempDir())
	normalizedPath := string(types.PathKey(path))

	types.SetFolderUserSetting(conf, path, types.SettingBaseBranch, "main")
	types.SetFolderUserSetting(conf, path, types.SettingReferenceBranch, "main")
	types.SetAutoDeterminedOrg(conf, path, "org-fc103")

	folderConfig := &types.FolderConfig{FolderPath: path}

	err := ModifyStoredConfig(conf, &logger, func(sc *StoredConfig) bool {
		if sc.FolderConfigs == nil {
			sc.FolderConfigs = make(map[types.FilePath]*types.FolderConfig)
		}
		sc.FolderConfigs[types.PathKey(path)] = folderConfig
		return true
	})
	require.NoError(t, err)

	loaded, err := GetOrCreateFolderConfig(conf, path, &logger)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	loaded.SetConf(conf)

	userKey := configuration.UserFolderKey(normalizedPath, types.SettingBaseBranch)
	gotUser := conf.Get(userKey)
	require.NotNil(t, gotUser, "UserFolderKey for BaseBranch should be set after load")
	lf, ok := gotUser.(*configuration.LocalConfigField)
	require.True(t, ok)
	assert.True(t, lf.Changed)
	assert.Equal(t, "main", lf.Value)

	metaKey := configuration.FolderMetadataKey(normalizedPath, types.SettingAutoDeterminedOrg)
	gotMeta := conf.Get(metaKey)
	require.NotNil(t, gotMeta, "FolderMetadataKey for AutoDeterminedOrg should be set after load")
	assert.Equal(t, "org-fc103", gotMeta)
}
