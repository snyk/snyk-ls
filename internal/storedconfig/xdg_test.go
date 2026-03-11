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
	"testing"

	"github.com/adrg/xdg"
	"github.com/rs/zerolog"

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

	// Don't create a folder config in storage for a folder that doesn't exist when createIfNotExist=false
	folderConfig, err := folderConfigFromStorage(conf, path, &logger, false)
	require.NoError(t, err)
	require.Nil(t, folderConfig, "folderConfig should be nil when createIfNotExist=false and config doesn't exist")
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
	storedConfig := GetStoredConfig(conf, &logger)
	require.NotNil(t, storedConfig)
}

func Test_UpdateFolderConfig_PersistsUserOverrides(t *testing.T) {
	conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	logger := zerolog.New(zerolog.NewTestWriter(t))

	tempDir := t.TempDir()
	path := types.FilePath(tempDir)

	// Create a folder config with user overrides
	folderConfig := &types.FolderConfig{
		FolderPath: path,
	}
	folderConfig.SetUserOverride(types.SettingEnabledSeverities, []string{"critical", "high"})
	folderConfig.SetUserOverride(types.SettingRiskScoreThreshold, 800)

	// Persist the config to storage
	err := UpdateFolderConfig(conf, folderConfig, &logger)
	require.NoError(t, err)

	// Retrieve the config from storage
	retrievedConfig, err := folderConfigFromStorage(conf, path, &logger, false)
	require.NoError(t, err)
	require.NotNil(t, retrievedConfig)

	// Verify user overrides were persisted
	require.True(t, retrievedConfig.HasUserOverride(types.SettingEnabledSeverities))
	require.True(t, retrievedConfig.HasUserOverride(types.SettingRiskScoreThreshold))

	severities, exists := retrievedConfig.GetUserOverride(types.SettingEnabledSeverities)
	require.True(t, exists)
	// JSON unmarshaling converts []string to []interface{}
	require.NotNil(t, severities)

	threshold, exists := retrievedConfig.GetUserOverride(types.SettingRiskScoreThreshold)
	require.True(t, exists)
	// JSON unmarshaling converts int to float64
	require.NotNil(t, threshold)
}
