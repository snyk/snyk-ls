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
	"fmt"
	"path/filepath"
	"testing"

	"github.com/adrg/xdg"
	"github.com/rs/zerolog"

	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"

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
	var _ = conf
	folderConfig, err := newFolderConfig(path, &logger)
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
	var _ = conf
	folderConfig, err := newFolderConfig(path, &logger)
	require.NoError(t, err)
	require.NotNil(t, folderConfig)
	require.Equal(t, types.PathKey(path), folderConfig.FolderPath)
}

func Test_SetFolderUserSetting_PersistsUserOverrides(t *testing.T) {
	conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	logger := zerolog.New(zerolog.NewTestWriter(t))

	tempDir := t.TempDir()
	path := types.FilePath(tempDir)

	// Write user overrides directly to configuration
	fp := string(types.PathKey(path))
	types.SetFolderUserSetting(conf, path, types.SettingEnabledSeverities, []string{"critical", "high"})
	types.SetFolderUserSetting(conf, path, types.SettingRiskScoreThreshold, 800)

	// Retrieve the config from storage
	retrievedConfig, err := newFolderConfig(path, &logger)
	require.NoError(t, err)
	require.NotNil(t, retrievedConfig)
	retrievedConfig.ConfigResolver = types.NewMinimalConfigResolver(conf)

	// Verify user overrides were persisted (read from configuration)
	require.True(t, types.HasUserOverride(conf, path, types.SettingEnabledSeverities))
	require.True(t, types.HasUserOverride(conf, path, types.SettingRiskScoreThreshold))

	severitiesVal := conf.Get(configresolver.UserFolderKey(fp, types.SettingEnabledSeverities))
	require.NotNil(t, severitiesVal)

	thresholdVal := conf.Get(configresolver.UserFolderKey(fp, types.SettingRiskScoreThreshold))
	require.NotNil(t, thresholdVal)
}
