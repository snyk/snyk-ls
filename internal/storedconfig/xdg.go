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
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/adrg/xdg"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/internal/types"
)

var storedConfigMu sync.Mutex

const (
	subDir        = "snyk"
	fileNameBase  = "ls-config"
	ConfigMainKey = "INTERNAL_LS_CONFIG"
)

type StoredConfig struct {
	FolderConfigs map[types.FilePath]*types.FolderConfig `json:"folderConfigs"`
}

func ConfigFile(ideName string) (string, error) {
	fileName := fmt.Sprintf("%s-%s", fileNameBase, ideName)
	path := filepath.Join(subDir, fileName)
	return xdg.ConfigFile(path)
}

func folderConfigFromStorage(conf configuration.Configuration, path types.FilePath, logger *zerolog.Logger, createIfNotExist bool) (*types.FolderConfig, error) {
	if err := types.ValidatePathForStorage(path); err != nil {
		logger.Error().Err(err).Str("path", string(path)).Msg("invalid folder path")
		return nil, err
	}
	normalizedPath := types.PathKey(path)
	return &types.FolderConfig{FolderPath: normalizedPath}, nil
}

func GetStoredConfig(conf configuration.Configuration, logger *zerolog.Logger, dontSave bool) (*StoredConfig, error) {
	storedConfigJsonString := conf.GetString(ConfigMainKey)

	if len(storedConfigJsonString) == 0 {
		logger.Trace().Msg("GetStoredConfig: No stored config found, will return a blank one")
		return createNewStoredConfig(conf, logger, dontSave), nil
	}

	var sc StoredConfig
	if err := json.Unmarshal([]byte(storedConfigJsonString), &sc); err != nil {
		logger.Err(err).Msg("Failed to unmarshal stored config")
		return createNewStoredConfig(conf, logger, dontSave), nil
	}
	if sc.FolderConfigs == nil {
		sc.FolderConfigs = map[types.FilePath]*types.FolderConfig{}
	}

	logger.Trace().
		Int("folderCount", len(sc.FolderConfigs)).
		Msg("GetStoredConfig: Loaded stored config from configuration")

	if !dontSave {
		_ = Save(conf, &sc)
	}
	return &sc, nil
}

func Save(conf configuration.Configuration, sc *StoredConfig) error {
	marshaled, err := json.Marshal(sc)
	if err != nil {
		return err
	}
	conf.Set(ConfigMainKey, string(marshaled))
	return nil
}

// ModifyStoredConfig atomically reads, modifies, and saves stored config.
// The modifier function receives the StoredConfig and returns true if changes were made.
// If changes were made, the config is saved automatically.
func ModifyStoredConfig(conf configuration.Configuration, logger *zerolog.Logger, modifier func(*StoredConfig) bool) error {
	storedConfigMu.Lock()
	defer storedConfigMu.Unlock()
	sc, err := GetStoredConfig(conf, logger, true)
	if err != nil {
		return err
	}
	if modifier(sc) {
		return Save(conf, sc)
	}
	return nil
}

func createNewStoredConfig(conf configuration.Configuration, logger *zerolog.Logger, dontSave bool) *StoredConfig {
	logger.Trace().Bool("dontSave", dontSave).Msg("createNewStoredConfig: Creating new stored config")
	config := StoredConfig{FolderConfigs: map[types.FilePath]*types.FolderConfig{}}
	if !dontSave {
		if err := Save(conf, &config); err != nil {
			logger.Err(err).Msg("Failed to save new stored config")
		}
	}
	return &config
}

func UpdateFolderConfig(conf configuration.Configuration, folderConfig *types.FolderConfig, logger *zerolog.Logger) error {
	if err := types.ValidatePathForStorage(folderConfig.FolderPath); err != nil {
		logger.Error().Err(err).Str("path", string(folderConfig.FolderPath)).Msg("invalid folder path")
		return err
	}
	return nil
}

// BatchUpdateFolderConfigs validates folder configs for batch update.
func BatchUpdateFolderConfigs(conf configuration.Configuration, folderConfigs []*types.FolderConfig, logger *zerolog.Logger) error {
	for _, fc := range folderConfigs {
		if err := types.ValidatePathForStorage(fc.FolderPath); err != nil {
			logger.Error().Err(err).Str("path", string(fc.FolderPath)).Msg("invalid folder path in batch update")
			return err
		}
	}

	logger.Debug().
		Int("folderCount", len(folderConfigs)).
		Msg("BatchUpdateFolderConfigs: validated all folders")
	return nil
}
