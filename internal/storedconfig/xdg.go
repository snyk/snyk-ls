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

package storedconfig

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/adrg/xdg"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

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

func folderConfigFromStorage(conf configuration.Configuration, path types.FilePath, logger *zerolog.Logger) (*types.FolderConfig, error) {
	if err := util.ValidatePathForStorage(path); err != nil {
		logger.Error().Err(err).Str("path", string(path)).Msg("invalid folder path")
		return nil, err
	}

	sc, err := GetStoredConfig(conf, logger)
	if err != nil {
		return nil, err
	}

	normalizedPath := util.PathKey(path)

	if sc.FolderConfigs[normalizedPath] == nil {
		folderConfig := &types.FolderConfig{}
		sc.FolderConfigs[normalizedPath] = folderConfig
	}

	// Normalize the folder path for consistent storage
	sc.FolderConfigs[normalizedPath].FolderPath = normalizedPath

	return sc.FolderConfigs[normalizedPath], nil
}

func GetStoredConfig(conf configuration.Configuration, logger *zerolog.Logger) (*StoredConfig, error) {
	storedConfigJsonString := conf.GetString(ConfigMainKey)

	var sc *StoredConfig
	if len(storedConfigJsonString) == 0 {
		return createNewStoredConfig(conf), nil
	} else {
		err := json.Unmarshal([]byte(storedConfigJsonString), &sc)
		if err != nil {
			logger.Err(err).Msg("Failed to unmarshal stored config")
			sc = createNewStoredConfig(conf)
			return sc, nil
		}
		// Normalize existing keys loaded from storage to ensure consistency
		if sc != nil && sc.FolderConfigs != nil {
			normalized := make(map[types.FilePath]*types.FolderConfig, len(sc.FolderConfigs))
			for k, v := range sc.FolderConfigs {
				nk := util.PathKey(k)
				normalized[nk] = v
			}
			sc.FolderConfigs = normalized
			// Best-effort save so subsequent reads are consistent
			_ = Save(conf, sc)
		}
	}
	return sc, nil
}

func Save(conf configuration.Configuration, sc *StoredConfig) error {
	marshaled, err := json.Marshal(sc)
	if err != nil {
		return err
	}
	conf.Set(ConfigMainKey, string(marshaled))
	return nil
}

func createNewStoredConfig(conf configuration.Configuration) *StoredConfig {
	config := StoredConfig{FolderConfigs: map[types.FilePath]*types.FolderConfig{}}
	conf.Set(ConfigMainKey, config)
	return &config
}

func UpdateFolderConfigs(conf configuration.Configuration, folderConfigs []types.FolderConfig, logger *zerolog.Logger) error {
	for _, folderConfig := range folderConfigs {
		err := UpdateFolderConfig(conf, &folderConfig, logger)
		if err != nil {
			return err
		}
	}
	return nil
}

func UpdateFolderConfig(conf configuration.Configuration, folderConfig *types.FolderConfig, logger *zerolog.Logger) error {
	if err := util.ValidatePathForStorage(folderConfig.FolderPath); err != nil {
		logger.Error().Err(err).Str("path", string(folderConfig.FolderPath)).Msg("invalid folder path")
		return err
	}

	// Validate the reference folder path for security and existence if provided
	if folderConfig.ReferenceFolderPath != "" {
		if err := util.ValidatePathStrict(folderConfig.ReferenceFolderPath); err != nil {
			logger.Error().Err(err).Str("referencePath", string(folderConfig.ReferenceFolderPath)).Msg("invalid reference folder path")
			return err
		}
	}

	sc, err := GetStoredConfig(conf, logger)
	if err != nil {
		return err
	}

	// Generate normalized key for consistent cross-platform storage
	normalizedPath := util.PathKey(folderConfig.FolderPath)

	// Normalize paths for consistent storage
	normalizedFolderConfig := *folderConfig
	normalizedFolderConfig.FolderPath = normalizedPath
	if folderConfig.ReferenceFolderPath != "" {
		normalizedFolderConfig.ReferenceFolderPath = util.PathKey(folderConfig.ReferenceFolderPath)
	}

	sc.FolderConfigs[normalizedPath] = &normalizedFolderConfig
	err = Save(conf, sc)
	if err != nil {
		return err
	}
	return nil
}
