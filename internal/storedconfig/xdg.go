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

	"github.com/adrg/xdg"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/internal/types"
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

func folderConfigFromStorage(conf configuration.Configuration, path types.FilePath, logger *zerolog.Logger, createIfNotExist bool) (*types.FolderConfig, error) {
	if err := types.ValidatePathForStorage(path); err != nil {
		logger.Error().Err(err).Str("path", string(path)).Msg("invalid folder path")
		return nil, err
	}

	// Always pass dontSave=true, assume the calling function will save later via UpdateFolderConfig if needed
	sc, err := GetStoredConfig(conf, logger, true)
	if err != nil {
		return nil, err
	}

	normalizedPath := types.PathKey(path)

	fc := sc.FolderConfigs[normalizedPath]

	if fc == nil {
		if !createIfNotExist {
			// Don't create: return nil if not found
			logger.Debug().
				Str("normalizedPath", string(normalizedPath)).
				Str("originalPath", string(path)).
				Msg("Folder config not found in storage, will not create as in do not create mode")
			return nil, nil
		}
		logger.Debug().
			Str("normalizedPath", string(normalizedPath)).
			Str("originalPath", string(path)).
			Int("existingFolderCount", len(sc.FolderConfigs)).
			Msg("Folder fc not found in storage, creating new one with OrgMigratedFromGlobalConfig=true")
		fc = &types.FolderConfig{
			// New folder configs should never go through org migration; we treat them as migrated.
			OrgMigratedFromGlobalConfig: true,
			// New folder configs should have their org determined via LDX-Sync.
			OrgSetByUser: false,
		}
	} else {
		logger.Trace().
			Str("normalizedPath", string(normalizedPath)).
			Bool("orgMigratedFromGlobalConfig", fc.OrgMigratedFromGlobalConfig).
			Msg("Found existing folder fc in storage")
	}

	// Normalize the folder path for consistent storage
	fc.FolderPath = normalizedPath

	// initialize feature flags if not set
	if fc.FeatureFlags == nil {
		fc.FeatureFlags = map[string]bool{}
	}
	return fc, nil
}

func GetStoredConfig(conf configuration.Configuration, logger *zerolog.Logger, dontSave bool) (*StoredConfig, error) {
	storedConfigJsonString := conf.GetString(ConfigMainKey)

	var sc *StoredConfig
	if len(storedConfigJsonString) == 0 {
		logger.Debug().Msg("GetStoredConfig: No stored config found, will return a blank one")
		return createNewStoredConfig(conf, logger, dontSave), nil
	} else {
		err := json.Unmarshal([]byte(storedConfigJsonString), &sc)
		if err != nil {
			logger.Err(err).Msg("Failed to unmarshal stored config")
			return createNewStoredConfig(conf, logger, dontSave), nil
		}

		logger.Trace().
			Int("folderCount", len(sc.FolderConfigs)).
			Msg("GetStoredConfig: Loaded stored config from configuration")

		// Normalize existing keys loaded from storage to ensure consistency
		if sc != nil {
			normalized := make(map[types.FilePath]*types.FolderConfig, len(sc.FolderConfigs))
			if sc.FolderConfigs == nil {
				sc.FolderConfigs = normalized
				return sc, nil
			}
			for k, v := range sc.FolderConfigs {
				nk := types.PathKey(k)
				normalized[nk] = v
			}
			sc.FolderConfigs = normalized
			if !dontSave {
				// Best-effort save so subsequent reads are consistent
				_ = Save(conf, sc)
			}
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

func createNewStoredConfig(conf configuration.Configuration, logger *zerolog.Logger, dontSave bool) *StoredConfig {
	logger.Debug().Bool("dontSave", dontSave).Msg("createNewStoredConfig: Creating new stored config")
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

	// Validate the reference folder path for security and existence if provided
	if folderConfig.ReferenceFolderPath != "" {
		if err := types.ValidatePathStrict(folderConfig.ReferenceFolderPath); err != nil {
			logger.Error().Err(err).Str("referencePath", string(folderConfig.ReferenceFolderPath)).Msg("invalid reference folder path")
			return err
		}
	}

	sc, err := GetStoredConfig(conf, logger, true)
	if err != nil {
		return err
	}

	// Generate normalized key for consistent cross-platform storage
	normalizedPath := types.PathKey(folderConfig.FolderPath)

	logger.Trace().
		Str("normalizedPath", string(normalizedPath)).
		Str("originalPath", string(folderConfig.FolderPath)).
		Bool("orgMigratedFromGlobalConfig", folderConfig.OrgMigratedFromGlobalConfig).
		Int("existingFolderCount", len(sc.FolderConfigs)).
		Msg("UpdateFolderConfig: Saving folder config to storage")

	// Normalize paths for consistent storage
	normalizedFolderConfig := *folderConfig
	normalizedFolderConfig.FolderPath = normalizedPath
	if folderConfig.ReferenceFolderPath != "" {
		normalizedFolderConfig.ReferenceFolderPath = types.PathKey(folderConfig.ReferenceFolderPath)
	}

	sc.FolderConfigs[normalizedPath] = &normalizedFolderConfig
	err = Save(conf, sc)
	if err != nil {
		return err
	}

	logger.Trace().
		Str("normalizedPath", string(normalizedPath)).
		Int("totalFolderCount", len(sc.FolderConfigs)).
		Msg("UpdateFolderConfig: Successfully saved folder config")
	return nil
}

// BatchUpdateFolderConfigs updates multiple folder configs in a single load/save cycle.
// This avoids O(N) load/save operations when updating N folders.
func BatchUpdateFolderConfigs(conf configuration.Configuration, folderConfigs []*types.FolderConfig, logger *zerolog.Logger) error {
	if len(folderConfigs) == 0 {
		return nil
	}

	// Validate all paths before loading
	for _, fc := range folderConfigs {
		if err := types.ValidatePathForStorage(fc.FolderPath); err != nil {
			logger.Error().Err(err).Str("path", string(fc.FolderPath)).Msg("invalid folder path in batch update")
			return err
		}
		if fc.ReferenceFolderPath != "" {
			if err := types.ValidatePathStrict(fc.ReferenceFolderPath); err != nil {
				logger.Error().Err(err).Str("referencePath", string(fc.ReferenceFolderPath)).Msg("invalid reference folder path in batch update")
				return err
			}
		}
	}

	// Single load
	sc, err := GetStoredConfig(conf, logger, true)
	if err != nil {
		return err
	}

	// Apply all updates in-memory
	for _, fc := range folderConfigs {
		normalizedPath := types.PathKey(fc.FolderPath)
		normalized := *fc
		normalized.FolderPath = normalizedPath
		if fc.ReferenceFolderPath != "" {
			normalized.ReferenceFolderPath = types.PathKey(fc.ReferenceFolderPath)
		}
		sc.FolderConfigs[normalizedPath] = &normalized
	}

	// Single save
	if err := Save(conf, sc); err != nil {
		logger.Err(err).Int("folderCount", len(folderConfigs)).Msg("BatchUpdateFolderConfigs: failed to save")
		return err
	}

	logger.Debug().
		Int("updatedFolderCount", len(folderConfigs)).
		Int("totalFolderCount", len(sc.FolderConfigs)).
		Msg("BatchUpdateFolderConfigs: saved all folder configs")
	return nil
}
