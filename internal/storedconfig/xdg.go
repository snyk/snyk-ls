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

	"github.com/snyk/snyk-ls/internal/constants"
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

func folderConfigFromStorage(conf configuration.Configuration, path types.FilePath, logger *zerolog.Logger, createIfNotExist bool) (*types.FolderConfig, error) {
	if err := util.ValidatePathForStorage(path); err != nil {
		logger.Error().Err(err).Str("path", string(path)).Msg("invalid folder path")
		return nil, err
	}

	// Always pass dontSave=true, assume the calling function will save later via UpdateFolderConfig if needed
	sc, err := GetStoredConfig(conf, logger, true)
	if err != nil {
		return nil, err
	}

	normalizedPath := util.PathKey(path)

	fc := sc.FolderConfigs[normalizedPath]

	// IDE-1548: Check if auto-org is enabled by default (false for EA rollout)
	autoOrgEnabledByDefault := conf.GetBool(constants.AutoOrgEnabledByDefaultKey)

	if fc == nil {
		if !createIfNotExist {
			// Don't create: return nil if not found
			logger.Debug().
				Str("normalizedPath", string(normalizedPath)).
				Str("originalPath", string(path)).
				Msg("Folder config not found in storage, will not create as in do not create mode")
			return nil, nil
		}
		if autoOrgEnabledByDefault {
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
			logger.Debug().
				Str("normalizedPath", string(normalizedPath)).
				Str("originalPath", string(path)).
				Int("existingFolderCount", len(sc.FolderConfigs)).
				Msg("Folder fc not found in storage, creating new one with auto-org (EA) disabled by default and marked as not migrated")
			fc = &types.FolderConfig{
				// Auto-org is disabled by default for EA rollout (see IDE-1548).
				// Users must explicitly opt-in to automatic organization selection.
				OrgSetByUser: true,
				// New folder configs are marked as not migrated for now (see IDE-1548).
				// When auto-org is enabled by default post-EA, these folders will go through migration.
				OrgMigratedFromGlobalConfig: false,
			}
		}
	} else {
		logger.Debug().
			Str("normalizedPath", string(normalizedPath)).
			Bool("orgMigratedFromGlobalConfig", fc.OrgMigratedFromGlobalConfig).
			Msg("Found existing folder fc in storage")

		if !autoOrgEnabledByDefault {
			// If the folder is not migrated (during EA, see IDE-1548, this means the user has not made the explicit choice to either change their preferred org or opt into auto-org),
			// then we need to opt them out of auto-org that has just been set as the default zero value for the field by Go.
			if !fc.OrgMigratedFromGlobalConfig && !fc.OrgSetByUser {
				logger.Debug().
					Str("normalizedPath", string(normalizedPath)).
					Msg("First time seeing this folder since new fields were added, since auto-org is disabled by default for EA rollout, opting out of auto-org")
				fc.OrgSetByUser = true
			}
		}
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

		logger.Debug().
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
				nk := util.PathKey(k)
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
		conf.Set(ConfigMainKey, config)
	}
	return &config
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

	sc, err := GetStoredConfig(conf, logger, true)
	if err != nil {
		return err
	}

	// Generate normalized key for consistent cross-platform storage
	normalizedPath := util.PathKey(folderConfig.FolderPath)

	logger.Debug().
		Str("normalizedPath", string(normalizedPath)).
		Str("originalPath", string(folderConfig.FolderPath)).
		Bool("orgMigratedFromGlobalConfig", folderConfig.OrgMigratedFromGlobalConfig).
		Int("existingFolderCount", len(sc.FolderConfigs)).
		Msg("UpdateFolderConfig: Saving folder config to storage")

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

	logger.Debug().
		Str("normalizedPath", string(normalizedPath)).
		Int("totalFolderCount", len(sc.FolderConfigs)).
		Msg("UpdateFolderConfig: Successfully saved folder config")
	return nil
}
