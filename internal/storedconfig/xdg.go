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
