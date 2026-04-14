/*
 * © 2022-2026 Snyk Limited
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
	"encoding/json"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/internal/types"
)

// legacyFolderConfig represents the old FolderConfig struct fields needed for migration.
// Only fields that are migrated to individual GAF keys are included.
type legacyFolderConfig struct {
	BaseBranch           string         `json:"baseBranch"`
	AdditionalParameters []string       `json:"additionalParameters,omitempty"`
	AdditionalEnv        string         `json:"additionalEnv,omitempty"`
	ReferenceFolderPath  types.FilePath `json:"referenceFolderPath,omitempty"`
	PreferredOrg         string         `json:"preferredOrg"`
	AutoDeterminedOrg    string         `json:"autoDeterminedOrg"`
	OrgSetByUser         bool           `json:"orgSetByUser"`
}

// legacyStoredConfig represents the old StoredConfig wrapper for migration.
type legacyStoredConfig struct {
	FolderConfigs map[types.FilePath]*legacyFolderConfig `json:"folderConfigs"`
}

// MigrateFromLegacyConfig checks for old-format INTERNAL_LS_CONFIG data and migrates
// each folder's settings to individual GAF prefix keys. After successful migration,
// the old key is cleared to prevent re-migration.
func MigrateFromLegacyConfig(conf configuration.Configuration, logger *zerolog.Logger) {
	l := logger.With().Str("method", "MigrateFromLegacyConfig").Logger()

	oldData := conf.GetString(ConfigMainKey)
	if oldData == "" {
		return
	}

	var sc legacyStoredConfig
	if err := json.Unmarshal([]byte(oldData), &sc); err != nil {
		l.Err(err).Msg("failed to parse legacy folder config, clearing key to prevent re-migration")
		conf.Set(ConfigMainKey, "")
		return
	}

	if len(sc.FolderConfigs) == 0 {
		conf.Set(ConfigMainKey, "")
		return
	}

	migratedCount := 0
	for path, fc := range sc.FolderConfigs {
		if fc == nil {
			continue
		}

		normalizedPath := types.PathKey(path)

		if fc.BaseBranch != "" {
			types.SetFolderUserSetting(conf, normalizedPath, types.SettingBaseBranch, fc.BaseBranch)
		}
		if len(fc.AdditionalParameters) > 0 {
			types.SetFolderUserSetting(conf, normalizedPath, types.SettingAdditionalParameters, fc.AdditionalParameters)
		}
		if fc.AdditionalEnv != "" {
			types.SetFolderUserSetting(conf, normalizedPath, types.SettingAdditionalEnvironment, fc.AdditionalEnv)
		}
		if fc.ReferenceFolderPath != "" {
			types.SetFolderUserSetting(conf, normalizedPath, types.SettingReferenceFolder, string(fc.ReferenceFolderPath))
		}

		// Always migrate org fields — orgSetByUser:false is a meaningful state
		types.SetPreferredOrgAndOrgSetByUser(conf, normalizedPath, fc.PreferredOrg, fc.OrgSetByUser)

		if fc.AutoDeterminedOrg != "" {
			types.SetAutoDeterminedOrg(conf, normalizedPath, fc.AutoDeterminedOrg)
		}

		migratedCount++
	}

	conf.Set(ConfigMainKey, "")
	l.Info().Int("folderCount", migratedCount).Msg("migrated legacy folder configs to individual GAF keys")
}
