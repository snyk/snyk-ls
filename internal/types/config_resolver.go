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

package types

import (
	"github.com/rs/zerolog"
)

// OrgResolverFunc is a function type that resolves the effective organization for a folder path.
// It should return the org with full resolution logic including global fallback.
type OrgResolverFunc func(folderPath FilePath) string

// ConfigResolver is the single entry point for reading configuration values.
// It encapsulates the resolution logic and ensures correct precedence:
// 1. Machine-wide settings → Locked LDX-Sync > Global Config > LDX-Sync > Default
// 2. Folder-scoped settings → FolderConfig (with LDX-Sync folder settings)
// 3. Org-scoped settings → Locked LDX-Sync > User Override > LDX-Sync > Global Default
type ConfigResolver struct {
	ldxSyncCache         *LDXSyncConfigCache
	ldxSyncMachineConfig map[string]*LDXSyncField
	globalSettings       *Settings
	orgResolver          OrgResolverFunc
	logger               *zerolog.Logger
}

// NewConfigResolver creates a new ConfigResolver with the given dependencies
func NewConfigResolver(ldxSyncCache *LDXSyncConfigCache, globalSettings *Settings, logger *zerolog.Logger) *ConfigResolver {
	return &ConfigResolver{
		ldxSyncCache:         ldxSyncCache,
		ldxSyncMachineConfig: make(map[string]*LDXSyncField),
		globalSettings:       globalSettings,
		logger:               logger,
	}
}

// SetLDXSyncCache updates the LDX-Sync org config cache reference
func (r *ConfigResolver) SetLDXSyncCache(cache *LDXSyncConfigCache) {
	r.ldxSyncCache = cache
}

// SetLDXSyncMachineConfig updates the LDX-Sync machine-wide config
func (r *ConfigResolver) SetLDXSyncMachineConfig(config map[string]*LDXSyncField) {
	r.ldxSyncMachineConfig = config
}

// GetLDXSyncMachineConfig returns the current LDX-Sync machine-wide config
func (r *ConfigResolver) GetLDXSyncMachineConfig() map[string]*LDXSyncField {
	return r.ldxSyncMachineConfig
}

// SetGlobalSettings updates the global settings reference
func (r *ConfigResolver) SetGlobalSettings(settings *Settings) {
	r.globalSettings = settings
}

// SetOrgResolver sets the function used to resolve the effective organization for a folder.
// This should be set by Config to provide full org resolution including global fallback.
func (r *ConfigResolver) SetOrgResolver(resolver OrgResolverFunc) {
	r.orgResolver = resolver
}

// GetValue resolves a configuration value for the given setting and folder.
// Returns the resolved value and the source it came from.
func (r *ConfigResolver) GetValue(settingName string, folderConfig *FolderConfig) (any, ConfigSource) {
	scope := GetSettingScope(settingName)

	switch scope {
	case SettingScopeMachine:
		return r.resolveMachineSetting(settingName)
	case SettingScopeFolder:
		return r.resolveFolderSetting(settingName, folderConfig)
	case SettingScopeOrg:
		return r.resolveOrgSetting(settingName, folderConfig)
	default:
		return r.resolveOrgSetting(settingName, folderConfig)
	}
}

// resolveMachineSetting resolves a machine-scoped setting
// Precedence: Locked LDX-Sync > Global Config (user setting) > LDX-Sync (enforced) > Default
func (r *ConfigResolver) resolveMachineSetting(settingName string) (any, ConfigSource) {
	// Check LDX-Sync machine config
	var ldxField *LDXSyncField
	if r.ldxSyncMachineConfig != nil {
		ldxField = r.ldxSyncMachineConfig[settingName]
	}

	ldxSyncHasField := ldxField != nil
	isLocked := ldxField != nil && ldxField.IsLocked

	// Get user's global setting value
	globalValue := r.getGlobalSettingValue(settingName)
	userHasSet := globalValue != nil

	var value any
	var source ConfigSource

	if ldxField != nil {
		if ldxField.IsLocked {
			// Locked: LDX-Sync value wins, user cannot override
			value = ldxField.Value
			source = ConfigSourceLDXSyncLocked
		} else if userHasSet {
			// User has set a value in global config, use it
			value = globalValue
			source = ConfigSourceGlobal
		} else {
			// Use LDX-Sync value as default (enforced)
			value = ldxField.Value
			source = ConfigSourceLDXSync
		}
	} else {
		if userHasSet {
			value = globalValue
			source = ConfigSourceGlobal
		} else {
			value = nil
			source = ConfigSourceDefault
		}
	}

	r.logResolution(settingName, "", "", value, source, ldxSyncHasField, isLocked, false)
	return value, source
}

// resolveFolderSetting resolves a folder-scoped setting from FolderConfig
func (r *ConfigResolver) resolveFolderSetting(settingName string, folderConfig *FolderConfig) (any, ConfigSource) {
	value := r.getFolderSettingValue(settingName, folderConfig)
	source := ConfigSourceFolder

	r.logResolution(settingName, string(folderConfig.FolderPath), "", value, source, false, false, false)
	return value, source
}

// resolveOrgSetting resolves an org-scoped setting with full precedence logic
func (r *ConfigResolver) resolveOrgSetting(settingName string, folderConfig *FolderConfig) (any, ConfigSource) {
	effectiveOrg := ""
	if folderConfig != nil {
		// Use orgResolver if available (provides full resolution including global fallback)
		// Otherwise fall back to GetEffectiveOrg (which doesn't include global fallback)
		if r.orgResolver != nil {
			effectiveOrg = r.orgResolver(folderConfig.FolderPath)
		} else {
			effectiveOrg = folderConfig.GetEffectiveOrg()
		}
	}

	var ldxField *LDXSyncField
	if r.ldxSyncCache != nil && effectiveOrg != "" {
		orgConfig := r.ldxSyncCache.GetOrgConfig(effectiveOrg)
		if orgConfig != nil {
			ldxField = orgConfig.GetField(settingName)
		}
	}

	ldxSyncHasField := ldxField != nil
	isLocked := ldxField != nil && ldxField.IsLocked
	userOverrideExists := folderConfig != nil && folderConfig.HasUserOverride(settingName)

	var value any
	var source ConfigSource

	if ldxField != nil {
		if ldxField.IsLocked {
			value = ldxField.Value
			source = ConfigSourceLDXSyncLocked
		} else if userOverrideExists {
			value, _ = folderConfig.GetUserOverride(settingName)
			source = ConfigSourceUserOverride
		} else {
			value = ldxField.Value
			source = ConfigSourceLDXSync
		}
	} else {
		if userOverrideExists {
			value, _ = folderConfig.GetUserOverride(settingName)
			source = ConfigSourceUserOverride
		} else {
			value = r.getGlobalSettingValue(settingName)
			if value != nil {
				source = ConfigSourceGlobal
			} else {
				source = ConfigSourceDefault
			}
		}
	}

	folderPath := ""
	if folderConfig != nil {
		folderPath = string(folderConfig.FolderPath)
	}
	r.logResolution(settingName, folderPath, effectiveOrg, value, source, userOverrideExists, ldxSyncHasField, isLocked)

	return value, source
}

// logResolution logs the config resolution decision for debugging
func (r *ConfigResolver) logResolution(settingName, folderPath, org string, value any, source ConfigSource, userOverrideExists, ldxSyncHasField, isLocked bool) {
	if r.logger == nil {
		return
	}

	r.logger.Debug().
		Str("setting", settingName).
		Str("folder", folderPath).
		Str("org", org).
		Str("source", source.String()).
		Interface("value", value).
		Bool("userOverrideExists", userOverrideExists).
		Bool("ldxSyncHasField", ldxSyncHasField).
		Bool("isLocked", isLocked).
		Msg("config value resolved")
}

// getGlobalSettingValue returns the value for a setting from global settings
func (r *ConfigResolver) getGlobalSettingValue(settingName string) any {
	if r.globalSettings == nil {
		return nil
	}

	switch settingName {
	case SettingApiEndpoint:
		return r.globalSettings.Endpoint
	case SettingAuthenticationMethod:
		return string(r.globalSettings.AuthenticationMethod)
	case SettingProxyInsecure:
		return r.globalSettings.Insecure
	case SettingAutoConfigureMcpServer:
		return r.globalSettings.AutoConfigureSnykMcpServer
	case SettingTrustEnabled:
		return r.globalSettings.EnableTrustedFoldersFeature
	case SettingBinaryBaseUrl:
		return r.globalSettings.CliBaseDownloadURL
	case SettingCliPath:
		return r.globalSettings.CliPath
	case SettingAutomaticDownload:
		return r.globalSettings.ManageBinariesAutomatically
	case SettingEnabledSeverities:
		if r.globalSettings.FilterSeverity != nil {
			return r.globalSettings.FilterSeverity
		}
		return nil
	case SettingRiskScoreThreshold:
		return r.globalSettings.RiskScoreThreshold
	case SettingEnabledProducts:
		return r.getEnabledProducts()
	case SettingScanAutomatic:
		return r.globalSettings.ScanningMode
	case SettingScanNetNew:
		return r.globalSettings.EnableDeltaFindings
	case SettingIssueViewOpenIssues:
		if r.globalSettings.IssueViewOptions != nil {
			return r.globalSettings.IssueViewOptions.OpenIssues
		}
		return nil
	case SettingIssueViewIgnoredIssues:
		if r.globalSettings.IssueViewOptions != nil {
			return r.globalSettings.IssueViewOptions.IgnoredIssues
		}
		return nil
	default:
		return nil
	}
}

// getEnabledProducts returns a list of enabled products from global settings
func (r *ConfigResolver) getEnabledProducts() []string {
	if r.globalSettings == nil {
		return nil
	}

	var products []string
	if r.globalSettings.ActivateSnykOpenSource == "true" {
		products = append(products, "oss")
	}
	if r.globalSettings.ActivateSnykCode == "true" {
		products = append(products, "code")
	}
	if r.globalSettings.ActivateSnykIac == "true" {
		products = append(products, "iac")
	}
	return products
}

// getFolderSettingValue returns the value for a folder-scoped setting
func (r *ConfigResolver) getFolderSettingValue(settingName string, folderConfig *FolderConfig) any {
	if folderConfig == nil {
		return nil
	}

	switch settingName {
	case SettingReferenceFolder:
		return string(folderConfig.ReferenceFolderPath)
	case SettingReferenceBranch:
		return folderConfig.BaseBranch
	case SettingAdditionalParameters:
		return folderConfig.AdditionalParameters
	case SettingAdditionalEnvironment:
		return folderConfig.AdditionalEnv
	default:
		return nil
	}
}

// Typed accessor methods for convenience

// GetBool returns a boolean value for the given setting
func (r *ConfigResolver) GetBool(settingName string, folderConfig *FolderConfig) bool {
	val, _ := r.GetValue(settingName, folderConfig)
	switch v := val.(type) {
	case bool:
		return v
	case string:
		return v == "true"
	default:
		return false
	}
}

// GetString returns a string value for the given setting
func (r *ConfigResolver) GetString(settingName string, folderConfig *FolderConfig) string {
	val, _ := r.GetValue(settingName, folderConfig)
	switch v := val.(type) {
	case string:
		return v
	default:
		return ""
	}
}

// GetStringSlice returns a string slice value for the given setting
func (r *ConfigResolver) GetStringSlice(settingName string, folderConfig *FolderConfig) []string {
	val, _ := r.GetValue(settingName, folderConfig)
	switch v := val.(type) {
	case []string:
		return v
	case []any:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	default:
		return nil
	}
}

// GetInt returns an integer value for the given setting
func (r *ConfigResolver) GetInt(settingName string, folderConfig *FolderConfig) int {
	val, _ := r.GetValue(settingName, folderConfig)
	switch v := val.(type) {
	case int:
		return v
	case *int:
		if v != nil {
			return *v
		}
		return 0
	case float64:
		return int(v)
	default:
		return 0
	}
}

// GetSource returns only the source for a given setting (useful for UI display)
func (r *ConfigResolver) GetSource(settingName string, folderConfig *FolderConfig) ConfigSource {
	_, source := r.GetValue(settingName, folderConfig)
	return source
}

// IsLocked returns true if the setting is locked by LDX-Sync for the folder's org
func (r *ConfigResolver) IsLocked(settingName string, folderConfig *FolderConfig) bool {
	if folderConfig == nil || r.ldxSyncCache == nil {
		return false
	}

	effectiveOrg := folderConfig.GetEffectiveOrg()
	if effectiveOrg == "" {
		return false
	}

	orgConfig := r.ldxSyncCache.GetOrgConfig(effectiveOrg)
	if orgConfig == nil {
		return false
	}

	field := orgConfig.GetField(settingName)
	return field != nil && field.IsLocked
}

// IsEnforced returns true if the setting is enforced by LDX-Sync for the folder's org
func (r *ConfigResolver) IsEnforced(settingName string, folderConfig *FolderConfig) bool {
	if folderConfig == nil || r.ldxSyncCache == nil {
		return false
	}

	effectiveOrg := folderConfig.GetEffectiveOrg()
	if effectiveOrg == "" {
		return false
	}

	orgConfig := r.ldxSyncCache.GetOrgConfig(effectiveOrg)
	if orgConfig == nil {
		return false
	}

	field := orgConfig.GetField(settingName)
	return field != nil && field.IsEnforced
}
