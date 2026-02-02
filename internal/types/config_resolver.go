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

// NewConfigResolver creates a new ConfigResolver with the given dependencies.
// orgResolver is required and should provide full org resolution including global fallback.
func NewConfigResolver(ldxSyncCache *LDXSyncConfigCache, globalSettings *Settings, orgResolver OrgResolverFunc, logger *zerolog.Logger) *ConfigResolver {
	return &ConfigResolver{
		ldxSyncCache:         ldxSyncCache,
		ldxSyncMachineConfig: make(map[string]*LDXSyncField),
		globalSettings:       globalSettings,
		orgResolver:          orgResolver,
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

// getEffectiveOrg returns the effective org for a folder path.
// It first checks the LDX-Sync FolderToOrgMapping cache, then falls back to the orgResolver.
func (r *ConfigResolver) getEffectiveOrg(folderPath FilePath) string {
	// First check if LDX-Sync has already resolved the org for this folder
	if r.ldxSyncCache != nil {
		if org := r.ldxSyncCache.GetOrgIdForFolder(folderPath); org != "" {
			return org
		}
	}
	// Fall back to orgResolver (which includes global org fallback)
	if r.orgResolver != nil {
		return r.orgResolver(folderPath)
	}
	return ""
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
			// Use LDX-Sync value
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
		effectiveOrg = r.getEffectiveOrg(folderConfig.FolderPath)
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

// GetEffectiveValue resolves a configuration value and returns it as an EffectiveValue
// with source information for display to the IDE.
func (r *ConfigResolver) GetEffectiveValue(settingName string, folderConfig *FolderConfig) EffectiveValue {
	value, source := r.GetValue(settingName, folderConfig)

	originScope := ""
	if source == ConfigSourceLDXSync || source == ConfigSourceLDXSyncLocked {
		originScope = r.getOriginScope(settingName, folderConfig)
	}

	return EffectiveValue{
		Value:       value,
		Source:      source.String(),
		OriginScope: originScope,
	}
}

// getOriginScope retrieves the server-side origin scope for a setting from LDX-Sync
func (r *ConfigResolver) getOriginScope(settingName string, folderConfig *FolderConfig) string {
	scope := GetSettingScope(settingName)

	switch scope {
	case SettingScopeMachine:
		if r.ldxSyncMachineConfig != nil {
			if field := r.ldxSyncMachineConfig[settingName]; field != nil {
				return field.OriginScope
			}
		}
	case SettingScopeOrg:
		if folderConfig != nil && r.ldxSyncCache != nil && r.orgResolver != nil {
			effectiveOrg := r.orgResolver(folderConfig.FolderPath)
			if effectiveOrg != "" {
				if orgConfig := r.ldxSyncCache.GetOrgConfig(effectiveOrg); orgConfig != nil {
					if field := orgConfig.GetField(settingName); field != nil {
						return field.OriginScope
					}
				}
			}
		}
	case SettingScopeFolder:
		// Folder-scoped settings don't have LDX-Sync origin scope
	}

	return ""
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

// globalSettingGetter is a function type that extracts a value from global settings
type globalSettingGetter func(*Settings) any

// globalSettingGetters maps setting names to their getter functions
var globalSettingGetters = map[string]globalSettingGetter{
	SettingApiEndpoint:            func(s *Settings) any { return s.Endpoint },
	SettingAuthenticationMethod:   func(s *Settings) any { return string(s.AuthenticationMethod) },
	SettingAutoConfigureMcpServer: func(s *Settings) any { return s.AutoConfigureSnykMcpServer },
	SettingAutomaticDownload:      func(s *Settings) any { return s.ManageBinariesAutomatically },
	SettingBinaryBaseUrl:          func(s *Settings) any { return s.CliBaseDownloadURL },
	SettingCliPath:                func(s *Settings) any { return s.CliPath },
	SettingEnabledProducts:        func(s *Settings) any { return getEnabledProductsFromSettings(s) },
	SettingEnabledSeverities: func(s *Settings) any {
		if s.FilterSeverity != nil {
			return s.FilterSeverity
		}
		return nil
	},
	SettingIssueViewIgnoredIssues: func(s *Settings) any {
		if s.IssueViewOptions != nil {
			return s.IssueViewOptions.IgnoredIssues
		}
		return nil
	},
	SettingIssueViewOpenIssues: func(s *Settings) any {
		if s.IssueViewOptions != nil {
			return s.IssueViewOptions.OpenIssues
		}
		return nil
	},
	SettingProxyInsecure:      func(s *Settings) any { return s.Insecure },
	SettingRiskScoreThreshold: func(s *Settings) any { return s.RiskScoreThreshold },
	SettingScanAutomatic:      func(s *Settings) any { return s.ScanningMode },
	SettingScanNetNew:         func(s *Settings) any { return s.EnableDeltaFindings },
	SettingTrustEnabled:       func(s *Settings) any { return s.EnableTrustedFoldersFeature },
}

// getGlobalSettingValue returns the value for a setting from global settings
func (r *ConfigResolver) getGlobalSettingValue(settingName string) any {
	if r.globalSettings == nil {
		return nil
	}

	if getter, exists := globalSettingGetters[settingName]; exists {
		return getter(r.globalSettings)
	}

	return nil
}

// getEnabledProductsFromSettings returns a list of enabled products from the given settings
func getEnabledProductsFromSettings(settings *Settings) []string {
	if settings == nil {
		return nil
	}

	var products []string
	if settings.ActivateSnykOpenSource == "true" {
		products = append(products, "oss")
	}
	if settings.ActivateSnykCode == "true" {
		products = append(products, "code")
	}
	if settings.ActivateSnykIac == "true" {
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
	if folderConfig == nil || r.ldxSyncCache == nil || r.orgResolver == nil {
		return false
	}

	effectiveOrg := r.orgResolver(folderConfig.FolderPath)
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
	if folderConfig == nil || r.ldxSyncCache == nil || r.orgResolver == nil {
		return false
	}

	effectiveOrg := r.orgResolver(folderConfig.FolderPath)
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
