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
	"sync"

	"github.com/rs/zerolog"

	"github.com/snyk/snyk-ls/internal/product"
)

//go:generate go tool github.com/golang/mock/mockgen -destination=mock_types/config_provider_mock.go -package=mock_types github.com/snyk/snyk-ls/internal/types ConfigProvider

// ConfigProvider is an interface for accessing configuration.
// This allows ConfigResolver to call back to Config without circular dependencies.
type ConfigProvider interface {
	FolderOrganization(path FilePath) string
	FilterSeverity() SeverityFilter
	RiskScoreThreshold() int
	IssueViewOptions() IssueViewOptions
	IsAutoScanEnabled() bool
	IsDeltaFindingsEnabled() bool
	IsSnykCodeEnabled() bool
	IsSnykOssEnabled() bool
	IsSnykIacEnabled() bool
}

// ConfigResolverInterface defines the contract for resolving configuration values.
// It is the single entry point for reading effective configuration, considering
// LDX-Sync org/machine config, user overrides, and global defaults.
// Implementations must be safe for concurrent use.
type ConfigResolverInterface interface {
	// Resolution methods
	GetValue(settingName string, folderConfig ImmutableFolderConfig) (any, ConfigSource)
	GetEffectiveValue(settingName string, folderConfig ImmutableFolderConfig) EffectiveValue
	GetBool(settingName string, folderConfig ImmutableFolderConfig) bool
	GetInt(settingName string, folderConfig ImmutableFolderConfig) int
	GetStringSlice(settingName string, folderConfig ImmutableFolderConfig) []string
	GetSeverityFilter(settingName string, folderConfig ImmutableFolderConfig) *SeverityFilter
	IsLocked(settingName string, folderConfig ImmutableFolderConfig) bool

	// Folder-aware convenience methods with fallback to global config
	FilterSeverityForFolder(folderConfig ImmutableFolderConfig) SeverityFilter
	RiskScoreThresholdForFolder(folderConfig ImmutableFolderConfig) int
	IssueViewOptionsForFolder(folderConfig ImmutableFolderConfig) IssueViewOptions
	IsAutoScanEnabledForFolder(folderConfig ImmutableFolderConfig) bool
	IsDeltaFindingsEnabledForFolder(folderConfig ImmutableFolderConfig) bool
	IsSnykCodeEnabledForFolder(folderConfig ImmutableFolderConfig) bool
	IsSnykOssEnabledForFolder(folderConfig ImmutableFolderConfig) bool
	IsSnykIacEnabledForFolder(folderConfig ImmutableFolderConfig) bool
	IsProductEnabledForFolder(p product.Product, folderConfig ImmutableFolderConfig) bool
	DisplayableIssueTypesForFolder(folderConfig ImmutableFolderConfig) map[product.FilterableIssueType]bool

	// Mutation methods for updating resolver state
	SetLDXSyncMachineConfig(config map[string]*LDXSyncField)
	GetLDXSyncMachineConfig() map[string]*LDXSyncField
	SetGlobalSettings(settings *Settings)
	SetLDXSyncCache(cache *LDXSyncConfigCache)
}

// ConfigResolver is the single entry point for reading configuration values.
// It encapsulates the resolution logic and ensures correct precedence:
// 1. Machine-wide settings → Locked LDX-Sync > Global Config > LDX-Sync > Default
// 2. Folder-scoped settings → FolderConfig (with LDX-Sync folder settings)
// 3. Org-scoped settings → Locked LDX-Sync > User Override > LDX-Sync > Global Default
// All methods are safe for concurrent use.
type ConfigResolver struct {
	mu                   sync.RWMutex
	ldxSyncCache         *LDXSyncConfigCache
	ldxSyncMachineConfig map[string]*LDXSyncField
	globalSettings       *Settings
	c                    ConfigProvider
	logger               *zerolog.Logger
}

// NewConfigResolver creates a new ConfigResolver with the given dependencies.
// c is the ConfigProvider (typically Config) used for org resolution.
func NewConfigResolver(ldxSyncCache *LDXSyncConfigCache, globalSettings *Settings, c ConfigProvider, logger *zerolog.Logger) *ConfigResolver {
	return &ConfigResolver{
		ldxSyncCache:         ldxSyncCache,
		ldxSyncMachineConfig: make(map[string]*LDXSyncField),
		globalSettings:       globalSettings,
		c:                    c,
		logger:               logger,
	}
}

// SetLDXSyncCache updates the LDX-Sync org config cache reference
func (r *ConfigResolver) SetLDXSyncCache(cache *LDXSyncConfigCache) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ldxSyncCache = cache
}

// SetLDXSyncMachineConfig updates the LDX-Sync machine-wide config
func (r *ConfigResolver) SetLDXSyncMachineConfig(config map[string]*LDXSyncField) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ldxSyncMachineConfig = config
}

// GetLDXSyncMachineConfig returns the current LDX-Sync machine-wide config
func (r *ConfigResolver) GetLDXSyncMachineConfig() map[string]*LDXSyncField {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.ldxSyncMachineConfig
}

// SetGlobalSettings updates the global settings reference
func (r *ConfigResolver) SetGlobalSettings(settings *Settings) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.globalSettings = settings
}

// getEffectiveOrg returns the effective org for a folder.
// Delegates to c.FolderOrganization which is the single source of truth.
// FolderOrganization handles all resolution logic including user preferences, AutoDeterminedOrg,
// and global fallback (with caching to avoid repeated API calls).
func (r *ConfigResolver) getEffectiveOrg(folderConfig ImmutableFolderConfig) string {
	if folderConfig == nil || r.c == nil {
		return ""
	}
	return r.c.FolderOrganization(folderConfig.GetFolderPath())
}

// GetValue resolves a configuration value for the given setting and folder.
// Returns the resolved value and the source it came from.
func (r *ConfigResolver) GetValue(settingName string, folderConfig ImmutableFolderConfig) (any, ConfigSource) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.getValueLocked(settingName, folderConfig)
}

// getValueLocked is the internal implementation of GetValue; caller must hold at least r.mu.RLock.
func (r *ConfigResolver) getValueLocked(settingName string, folderConfig ImmutableFolderConfig) (any, ConfigSource) {
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
		} else if ldxField.IsEnforced {
			// Enforced: use LDX-Sync value, but user can override
			value = ldxField.Value
			source = ConfigSourceLDXSyncEnforced
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
func (r *ConfigResolver) resolveFolderSetting(settingName string, folderConfig ImmutableFolderConfig) (any, ConfigSource) {
	value := r.getFolderSettingValue(settingName, folderConfig)
	source := ConfigSourceFolder

	r.logResolution(settingName, string(folderConfig.GetFolderPath()), "", value, source, false, false, false)
	return value, source
}

// resolveOrgSetting resolves an org-scoped setting with full precedence logic
func (r *ConfigResolver) resolveOrgSetting(settingName string, folderConfig ImmutableFolderConfig) (any, ConfigSource) {
	// Only look up org if we have an LDX-Sync cache with actual data to query.
	// This avoids triggering FolderOrganization() calls (which may call Organization() and trigger API calls)
	// when there's no LDX-Sync data to look up anyway.
	// The cache is always initialized but may be empty if LDX-Sync hasn't returned data yet.
	var effectiveOrg string
	var ldxField *LDXSyncField
	if r.ldxSyncCache != nil && !r.ldxSyncCache.IsEmpty() {
		effectiveOrg = r.getEffectiveOrg(folderConfig)
		if effectiveOrg != "" {
			orgConfig := r.ldxSyncCache.GetOrgConfig(effectiveOrg)
			if orgConfig != nil {
				ldxField = orgConfig.GetField(settingName)
			}
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
		} else if ldxField.IsEnforced {
			value = ldxField.Value
			source = ConfigSourceLDXSyncEnforced
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
		folderPath = string(folderConfig.GetFolderPath())
	}
	r.logResolution(settingName, folderPath, effectiveOrg, value, source, userOverrideExists, ldxSyncHasField, isLocked)

	return value, source
}

// GetEffectiveValue resolves a configuration value and returns it as an EffectiveValue
// with source information for display to the IDE.
func (r *ConfigResolver) GetEffectiveValue(settingName string, folderConfig ImmutableFolderConfig) EffectiveValue {
	r.mu.RLock()
	defer r.mu.RUnlock()
	value, source := r.getValueLocked(settingName, folderConfig)

	originScope := ""
	if source == ConfigSourceLDXSync || source == ConfigSourceLDXSyncEnforced || source == ConfigSourceLDXSyncLocked {
		originScope = r.getOriginScope(settingName, folderConfig)
	}

	return EffectiveValue{
		Value:       value,
		Source:      source.String(),
		OriginScope: originScope,
	}
}

// getOriginScope retrieves the server-side origin scope for a setting from LDX-Sync
func (r *ConfigResolver) getOriginScope(settingName string, folderConfig ImmutableFolderConfig) string {
	scope := GetSettingScope(settingName)

	switch scope {
	case SettingScopeMachine:
		if r.ldxSyncMachineConfig != nil {
			if field := r.ldxSyncMachineConfig[settingName]; field != nil {
				return field.OriginScope
			}
		}
	case SettingScopeOrg:
		if folderConfig != nil && r.ldxSyncCache != nil && r.c != nil {
			effectiveOrg := r.c.FolderOrganization(folderConfig.GetFolderPath())
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
	SettingSnykCodeEnabled:        func(s *Settings) any { return s.ActivateSnykCode },
	SettingSnykOssEnabled:         func(s *Settings) any { return s.ActivateSnykOpenSource },
	SettingSnykIacEnabled:         func(s *Settings) any { return s.ActivateSnykIac },
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
	SettingCodeEndpoint:                    func(s *Settings) any { return s.SnykCodeApi },
	SettingProxyHttp:                       func(s *Settings) any { return s.ProxyHttp },
	SettingProxyHttps:                      func(s *Settings) any { return s.ProxyHttps },
	SettingProxyNoProxy:                    func(s *Settings) any { return s.ProxyNoProxy },
	SettingProxyInsecure:                   func(s *Settings) any { return s.Insecure },
	SettingPublishSecurityAtInceptionRules: func(s *Settings) any { return s.PublishSecurityAtInceptionRules },
	SettingCliReleaseChannel:               func(s *Settings) any { return s.CliReleaseChannel },
	SettingRiskScoreThreshold:              func(s *Settings) any { return s.RiskScoreThreshold },
	SettingScanAutomatic:                   func(s *Settings) any { return s.ScanningMode },
	SettingScanNetNew:                      func(s *Settings) any { return s.EnableDeltaFindings },
	SettingTrustEnabled:                    func(s *Settings) any { return s.EnableTrustedFoldersFeature },
}

// getGlobalSettingValue returns the value for a setting from global settings.
// Returns nil if the setting is not set (empty string, nil pointer, etc.). This is distinct from Config; by comparing
// the two, we can distinguish between "value set equal to the default" and "value not set, so inheriting from default"
func (r *ConfigResolver) getGlobalSettingValue(settingName string) any {
	if r.globalSettings == nil {
		return nil
	}

	if getter, exists := globalSettingGetters[settingName]; exists {
		value := getter(r.globalSettings)
		if isUnset(value) {
			return nil
		}
		return value
	}

	return nil
}

// isUnset returns true if the value represents an unset/empty setting (meaning we should fall back to the default)
func isUnset(value any) bool {
	if value == nil {
		return true
	}
	switch v := value.(type) {
	case string:
		return v == ""
	case *string:
		return v == nil || *v == ""
	case *int:
		return v == nil
	case *bool:
		return v == nil
	case *SeverityFilter:
		return v == nil
	case *IssueViewOptions:
		return v == nil
	}
	return false
}

// getFolderSettingValue returns the value for a folder-scoped setting
func (r *ConfigResolver) getFolderSettingValue(settingName string, folderConfig ImmutableFolderConfig) any {
	if folderConfig == nil {
		return nil
	}

	switch settingName {
	case SettingReferenceFolder:
		return string(folderConfig.GetReferenceFolderPath())
	case SettingReferenceBranch:
		return folderConfig.GetBaseBranch()
	case SettingAdditionalParameters:
		return folderConfig.GetAdditionalParameters()
	case SettingAdditionalEnvironment:
		return folderConfig.GetAdditionalEnv()
	default:
		return nil
	}
}

// Typed accessor methods for convenience

// GetBool returns a boolean value for the given setting
func (r *ConfigResolver) GetBool(settingName string, folderConfig ImmutableFolderConfig) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	val, _ := r.getValueLocked(settingName, folderConfig)
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
func (r *ConfigResolver) GetString(settingName string, folderConfig ImmutableFolderConfig) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	val, _ := r.getValueLocked(settingName, folderConfig)
	switch v := val.(type) {
	case string:
		return v
	default:
		return ""
	}
}

// GetStringSlice returns a string slice value for the given setting
func (r *ConfigResolver) GetStringSlice(settingName string, folderConfig ImmutableFolderConfig) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	val, _ := r.getValueLocked(settingName, folderConfig)
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
func (r *ConfigResolver) GetInt(settingName string, folderConfig ImmutableFolderConfig) int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	val, _ := r.getValueLocked(settingName, folderConfig)
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
func (r *ConfigResolver) GetSource(settingName string, folderConfig ImmutableFolderConfig) ConfigSource {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, source := r.getValueLocked(settingName, folderConfig)
	return source
}

// GetSeverityFilter returns a SeverityFilter value for the given setting
func (r *ConfigResolver) GetSeverityFilter(settingName string, folderConfig ImmutableFolderConfig) *SeverityFilter {
	r.mu.RLock()
	defer r.mu.RUnlock()
	val, _ := r.getValueLocked(settingName, folderConfig)
	switch v := val.(type) {
	case *SeverityFilter:
		return v
	case SeverityFilter:
		return &v
	default:
		return nil
	}
}

// IsLocked returns true if the setting is locked by LDX-Sync for the folder's org
func (r *ConfigResolver) IsLocked(settingName string, folderConfig ImmutableFolderConfig) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if folderConfig == nil || r.ldxSyncCache == nil || r.c == nil {
		return false
	}

	effectiveOrg := r.c.FolderOrganization(folderConfig.GetFolderPath())
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

// isSettingEnabledForFolder resolves a boolean setting for a folder with fallback to global config.
func (r *ConfigResolver) isSettingEnabledForFolder(folderConfig ImmutableFolderConfig, settingName string, fallback func() bool) bool {
	val, source := r.GetValue(settingName, folderConfig)
	if source != ConfigSourceDefault {
		if enabled, ok := val.(bool); ok {
			return enabled
		}
	}
	return fallback()
}

func (r *ConfigResolver) FilterSeverityForFolder(folderConfig ImmutableFolderConfig) SeverityFilter {
	if r.c == nil {
		return SeverityFilter{}
	}
	val, source := r.GetValue(SettingEnabledSeverities, folderConfig)
	if source != ConfigSourceDefault {
		if filter, ok := val.(*SeverityFilter); ok && filter != nil {
			return *filter
		}
	}
	return r.c.FilterSeverity()
}

func (r *ConfigResolver) RiskScoreThresholdForFolder(folderConfig ImmutableFolderConfig) int {
	if r.c == nil {
		return 0
	}
	val, source := r.GetValue(SettingRiskScoreThreshold, folderConfig)
	if source != ConfigSourceDefault {
		if threshold, ok := val.(int); ok {
			return threshold
		}
	}
	return r.c.RiskScoreThreshold()
}

func (r *ConfigResolver) IssueViewOptionsForFolder(folderConfig ImmutableFolderConfig) IssueViewOptions {
	if r.c == nil {
		return IssueViewOptions{}
	}
	result := r.c.IssueViewOptions()
	if val, source := r.GetValue(SettingIssueViewOpenIssues, folderConfig); source != ConfigSourceDefault {
		if open, ok := val.(bool); ok {
			result.OpenIssues = open
		}
	}
	if val, source := r.GetValue(SettingIssueViewIgnoredIssues, folderConfig); source != ConfigSourceDefault {
		if ignored, ok := val.(bool); ok {
			result.IgnoredIssues = ignored
		}
	}
	return result
}

func (r *ConfigResolver) IsAutoScanEnabledForFolder(folderConfig ImmutableFolderConfig) bool {
	if r.c == nil {
		return false
	}
	return r.isSettingEnabledForFolder(folderConfig, SettingScanAutomatic, r.c.IsAutoScanEnabled)
}

func (r *ConfigResolver) IsDeltaFindingsEnabledForFolder(folderConfig ImmutableFolderConfig) bool {
	if r.c == nil {
		return false
	}
	return r.isSettingEnabledForFolder(folderConfig, SettingScanNetNew, r.c.IsDeltaFindingsEnabled)
}

func (r *ConfigResolver) IsSnykCodeEnabledForFolder(folderConfig ImmutableFolderConfig) bool {
	if r.c == nil {
		return false
	}
	return r.isSettingEnabledForFolder(folderConfig, SettingSnykCodeEnabled, r.c.IsSnykCodeEnabled)
}

func (r *ConfigResolver) IsSnykOssEnabledForFolder(folderConfig ImmutableFolderConfig) bool {
	if r.c == nil {
		return false
	}
	return r.isSettingEnabledForFolder(folderConfig, SettingSnykOssEnabled, r.c.IsSnykOssEnabled)
}

func (r *ConfigResolver) IsSnykIacEnabledForFolder(folderConfig ImmutableFolderConfig) bool {
	if r.c == nil {
		return false
	}
	return r.isSettingEnabledForFolder(folderConfig, SettingSnykIacEnabled, r.c.IsSnykIacEnabled)
}

func (r *ConfigResolver) IsProductEnabledForFolder(p product.Product, folderConfig ImmutableFolderConfig) bool {
	switch p {
	case product.ProductCode:
		return r.IsSnykCodeEnabledForFolder(folderConfig)
	case product.ProductOpenSource:
		return r.IsSnykOssEnabledForFolder(folderConfig)
	case product.ProductInfrastructureAsCode:
		return r.IsSnykIacEnabledForFolder(folderConfig)
	default:
		return false
	}
}

func (r *ConfigResolver) DisplayableIssueTypesForFolder(folderConfig ImmutableFolderConfig) map[product.FilterableIssueType]bool {
	enabled := make(map[product.FilterableIssueType]bool)
	enabled[product.FilterableIssueTypeOpenSource] = r.IsSnykOssEnabledForFolder(folderConfig)
	enabled[product.FilterableIssueTypeCodeSecurity] = r.IsSnykCodeEnabledForFolder(folderConfig)
	enabled[product.FilterableIssueTypeInfrastructureAsCode] = r.IsSnykIacEnabledForFolder(folderConfig)
	return enabled
}

// IsEnforced returns true if the setting is enforced by LDX-Sync for the folder's org
func (r *ConfigResolver) IsEnforced(settingName string, folderConfig ImmutableFolderConfig) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if folderConfig == nil || r.ldxSyncCache == nil || r.c == nil {
		return false
	}

	effectiveOrg := r.c.FolderOrganization(folderConfig.GetFolderPath())
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
