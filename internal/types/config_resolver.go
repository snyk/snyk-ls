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
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/internal/product"
)

//go:generate go tool github.com/golang/mock/mockgen -destination=mock_types/config_provider_mock.go -package=mock_types github.com/snyk/snyk-ls/internal/types ConfigProvider
//go:generate go tool github.com/golang/mock/mockgen -destination=mock_types/config_resolver_interface_mock.go -package=mock_types github.com/snyk/snyk-ls/internal/types ConfigResolverInterface

// ConfigProvider provides read-only access to Config struct fields.
// Used by ConfigResolver's ForFolder methods as a fallback when configuration returns defaults.
// Settings migrated to GAF (UserGlobalKey) no longer need fallback; GetValue returns correct defaults.
type ConfigProvider interface {
	FilterSeverity() SeverityFilter
	IssueViewOptions() IssueViewOptions
}

// ConfigResolverInterface defines the contract for resolving configuration values.
// It is the single entry point for reading effective configuration, considering
// LDX-Sync org/machine config, user overrides, and global defaults.
// Implementations must be safe for concurrent use.
type ConfigResolverInterface interface {
	// Resolution methods
	GetValue(settingName string, folderConfig *FolderConfig) (any, ConfigSource)
	GetEffectiveValue(settingName string, folderConfig *FolderConfig) EffectiveValue
	GetBool(settingName string, folderConfig *FolderConfig) bool
	GetInt(settingName string, folderConfig *FolderConfig) int
	GetStringSlice(settingName string, folderConfig *FolderConfig) []string
	GetSeverityFilter(settingName string, folderConfig *FolderConfig) *SeverityFilter
	IsLocked(settingName string, folderConfig *FolderConfig) bool

	// Folder-aware convenience methods with fallback to global config
	FilterSeverityForFolder(folderConfig *FolderConfig) SeverityFilter
	RiskScoreThresholdForFolder(folderConfig *FolderConfig) int
	IssueViewOptionsForFolder(folderConfig *FolderConfig) IssueViewOptions
	IsAutoScanEnabledForFolder(folderConfig *FolderConfig) bool
	IsDeltaFindingsEnabledForFolder(folderConfig *FolderConfig) bool
	IsSnykCodeEnabledForFolder(folderConfig *FolderConfig) bool
	IsSnykOssEnabledForFolder(folderConfig *FolderConfig) bool
	IsSnykIacEnabledForFolder(folderConfig *FolderConfig) bool
	IsSnykSecretsEnabledForFolder(folderConfig *FolderConfig) bool
	IsProductEnabledForFolder(p product.Product, folderConfig *FolderConfig) bool
	DisplayableIssueTypesForFolder(folderConfig *FolderConfig) map[product.FilterableIssueType]bool

	// Mutation methods for updating resolver state
	SetLDXSyncMachineConfig(config map[string]*LDXSyncField)
	GetLDXSyncMachineConfig() map[string]*LDXSyncField
	SetLDXSyncCache(cache *LDXSyncConfigCache)

	// Configuration returns the underlying configuration for direct prefix key access.
	Configuration() configuration.Configuration
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
	c                    ConfigProvider
	logger               *zerolog.Logger
	prefixKeyResolver    *configuration.ConfigResolver
	prefixKeyConf        configuration.Configuration
}

var _ ConfigResolverInterface = (*ConfigResolver)(nil)

// folderMetadataSettings are stored under FolderMetadataKey, not UserFolderKey.
// Configuration resolver only reads UserFolderKey; metadata must be read directly.
var folderMetadataSettings = map[string]bool{
	SettingLocalBranches:     true,
	SettingAutoDeterminedOrg: true,
}

// NewConfigResolver creates a new ConfigResolver with the given dependencies.
// c provides read-only access to Config struct fields for fallback values.
func NewConfigResolver(ldxSyncCache *LDXSyncConfigCache, c ConfigProvider, logger *zerolog.Logger) *ConfigResolver {
	return &ConfigResolver{
		ldxSyncCache:         ldxSyncCache,
		ldxSyncMachineConfig: make(map[string]*LDXSyncField),
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

// Configuration returns the underlying configuration for direct prefix key access.
func (r *ConfigResolver) Configuration() configuration.Configuration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.prefixKeyConf
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

// SetPrefixKeyResolver wires the ConfigResolver and Configuration for prefix-key-based resolution.
// When set, GetValue delegates to the configuration resolver instead of the legacy implementation.
func (r *ConfigResolver) SetPrefixKeyResolver(prefixKeyResolver *configuration.ConfigResolver, prefixKeyConf configuration.Configuration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prefixKeyResolver = prefixKeyResolver
	r.prefixKeyConf = prefixKeyConf
}

func mapConfigSource(gafSource configuration.ConfigSource) ConfigSource {
	switch gafSource {
	case configuration.ConfigSourceDefault:
		return ConfigSourceDefault
	case configuration.ConfigSourceUserGlobal:
		return ConfigSourceGlobal
	case configuration.ConfigSourceUserOverride:
		return ConfigSourceUserOverride
	case configuration.ConfigSourceFolder:
		return ConfigSourceFolder
	case configuration.ConfigSourceRemote:
		return ConfigSourceLDXSync
	case configuration.ConfigSourceRemoteLocked:
		return ConfigSourceLDXSyncLocked
	default:
		return ConfigSourceDefault
	}
}

// getEffectiveOrg returns the effective org for a folder.
// When r.prefixKeyConf is set, reads from Configuration (UserFolderKey/FolderMetadataKey).
// Otherwise falls back to struct-based reads (legacy).
func (r *ConfigResolver) getEffectiveOrg(folderConfig *FolderConfig) string {
	if folderConfig == nil {
		return ""
	}

	folderPath := string(PathKey(folderConfig.GetFolderPath()))
	if folderPath == "" {
		return r.getGlobalOrg()
	}
	if r.prefixKeyConf == nil {
		return r.getGlobalOrg()
	}
	return r.getEffectiveOrgFromConf(folderPath)
}

// getEffectiveOrgFromConf reads org from Configuration: OrgSetByUser+PreferredOrg from UserFolderKey,
// AutoDeterminedOrg from FolderMetadataKey, fallback to global org.
func (r *ConfigResolver) getEffectiveOrgFromConf(folderPath string) string {
	preferred, orgSetByUser := r.getPreferredOrgFromConf(folderPath)
	if orgSetByUser {
		if preferred != "" {
			return preferred
		}
		return r.getGlobalOrg()
	}
	if auto := r.getAutoDeterminedOrgFromConf(folderPath); auto != "" {
		return auto
	}
	return r.getGlobalOrg()
}

func (r *ConfigResolver) getPreferredOrgFromConf(folderPath string) (string, bool) {
	orgSetKey := configuration.UserFolderKey(folderPath, SettingOrgSetByUser)
	if !r.prefixKeyConf.IsSet(orgSetKey) {
		return "", false
	}
	lf, ok := r.prefixKeyConf.Get(orgSetKey).(*configuration.LocalConfigField)
	if !ok || lf == nil || !lf.Changed {
		return "", false
	}
	orgSetByUser, ok := lf.Value.(bool)
	if !ok || !orgSetByUser {
		return "", false
	}
	prefKey := configuration.UserFolderKey(folderPath, SettingPreferredOrg)
	if !r.prefixKeyConf.IsSet(prefKey) {
		return "", true
	}
	pf, ok := r.prefixKeyConf.Get(prefKey).(*configuration.LocalConfigField)
	if !ok || pf == nil || !pf.Changed {
		return "", true
	}
	preferred, ok := pf.Value.(string)
	if !ok {
		return "", true
	}
	return preferred, true
}

func (r *ConfigResolver) getAutoDeterminedOrgFromConf(folderPath string) string {
	metaKey := configuration.FolderMetadataKey(folderPath, SettingAutoDeterminedOrg)
	val := r.prefixKeyConf.Get(metaKey)
	if val == nil {
		return ""
	}
	autoDetermined, ok := val.(string)
	if !ok || autoDetermined == "" {
		return ""
	}
	return autoDetermined
}

// getGlobalOrg returns the global organization from configuration, used as fallback
// when no folder-specific org is available.
func (r *ConfigResolver) getGlobalOrg() string {
	if r.prefixKeyConf == nil {
		return ""
	}
	key := configuration.UserGlobalKey(SettingOrganization)
	val := r.prefixKeyConf.Get(key)
	if s, ok := val.(string); ok {
		return s
	}
	return ""
}

// GetValue resolves a configuration value for the given setting and folder.
// Returns the resolved value and the source it came from.
func (r *ConfigResolver) GetValue(settingName string, folderConfig *FolderConfig) (any, ConfigSource) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.getValueLocked(settingName, folderConfig)
}

// getValueLocked is the internal implementation of GetValue; caller must hold at least r.mu.RLock.
func (r *ConfigResolver) getValueLocked(settingName string, folderConfig *FolderConfig) (any, ConfigSource) {
	if r.prefixKeyResolver != nil {
		// Handle folder metadata settings separately — stored under FolderMetadataKey, not UserFolderKey
		if folderMetadataSettings[settingName] && folderConfig != nil && r.prefixKeyConf != nil {
			folderPath := string(PathKey(folderConfig.GetFolderPath()))
			if folderPath != "" {
				val := r.prefixKeyConf.Get(configuration.FolderMetadataKey(folderPath, settingName))
				if val != nil {
					return val, ConfigSourceFolder
				}
			}
			return nil, ConfigSourceDefault
		}
		// All other settings: delegate to configuration resolver
		effectiveOrg := r.getEffectiveOrg(folderConfig)
		folderPath := ""
		if folderConfig != nil {
			folderPath = string(PathKey(folderConfig.GetFolderPath()))
		}
		val, gafSource := r.prefixKeyResolver.Resolve(settingName, effectiveOrg, folderPath)
		return val, mapConfigSource(gafSource)
	}

	// Legacy fallback removed: prefixKeyResolver must be set in production.
	// Return default to avoid breaking tests that don't set configuration resolver.
	if r.logger != nil {
		r.logger.Warn().Str("setting", settingName).Msg("ConfigResolver: prefixKeyResolver is nil, returning default")
	}
	return nil, ConfigSourceDefault
}

// GetEffectiveValue resolves a configuration value and returns it as an EffectiveValue
// with source information for display to the IDE.
func (r *ConfigResolver) GetEffectiveValue(settingName string, folderConfig *FolderConfig) EffectiveValue {
	r.mu.RLock()
	defer r.mu.RUnlock()
	value, source := r.getValueLocked(settingName, folderConfig)

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
		if folderConfig != nil && r.ldxSyncCache != nil {
			effectiveOrg := r.getEffectiveOrg(folderConfig)
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

// isUnset returns true if the value represents an unset/empty setting (meaning we should fall back to the default)

// Typed accessor methods for convenience

// GetBool returns a boolean value for the given setting
func (r *ConfigResolver) GetBool(settingName string, folderConfig *FolderConfig) bool {
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
func (r *ConfigResolver) GetString(settingName string, folderConfig *FolderConfig) string {
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
func (r *ConfigResolver) GetStringSlice(settingName string, folderConfig *FolderConfig) []string {
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
func (r *ConfigResolver) GetInt(settingName string, folderConfig *FolderConfig) int {
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
func (r *ConfigResolver) GetSource(settingName string, folderConfig *FolderConfig) ConfigSource {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, source := r.getValueLocked(settingName, folderConfig)
	return source
}

// GetSeverityFilter returns a SeverityFilter value for the given setting
func (r *ConfigResolver) GetSeverityFilter(settingName string, folderConfig *FolderConfig) *SeverityFilter {
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
func (r *ConfigResolver) IsLocked(settingName string, folderConfig *FolderConfig) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.prefixKeyResolver != nil {
		effectiveOrg := r.getEffectiveOrg(folderConfig)
		return r.prefixKeyResolver.IsLocked(settingName, effectiveOrg)
	}

	if folderConfig == nil || r.ldxSyncCache == nil {
		return false
	}

	effectiveOrg := r.getEffectiveOrg(folderConfig)
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

// isSettingEnabledForFolder resolves a boolean setting for a folder.
// GAF prefix key resolver returns correct values including defaults; no fallback needed.
func (r *ConfigResolver) isSettingEnabledForFolder(folderConfig *FolderConfig, settingName string) bool {
	return r.GetBool(settingName, folderConfig)
}

func (r *ConfigResolver) FilterSeverityForFolder(folderConfig *FolderConfig) SeverityFilter {
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

func (r *ConfigResolver) RiskScoreThresholdForFolder(folderConfig *FolderConfig) int {
	val, source := r.GetValue(SettingRiskScoreThreshold, folderConfig)
	if source != ConfigSourceDefault {
		if threshold, ok := val.(int); ok {
			return threshold
		}
	}
	return 0
}

func (r *ConfigResolver) IssueViewOptionsForFolder(folderConfig *FolderConfig) IssueViewOptions {
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

func (r *ConfigResolver) IsAutoScanEnabledForFolder(folderConfig *FolderConfig) bool {
	return r.isSettingEnabledForFolder(folderConfig, SettingScanAutomatic)
}

func (r *ConfigResolver) IsDeltaFindingsEnabledForFolder(folderConfig *FolderConfig) bool {
	return r.isSettingEnabledForFolder(folderConfig, SettingScanNetNew)
}

func (r *ConfigResolver) IsSnykCodeEnabledForFolder(folderConfig *FolderConfig) bool {
	return r.isSettingEnabledForFolder(folderConfig, SettingSnykCodeEnabled)
}

func (r *ConfigResolver) IsSnykOssEnabledForFolder(folderConfig *FolderConfig) bool {
	return r.isSettingEnabledForFolder(folderConfig, SettingSnykOssEnabled)
}

func (r *ConfigResolver) IsSnykIacEnabledForFolder(folderConfig *FolderConfig) bool {
	return r.isSettingEnabledForFolder(folderConfig, SettingSnykIacEnabled)
}

func (r *ConfigResolver) IsSnykSecretsEnabledForFolder(folderConfig *FolderConfig) bool {
	return r.isSettingEnabledForFolder(folderConfig, SettingSnykSecretsEnabled)
}

func (r *ConfigResolver) IsProductEnabledForFolder(p product.Product, folderConfig *FolderConfig) bool {
	switch p {
	case product.ProductCode:
		return r.IsSnykCodeEnabledForFolder(folderConfig)
	case product.ProductOpenSource:
		return r.IsSnykOssEnabledForFolder(folderConfig)
	case product.ProductInfrastructureAsCode:
		return r.IsSnykIacEnabledForFolder(folderConfig)
	case product.ProductSecrets:
		return r.IsSnykSecretsEnabledForFolder(folderConfig)
	default:
		return false
	}
}

func (r *ConfigResolver) DisplayableIssueTypesForFolder(folderConfig *FolderConfig) map[product.FilterableIssueType]bool {
	enabled := make(map[product.FilterableIssueType]bool)
	enabled[product.FilterableIssueTypeOpenSource] = r.IsSnykOssEnabledForFolder(folderConfig)
	enabled[product.FilterableIssueTypeCodeSecurity] = r.IsSnykCodeEnabledForFolder(folderConfig)
	enabled[product.FilterableIssueTypeInfrastructureAsCode] = r.IsSnykIacEnabledForFolder(folderConfig)
	enabled[product.FilterableIssueTypeSecrets] = r.IsSnykSecretsEnabledForFolder(folderConfig)
	return enabled
}
