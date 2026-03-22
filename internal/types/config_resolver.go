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
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/internal/product"
)

//go:generate go tool github.com/golang/mock/mockgen -destination=mock_types/config_resolver_interface_mock.go -package=mock_types github.com/snyk/snyk-ls/internal/types ConfigResolverInterface

// ConfigSource is the GAF config source type used by the resolver.
type ConfigSource = configresolver.ConfigSource

// ConfigResolverInterface defines the contract for resolving configuration values.
// It is the single entry point for reading effective configuration, considering
// LDX-Sync org/machine config, user overrides, and global defaults.
// Implementations must be safe for concurrent use.
type ConfigResolverInterface interface {
	// Resolution methods
	GetValue(settingName string, folderConfig *FolderConfig) (any, ConfigSource)
	GetEffectiveValue(settingName string, folderConfig *FolderConfig) EffectiveValue
	GetBool(settingName string, folderConfig *FolderConfig) bool
	GetString(settingName string, folderConfig *FolderConfig) string
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

	// Configuration returns the underlying configuration for direct prefix key access.
	Configuration() configuration.Configuration

	// ConfigurationOptionsMetaData returns the registered ConfigurationOptionsMetaData for annotation lookup.
	ConfigurationOptionsMetaData() workflow.ConfigurationOptionsMetaData
}

// ConfigResolver is the single entry point for reading configuration values.
// It encapsulates the resolution logic and ensures correct precedence:
// 1. Machine-wide settings → Locked LDX-Sync > Global Config > LDX-Sync > Default
// 2. Folder-scoped settings → FolderConfig (with LDX-Sync folder settings)
// 3. Org-scoped settings → Locked LDX-Sync > User Override > LDX-Sync > Global Default
// All methods are safe for concurrent use.
type ConfigResolver struct {
	mu                sync.RWMutex
	logger            *zerolog.Logger
	prefixKeyResolver *configresolver.Resolver
	prefixKeyConf     configuration.Configuration
	fm                workflow.ConfigurationOptionsMetaData
}

var _ ConfigResolverInterface = (*ConfigResolver)(nil)

// folderMetadataSettings are stored under FolderMetadataKey, not UserFolderKey.
// Configuration resolver only reads UserFolderKey; metadata must be read directly.
var folderMetadataSettings = map[string]bool{
	SettingLocalBranches:     true,
	SettingAutoDeterminedOrg: true,
}

// folderNativeSettings are folder-native settings where a UserFolderKey value represents
// the folder's authoritative value, not a user override of an org default. These settings
// may still be sourced from a locked remote (which takes precedence), but when the value
// comes from UserFolderKey (e.g. git enrichment), their wire source string is "folder".
var folderNativeSettings = map[string]bool{
	SettingPreferredOrg: true,
	SettingOrgSetByUser: true,
	SettingBaseBranch:   true,
}

// NewConfigResolver creates a new ConfigResolver with the given dependencies.
func NewConfigResolver(logger *zerolog.Logger) *ConfigResolver {
	return &ConfigResolver{
		logger: logger,
	}
}

// Configuration returns the underlying configuration for direct prefix key access.
func (r *ConfigResolver) Configuration() configuration.Configuration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.prefixKeyConf
}

// SetPrefixKeyResolver wires the ConfigResolver, Configuration, and ConfigurationOptionsMetaData for prefix-key-based resolution.
// When set, GetValue delegates to the configuration resolver instead of the legacy implementation.
func (r *ConfigResolver) SetPrefixKeyResolver(prefixKeyResolver *configresolver.Resolver, prefixKeyConf configuration.Configuration, fm workflow.ConfigurationOptionsMetaData) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prefixKeyResolver = prefixKeyResolver
	r.prefixKeyConf = prefixKeyConf
	r.fm = fm
}

// ConfigurationOptionsMetaData returns the registered ConfigurationOptionsMetaData, or nil if not set.
func (r *ConfigResolver) ConfigurationOptionsMetaData() workflow.ConfigurationOptionsMetaData {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.fm
}

// configSourceString converts a GAF ConfigSource to the wire string sent to the IDE.
// ConfigSourceLocal is returned only for folder metadata settings (local_branches, auto_determined_org)
// and maps to "folder" — they are automatically determined per-folder by the LS.
// For UserFolderOverride sources, folder-native settings use "folder"; all others use "user-override".
func configSourceString(source configresolver.ConfigSource, settingName string) string {
	switch source {
	case configresolver.ConfigSourceDefault:
		return "default"
	case configresolver.ConfigSourceLocal:
		return "folder"
	case configresolver.ConfigSourceUserGlobal:
		return "global"
	case configresolver.ConfigSourceUserFolderOverride:
		if folderNativeSettings[settingName] {
			return "folder"
		}
		return "user-override"
	case configresolver.ConfigSourceRemote:
		return "ldx-sync"
	case configresolver.ConfigSourceRemoteLocked:
		return "ldx-sync-locked"
	default:
		return "default"
	}
}

// getFolderPath returns the normalized folder path from a FolderConfig, or "" if nil.
func (r *ConfigResolver) getFolderPath(folderConfig *FolderConfig) string {
	if folderConfig == nil {
		return ""
	}
	return string(PathKey(folderConfig.GetFolderPath()))
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
	orgSetKey := configresolver.UserFolderKey(folderPath, SettingOrgSetByUser)
	if !r.prefixKeyConf.IsSet(orgSetKey) {
		return "", false
	}
	lf, ok := r.prefixKeyConf.Get(orgSetKey).(*configresolver.LocalConfigField)
	if !ok || lf == nil || !lf.Changed {
		return "", false
	}
	orgSetByUser, ok := lf.Value.(bool)
	if !ok || !orgSetByUser {
		return "", false
	}
	prefKey := configresolver.UserFolderKey(folderPath, SettingPreferredOrg)
	if !r.prefixKeyConf.IsSet(prefKey) {
		return "", true
	}
	pf, ok := r.prefixKeyConf.Get(prefKey).(*configresolver.LocalConfigField)
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
	metaKey := configresolver.FolderMetadataKey(folderPath, SettingAutoDeterminedOrg)
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
// Reads from UserGlobalKey(SettingOrganization) first (set by SetOrganization via LSP
// settings; no GAF default function, so no network call), then falls back to the bare
// ORGANIZATION key (reads stored value without triggering /rest/self auto-determination).
// This is intentionally a hot-path read used by StateSnapshot — it must not make network
// calls. The distinguished org auto-determination path is GetGlobalOrganization.
func (r *ConfigResolver) getGlobalOrg() string {
	if r.prefixKeyConf == nil {
		return ""
	}
	key := configresolver.UserGlobalKey(SettingOrganization)
	val := r.prefixKeyConf.Get(key)
	if s, ok := val.(string); ok && s != "" {
		return s
	}
	if s, ok := r.prefixKeyConf.Get(configuration.ORGANIZATION).(string); ok && s != "" {
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
				val := r.prefixKeyConf.Get(configresolver.FolderMetadataKey(folderPath, settingName))
				if val != nil {
					return val, configresolver.ConfigSourceLocal
				}
			}
			return nil, configresolver.ConfigSourceDefault
		}
		// All other settings: delegate to configuration resolver
		effectiveOrg := r.getEffectiveOrg(folderConfig)
		folderPath := ""
		if folderConfig != nil {
			folderPath = string(PathKey(folderConfig.GetFolderPath()))
		}
		val, source := r.prefixKeyResolver.Resolve(settingName, effectiveOrg, folderPath)
		return val, source
	}

	// Legacy fallback removed: prefixKeyResolver must be set in production.
	// Return default to avoid breaking tests that don't set configuration resolver.
	if r.logger != nil {
		r.logger.Warn().Str("setting", settingName).Msg("ConfigResolver: prefixKeyResolver is nil, returning default")
	}
	return nil, configresolver.ConfigSourceDefault
}

// GetEffectiveValue resolves a configuration value and returns it as an EffectiveValue
// with source information for display to the IDE.
func (r *ConfigResolver) GetEffectiveValue(settingName string, folderConfig *FolderConfig) EffectiveValue {
	r.mu.RLock()
	defer r.mu.RUnlock()
	value, source := r.getValueLocked(settingName, folderConfig)

	originScope := ""
	if source == configresolver.ConfigSourceRemote || source == configresolver.ConfigSourceRemoteLocked {
		originScope = r.getOriginScope(settingName, folderConfig)
	}

	return EffectiveValue{
		Value:       value,
		Source:      configSourceString(source, settingName),
		OriginScope: originScope,
	}
}

// getOriginScope retrieves the server-side origin scope for a setting from LDX-Sync.
// Reads from GAF RemoteMachineKey / RemoteOrgKey prefix keys (already populated by WriteOrgConfigToConfiguration
// and WriteMachineConfigToConfiguration), avoiding a separate cache.
func (r *ConfigResolver) getOriginScope(settingName string, folderConfig *FolderConfig) string {
	if r.prefixKeyConf == nil {
		return ""
	}
	switch GetSettingScope(r.fm, settingName) {
	case configresolver.MachineScope:
		key := configresolver.RemoteMachineKey(settingName)
		if val := r.prefixKeyConf.Get(key); val != nil {
			if field, ok := val.(*configresolver.RemoteConfigField); ok && field != nil {
				return field.Origin
			}
		}
	case configresolver.FolderScope:
		if folderConfig != nil {
			effectiveOrg := r.getEffectiveOrg(folderConfig)
			if effectiveOrg != "" {
				key := configresolver.RemoteOrgKey(effectiveOrg, settingName)
				if val := r.prefixKeyConf.Get(key); val != nil {
					if field, ok := val.(*configresolver.RemoteConfigField); ok && field != nil {
						return field.Origin
					}
				}
			}
		}
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

// IsLocked returns true if the setting is locked by LDX-Sync for the folder's org.
// Checks both folder-level and org-level remote locks.
func (r *ConfigResolver) IsLocked(settingName string, folderConfig *FolderConfig) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.prefixKeyResolver == nil {
		return false
	}
	effectiveOrg := r.getEffectiveOrg(folderConfig)
	folderPath := r.getFolderPath(folderConfig)
	return r.prefixKeyResolver.IsLocked(settingName, effectiveOrg, folderPath)
}

// isSettingEnabledForFolder resolves a boolean setting for a folder.
// GAF prefix key resolver returns correct values including defaults; no fallback needed.
func (r *ConfigResolver) isSettingEnabledForFolder(folderConfig *FolderConfig, settingName string) bool {
	return r.GetBool(settingName, folderConfig)
}

func (r *ConfigResolver) FilterSeverityForFolder(folderConfig *FolderConfig) SeverityFilter {
	val, source := r.GetValue(SettingEnabledSeverities, folderConfig)
	if source != configresolver.ConfigSourceDefault {
		if filter, ok := val.(*SeverityFilter); ok && filter != nil {
			return *filter
		}
	}
	if r.prefixKeyConf != nil {
		return GetFilterSeverityFromConfig(r.prefixKeyConf)
	}
	return SeverityFilter{}
}

func (r *ConfigResolver) RiskScoreThresholdForFolder(folderConfig *FolderConfig) int {
	val, source := r.GetValue(SettingRiskScoreThreshold, folderConfig)
	if source != configresolver.ConfigSourceDefault {
		if threshold, ok := val.(int); ok {
			return threshold
		}
	}
	return 0
}

func (r *ConfigResolver) IssueViewOptionsForFolder(folderConfig *FolderConfig) IssueViewOptions {
	result := IssueViewOptions{}
	if r.prefixKeyConf != nil {
		result = GetIssueViewOptionsFromConfig(r.prefixKeyConf)
	}
	if val, source := r.GetValue(SettingIssueViewOpenIssues, folderConfig); source != configresolver.ConfigSourceDefault {
		if open, ok := val.(bool); ok {
			result.OpenIssues = open
		}
	}
	if val, source := r.GetValue(SettingIssueViewIgnoredIssues, folderConfig); source != configresolver.ConfigSourceDefault {
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
