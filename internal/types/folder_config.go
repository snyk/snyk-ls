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
	"maps"
	"strings"

	"github.com/snyk/code-client-go/pkg/code/sast_contract"
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/internal/product"
)

// ImmutableFolderConfig provides read-only access to stored folder configuration.
// Use this interface for consumers that only need to read config values,
// enforcing immutability at the type level.
type ImmutableFolderConfig interface {
	GetFolderPath() FilePath
	GetPreferredOrg() string
	GetAutoDeterminedOrg() string
	IsOrgSetByUser() bool
	GetBaseBranch() string
	GetLocalBranches() []string
	GetAdditionalParameters() []string
	GetAdditionalEnv() string
	GetReferenceFolderPath() FilePath
	GetScanCommandConfig() map[product.Product]ScanCommandConfig
	GetFeatureFlag(flag string) bool
	HasUserOverride(settingName string) bool
	GetUserOverride(settingName string) (any, bool)
}

// FolderConfig is the internal storage representation of folder configuration.
// This is persisted to disk and contains all folder-specific settings including user overrides.
// For the public LSP contract, see LspFolderConfig in lsp.go.
type FolderConfig struct {
	FolderPath                  FilePath                              `json:"folderPath"`
	BaseBranch                  string                                `json:"baseBranch"`
	LocalBranches               []string                              `json:"localBranches,omitempty"`
	AdditionalParameters        []string                              `json:"additionalParameters,omitempty"`
	AdditionalEnv               string                                `json:"additionalEnv,omitempty"`
	ReferenceFolderPath         FilePath                              `json:"referenceFolderPath,omitempty"`
	ScanCommandConfig           map[product.Product]ScanCommandConfig `json:"scanCommandConfig,omitempty"`
	PreferredOrg                string                                `json:"preferredOrg"`
	AutoDeterminedOrg           string                                `json:"autoDeterminedOrg"`
	OrgMigratedFromGlobalConfig bool                                  `json:"orgMigratedFromGlobalConfig"`
	OrgSetByUser                bool                                  `json:"orgSetByUser"`
	FeatureFlags                map[string]bool                       `json:"featureFlags"`
	SastSettings                *sast_contract.SastResponse           `json:"sastSettings"`
	// UserOverrides stores user-specified overrides for org-scope settings.
	// Key presence indicates the user has explicitly set this value (even if it matches the default).
	// Key absence means we should use LDX-Sync or default value.
	// This is LS-managed and should not be directly set by the IDE.
	UserOverrides map[string]any `json:"userOverrides,omitempty"`
	// EffectiveConfig contains computed effective values for org-scope settings.
	// Sent to IDE for display and to drive IDE behavior. Read-only from IDE perspective.
	// Key is the setting name (e.g., SettingEnabledSeverities), value is EffectiveValue.
	EffectiveConfig map[string]EffectiveValue `json:"effectiveConfig,omitempty"`

	// conf is an optional reference to GAF Configuration for dual-write.
	// When set, SetUserOverride/ResetToDefault also write to prefix keys.
	// Not serialized (json:"-"). Set via SetConf().
	conf configuration.Configuration `json:"-"`
}

func (fc *FolderConfig) Clone() *FolderConfig {
	if fc == nil {
		return nil
	}

	clone := &FolderConfig{
		FolderPath:                  fc.FolderPath,
		BaseBranch:                  fc.BaseBranch,
		AdditionalEnv:               fc.AdditionalEnv,
		ReferenceFolderPath:         fc.ReferenceFolderPath,
		PreferredOrg:                fc.PreferredOrg,
		AutoDeterminedOrg:           fc.AutoDeterminedOrg,
		OrgMigratedFromGlobalConfig: fc.OrgMigratedFromGlobalConfig,
		OrgSetByUser:                fc.OrgSetByUser,
	}

	if fc.LocalBranches != nil {
		clone.LocalBranches = make([]string, len(fc.LocalBranches))
		copy(clone.LocalBranches, fc.LocalBranches)
	}

	if fc.AdditionalParameters != nil {
		clone.AdditionalParameters = make([]string, len(fc.AdditionalParameters))
		copy(clone.AdditionalParameters, fc.AdditionalParameters)
	}

	if fc.ScanCommandConfig != nil {
		clone.ScanCommandConfig = make(map[product.Product]ScanCommandConfig, len(fc.ScanCommandConfig))
		maps.Copy(clone.ScanCommandConfig, fc.ScanCommandConfig)
	}

	if fc.FeatureFlags != nil {
		clone.FeatureFlags = make(map[string]bool, len(fc.FeatureFlags))
		maps.Copy(clone.FeatureFlags, fc.FeatureFlags)
	}

	if fc.SastSettings != nil {
		clone.SastSettings = &sast_contract.SastResponse{
			SastEnabled:                 fc.SastSettings.SastEnabled,
			LocalCodeEngine:             fc.SastSettings.LocalCodeEngine,
			Org:                         fc.SastSettings.Org,
			ReportFalsePositivesEnabled: fc.SastSettings.ReportFalsePositivesEnabled,
			AutofixEnabled:              fc.SastSettings.AutofixEnabled,
		}
		if fc.SastSettings.SupportedLanguages != nil {
			clone.SastSettings.SupportedLanguages = make([]string, len(fc.SastSettings.SupportedLanguages))
			copy(clone.SastSettings.SupportedLanguages, fc.SastSettings.SupportedLanguages)
		}
	}

	if fc.UserOverrides != nil {
		clone.UserOverrides = make(map[string]any, len(fc.UserOverrides))
		maps.Copy(clone.UserOverrides, fc.UserOverrides)
	}

	if fc.EffectiveConfig != nil {
		clone.EffectiveConfig = make(map[string]EffectiveValue, len(fc.EffectiveConfig))
		maps.Copy(clone.EffectiveConfig, fc.EffectiveConfig)
	}

	clone.conf = fc.conf

	return clone
}

// HasUserOverride checks if the user has explicitly set a value for the given setting
func (fc *FolderConfig) HasUserOverride(settingName string) bool {
	_, exists := fc.GetUserOverride(settingName)
	return exists
}

// GetUserOverride returns the user override value for the given setting, or nil if not set
func (fc *FolderConfig) GetUserOverride(settingName string) (any, bool) {
	if fc == nil || fc.UserOverrides == nil {
		return nil, false
	}
	val, exists := fc.UserOverrides[settingName]
	return val, exists
}

// GetFolderPath returns the folder path
func (fc *FolderConfig) GetFolderPath() FilePath {
	if fc == nil {
		return ""
	}
	return fc.FolderPath
}

// GetPreferredOrg returns the preferred org
func (fc *FolderConfig) GetPreferredOrg() string {
	if fc == nil {
		return ""
	}
	return fc.PreferredOrg
}

// GetAutoDeterminedOrg returns the automatically determined org (e.g. from LDX-Sync)
func (fc *FolderConfig) GetAutoDeterminedOrg() string {
	if fc == nil {
		return ""
	}
	return fc.AutoDeterminedOrg
}

// IsOrgSetByUser returns whether the org was explicitly set by the user
func (fc *FolderConfig) IsOrgSetByUser() bool {
	if fc == nil {
		return false
	}
	return fc.OrgSetByUser
}

// GetBaseBranch returns the base branch
func (fc *FolderConfig) GetBaseBranch() string {
	if fc == nil {
		return ""
	}
	return fc.BaseBranch
}

// GetLocalBranches returns the local branches
func (fc *FolderConfig) GetLocalBranches() []string {
	if fc == nil {
		return nil
	}
	return fc.LocalBranches
}

// GetAdditionalParameters returns the additional CLI parameters
func (fc *FolderConfig) GetAdditionalParameters() []string {
	if fc == nil {
		return nil
	}
	return fc.AdditionalParameters
}

// GetAdditionalEnv returns the additional environment variables
func (fc *FolderConfig) GetAdditionalEnv() string {
	if fc == nil {
		return ""
	}
	return fc.AdditionalEnv
}

// GetReferenceFolderPath returns the reference folder path
func (fc *FolderConfig) GetReferenceFolderPath() FilePath {
	if fc == nil {
		return ""
	}
	return fc.ReferenceFolderPath
}

// GetScanCommandConfig returns the scan command configuration per product
func (fc *FolderConfig) GetScanCommandConfig() map[product.Product]ScanCommandConfig {
	if fc == nil || fc.ScanCommandConfig == nil {
		return nil
	}
	return fc.ScanCommandConfig
}

// GetFeatureFlag returns the value of a feature flag, defaulting to false
func (fc *FolderConfig) GetFeatureFlag(flag string) bool {
	if fc == nil || fc.FeatureFlags == nil {
		return false
	}
	return fc.FeatureFlags[flag]
}

// Conf returns the GAF Configuration reference for dual-write. Used by ToLspFolderConfig
// to obtain FlagMetadata for iterating registered settings.
func (fc *FolderConfig) Conf() configuration.Configuration {
	return fc.conf
}

// SetConf sets the GAF Configuration for dual-write. When set, SetUserOverride and
// ResetToDefault also write to Configuration prefix keys.
func (fc *FolderConfig) SetConf(conf configuration.Configuration) {
	fc.conf = conf
}

// SetUserOverride explicitly sets a user override value for the given setting
func (fc *FolderConfig) SetUserOverride(settingName string, value any) {
	if fc.UserOverrides == nil {
		fc.UserOverrides = make(map[string]any)
	}
	fc.UserOverrides[settingName] = value

	if fc.conf != nil {
		key := configuration.UserFolderKey(string(PathKey(fc.FolderPath)), settingName)
		fc.conf.Set(key, &configuration.LocalConfigField{Value: value, Changed: true})
	}
}

// ResetToDefault removes a user override, reverting to LDX-Sync or default value
func (fc *FolderConfig) ResetToDefault(settingName string) {
	if fc.UserOverrides != nil {
		delete(fc.UserOverrides, settingName)
	}

	if fc.conf != nil {
		key := configuration.UserFolderKey(string(PathKey(fc.FolderPath)), settingName)
		fc.conf.Unset(key)
	}
}

// SyncToConfiguration writes folder state to GAF Configuration under the correct prefix keys:
//   - UserFolderKey: user overrides, user-settable folder settings (BaseBranch, OrgSetByUser,
//     PreferredOrg, AdditionalParameters, AdditionalEnvironment, ReferenceFolder, ScanCommandConfig)
//   - FolderMetadataKey: LS-enriched metadata (AutoDeterminedOrg, LocalBranches)
func (fc *FolderConfig) SyncToConfiguration() {
	if fc == nil || fc.conf == nil {
		return
	}

	folderPath := string(PathKey(fc.FolderPath))

	for name, value := range fc.UserOverrides {
		key := configuration.UserFolderKey(folderPath, name)
		fc.conf.Set(key, &configuration.LocalConfigField{Value: value, Changed: true})
	}

	setUserFolderValue := func(name string, value any) {
		if value == nil {
			return
		}
		switch v := value.(type) {
		case string:
			if v == "" {
				return
			}
		case []string:
			if len(v) == 0 {
				return
			}
		case map[product.Product]ScanCommandConfig:
			if len(v) == 0 {
				return
			}
		}
		fc.conf.Set(configuration.UserFolderKey(folderPath, name), &configuration.LocalConfigField{Value: value, Changed: true})
	}

	// User-settable folder settings → UserFolderKey
	fc.conf.Set(configuration.UserFolderKey(folderPath, SettingOrgSetByUser), &configuration.LocalConfigField{Value: fc.OrgSetByUser, Changed: true})
	if fc.OrgSetByUser {
		setUserFolderValue(SettingPreferredOrg, fc.PreferredOrg)
	}
	setUserFolderValue(SettingBaseBranch, fc.BaseBranch)
	setUserFolderValue(SettingReferenceBranch, fc.BaseBranch)
	setUserFolderValue(SettingAdditionalParameters, fc.AdditionalParameters)
	setUserFolderValue(SettingAdditionalEnvironment, fc.AdditionalEnv)
	setUserFolderValue(SettingReferenceFolder, fc.ReferenceFolderPath)
	setUserFolderValue(SettingScanCommandConfig, fc.ScanCommandConfig)

	// LS-enriched metadata → FolderMetadataKey
	if fc.AutoDeterminedOrg != "" {
		fc.conf.Set(configuration.FolderMetadataKey(folderPath, SettingAutoDeterminedOrg), fc.AutoDeterminedOrg)
	}
	if len(fc.LocalBranches) > 0 {
		fc.conf.Set(configuration.FolderMetadataKey(folderPath, SettingLocalBranches), fc.LocalBranches)
	}
}

// SanitizeForIDE returns a copy of the FolderConfig prepared for sending to the IDE.
// - UserOverrides, FeatureFlags, SastSettings are cleared (LS-managed, not exposed to IDE)
// - EffectiveConfig is kept (IDE needs this for display and behavior)
// Deprecated: Use ToLspFolderConfig instead for the new LSP contract.
func (fc *FolderConfig) SanitizeForIDE() FolderConfig {
	sanitized := *fc
	sanitized.UserOverrides = nil

	// TODO we might reinstate these when we fix IDE-1539, and have the IDEs use these instead of looking them up.
	sanitized.FeatureFlags = nil
	sanitized.SastSettings = nil

	return sanitized
}

// isMeaningfulValue returns false for nil or zero values that should not be sent to the IDE.
func isMeaningfulValue(value any) bool {
	if value == nil {
		return false
	}
	switch v := value.(type) {
	case string:
		return v != ""
	case int:
		return v != 0
	case bool:
		return true
	case *SeverityFilter:
		return v != nil
	case []string:
		return len(v) > 0
	}
	return true
}

// ToLspFolderConfig converts a FolderConfig to LspFolderConfig for sending to IDE.
// Uses ONLY ConfigResolverInterface + FlagMetadata. Iterates all org and folder-scope
// settings via FlagsByAnnotation and resolves each through the resolver.
// If resolver is nil or FlagMetadata unavailable, returns LspFolderConfig with empty settings.
func (fc *FolderConfig) ToLspFolderConfig(resolver ConfigResolverInterface) *LspFolderConfig {
	if fc == nil {
		return nil
	}

	settings := make(map[string]*ConfigSetting)
	if resolver == nil {
		return &LspFolderConfig{FolderPath: fc.FolderPath, Settings: settings}
	}

	conf := fc.Conf()
	fm, hasFM := conf.(configuration.FlagMetadata)
	if !hasFM {
		return &LspFolderConfig{FolderPath: fc.FolderPath, Settings: settings}
	}

	for _, scope := range []string{"org", "folder"} {
		for _, name := range fm.FlagsByAnnotation(configuration.AnnotationScope, scope) {
			if wo, found := fm.GetFlagAnnotation(name, configuration.AnnotationWriteOnly); found && wo == "true" {
				continue
			}
			ev := resolver.GetEffectiveValue(name, fc)
			cs := &ConfigSetting{
				Value:       ev.Value,
				Source:      ev.Source,
				OriginScope: ev.OriginScope,
				IsLocked:    strings.Contains(ev.Source, "locked"),
			}
			if !isMeaningfulValue(ev.Value) {
				continue
			}
			switch name {
			case SettingEnabledSeverities:
				if filter, ok := ev.Value.(*SeverityFilter); ok && filter != nil {
					cs.Value = *filter
					settings[name] = cs
				}
			case SettingCweIds, SettingCveIds, SettingRuleIds:
				if sl, ok := ev.Value.([]string); ok && len(sl) > 0 {
					settings[name] = cs
				}
			default:
				settings[name] = cs
			}
		}
	}

	return &LspFolderConfig{FolderPath: fc.FolderPath, Settings: settings}
}

// ApplyLspUpdate applies changes from an LspFolderConfig using PATCH semantics.
// For *LocalConfigField org-scope settings:
//   - nil = omitted (don't change)
//   - Changed: true + Value: nil = clear override (reset to default)
//   - Changed: true + Value: non-nil = set override
//
// For pointer fields (folder-scope):
//   - nil = don't change
//   - non-nil = set value
//
// Returns true if any changes were made.
func (fc *FolderConfig) ApplyLspUpdate(update *LspFolderConfig) bool {
	if fc == nil || update == nil {
		return false
	}

	changed := fc.applyFolderScopeUpdates(update)
	changed = fc.applyOrgScopeUpdates(update) || changed

	return changed
}

// getSettingValue returns the value from Settings map for a given key, with type conversion.
func getSettingValue[T any](settings map[string]*ConfigSetting, name string) (T, bool) {
	if settings == nil {
		var zero T
		return zero, false
	}
	cs := settings[name]
	if cs == nil || cs.Value == nil {
		var zero T
		return zero, false
	}
	v, ok := cs.Value.(T)
	return v, ok
}

// getStringSliceFromSetting extracts []string from ConfigSetting.Value, handling JSON []interface{} unmarshaling.
func getStringSliceFromSetting(settings map[string]*ConfigSetting, name string) ([]string, bool) {
	cs := settings[name]
	if cs == nil || cs.Value == nil {
		return nil, false
	}
	if sl, ok := cs.Value.([]string); ok {
		return sl, true
	}
	if ifaces, ok := cs.Value.([]interface{}); ok && len(ifaces) > 0 {
		result := make([]string, 0, len(ifaces))
		for _, v := range ifaces {
			if s, ok := v.(string); ok {
				result = append(result, s)
			}
		}
		return result, len(result) > 0
	}
	return nil, false
}

// applyFolderScopeUpdates applies folder-scope field updates from Settings map
func (fc *FolderConfig) applyFolderScopeUpdates(update *LspFolderConfig) bool {
	if update.Settings == nil {
		return false
	}
	changed := fc.applyBasicFolderFields(update)
	preferredOrgUpdated := fc.applyPreferredOrg(update)
	if preferredOrgUpdated {
		changed = true
	}
	if fc.applyOrgSetByUser(update, preferredOrgUpdated) {
		changed = true
	}
	return changed
}

func (fc *FolderConfig) applyBasicFolderFields(update *LspFolderConfig) bool {
	changed := false
	if baseBranch, ok := getSettingValue[string](update.Settings, SettingBaseBranch); ok && baseBranch != fc.BaseBranch {
		fc.BaseBranch = baseBranch
		changed = true
	}
	if localBranches, ok := getStringSliceFromSetting(update.Settings, SettingLocalBranches); ok {
		fc.LocalBranches = localBranches
		changed = true
	}
	if additionalParams, ok := getStringSliceFromSetting(update.Settings, SettingAdditionalParameters); ok {
		fc.AdditionalParameters = additionalParams
		changed = true
	}
	if additionalEnv, ok := getSettingValue[string](update.Settings, SettingAdditionalEnvironment); ok && additionalEnv != fc.AdditionalEnv {
		fc.AdditionalEnv = additionalEnv
		changed = true
	}
	if refFolder, ok := getSettingValue[string](update.Settings, SettingReferenceFolder); ok && FilePath(refFolder) != fc.ReferenceFolderPath {
		fc.ReferenceFolderPath = FilePath(refFolder)
		changed = true
	}
	if scanCmdConfig, ok := getSettingValue[map[product.Product]ScanCommandConfig](update.Settings, SettingScanCommandConfig); ok && len(scanCmdConfig) > 0 {
		fc.ScanCommandConfig = scanCmdConfig
		changed = true
	}
	return changed
}

func (fc *FolderConfig) applyPreferredOrg(update *LspFolderConfig) bool {
	preferredOrg, ok := getSettingValue[string](update.Settings, SettingPreferredOrg)
	if !ok || preferredOrg == fc.PreferredOrg {
		return false
	}
	fc.PreferredOrg = preferredOrg
	fc.OrgSetByUser = true
	return true
}

func (fc *FolderConfig) applyOrgSetByUser(update *LspFolderConfig, preferredOrgUpdated bool) bool {
	if preferredOrgUpdated {
		return false
	}
	orgSetByUser, ok := getSettingValue[bool](update.Settings, SettingOrgSetByUser)
	if !ok || orgSetByUser == fc.OrgSetByUser {
		return false
	}
	fc.OrgSetByUser = orgSetByUser
	return true
}

// applyOrgScopeUpdates applies org-scope setting updates from Settings map using PATCH semantics:
//   - nil = omitted (don't change)
//   - Changed: true + Value: nil = clear override (reset to default)
//   - Changed: true + Value: non-nil = set override
//
// Iterates over Settings entries with Changed: true and scope from GetSettingScope (org-scope only).
func (fc *FolderConfig) applyOrgScopeUpdates(update *LspFolderConfig) bool {
	if update.Settings == nil {
		return false
	}
	changed := false
	for name, cs := range update.Settings {
		if cs == nil || !cs.Changed {
			continue
		}
		if !IsOrgScopedSetting(name) {
			continue
		}
		if cs.Value == nil {
			if fc.HasUserOverride(name) {
				fc.ResetToDefault(name)
				changed = true
			}
			continue
		}
		fc.SetUserOverride(name, cs.Value)
		changed = true
	}
	return changed
}

// FolderConfigsParam is used internally for storage operations.
type FolderConfigsParam struct {
	FolderConfigs []FolderConfig `json:"folderConfigs"`
}
