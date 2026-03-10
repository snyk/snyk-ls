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
	"strings"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/internal/product"
)

// FeatureFlagPrefix is used for storing per-folder feature flags in configuration
// under FolderMetadataKey(folderPath, FeatureFlagPrefix + flagName).
const FeatureFlagPrefix = "ff_"

// FolderConfig is a thin wrapper around a folder path and a ConfigResolver.
// All configuration values (including SAST settings) are stored in configuration
// prefix keys and accessed via the ConfigResolver or typed helpers (e.g. GetSastSettings).
// EffectiveConfig is populated for HTML template display only (LDX-Sync config section).
type FolderConfig struct {
	FolderPath      FilePath                  `json:"folderPath"`
	ConfigResolver  ConfigResolverInterface   `json:"-"`
	EffectiveConfig map[string]EffectiveValue `json:"effectiveConfig,omitempty"`
	Engine          workflow.Engine           `json:"-"`
}

func (fc *FolderConfig) Clone() *FolderConfig {
	if fc == nil {
		return nil
	}

	return &FolderConfig{
		FolderPath:     fc.FolderPath,
		ConfigResolver: fc.ConfigResolver,
		Engine:         fc.Engine,
	}
}

// PreferredOrg returns the preferred org from configuration (for template/display).
func (fc *FolderConfig) PreferredOrg() string {
	s := ReadFolderConfigSnapshot(fc.Conf(), fc.FolderPath)
	return s.PreferredOrg
}

// AutoDeterminedOrg returns the auto-determined org from configuration (for template/display).
func (fc *FolderConfig) AutoDeterminedOrg() string {
	s := ReadFolderConfigSnapshot(fc.Conf(), fc.FolderPath)
	return s.AutoDeterminedOrg
}

// OrgSetByUser returns whether org was set by user from configuration (for template/display).
func (fc *FolderConfig) OrgSetByUser() bool {
	s := ReadFolderConfigSnapshot(fc.Conf(), fc.FolderPath)
	return s.OrgSetByUser
}

// AdditionalParameters returns additional parameters from configuration (for template/display).
func (fc *FolderConfig) AdditionalParameters() []string {
	s := ReadFolderConfigSnapshot(fc.Conf(), fc.FolderPath)
	return s.AdditionalParameters
}

// AdditionalEnv returns additional env from configuration (for template/display).
func (fc *FolderConfig) AdditionalEnv() string {
	s := ReadFolderConfigSnapshot(fc.Conf(), fc.FolderPath)
	return s.AdditionalEnv
}

// ScanCommandConfig returns scan command config from configuration (for template/display).
func (fc *FolderConfig) ScanCommandConfig() map[product.Product]ScanCommandConfig {
	s := ReadFolderConfigSnapshot(fc.Conf(), fc.FolderPath)
	return s.ScanCommandConfig
}

// BaseBranch returns base branch from configuration (for template/display).
func (fc *FolderConfig) BaseBranch() string {
	s := ReadFolderConfigSnapshot(fc.Conf(), fc.FolderPath)
	return s.BaseBranch
}

// ReferenceFolderPath returns reference folder path from configuration (for template/display).
func (fc *FolderConfig) ReferenceFolderPath() FilePath {
	s := ReadFolderConfigSnapshot(fc.Conf(), fc.FolderPath)
	return s.ReferenceFolderPath
}

// UserOverrides returns user overrides from configuration (for template/display).
func (fc *FolderConfig) UserOverrides() map[string]any {
	s := ReadFolderConfigSnapshot(fc.Conf(), fc.FolderPath)
	return s.UserOverrides
}

// GetFolderPath returns the folder path
func (fc *FolderConfig) GetFolderPath() FilePath {
	if fc == nil {
		return ""
	}
	return fc.FolderPath
}

// GetFeatureFlag returns the value of a feature flag from configuration, defaulting to false.
func (fc *FolderConfig) GetFeatureFlag(flag string) bool {
	if fc == nil {
		return false
	}
	conf := fc.Conf()
	if conf == nil {
		return false
	}
	key := configresolver.FolderMetadataKey(string(PathKey(fc.FolderPath)), FeatureFlagPrefix+flag)
	return conf.GetBool(key)
}

// SetFeatureFlag writes a feature flag value to configuration under the folder metadata prefix.
func (fc *FolderConfig) SetFeatureFlag(flag string, value bool) {
	if fc == nil {
		return
	}
	conf := fc.Conf()
	if conf == nil {
		return
	}
	key := configresolver.FolderMetadataKey(string(PathKey(fc.FolderPath)), FeatureFlagPrefix+flag)
	conf.PersistInStorage(key)
	conf.Set(key, value)
}

// Conf returns the configuration for prefix key access.
// Delegates to ConfigResolver.Configuration() when available.
func (fc *FolderConfig) Conf() configuration.Configuration {
	if fc.ConfigResolver != nil {
		return fc.ConfigResolver.Configuration()
	}
	return nil
}

// SetConf is a transitional helper that creates a minimal ConfigResolver wrapper
// for code that only has a configuration. Prefer setting ConfigResolver directly.
// Deprecated: Set fc.ConfigResolver instead.
func (fc *FolderConfig) SetConf(conf configuration.Configuration) {
	if fc.ConfigResolver != nil {
		return
	}
	if conf == nil {
		return
	}
	logger := zerolog.Nop()
	r := NewConfigResolver(&logger)
	r.SetPrefixKeyResolver(nil, conf)
	fc.ConfigResolver = r
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
// Uses fc.ConfigResolver + FlagMetadata. Iterates all org and folder-scope settings
// via FlagsByAnnotation and resolves each through the resolver.
// If ConfigResolver is nil or FlagMetadata unavailable, returns LspFolderConfig with empty settings.
func (fc *FolderConfig) ToLspFolderConfig() *LspFolderConfig {
	if fc == nil {
		return nil
	}

	settings := make(map[string]*ConfigSetting)
	resolver := fc.ConfigResolver
	if resolver == nil {
		return &LspFolderConfig{FolderPath: fc.FolderPath, Settings: settings}
	}

	conf := fc.Conf()
	fm, hasFM := conf.(workflow.FlagMetadata)
	if !hasFM {
		return &LspFolderConfig{FolderPath: fc.FolderPath, Settings: settings}
	}

	for _, scope := range []string{"org", "folder"} {
		for _, name := range fm.FlagsByAnnotation(configresolver.AnnotationScope, scope) {
			if wo, found := fm.GetFlagAnnotation(name, configresolver.AnnotationWriteOnly); found && wo == "true" {
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

// getScanCommandConfigFromSetting extracts map[product.Product]ScanCommandConfig from ConfigSetting.Value,
// handling JSON unmarshaling where keys become strings and struct fields become map[string]interface{}.
func getScanCommandConfigFromSetting(settings map[string]*ConfigSetting, name string) (map[product.Product]ScanCommandConfig, bool) {
	if v, ok := getSettingValue[map[product.Product]ScanCommandConfig](settings, name); ok {
		return v, true
	}
	cs := settings[name]
	if cs == nil || cs.Value == nil {
		return nil, false
	}
	raw, ok := cs.Value.(map[string]interface{})
	if !ok || len(raw) == 0 {
		return nil, false
	}
	result := make(map[product.Product]ScanCommandConfig, len(raw))
	for k, v := range raw {
		inner, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		var cfg ScanCommandConfig
		if s, ok := inner["preScanCommand"].(string); ok {
			cfg.PreScanCommand = s
		}
		if b, ok := inner["preScanOnlyReferenceFolder"].(bool); ok {
			cfg.PreScanOnlyReferenceFolder = b
		}
		if s, ok := inner["postScanCommand"].(string); ok {
			cfg.PostScanCommand = s
		}
		if b, ok := inner["postScanOnlyReferenceFolder"].(bool); ok {
			cfg.PostScanOnlyReferenceFolder = b
		}
		result[product.Product(k)] = cfg
	}
	if len(result) == 0 {
		return nil, false
	}
	return result, true
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
	conf := fc.Conf()
	if conf == nil {
		return false
	}
	fp := string(PathKey(fc.FolderPath))
	if fp == "" {
		return false
	}
	setUser := func(name string, val any) {
		key := configresolver.UserFolderKey(fp, name)
		conf.PersistInStorage(key)
		conf.Set(key, &configresolver.LocalConfigField{Value: val, Changed: true})
	}
	setMeta := func(name string, val any) {
		key := configresolver.FolderMetadataKey(fp, name)
		conf.PersistInStorage(key)
		conf.Set(key, val)
	}

	changed := false
	if baseBranch, ok := getSettingValue[string](update.Settings, SettingBaseBranch); ok {
		cur := getStringFromConfig(conf, fp, SettingBaseBranch)
		if baseBranch != cur {
			setUser(SettingBaseBranch, baseBranch)
			setUser(SettingReferenceBranch, baseBranch)
			changed = true
		}
	}
	if localBranches, ok := getStringSliceFromSetting(update.Settings, SettingLocalBranches); ok {
		setMeta(SettingLocalBranches, localBranches)
		changed = true
	}
	if additionalParams, ok := getStringSliceFromSetting(update.Settings, SettingAdditionalParameters); ok {
		setUser(SettingAdditionalParameters, additionalParams)
		changed = true
	}
	if additionalEnv, ok := getSettingValue[string](update.Settings, SettingAdditionalEnvironment); ok {
		cur := getStringFromConfig(conf, fp, SettingAdditionalEnvironment)
		if additionalEnv != cur {
			setUser(SettingAdditionalEnvironment, additionalEnv)
			changed = true
		}
	}
	if refFolder, ok := getSettingValue[string](update.Settings, SettingReferenceFolder); ok {
		cur := getStringFromConfig(conf, fp, SettingReferenceFolder)
		if FilePath(refFolder) != FilePath(cur) {
			setUser(SettingReferenceFolder, refFolder)
			changed = true
		}
	}
	if scanCmdConfig, ok := getScanCommandConfigFromSetting(update.Settings, SettingScanCommandConfig); ok && len(scanCmdConfig) > 0 {
		setUser(SettingScanCommandConfig, scanCmdConfig)
		changed = true
	}
	return changed
}

func getStringFromConfig(conf configuration.Configuration, fp, name string) string {
	key := configresolver.UserFolderKey(fp, name)
	val := conf.Get(key)
	if val == nil {
		return ""
	}
	lf, ok := val.(*configresolver.LocalConfigField)
	if !ok || lf == nil || !lf.Changed {
		return ""
	}
	s, _ := lf.Value.(string)
	return s
}

func getBoolFromConfig(conf configuration.Configuration, fp, name string) bool {
	key := configresolver.UserFolderKey(fp, name)
	val := conf.Get(key)
	if val == nil {
		return false
	}
	lf, ok := val.(*configresolver.LocalConfigField)
	if !ok || lf == nil || !lf.Changed {
		return false
	}
	b, _ := lf.Value.(bool)
	return b
}

func (fc *FolderConfig) applyPreferredOrg(update *LspFolderConfig) bool {
	conf := fc.Conf()
	if conf == nil {
		return false
	}
	fp := string(PathKey(fc.FolderPath))
	if fp == "" {
		return false
	}

	preferredOrg, ok := getSettingValue[string](update.Settings, SettingPreferredOrg)
	if !ok {
		return false
	}
	curPreferred := getStringFromConfig(conf, fp, SettingPreferredOrg)
	if preferredOrg == curPreferred {
		return false
	}

	keyPreferred := configresolver.UserFolderKey(fp, SettingPreferredOrg)
	keyOrgSetByUser := configresolver.UserFolderKey(fp, SettingOrgSetByUser)
	orgSetByUser := preferredOrg != ""
	conf.PersistInStorage(keyPreferred)
	conf.PersistInStorage(keyOrgSetByUser)
	conf.Set(keyPreferred, &configresolver.LocalConfigField{Value: preferredOrg, Changed: true})
	conf.Set(keyOrgSetByUser, &configresolver.LocalConfigField{Value: orgSetByUser, Changed: true})
	return true
}

func (fc *FolderConfig) applyOrgSetByUser(update *LspFolderConfig, preferredOrgUpdated bool) bool {
	if preferredOrgUpdated {
		return false
	}
	conf := fc.Conf()
	if conf == nil {
		return false
	}
	fp := string(PathKey(fc.FolderPath))
	if fp == "" {
		return false
	}

	orgSetByUser, ok := getSettingValue[bool](update.Settings, SettingOrgSetByUser)
	if !ok {
		return false
	}
	cur := getBoolFromConfig(conf, fp, SettingOrgSetByUser)
	if orgSetByUser == cur {
		return false
	}

	key := configresolver.UserFolderKey(fp, SettingOrgSetByUser)
	conf.PersistInStorage(key)
	conf.Set(key, &configresolver.LocalConfigField{Value: orgSetByUser, Changed: true})
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
	conf := fc.Conf()
	if conf == nil {
		return false
	}
	fp := string(PathKey(fc.FolderPath))
	if fp == "" {
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
		key := configresolver.UserFolderKey(fp, name)
		if cs.Value == nil {
			if HasUserOverride(conf, fc.FolderPath, name) {
				conf.Unset(key)
				changed = true
			}
			continue
		}
		conf.PersistInStorage(key)
		conf.Set(key, &configresolver.LocalConfigField{Value: cs.Value, Changed: true})
		changed = true
	}
	return changed
}
