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
	"reflect"
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
	var fm workflow.ConfigurationOptionsMetaData
	if fc.ConfigResolver != nil {
		fm = fc.ConfigResolver.ConfigurationOptionsMetaData()
	}
	s := ReadFolderConfigSnapshot(fc.Conf(), fc.FolderPath, fm)
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

// NewMinimalConfigResolver creates a ConfigResolver backed only by a Configuration
// (no prefix key resolver, no ConfigurationOptionsMetaData). Useful in tests and as a fallback
// when a full resolver is not available.
func NewMinimalConfigResolver(conf configuration.Configuration) ConfigResolverInterface {
	if conf == nil {
		return nil
	}
	logger := zerolog.Nop()
	r := NewConfigResolver(&logger)
	r.SetPrefixKeyResolver(nil, conf, nil)
	return r
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
	case []string:
		return len(v) > 0
	}
	return true
}

// ToLspFolderConfig converts a FolderConfig to LspFolderConfig for sending to IDE.
// Uses fc.ConfigResolver + ConfigurationOptionsMetaData. Iterates all org and folder-scope settings
// via ConfigurationOptionsByAnnotation and resolves each through the resolver.
// If ConfigResolver is nil or ConfigurationOptionsMetaData unavailable, returns LspFolderConfig with empty settings.
func (fc *FolderConfig) ToLspFolderConfig() *LspFolderConfig {
	if fc == nil {
		return nil
	}

	settings := make(map[string]*ConfigSetting)
	resolver := fc.ConfigResolver
	if resolver == nil {
		return &LspFolderConfig{FolderPath: fc.FolderPath, Settings: settings}
	}

	fm := resolver.ConfigurationOptionsMetaData()
	if fm == nil {
		return &LspFolderConfig{FolderPath: fc.FolderPath, Settings: settings}
	}

	for _, name := range fm.ConfigurationOptionsByAnnotation(configresolver.AnnotationScope, string(configresolver.FolderScope)) {
		if wo, found := fm.GetConfigurationOptionAnnotation(name, configresolver.AnnotationWriteOnly); found && wo == "true" {
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
		case SettingCweIds, SettingCveIds, SettingRuleIds:
			if sl, ok := ev.Value.([]string); ok && len(sl) > 0 {
				settings[name] = cs
			}
		default:
			settings[name] = cs
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

	return fc.applyFolderScopeUpdates(update)
}

// getSettingValue returns the value from Settings map for a given key, with type conversion.
// Only returns a value when Changed is true, consistent with global settings handlers.
func getSettingValue[T any](settings map[string]*ConfigSetting, name string) (T, bool) {
	if settings == nil {
		var zero T
		return zero, false
	}
	cs := settings[name]
	if cs == nil || !cs.Changed || cs.Value == nil {
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
	if ifaces, ok := cs.Value.([]interface{}); ok {
		result := make([]string, 0, len(ifaces))
		for _, v := range ifaces {
			if s, ok := v.(string); ok {
				result = append(result, s)
			}
		}
		return result, true
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

// applyFolderScopeUpdates applies all folder-scope field updates from the Settings map.
// Settings with custom side-effect logic are handled explicitly first (tracking which names
// were handled). All remaining folder-scoped settings with Changed: true are applied via
// generic PATCH semantics: nil value clears the override, non-nil value sets it.
func (fc *FolderConfig) applyFolderScopeUpdates(update *LspFolderConfig) bool {
	if update.Settings == nil {
		return false
	}

	var fm workflow.ConfigurationOptionsMetaData
	if fc.ConfigResolver != nil {
		fm = fc.ConfigResolver.ConfigurationOptionsMetaData()
	}

	handled := make(map[string]bool)
	changed := fc.applyBasicFolderFields(update, handled)
	preferredOrgUpdated := fc.applyPreferredOrg(update, handled)
	orgSetByUserUpdated := fc.applyOrgSetByUser(update, preferredOrgUpdated, handled)
	if preferredOrgUpdated || orgSetByUserUpdated {
		changed = true
	}

	// Generic PATCH for remaining folder-scoped settings
	if fc.applyGenericFolderOverrides(update.Settings, handled, fm) {
		changed = true
	}
	return changed
}

func (fc *FolderConfig) applyGenericFolderOverrides(settings map[string]*ConfigSetting, handled map[string]bool, fm workflow.ConfigurationOptionsMetaData) bool {
	conf := fc.Conf()
	if conf == nil {
		return false
	}
	fp := string(PathKey(fc.FolderPath))
	if fp == "" {
		return false
	}
	changed := false
	for name, cs := range settings {
		if handled[name] || cs == nil || !cs.Changed {
			continue
		}
		if !IsFolderScopedSetting(fm, name) {
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
		if curVal, ok := getUserFolderValue(conf, fp, name); ok && reflect.DeepEqual(cs.Value, curVal) {
			continue
		}
		conf.PersistInStorage(key)
		conf.Set(key, &configresolver.LocalConfigField{Value: cs.Value, Changed: true})
		changed = true
	}
	return changed
}

func (fc *FolderConfig) applyBasicFolderFields(update *LspFolderConfig, handled map[string]bool) bool {
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

	changed := false
	handled[SettingBaseBranch] = true
	handled[SettingReferenceBranch] = true
	changed = fc.applyBaseBranch(update, conf, fp, setUser) || changed
	handled[SettingLocalBranches] = true
	changed = fc.applyLocalBranches(update, conf, fp) || changed
	handled[SettingAdditionalParameters] = true
	changed = fc.applyStringSliceField(update, conf, fp, SettingAdditionalParameters, setUser) || changed
	handled[SettingAdditionalEnvironment] = true
	changed = fc.applyStringField(update, conf, fp, SettingAdditionalEnvironment, setUser) || changed
	handled[SettingReferenceFolder] = true
	changed = fc.applyStringField(update, conf, fp, SettingReferenceFolder, setUser) || changed
	handled[SettingScanCommandConfig] = true
	changed = fc.applyScanCommandConfig(update, conf, fp, setUser) || changed
	return changed
}

func (fc *FolderConfig) applyBaseBranch(update *LspFolderConfig, conf configuration.Configuration, fp string, setUser func(string, any)) bool {
	baseBranch, ok := getSettingValue[string](update.Settings, SettingBaseBranch)
	if !ok {
		return false
	}
	if baseBranch == getStringFromConfig(conf, fp, SettingBaseBranch) {
		return false
	}
	setUser(SettingBaseBranch, baseBranch)
	setUser(SettingReferenceBranch, baseBranch)
	return true
}

func (fc *FolderConfig) applyLocalBranches(update *LspFolderConfig, conf configuration.Configuration, fp string) bool {
	localBranches, ok := getStringSliceFromSetting(update.Settings, SettingLocalBranches)
	if !ok {
		return false
	}
	curKey := configresolver.FolderMetadataKey(fp, SettingLocalBranches)
	if reflect.DeepEqual(localBranches, getStoredStringSlice(conf, curKey)) {
		return false
	}
	conf.PersistInStorage(curKey)
	conf.Set(curKey, localBranches)
	return true
}

func (fc *FolderConfig) applyStringField(update *LspFolderConfig, conf configuration.Configuration, fp, name string, setUser func(string, any)) bool {
	val, ok := getSettingValue[string](update.Settings, name)
	if !ok {
		return false
	}
	if val == getStringFromConfig(conf, fp, name) {
		return false
	}
	setUser(name, val)
	return true
}

func (fc *FolderConfig) applyStringSliceField(update *LspFolderConfig, conf configuration.Configuration, fp, name string, setUser func(string, any)) bool {
	val, ok := getStringSliceFromSetting(update.Settings, name)
	if !ok {
		return false
	}
	if reflect.DeepEqual(val, getStringSliceFromUserConfig(conf, fp, name)) {
		return false
	}
	setUser(name, val)
	return true
}

func (fc *FolderConfig) applyScanCommandConfig(update *LspFolderConfig, conf configuration.Configuration, fp string, setUser func(string, any)) bool {
	scanCmdConfig, ok := getScanCommandConfigFromSetting(update.Settings, SettingScanCommandConfig)
	if !ok || len(scanCmdConfig) == 0 {
		return false
	}
	if v, ok := getUserFolderValue(conf, fp, SettingScanCommandConfig); ok && reflect.DeepEqual(scanCmdConfig, v) {
		return false
	}
	setUser(SettingScanCommandConfig, scanCmdConfig)
	return true
}

func getStringFromConfig(conf configuration.Configuration, fp, name string) string {
	key := configresolver.UserFolderKey(fp, name)
	val := conf.Get(key)
	if val == nil {
		return ""
	}
	lf, ok := coerceToLocalConfigField(val)
	if !ok {
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
	lf, ok := coerceToLocalConfigField(val)
	if !ok {
		return false
	}
	b, _ := lf.Value.(bool)
	return b
}

// getStoredStringSlice reads a raw config value and coerces it to []string,
// handling both []string (in-memory) and []interface{} (after JSON round-trip).
func getStoredStringSlice(conf configuration.Configuration, key string) []string {
	val := conf.Get(key)
	if val == nil {
		return nil
	}
	switch v := val.(type) {
	case []string:
		return v
	case []interface{}:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

// getStringSliceFromUserConfig reads a user folder setting and coerces the value to []string.
func getStringSliceFromUserConfig(conf configuration.Configuration, fp, name string) []string {
	v, ok := getUserFolderValue(conf, fp, name)
	if !ok || v == nil {
		return nil
	}
	switch typed := v.(type) {
	case []string:
		return typed
	case []interface{}:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

func (fc *FolderConfig) applyPreferredOrg(update *LspFolderConfig, handled map[string]bool) bool {
	handled[SettingPreferredOrg] = true
	handled[SettingOrgSetByUser] = true

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

func (fc *FolderConfig) applyOrgSetByUser(update *LspFolderConfig, _ bool, handled map[string]bool) bool {
	handled[SettingOrgSetByUser] = true

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
