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

	"github.com/snyk/code-client-go/pkg/code/sast_contract"

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
	GetAdditionalParameters() []string
	GetAdditionalEnv() string
	GetReferenceFolderPath() FilePath
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

// GetFeatureFlag returns the value of a feature flag, defaulting to false
func (fc *FolderConfig) GetFeatureFlag(flag string) bool {
	if fc == nil || fc.FeatureFlags == nil {
		return false
	}
	return fc.FeatureFlags[flag]
}

// SetUserOverride explicitly sets a user override value for the given setting
func (fc *FolderConfig) SetUserOverride(settingName string, value any) {
	if fc.UserOverrides == nil {
		fc.UserOverrides = make(map[string]any)
	}
	fc.UserOverrides[settingName] = value
}

// ResetToDefault removes a user override, reverting to LDX-Sync or default value
func (fc *FolderConfig) ResetToDefault(settingName string) {
	if fc.UserOverrides != nil {
		delete(fc.UserOverrides, settingName)
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

// ToLspFolderConfig converts a FolderConfig to LspFolderConfig for sending to IDE.
// The resolver is used to compute effective values for org-scope settings.
// If resolver is nil, org-scope settings will not be populated.
func (fc *FolderConfig) ToLspFolderConfig(resolver ConfigResolverInterface) *LspFolderConfig {
	if fc == nil {
		return nil
	}

	lspConfig := &LspFolderConfig{
		FolderPath: fc.FolderPath,
	}

	// Folder-scope settings (direct copy)
	if fc.BaseBranch != "" {
		lspConfig.BaseBranch = &fc.BaseBranch
	}
	if len(fc.LocalBranches) > 0 {
		lspConfig.LocalBranches = fc.LocalBranches
	}
	if len(fc.AdditionalParameters) > 0 {
		lspConfig.AdditionalParameters = fc.AdditionalParameters
	}
	if fc.AdditionalEnv != "" {
		lspConfig.AdditionalEnv = &fc.AdditionalEnv
	}
	if fc.ReferenceFolderPath != "" {
		lspConfig.ReferenceFolderPath = &fc.ReferenceFolderPath
	}
	if len(fc.ScanCommandConfig) > 0 {
		lspConfig.ScanCommandConfig = fc.ScanCommandConfig
	}

	// Org info
	if fc.PreferredOrg != "" {
		lspConfig.PreferredOrg = &fc.PreferredOrg
	}
	if fc.AutoDeterminedOrg != "" {
		lspConfig.AutoDeterminedOrg = &fc.AutoDeterminedOrg
	}
	lspConfig.OrgSetByUser = &fc.OrgSetByUser
	lspConfig.OrgMigratedFromGlobalConfig = &fc.OrgMigratedFromGlobalConfig

	// Org-scope settings (computed via resolver).
	// All settings are sent as NullableFields so the baseline can cover them for echo detection.
	fc.populateResolvedFields(lspConfig, resolver)

	return lspConfig
}

// populateResolvedFields fills NullableField entries on lspConfig using the resolver.
// It is a no-op when resolver is nil.
func (fc *FolderConfig) populateResolvedFields(lspConfig *LspFolderConfig, resolver ConfigResolverInterface) {
	if resolver == nil {
		return
	}
	for _, desc := range settingRegistry {
		if desc.populate != nil {
			desc.populate(lspConfig, resolver, fc)
		}
	}
}

// ApplyLspUpdate applies changes from an LspFolderConfig using PATCH semantics.
// For NullableField org-scope settings:
// - Omitted (not present in JSON) = don't change
// - Null (explicit null in JSON) = clear override (reset to default)
// - Value (explicit value in JSON) = set override
// For pointer fields (folder-scope):
// - nil = don't change
// - non-nil = set value
// Echo detection (filtering echoes from the IDE) is handled externally by FilterFolderEchoes
// before calling ApplyLspUpdate.
// Returns true if any changes were made.
func (fc *FolderConfig) ApplyLspUpdate(update *LspFolderConfig) bool {
	if fc == nil || update == nil {
		return false
	}

	changed := fc.applyFolderScopeUpdates(update)
	changed = fc.applyOrgScopeUpdates(update) || changed

	return changed
}

// applyFolderScopeUpdates applies folder-scope field updates (direct fields, not user overrides)
func (fc *FolderConfig) applyFolderScopeUpdates(update *LspFolderConfig) bool {
	changed := fc.applyBasicFolderFields(update)
	preferredOrgUpdated := fc.applyPreferredOrg(update)
	if preferredOrgUpdated {
		changed = true
	}
	if fc.applyOrgFlags(update, preferredOrgUpdated) {
		changed = true
	}
	return changed
}

func (fc *FolderConfig) applyBasicFolderFields(update *LspFolderConfig) bool {
	changed := false
	if update.BaseBranch != nil && *update.BaseBranch != fc.BaseBranch {
		fc.BaseBranch = *update.BaseBranch
		changed = true
	}
	if update.LocalBranches != nil {
		fc.LocalBranches = update.LocalBranches
		changed = true
	}
	if update.AdditionalParameters != nil {
		fc.AdditionalParameters = update.AdditionalParameters
		changed = true
	}
	if update.AdditionalEnv != nil && *update.AdditionalEnv != fc.AdditionalEnv {
		fc.AdditionalEnv = *update.AdditionalEnv
		changed = true
	}
	if update.ReferenceFolderPath != nil && *update.ReferenceFolderPath != fc.ReferenceFolderPath {
		fc.ReferenceFolderPath = *update.ReferenceFolderPath
		changed = true
	}
	if len(update.ScanCommandConfig) > 0 {
		fc.ScanCommandConfig = update.ScanCommandConfig
		changed = true
	}
	return changed
}

func (fc *FolderConfig) applyPreferredOrg(update *LspFolderConfig) bool {
	if update.PreferredOrg != nil && *update.PreferredOrg != fc.PreferredOrg {
		fc.PreferredOrg = *update.PreferredOrg
		fc.OrgSetByUser = true
		return true
	}
	return false
}

func (fc *FolderConfig) applyOrgFlags(update *LspFolderConfig, preferredOrgUpdated bool) bool {
	changed := false
	// Apply OrgSetByUser only if explicitly set (pointer is non-nil) and PreferredOrg was NOT updated
	// (updating PreferredOrg already sets OrgSetByUser=true as a side effect)
	if !preferredOrgUpdated && update.OrgSetByUser != nil && *update.OrgSetByUser != fc.OrgSetByUser {
		fc.OrgSetByUser = *update.OrgSetByUser
		changed = true
	}
	// Apply OrgMigratedFromGlobalConfig only if explicitly set (pointer is non-nil)
	if update.OrgMigratedFromGlobalConfig != nil && *update.OrgMigratedFromGlobalConfig != fc.OrgMigratedFromGlobalConfig {
		fc.OrgMigratedFromGlobalConfig = *update.OrgMigratedFromGlobalConfig
		changed = true
	}
	return changed
}

// applyOrgScopeUpdates applies org-scope setting updates using NullableField PATCH semantics:
// - Omitted = don't change
// - Null = clear override (reset to default)
// - Value = set override
// Echo detection is handled externally by FilterFolderEchoes before calling ApplyLspUpdate.
// nullableFieldEntry pairs a NullableField accessor with its setting name and value getter.
type nullableFieldEntry struct {
	field interface {
		IsOmitted() bool
		IsNull() bool
		HasValue() bool
	}
	settingName string
	getValue    func() any
}

func (fc *FolderConfig) applyOrgScopeUpdates(update *LspFolderConfig) bool {
	changed := false
	for _, desc := range settingRegistry {
		if desc.makeNullableEntry == nil {
			continue
		}
		if applyNullableField(fc, desc.makeNullableEntry(update)) {
			changed = true
		}
	}
	return changed
}

func applyNullableField(fc *FolderConfig, e nullableFieldEntry) bool {
	if e.field.IsOmitted() {
		return false
	}
	if e.field.IsNull() {
		if fc.HasUserOverride(e.settingName) {
			fc.ResetToDefault(e.settingName)
			return true
		}
		return false
	}
	fc.SetUserOverride(e.settingName, e.getValue())
	return true
}

// FolderConfigsParam is used internally for storage operations.
// For LSP notifications, use LspFolderConfigsParam instead.
type FolderConfigsParam struct {
	FolderConfigs []FolderConfig `json:"folderConfigs"`
}

// FilterFolderEchoes marks NullableFields in incoming as omitted when their values match
// what was previously sent to the IDE (recorded in baseline). This prevents IDE echo-back
// from creating spurious user overrides.
func FilterFolderEchoes(incoming *LspFolderConfig, path FilePath, baseline *SentConfigBaseline) {
	for _, desc := range settingRegistry {
		if desc.scope != SettingScopeOrg || desc.makeNullableEntry == nil || desc.clearPresent == nil {
			continue
		}
		if !desc.isPresent(incoming) {
			continue
		}
		entry := desc.makeNullableEntry(incoming)
		if entry.field.IsOmitted() || entry.field.IsNull() {
			continue
		}
		if baseline.IsFolderEcho(path, desc.settingName, entry.getValue()) {
			desc.clearPresent(incoming)
		}
	}
}

// RecordFolderConfigBaseline records each present NullableField value from lspConfig into
// the baseline for path. Called after building the LspFolderConfig to send to the IDE so
// that subsequent echo-back from the IDE can be detected and ignored.
func RecordFolderConfigBaseline(path FilePath, lspConfig *LspFolderConfig, baseline *SentConfigBaseline) {
	for _, desc := range settingRegistry {
		if desc.scope != SettingScopeOrg || desc.makeNullableEntry == nil {
			continue
		}
		if !desc.isPresent(lspConfig) {
			continue
		}
		entry := desc.makeNullableEntry(lspConfig)
		if !entry.field.IsOmitted() && !entry.field.IsNull() {
			baseline.RecordFolderValue(path, desc.settingName, entry.getValue())
		}
	}
}

// asSeverityFilter converts an any value to *SeverityFilter, mirroring GetSeverityFilter type assertions.
func asSeverityFilter(val any) *SeverityFilter {
	switch v := val.(type) {
	case *SeverityFilter:
		return v
	case SeverityFilter:
		return &v
	default:
		return nil
	}
}

// asInt converts an any value to int, mirroring GetInt type assertions.
func asInt(val any) int {
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

// asBool converts an any value to bool, mirroring GetBool type assertions.
func asBool(val any) bool {
	switch v := val.(type) {
	case bool:
		return v
	case string:
		return v == "true"
	default:
		return false
	}
}

// asStringSlice converts an any value to []string, mirroring GetStringSlice type assertions.
func asStringSlice(val any) []string {
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
