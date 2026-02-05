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

	"github.com/snyk/go-application-framework/pkg/local_workflows/code_workflow/sast_contract"

	"github.com/snyk/snyk-ls/internal/product"
)

// StoredFolderConfig is the internal storage representation of folder configuration.
// This is persisted to disk and contains all folder-specific settings including user overrides.
// For the public LSP contract, see LspFolderConfig in lsp.go.
type StoredFolderConfig struct {
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
	// ModifiedFields is sent from IDE to LS when user changes settings.
	// Key is the setting name, value is the new value (or null to clear/reset override).
	// Only fields the user actually modified should be included.
	// This field is ignored when LS sends to IDE.
	ModifiedFields map[string]any `json:"modifiedFields,omitempty"`
}

func (fc *StoredFolderConfig) Clone() *StoredFolderConfig {
	if fc == nil {
		return nil
	}

	clone := &StoredFolderConfig{
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

	if fc.ModifiedFields != nil {
		clone.ModifiedFields = make(map[string]any, len(fc.ModifiedFields))
		maps.Copy(clone.ModifiedFields, fc.ModifiedFields)
	}

	return clone
}

// HasUserOverride checks if the user has explicitly set a value for the given setting
func (fc *StoredFolderConfig) HasUserOverride(settingName string) bool {
	_, exists := fc.GetUserOverride(settingName)
	return exists
}

// GetUserOverride returns the user override value for the given setting, or nil if not set
func (fc *StoredFolderConfig) GetUserOverride(settingName string) (any, bool) {
	if fc == nil || fc.UserOverrides == nil {
		return nil, false
	}
	val, exists := fc.UserOverrides[settingName]
	return val, exists
}

// SetUserOverride explicitly sets a user override value for the given setting
func (fc *StoredFolderConfig) SetUserOverride(settingName string, value any) {
	if fc.UserOverrides == nil {
		fc.UserOverrides = make(map[string]any)
	}
	fc.UserOverrides[settingName] = value
}

// ResetToDefault removes a user override, reverting to LDX-Sync or default value
func (fc *StoredFolderConfig) ResetToDefault(settingName string) {
	if fc.UserOverrides != nil {
		delete(fc.UserOverrides, settingName)
	}
}

// SanitizeForIDE returns a copy of the StoredFolderConfig prepared for sending to the IDE.
// - UserOverrides, FeatureFlags, SastSettings are cleared (LS-managed, not exposed to IDE)
// - EffectiveConfig is kept (IDE needs this for display and behavior)
// - ModifiedFields is cleared (only used for IDE → LS communication)
// Deprecated: Use ToLspFolderConfig instead for the new LSP contract.
func (fc *StoredFolderConfig) SanitizeForIDE() StoredFolderConfig {
	sanitized := *fc
	sanitized.UserOverrides = nil
	sanitized.ModifiedFields = nil

	// TODO we might reinstate these when we fix IDE-1539, and have the IDEs use these instead of looking them up.
	sanitized.FeatureFlags = nil
	sanitized.SastSettings = nil

	return sanitized
}

// ToLspFolderConfig converts a StoredFolderConfig to LspFolderConfig for sending to IDE.
// The resolver is used to compute effective values for org-scope settings.
// If resolver is nil, org-scope settings will not be populated.
func (fc *StoredFolderConfig) ToLspFolderConfig(resolver ConfigResolverInterface) *LspFolderConfig {
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

	// Org info
	if fc.PreferredOrg != "" {
		lspConfig.PreferredOrg = &fc.PreferredOrg
	}
	if fc.AutoDeterminedOrg != "" {
		lspConfig.AutoDeterminedOrg = &fc.AutoDeterminedOrg
	}

	// Org-scope settings (computed via resolver)
	if resolver != nil {
		// Severity filter
		if val := resolver.GetSeverityFilter(SettingEnabledSeverities, fc); val != nil {
			lspConfig.EnabledSeverities = val
		}

		// Risk score threshold
		if threshold := resolver.GetInt(SettingRiskScoreThreshold, fc); threshold != 0 {
			lspConfig.RiskScoreThreshold = &threshold
		}

		// Scan settings
		scanAuto := resolver.GetBool(SettingScanAutomatic, fc)
		lspConfig.ScanAutomatic = &scanAuto

		scanNetNew := resolver.GetBool(SettingScanNetNew, fc)
		lspConfig.ScanNetNew = &scanNetNew

		// Product enablement
		codeEnabled := resolver.GetBool(SettingSnykCodeEnabled, fc)
		lspConfig.SnykCodeEnabled = &codeEnabled

		ossEnabled := resolver.GetBool(SettingSnykOssEnabled, fc)
		lspConfig.SnykOssEnabled = &ossEnabled

		iacEnabled := resolver.GetBool(SettingSnykIacEnabled, fc)
		lspConfig.SnykIacEnabled = &iacEnabled

		// Issue view options
		openIssues := resolver.GetBool(SettingIssueViewOpenIssues, fc)
		lspConfig.IssueViewOpenIssues = &openIssues

		ignoredIssues := resolver.GetBool(SettingIssueViewIgnoredIssues, fc)
		lspConfig.IssueViewIgnoredIssues = &ignoredIssues
	}

	return lspConfig
}

// StoredFolderConfigsParam is used internally for storage operations.
// For LSP notifications, use LspFolderConfigsParam instead.
type StoredFolderConfigsParam struct {
	StoredFolderConfigs []StoredFolderConfig `json:"folderConfigs"`
}
