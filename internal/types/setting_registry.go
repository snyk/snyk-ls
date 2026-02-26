/*
 * © 2026 Snyk Limited
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

import "reflect"

// settingDescriptor holds all metadata for a single setting.
// Function fields are optional; nil means the capability does not apply to this setting.
type settingDescriptor struct {
	settingName string
	scope       SettingScope

	// Global config layer: reads from Settings struct / ConfigProvider.
	getFromSettings func(s *Settings) any     // globalSettingGetters replacement
	getFromConfig   func(c ConfigProvider) any // reconciledGlobalValueGetters replacement

	// Org-scope NullableField layer (nil for machine/folder-scope settings).
	isPresent         func(cfg *LspFolderConfig) bool
	clearPresent      func(cfg *LspFolderConfig)
	makeNullableEntry func(update *LspFolderConfig) nullableFieldEntry
	populate          func(lspConfig *LspFolderConfig, resolver ConfigResolverInterface, fc ImmutableFolderConfig) bool
	// valuesEqual performs type-coercing equality for echo detection.
	// Used by SentConfigBaseline to compare recorded and incoming values.
	valuesEqual func(a, b any) bool
}

// settingRegistry is the single source of truth for all setting metadata.
// One entry per setting, ordered by scope then name for readability.
var settingRegistry = []settingDescriptor{
	// -----------------------------------------------------------------------
	// Machine-scope settings — getFromSettings only, no NullableField accessors
	// -----------------------------------------------------------------------
	{
		settingName:     SettingApiEndpoint,
		scope:           SettingScopeMachine,
		getFromSettings: func(s *Settings) any { return s.Endpoint },
	},
	{
		settingName:     SettingCodeEndpoint,
		scope:           SettingScopeMachine,
		getFromSettings: func(s *Settings) any { return s.SnykCodeApi },
	},
	{
		settingName:     SettingAuthenticationMethod,
		scope:           SettingScopeMachine,
		getFromSettings: func(s *Settings) any { return string(s.AuthenticationMethod) },
	},
	{
		settingName:     SettingProxyHttp,
		scope:           SettingScopeMachine,
		getFromSettings: func(s *Settings) any { return s.ProxyHttp },
	},
	{
		settingName:     SettingProxyHttps,
		scope:           SettingScopeMachine,
		getFromSettings: func(s *Settings) any { return s.ProxyHttps },
	},
	{
		settingName:     SettingProxyNoProxy,
		scope:           SettingScopeMachine,
		getFromSettings: func(s *Settings) any { return s.ProxyNoProxy },
	},
	{
		settingName:     SettingProxyInsecure,
		scope:           SettingScopeMachine,
		getFromSettings: func(s *Settings) any { return s.Insecure },
	},
	{
		settingName:     SettingAutoConfigureMcpServer,
		scope:           SettingScopeMachine,
		getFromSettings: func(s *Settings) any { return s.AutoConfigureSnykMcpServer },
	},
	{
		settingName:     SettingPublishSecurityAtInceptionRules,
		scope:           SettingScopeMachine,
		getFromSettings: func(s *Settings) any { return s.PublishSecurityAtInceptionRules },
	},
	{
		settingName:     SettingTrustEnabled,
		scope:           SettingScopeMachine,
		getFromSettings: func(s *Settings) any { return s.EnableTrustedFoldersFeature },
	},
	{
		settingName:     SettingBinaryBaseUrl,
		scope:           SettingScopeMachine,
		getFromSettings: func(s *Settings) any { return s.CliBaseDownloadURL },
	},
	{
		settingName:     SettingCliPath,
		scope:           SettingScopeMachine,
		getFromSettings: func(s *Settings) any { return s.CliPath },
	},
	{
		settingName:     SettingAutomaticDownload,
		scope:           SettingScopeMachine,
		getFromSettings: func(s *Settings) any { return s.ManageBinariesAutomatically },
	},
	{
		settingName:     SettingCliReleaseChannel,
		scope:           SettingScopeMachine,
		getFromSettings: func(s *Settings) any { return s.CliReleaseChannel },
	},

	// -----------------------------------------------------------------------
	// Org-scope settings — getFromSettings + optional getFromConfig + NullableField accessors
	// -----------------------------------------------------------------------
	{
		settingName: SettingEnabledSeverities,
		scope:       SettingScopeOrg,
		getFromSettings: func(s *Settings) any {
			if s.FilterSeverity != nil {
				return s.FilterSeverity
			}
			return nil
		},
		getFromConfig: func(c ConfigProvider) any { return &[]SeverityFilter{c.FilterSeverity()}[0] },
		isPresent:     func(cfg *LspFolderConfig) bool { return cfg.EnabledSeverities != nil },
		clearPresent:  func(cfg *LspFolderConfig) { cfg.EnabledSeverities = nil },
		valuesEqual: func(a, b any) bool {
			return reflect.DeepEqual(asSeverityFilter(a), asSeverityFilter(b))
		},
		makeNullableEntry: func(update *LspFolderConfig) nullableFieldEntry {
			return nullableFieldEntry{
				field:       &update.EnabledSeverities,
				settingName: SettingEnabledSeverities,
				getValue:    func() any { return update.EnabledSeverities.Get() },
			}
		},
		populate: func(lspConfig *LspFolderConfig, resolver ConfigResolverInterface, fc ImmutableFolderConfig) bool {
			sf := resolver.FilterSeverityForFolder(fc)
			lspConfig.EnabledSeverities = NullableField[SeverityFilter]{true: sf}
			return true
		},
	},
	{
		settingName:     SettingRiskScoreThreshold,
		scope:           SettingScopeOrg,
		getFromSettings: func(s *Settings) any { return s.RiskScoreThreshold },
		getFromConfig:   func(c ConfigProvider) any { return c.RiskScoreThreshold() },
		isPresent:       func(cfg *LspFolderConfig) bool { return cfg.RiskScoreThreshold != nil },
		clearPresent:    func(cfg *LspFolderConfig) { cfg.RiskScoreThreshold = nil },
		valuesEqual: func(a, b any) bool {
			return asInt(a) == asInt(b)
		},
		makeNullableEntry: func(update *LspFolderConfig) nullableFieldEntry {
			return nullableFieldEntry{
				field:       &update.RiskScoreThreshold,
				settingName: SettingRiskScoreThreshold,
				getValue:    func() any { return update.RiskScoreThreshold.Get() },
			}
		},
		populate: func(lspConfig *LspFolderConfig, resolver ConfigResolverInterface, fc ImmutableFolderConfig) bool {
			lspConfig.RiskScoreThreshold = NullableField[int]{true: resolver.RiskScoreThresholdForFolder(fc)}
			return true
		},
	},
	{
		settingName:     SettingScanAutomatic,
		scope:           SettingScopeOrg,
		getFromSettings: func(s *Settings) any { return s.ScanningMode },
		getFromConfig:   func(c ConfigProvider) any { return c.IsAutoScanEnabled() },
		isPresent:       func(cfg *LspFolderConfig) bool { return cfg.ScanAutomatic != nil },
		clearPresent:    func(cfg *LspFolderConfig) { cfg.ScanAutomatic = nil },
		valuesEqual: func(a, b any) bool {
			return asBool(a) == asBool(b)
		},
		makeNullableEntry: func(update *LspFolderConfig) nullableFieldEntry {
			return nullableFieldEntry{
				field:       &update.ScanAutomatic,
				settingName: SettingScanAutomatic,
				getValue:    func() any { return update.ScanAutomatic.Get() },
			}
		},
		populate: func(lspConfig *LspFolderConfig, resolver ConfigResolverInterface, fc ImmutableFolderConfig) bool {
			lspConfig.ScanAutomatic = NullableField[bool]{true: resolver.IsAutoScanEnabledForFolder(fc)}
			return true
		},
	},
	{
		settingName:     SettingScanNetNew,
		scope:           SettingScopeOrg,
		getFromSettings: func(s *Settings) any { return s.EnableDeltaFindings },
		getFromConfig:   func(c ConfigProvider) any { return c.IsDeltaFindingsEnabled() },
		isPresent:       func(cfg *LspFolderConfig) bool { return cfg.ScanNetNew != nil },
		clearPresent:    func(cfg *LspFolderConfig) { cfg.ScanNetNew = nil },
		valuesEqual: func(a, b any) bool {
			return asBool(a) == asBool(b)
		},
		makeNullableEntry: func(update *LspFolderConfig) nullableFieldEntry {
			return nullableFieldEntry{
				field:       &update.ScanNetNew,
				settingName: SettingScanNetNew,
				getValue:    func() any { return update.ScanNetNew.Get() },
			}
		},
		populate: func(lspConfig *LspFolderConfig, resolver ConfigResolverInterface, fc ImmutableFolderConfig) bool {
			lspConfig.ScanNetNew = NullableField[bool]{true: resolver.IsDeltaFindingsEnabledForFolder(fc)}
			return true
		},
	},
	{
		settingName:     SettingSnykCodeEnabled,
		scope:           SettingScopeOrg,
		getFromSettings: func(s *Settings) any { return s.ActivateSnykCode },
		getFromConfig:   func(c ConfigProvider) any { return c.IsSnykCodeEnabled() },
		isPresent:       func(cfg *LspFolderConfig) bool { return cfg.SnykCodeEnabled != nil },
		clearPresent:    func(cfg *LspFolderConfig) { cfg.SnykCodeEnabled = nil },
		valuesEqual: func(a, b any) bool {
			return asBool(a) == asBool(b)
		},
		makeNullableEntry: func(update *LspFolderConfig) nullableFieldEntry {
			return nullableFieldEntry{
				field:       &update.SnykCodeEnabled,
				settingName: SettingSnykCodeEnabled,
				getValue:    func() any { return update.SnykCodeEnabled.Get() },
			}
		},
		populate: func(lspConfig *LspFolderConfig, resolver ConfigResolverInterface, fc ImmutableFolderConfig) bool {
			lspConfig.SnykCodeEnabled = NullableField[bool]{true: resolver.IsSnykCodeEnabledForFolder(fc)}
			return true
		},
	},
	{
		settingName:     SettingSnykOssEnabled,
		scope:           SettingScopeOrg,
		getFromSettings: func(s *Settings) any { return s.ActivateSnykOpenSource },
		getFromConfig:   func(c ConfigProvider) any { return c.IsSnykOssEnabled() },
		isPresent:       func(cfg *LspFolderConfig) bool { return cfg.SnykOssEnabled != nil },
		clearPresent:    func(cfg *LspFolderConfig) { cfg.SnykOssEnabled = nil },
		valuesEqual: func(a, b any) bool {
			return asBool(a) == asBool(b)
		},
		makeNullableEntry: func(update *LspFolderConfig) nullableFieldEntry {
			return nullableFieldEntry{
				field:       &update.SnykOssEnabled,
				settingName: SettingSnykOssEnabled,
				getValue:    func() any { return update.SnykOssEnabled.Get() },
			}
		},
		populate: func(lspConfig *LspFolderConfig, resolver ConfigResolverInterface, fc ImmutableFolderConfig) bool {
			lspConfig.SnykOssEnabled = NullableField[bool]{true: resolver.IsSnykOssEnabledForFolder(fc)}
			return true
		},
	},
	{
		settingName:     SettingSnykIacEnabled,
		scope:           SettingScopeOrg,
		getFromSettings: func(s *Settings) any { return s.ActivateSnykIac },
		getFromConfig:   func(c ConfigProvider) any { return c.IsSnykIacEnabled() },
		isPresent:       func(cfg *LspFolderConfig) bool { return cfg.SnykIacEnabled != nil },
		clearPresent:    func(cfg *LspFolderConfig) { cfg.SnykIacEnabled = nil },
		valuesEqual: func(a, b any) bool {
			return asBool(a) == asBool(b)
		},
		makeNullableEntry: func(update *LspFolderConfig) nullableFieldEntry {
			return nullableFieldEntry{
				field:       &update.SnykIacEnabled,
				settingName: SettingSnykIacEnabled,
				getValue:    func() any { return update.SnykIacEnabled.Get() },
			}
		},
		populate: func(lspConfig *LspFolderConfig, resolver ConfigResolverInterface, fc ImmutableFolderConfig) bool {
			lspConfig.SnykIacEnabled = NullableField[bool]{true: resolver.IsSnykIacEnabledForFolder(fc)}
			return true
		},
	},
	{
		settingName: SettingIssueViewOpenIssues,
		scope:       SettingScopeOrg,
		getFromSettings: func(s *Settings) any {
			if s.IssueViewOptions != nil {
				return s.IssueViewOptions.OpenIssues
			}
			return nil
		},
		getFromConfig: func(c ConfigProvider) any { return c.IssueViewOptions().OpenIssues },
		isPresent:     func(cfg *LspFolderConfig) bool { return cfg.IssueViewOpenIssues != nil },
		clearPresent:  func(cfg *LspFolderConfig) { cfg.IssueViewOpenIssues = nil },
		valuesEqual: func(a, b any) bool {
			return asBool(a) == asBool(b)
		},
		makeNullableEntry: func(update *LspFolderConfig) nullableFieldEntry {
			return nullableFieldEntry{
				field:       &update.IssueViewOpenIssues,
				settingName: SettingIssueViewOpenIssues,
				getValue:    func() any { return update.IssueViewOpenIssues.Get() },
			}
		},
		populate: func(lspConfig *LspFolderConfig, resolver ConfigResolverInterface, fc ImmutableFolderConfig) bool {
			lspConfig.IssueViewOpenIssues = NullableField[bool]{true: resolver.IssueViewOptionsForFolder(fc).OpenIssues}
			return true
		},
	},
	{
		settingName: SettingIssueViewIgnoredIssues,
		scope:       SettingScopeOrg,
		getFromSettings: func(s *Settings) any {
			if s.IssueViewOptions != nil {
				return s.IssueViewOptions.IgnoredIssues
			}
			return nil
		},
		getFromConfig: func(c ConfigProvider) any { return c.IssueViewOptions().IgnoredIssues },
		isPresent:     func(cfg *LspFolderConfig) bool { return cfg.IssueViewIgnoredIssues != nil },
		clearPresent:  func(cfg *LspFolderConfig) { cfg.IssueViewIgnoredIssues = nil },
		valuesEqual: func(a, b any) bool {
			return asBool(a) == asBool(b)
		},
		makeNullableEntry: func(update *LspFolderConfig) nullableFieldEntry {
			return nullableFieldEntry{
				field:       &update.IssueViewIgnoredIssues,
				settingName: SettingIssueViewIgnoredIssues,
				getValue:    func() any { return update.IssueViewIgnoredIssues.Get() },
			}
		},
		populate: func(lspConfig *LspFolderConfig, resolver ConfigResolverInterface, fc ImmutableFolderConfig) bool {
			lspConfig.IssueViewIgnoredIssues = NullableField[bool]{true: resolver.IssueViewOptionsForFolder(fc).IgnoredIssues}
			return true
		},
	},
	{
		settingName:  SettingCweIds,
		scope:        SettingScopeOrg,
		isPresent:    func(cfg *LspFolderConfig) bool { return cfg.CweIds != nil },
		clearPresent: func(cfg *LspFolderConfig) { cfg.CweIds = nil },
		valuesEqual: func(a, b any) bool {
			return reflect.DeepEqual(asStringSlice(a), asStringSlice(b))
		},
		makeNullableEntry: func(update *LspFolderConfig) nullableFieldEntry {
			return nullableFieldEntry{
				field:       &update.CweIds,
				settingName: SettingCweIds,
				getValue:    func() any { return update.CweIds.Get() },
			}
		},
		populate: func(lspConfig *LspFolderConfig, resolver ConfigResolverInterface, fc ImmutableFolderConfig) bool {
			val, _ := resolver.GetValue(SettingCweIds, fc)
			if ids := asStringSlice(val); len(ids) > 0 {
				lspConfig.CweIds = NullableField[[]string]{true: ids}
				return true
			}
			return false
		},
	},
	{
		settingName:  SettingCveIds,
		scope:        SettingScopeOrg,
		isPresent:    func(cfg *LspFolderConfig) bool { return cfg.CveIds != nil },
		clearPresent: func(cfg *LspFolderConfig) { cfg.CveIds = nil },
		valuesEqual: func(a, b any) bool {
			return reflect.DeepEqual(asStringSlice(a), asStringSlice(b))
		},
		makeNullableEntry: func(update *LspFolderConfig) nullableFieldEntry {
			return nullableFieldEntry{
				field:       &update.CveIds,
				settingName: SettingCveIds,
				getValue:    func() any { return update.CveIds.Get() },
			}
		},
		populate: func(lspConfig *LspFolderConfig, resolver ConfigResolverInterface, fc ImmutableFolderConfig) bool {
			val, _ := resolver.GetValue(SettingCveIds, fc)
			if ids := asStringSlice(val); len(ids) > 0 {
				lspConfig.CveIds = NullableField[[]string]{true: ids}
				return true
			}
			return false
		},
	},
	{
		settingName:  SettingRuleIds,
		scope:        SettingScopeOrg,
		isPresent:    func(cfg *LspFolderConfig) bool { return cfg.RuleIds != nil },
		clearPresent: func(cfg *LspFolderConfig) { cfg.RuleIds = nil },
		valuesEqual: func(a, b any) bool {
			return reflect.DeepEqual(asStringSlice(a), asStringSlice(b))
		},
		makeNullableEntry: func(update *LspFolderConfig) nullableFieldEntry {
			return nullableFieldEntry{
				field:       &update.RuleIds,
				settingName: SettingRuleIds,
				getValue:    func() any { return update.RuleIds.Get() },
			}
		},
		populate: func(lspConfig *LspFolderConfig, resolver ConfigResolverInterface, fc ImmutableFolderConfig) bool {
			val, _ := resolver.GetValue(SettingRuleIds, fc)
			if ids := asStringSlice(val); len(ids) > 0 {
				lspConfig.RuleIds = NullableField[[]string]{true: ids}
				return true
			}
			return false
		},
	},

	// -----------------------------------------------------------------------
	// Folder-scope settings — scope only, no getters or NullableField accessors
	// -----------------------------------------------------------------------
	{settingName: SettingReferenceFolder, scope: SettingScopeFolder},
	{settingName: SettingReferenceBranch, scope: SettingScopeFolder},
	{settingName: SettingAdditionalParameters, scope: SettingScopeFolder},
	{settingName: SettingAdditionalEnvironment, scope: SettingScopeFolder},
}

// Derived maps built from settingRegistry at init time for O(1) lookup performance.
var (
	settingScopeByName        map[string]SettingScope
	globalSettingGetterByName map[string]func(*Settings) any
	reconciledGetterByName    map[string]func(ConfigProvider) any
	clearPresenterByName      map[string]func(*LspFolderConfig)
	// valuesEqualByName holds the type-coercing equality function for each setting.
	// Used by SentConfigBaseline to compare recorded and incoming values.
	valuesEqualByName map[string]func(a, b any) bool
)

func init() {
	settingScopeByName = make(map[string]SettingScope, len(settingRegistry))
	globalSettingGetterByName = make(map[string]func(*Settings) any)
	reconciledGetterByName = make(map[string]func(ConfigProvider) any)
	clearPresenterByName = make(map[string]func(*LspFolderConfig))
	valuesEqualByName = make(map[string]func(a, b any) bool)

	for _, desc := range settingRegistry {
		settingScopeByName[desc.settingName] = desc.scope
		if desc.getFromSettings != nil {
			globalSettingGetterByName[desc.settingName] = desc.getFromSettings
		}
		if desc.getFromConfig != nil {
			reconciledGetterByName[desc.settingName] = desc.getFromConfig
		}
		if desc.clearPresent != nil {
			clearPresenterByName[desc.settingName] = desc.clearPresent
		}
		if desc.valuesEqual != nil {
			valuesEqualByName[desc.settingName] = desc.valuesEqual
		}
	}
}

// OrgScopeSettingNames returns the names of all org-scope settings from the registry.
func OrgScopeSettingNames() []string {
	var names []string
	for _, desc := range settingRegistry {
		if desc.scope == SettingScopeOrg {
			names = append(names, desc.settingName)
		}
	}
	return names
}

// OrgScopeFieldPresence returns a map of org-scope setting names to their NullableField presence flag.
// This replaces the hand-written fieldsToCheck literal in configuration.go.
func OrgScopeFieldPresence(cfg *LspFolderConfig) map[string]bool {
	result := make(map[string]bool)
	for _, desc := range settingRegistry {
		if desc.isPresent != nil {
			result[desc.settingName] = desc.isPresent(cfg)
		}
	}
	return result
}

// ClearLockedField sets the NullableField for settingName to nil (omitted)
// so that ApplyLspUpdate will not apply it. This replaces the clearLockedField switch in configuration.go.
func ClearLockedField(cfg *LspFolderConfig, settingName string) {
	if f, ok := clearPresenterByName[settingName]; ok {
		f(cfg)
	}
}
