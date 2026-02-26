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

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// allKnownSettings lists every Setting* constant that should appear in the registry.
// SettingEnabledProducts is excluded because it is a raw API field converted into
// individual product boolean settings; it is never stored in the registry directly.
var allKnownSettings = []string{
	// Machine-scope
	SettingApiEndpoint,
	SettingCodeEndpoint,
	SettingAuthenticationMethod,
	SettingProxyHttp,
	SettingProxyHttps,
	SettingProxyNoProxy,
	SettingProxyInsecure,
	SettingAutoConfigureMcpServer,
	SettingPublishSecurityAtInceptionRules,
	SettingTrustEnabled,
	SettingBinaryBaseUrl,
	SettingCliPath,
	SettingAutomaticDownload,
	SettingCliReleaseChannel,
	// Org-scope
	SettingEnabledSeverities,
	SettingRiskScoreThreshold,
	SettingCweIds,
	SettingCveIds,
	SettingRuleIds,
	SettingSnykCodeEnabled,
	SettingSnykOssEnabled,
	SettingSnykIacEnabled,
	SettingScanAutomatic,
	SettingScanNetNew,
	SettingIssueViewOpenIssues,
	SettingIssueViewIgnoredIssues,
	// Folder-scope
	SettingReferenceFolder,
	SettingReferenceBranch,
	SettingAdditionalParameters,
	SettingAdditionalEnvironment,
}

func TestSettingRegistry_Completeness(t *testing.T) {
	t.Run("every known setting has a registry entry", func(t *testing.T) {
		for _, name := range allKnownSettings {
			t.Run(name, func(t *testing.T) {
				_, ok := settingScopeByName[name]
				assert.True(t, ok, "setting %q not found in registry", name)
			})
		}
	})

	t.Run("registry has no extra entries", func(t *testing.T) {
		knownSet := make(map[string]bool, len(allKnownSettings))
		for _, name := range allKnownSettings {
			knownSet[name] = true
		}
		for _, desc := range settingRegistry {
			assert.True(t, knownSet[desc.settingName],
				"registry contains unexpected setting %q", desc.settingName)
		}
	})
}

func TestSettingRegistry_Scope(t *testing.T) {
	expectedScopes := map[string]SettingScope{
		// Machine-scope
		SettingApiEndpoint:                     SettingScopeMachine,
		SettingCodeEndpoint:                    SettingScopeMachine,
		SettingAuthenticationMethod:            SettingScopeMachine,
		SettingProxyHttp:                       SettingScopeMachine,
		SettingProxyHttps:                      SettingScopeMachine,
		SettingProxyNoProxy:                    SettingScopeMachine,
		SettingProxyInsecure:                   SettingScopeMachine,
		SettingAutoConfigureMcpServer:          SettingScopeMachine,
		SettingPublishSecurityAtInceptionRules: SettingScopeMachine,
		SettingTrustEnabled:                    SettingScopeMachine,
		SettingBinaryBaseUrl:                   SettingScopeMachine,
		SettingCliPath:                         SettingScopeMachine,
		SettingAutomaticDownload:               SettingScopeMachine,
		SettingCliReleaseChannel:               SettingScopeMachine,
		// Org-scope
		SettingEnabledSeverities:      SettingScopeOrg,
		SettingRiskScoreThreshold:     SettingScopeOrg,
		SettingCweIds:                 SettingScopeOrg,
		SettingCveIds:                 SettingScopeOrg,
		SettingRuleIds:                SettingScopeOrg,
		SettingSnykCodeEnabled:        SettingScopeOrg,
		SettingSnykOssEnabled:         SettingScopeOrg,
		SettingSnykIacEnabled:         SettingScopeOrg,
		SettingScanAutomatic:          SettingScopeOrg,
		SettingScanNetNew:             SettingScopeOrg,
		SettingIssueViewOpenIssues:    SettingScopeOrg,
		SettingIssueViewIgnoredIssues: SettingScopeOrg,
		// Folder-scope
		SettingReferenceFolder:       SettingScopeFolder,
		SettingReferenceBranch:       SettingScopeFolder,
		SettingAdditionalParameters:  SettingScopeFolder,
		SettingAdditionalEnvironment: SettingScopeFolder,
	}

	for name, expectedScope := range expectedScopes {
		t.Run(name, func(t *testing.T) {
			actual, ok := settingScopeByName[name]
			require.True(t, ok, "setting %q not found in registry", name)
			assert.Equal(t, expectedScope, actual, "setting %q has wrong scope", name)
		})
	}
}

func TestSettingRegistry_GetFromSettings(t *testing.T) {
	// These settings must have getFromSettings != nil, matching the old globalSettingGetters map.
	settingsWithGetter := []string{
		SettingApiEndpoint,
		SettingAuthenticationMethod,
		SettingAutoConfigureMcpServer,
		SettingAutomaticDownload,
		SettingBinaryBaseUrl,
		SettingCliPath,
		SettingSnykCodeEnabled,
		SettingSnykOssEnabled,
		SettingSnykIacEnabled,
		SettingEnabledSeverities,
		SettingIssueViewIgnoredIssues,
		SettingIssueViewOpenIssues,
		SettingCodeEndpoint,
		SettingProxyHttp,
		SettingProxyHttps,
		SettingProxyNoProxy,
		SettingProxyInsecure,
		SettingPublishSecurityAtInceptionRules,
		SettingCliReleaseChannel,
		SettingRiskScoreThreshold,
		SettingScanAutomatic,
		SettingScanNetNew,
		SettingTrustEnabled,
	}

	for _, name := range settingsWithGetter {
		t.Run(name, func(t *testing.T) {
			_, ok := globalSettingGetterByName[name]
			assert.True(t, ok, "setting %q should have a getFromSettings getter", name)
		})
	}
}

func TestSettingRegistry_GetFromConfig(t *testing.T) {
	// These settings must have getFromConfig != nil, matching the old reconciledGlobalValueGetters map.
	settingsWithReconciler := []string{
		SettingSnykCodeEnabled,
		SettingSnykOssEnabled,
		SettingSnykIacEnabled,
		SettingScanAutomatic,
		SettingScanNetNew,
		SettingEnabledSeverities,
		SettingRiskScoreThreshold,
		SettingIssueViewOpenIssues,
		SettingIssueViewIgnoredIssues,
	}

	for _, name := range settingsWithReconciler {
		t.Run(name, func(t *testing.T) {
			_, ok := reconciledGetterByName[name]
			assert.True(t, ok, "setting %q should have a getFromConfig getter", name)
		})
	}
}

func TestSettingRegistry_OrgScopeAccessors_IsPresentClearPresent(t *testing.T) {
	for _, desc := range settingRegistry {
		if desc.scope != SettingScopeOrg || desc.isPresent == nil {
			continue
		}
		t.Run(desc.settingName, func(t *testing.T) {
			cfg := buildLspFolderConfigWithAllPresent()
			assert.True(t, desc.isPresent(cfg), "isPresent should return true before clearPresent")

			require.NotNil(t, desc.clearPresent, "clearPresent must not be nil when isPresent is set")
			desc.clearPresent(cfg)
			assert.False(t, desc.isPresent(cfg), "isPresent should return false after clearPresent")
		})
	}
}

func TestSettingRegistry_OrgScopeAccessors_MakeNullableEntrySettingName(t *testing.T) {
	update := buildLspFolderConfigWithAllPresent()

	for _, desc := range settingRegistry {
		if desc.makeNullableEntry == nil {
			continue
		}
		t.Run(desc.settingName, func(t *testing.T) {
			entry := desc.makeNullableEntry(update)
			assert.Equal(t, desc.settingName, entry.settingName,
				"makeNullableEntry for %q returned wrong settingName", desc.settingName)
		})
	}
}

func TestSettingRegistry_Populate(t *testing.T) {
	for _, desc := range settingRegistry {
		if desc.populate == nil {
			continue
		}
		t.Run(desc.settingName, func(t *testing.T) {
			cache := NewLDXSyncConfigCache()
			orgConfig := NewLDXSyncOrgConfig("org1")
			seedValue := seedValueForSetting(desc.settingName)
			orgConfig.SetField(desc.settingName, seedValue, false, false, "org")
			cache.SetOrgConfig(orgConfig)

			resolver := NewConfigResolver(cache, nil, nil, nil)
			// AutoDeterminedOrg tells the resolver which org to look up in the cache
			fc := &FolderConfig{FolderPath: "/test", AutoDeterminedOrg: "org1"}
			lspConfig := &LspFolderConfig{}

			populated := desc.populate(lspConfig, resolver, fc)
			assert.True(t, populated, "populate should return true when LDX-Sync value is available")

			require.NotNil(t, desc.isPresent, "isPresent must not be nil when populate is set")
			assert.True(t, desc.isPresent(lspConfig), "field should be marked present after populate")
		})
	}
}

func TestOrgScopeFieldPresence(t *testing.T) {
	cfg := &LspFolderConfig{
		SnykCodeEnabled:   NullableField[bool]{true: true},
		SnykOssEnabled:    nil,
		EnabledSeverities: NullableField[SeverityFilter]{true: SeverityFilter{Critical: true}},
	}

	presence := OrgScopeFieldPresence(cfg)

	assert.True(t, presence[SettingSnykCodeEnabled], "SnykCodeEnabled should be present")
	assert.False(t, presence[SettingSnykOssEnabled], "SnykOssEnabled should not be present")
	assert.True(t, presence[SettingEnabledSeverities], "EnabledSeverities should be present")

	// All org-scope settings should appear in the map, even if not present
	assert.Contains(t, presence, SettingRiskScoreThreshold)
	assert.Contains(t, presence, SettingScanAutomatic)
	assert.Contains(t, presence, SettingScanNetNew)
	assert.Contains(t, presence, SettingSnykIacEnabled)
	assert.Contains(t, presence, SettingIssueViewOpenIssues)
	assert.Contains(t, presence, SettingIssueViewIgnoredIssues)
	assert.Contains(t, presence, SettingCweIds)
	assert.Contains(t, presence, SettingCveIds)
	assert.Contains(t, presence, SettingRuleIds)

	// Machine-scope and folder-scope settings should not appear
	assert.NotContains(t, presence, SettingApiEndpoint)
	assert.NotContains(t, presence, SettingReferenceFolder)
}

func TestClearLockedField(t *testing.T) {
	orgScopeSettingsWithPresence := []string{
		SettingEnabledSeverities,
		SettingRiskScoreThreshold,
		SettingScanAutomatic,
		SettingScanNetNew,
		SettingSnykCodeEnabled,
		SettingSnykOssEnabled,
		SettingSnykIacEnabled,
		SettingIssueViewOpenIssues,
		SettingIssueViewIgnoredIssues,
		SettingCweIds,
		SettingCveIds,
		SettingRuleIds,
	}

	for _, name := range orgScopeSettingsWithPresence {
		t.Run(name, func(t *testing.T) {
			cfg := buildLspFolderConfigWithAllPresent()
			ClearLockedField(cfg, name)

			// Find the descriptor and verify the field is now not present
			found := false
			for _, desc := range settingRegistry {
				if desc.settingName == name {
					found = true
					require.NotNil(t, desc.isPresent, "descriptor for %q must have isPresent", name)
					assert.False(t, desc.isPresent(cfg),
						"field %q should not be present after ClearLockedField", name)
					break
				}
			}
			assert.True(t, found, "no registry entry found for %q", name)
		})
	}

	t.Run("unknown setting does not panic", func(t *testing.T) {
		cfg := &LspFolderConfig{}
		assert.NotPanics(t, func() { ClearLockedField(cfg, "unknown_setting") })
	})
}

func TestOrgScopeSettingNames(t *testing.T) {
	names := OrgScopeSettingNames()

	expectedOrgSettings := []string{
		SettingEnabledSeverities,
		SettingRiskScoreThreshold,
		SettingCweIds,
		SettingCveIds,
		SettingRuleIds,
		SettingSnykCodeEnabled,
		SettingSnykOssEnabled,
		SettingSnykIacEnabled,
		SettingScanAutomatic,
		SettingScanNetNew,
		SettingIssueViewOpenIssues,
		SettingIssueViewIgnoredIssues,
	}

	assert.ElementsMatch(t, expectedOrgSettings, names)
}

// buildLspFolderConfigWithAllPresent creates an LspFolderConfig with every NullableField marked present.
func buildLspFolderConfigWithAllPresent() *LspFolderConfig {
	return &LspFolderConfig{
		EnabledSeverities:      NullableField[SeverityFilter]{true: SeverityFilter{Critical: true}},
		RiskScoreThreshold:     NullableField[int]{true: 500},
		ScanAutomatic:          NullableField[bool]{true: true},
		ScanNetNew:             NullableField[bool]{true: true},
		SnykCodeEnabled:        NullableField[bool]{true: true},
		SnykOssEnabled:         NullableField[bool]{true: true},
		SnykIacEnabled:         NullableField[bool]{true: true},
		IssueViewOpenIssues:    NullableField[bool]{true: true},
		IssueViewIgnoredIssues: NullableField[bool]{true: true},
		CweIds:                 NullableField[[]string]{true: []string{"CWE-79"}},
		CveIds:                 NullableField[[]string]{true: []string{"CVE-2021-44228"}},
		RuleIds:                NullableField[[]string]{true: []string{"rule1"}},
	}
}

func TestSettingRegistry_ValuesEqual(t *testing.T) {
	for _, desc := range settingRegistry {
		if desc.makeNullableEntry == nil {
			continue
		}
		t.Run(desc.settingName, func(t *testing.T) {
			require.NotNil(t, desc.valuesEqual,
				"org-scope setting %q must provide valuesEqual on the descriptor", desc.settingName)

			// Self-equality: getValue() compared to itself must be true
			update := buildLspFolderConfigWithAllPresent()
			entry := desc.makeNullableEntry(update)
			val := entry.getValue()
			assert.True(t, desc.valuesEqual(val, val),
				"valuesEqual should return true when comparing a value to itself")
		})
	}
}

func TestSettingRegistry_ValuesEqual_TypeCoercion(t *testing.T) {
	findDesc := func(settingName string) *settingDescriptor {
		for i := range settingRegistry {
			if settingRegistry[i].settingName == settingName {
				return &settingRegistry[i]
			}
		}
		return nil
	}

	t.Run("RiskScoreThreshold: int vs float64", func(t *testing.T) {
		desc := findDesc(SettingRiskScoreThreshold)
		require.NotNil(t, desc)
		require.NotNil(t, desc.valuesEqual)
		assert.True(t, desc.valuesEqual(500, float64(500)), "int(500) and float64(500) should be equal")
		assert.False(t, desc.valuesEqual(500, float64(600)), "int(500) and float64(600) should not be equal")
	})

	t.Run("ScanAutomatic: bool comparison", func(t *testing.T) {
		desc := findDesc(SettingScanAutomatic)
		require.NotNil(t, desc)
		require.NotNil(t, desc.valuesEqual)
		assert.True(t, desc.valuesEqual(true, true))
		assert.False(t, desc.valuesEqual(true, false))
		assert.False(t, desc.valuesEqual(false, true))
	})

	t.Run("EnabledSeverities: SeverityFilter vs *SeverityFilter", func(t *testing.T) {
		sf := SeverityFilter{Critical: true, High: true}
		desc := findDesc(SettingEnabledSeverities)
		require.NotNil(t, desc)
		require.NotNil(t, desc.valuesEqual)
		assert.True(t, desc.valuesEqual(sf, &sf), "SeverityFilter vs *SeverityFilter should be equal")
		assert.True(t, desc.valuesEqual(&sf, sf), "*SeverityFilter vs SeverityFilter should be equal")
		different := SeverityFilter{Critical: true, High: false}
		assert.False(t, desc.valuesEqual(sf, different), "different SeverityFilter values should not be equal")
	})

	t.Run("CweIds: []string comparison", func(t *testing.T) {
		desc := findDesc(SettingCweIds)
		require.NotNil(t, desc)
		require.NotNil(t, desc.valuesEqual)
		assert.True(t, desc.valuesEqual([]string{"CWE-79", "CWE-89"}, []string{"CWE-79", "CWE-89"}))
		assert.False(t, desc.valuesEqual([]string{"CWE-79"}, []string{"CWE-89"}))
		// []any (from JSON unmarshaling) vs []string
		assert.True(t, desc.valuesEqual([]string{"CWE-79"}, []any{"CWE-79"}))
	})
}

// seedValueForSetting returns a representative test value for the given setting name.
func seedValueForSetting(settingName string) any {
	switch settingName {
	case SettingEnabledSeverities:
		return SeverityFilter{Critical: true, High: true, Medium: true, Low: true}
	case SettingRiskScoreThreshold:
		return 500
	case SettingCweIds, SettingCveIds, SettingRuleIds:
		return []string{"test-id"}
	default:
		return true
	}
}
