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

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

// mockConfigProvider is a simple ConfigProvider for tests.
type mockConfigProvider struct {
	folderConfigs map[FilePath]*FolderConfig
}

func (m *mockConfigProvider) FolderOrganization(path FilePath) string {
	fc, ok := m.folderConfigs[PathKey(path)]
	if !ok || fc == nil {
		return ""
	}
	if fc.OrgSetByUser {
		return fc.PreferredOrg
	}
	return fc.AutoDeterminedOrg
}

func (m *mockConfigProvider) FilterSeverity() SeverityFilter {
	return SeverityFilter{Critical: true, High: true, Medium: true, Low: true}
}

func (m *mockConfigProvider) RiskScoreThreshold() int { return 0 }

func (m *mockConfigProvider) IssueViewOptions() IssueViewOptions {
	return IssueViewOptions{OpenIssues: true, IgnoredIssues: true}
}

func (m *mockConfigProvider) IsAutoScanEnabled() bool      { return true }
func (m *mockConfigProvider) IsDeltaFindingsEnabled() bool { return false }
func (m *mockConfigProvider) IsSnykCodeEnabled() bool      { return true }
func (m *mockConfigProvider) IsSnykOssEnabled() bool       { return true }
func (m *mockConfigProvider) IsSnykIacEnabled() bool       { return true }

func newMockConfigProvider(folderConfigs map[FilePath]*FolderConfig) *mockConfigProvider {
	normalized := make(map[FilePath]*FolderConfig, len(folderConfigs))
	for k, v := range folderConfigs {
		normalized[PathKey(k)] = v
	}
	return &mockConfigProvider{folderConfigs: normalized}
}

func TestConfigResolver_GetValue_MachineScope(t *testing.T) {
	logger := zerolog.Nop()
	globalSettings := &Settings{
		Endpoint: "https://api.snyk.io",
	}
	resolver := NewConfigResolver(nil, globalSettings, nil, &logger)

	t.Run("returns global value for machine-scoped setting", func(t *testing.T) {
		value, source := resolver.GetValue(SettingApiEndpoint, nil)
		assert.Equal(t, "https://api.snyk.io", value)
		assert.Equal(t, ConfigSourceGlobal, source)
	})

	t.Run("returns default source when global value is nil", func(t *testing.T) {
		value, source := resolver.GetValue(SettingCodeEndpoint, nil)
		assert.Nil(t, value)
		assert.Equal(t, ConfigSourceDefault, source)
	})

	t.Run("returns default source when global string value is empty", func(t *testing.T) {
		// Create settings with empty string for ActivateSnykCode (not set by user)
		emptySettings := &Settings{
			ActivateSnykCode: "", // Empty string should be treated as "not set"
		}
		emptyResolver := NewConfigResolver(nil, emptySettings, nil, &logger)

		value, source := emptyResolver.GetValue(SettingSnykCodeEnabled, nil)
		assert.Nil(t, value)
		assert.Equal(t, ConfigSourceDefault, source, "empty string should return ConfigSourceDefault, not ConfigSourceGlobal")
	})

	t.Run("returns global source when global string value is explicitly set", func(t *testing.T) {
		// Create settings with explicit value
		explicitSettings := &Settings{
			ActivateSnykCode: "true",
		}
		explicitResolver := NewConfigResolver(nil, explicitSettings, nil, &logger)

		value, source := explicitResolver.GetValue(SettingSnykCodeEnabled, nil)
		assert.Equal(t, "true", value)
		assert.Equal(t, ConfigSourceGlobal, source)
	})
}

func TestConfigResolver_GetValue_FolderScope(t *testing.T) {
	logger := zerolog.Nop()
	resolver := NewConfigResolver(nil, nil, nil, &logger)

	folderConfig := &FolderConfig{
		FolderPath:           PathKey("/path/to/folder"),
		BaseBranch:           "main",
		ReferenceFolderPath:  PathKey("/path/to/reference"),
		AdditionalParameters: []string{"--debug"},
	}

	t.Run("returns folder value for reference_branch", func(t *testing.T) {
		value, source := resolver.GetValue(SettingReferenceBranch, folderConfig)
		assert.Equal(t, "main", value)
		assert.Equal(t, ConfigSourceFolder, source)
	})

	t.Run("returns folder value for reference_folder", func(t *testing.T) {
		value, source := resolver.GetValue(SettingReferenceFolder, folderConfig)
		assert.Equal(t, string(PathKey("/path/to/reference")), value)
		assert.Equal(t, ConfigSourceFolder, source)
	})

	t.Run("returns folder value for additional_parameters", func(t *testing.T) {
		value, source := resolver.GetValue(SettingAdditionalParameters, folderConfig)
		assert.Equal(t, []string{"--debug"}, value)
		assert.Equal(t, ConfigSourceFolder, source)
	})
}

func TestConfigResolver_GetValue_OrgScope_NoLDXSync(t *testing.T) {
	logger := zerolog.Nop()
	globalSettings := &Settings{
		ActivateSnykCode: "true",
	}

	folderConfig := &FolderConfig{
		FolderPath:   PathKey("/path/to/folder"),
		PreferredOrg: "org1",
		OrgSetByUser: true,
	}
	configProvider := newMockConfigProvider(map[FilePath]*FolderConfig{folderConfig.FolderPath: folderConfig})
	resolver := NewConfigResolver(nil, globalSettings, configProvider, &logger)

	t.Run("returns global value when no LDX-Sync cache", func(t *testing.T) {
		value, source := resolver.GetValue(SettingSnykCodeEnabled, folderConfig)
		assert.Equal(t, "true", value)
		assert.Equal(t, ConfigSourceGlobal, source)
	})

	t.Run("returns user override when set and no LDX-Sync", func(t *testing.T) {
		folderConfig.SetUserOverride(SettingEnabledSeverities, []string{"critical", "high"})

		value, source := resolver.GetValue(SettingEnabledSeverities, folderConfig)
		assert.Equal(t, []string{"critical", "high"}, value)
		assert.Equal(t, ConfigSourceUserOverride, source)
	})
}

func TestConfigResolver_GetValue_OrgScope_WithLDXSync(t *testing.T) {
	logger := zerolog.Nop()
	globalSettings := &Settings{}

	ldxCache := NewLDXSyncConfigCache()
	orgConfig := NewLDXSyncOrgConfig("org1")
	orgConfig.SetField(SettingEnabledSeverities, []string{"critical"}, false, false, "org")
	ldxCache.SetOrgConfig(orgConfig)

	folderConfig := &FolderConfig{
		FolderPath:   PathKey("/path/to/folder"),
		PreferredOrg: "org1",
		OrgSetByUser: true,
	}
	configProvider := newMockConfigProvider(map[FilePath]*FolderConfig{folderConfig.FolderPath: folderConfig})
	resolver := NewConfigResolver(ldxCache, globalSettings, configProvider, &logger)

	t.Run("returns LDX-Sync value when no user override", func(t *testing.T) {
		value, source := resolver.GetValue(SettingEnabledSeverities, folderConfig)
		assert.Equal(t, []string{"critical"}, value)
		assert.Equal(t, ConfigSourceLDXSync, source)
	})

	t.Run("returns user override when set", func(t *testing.T) {
		folderConfig.SetUserOverride(SettingEnabledSeverities, []string{"critical", "high"})

		value, source := resolver.GetValue(SettingEnabledSeverities, folderConfig)
		assert.Equal(t, []string{"critical", "high"}, value)
		assert.Equal(t, ConfigSourceUserOverride, source)
	})
}

func TestConfigResolver_GetValue_OrgScope_Locked(t *testing.T) {
	logger := zerolog.Nop()
	globalSettings := &Settings{}

	ldxCache := NewLDXSyncConfigCache()
	orgConfig := NewLDXSyncOrgConfig("org1")
	orgConfig.SetField(SettingEnabledSeverities, []string{"critical"}, true, false, "group")
	ldxCache.SetOrgConfig(orgConfig)

	folderConfig := &FolderConfig{
		FolderPath:   PathKey("/path/to/folder"),
		PreferredOrg: "org1",
		OrgSetByUser: true,
	}
	configProvider := newMockConfigProvider(map[FilePath]*FolderConfig{folderConfig.FolderPath: folderConfig})
	resolver := NewConfigResolver(ldxCache, globalSettings, configProvider, &logger)

	t.Run("returns LDX-Sync locked value even when user override exists", func(t *testing.T) {
		folderConfig.SetUserOverride(SettingEnabledSeverities, []string{"critical", "high", "medium"})

		value, source := resolver.GetValue(SettingEnabledSeverities, folderConfig)
		assert.Equal(t, []string{"critical"}, value)
		assert.Equal(t, ConfigSourceLDXSyncLocked, source)
	})
}

func TestConfigResolver_GetValue_OrgScope_DifferentOrgs(t *testing.T) {
	logger := zerolog.Nop()
	globalSettings := &Settings{}

	ldxCache := NewLDXSyncConfigCache()

	org1Config := NewLDXSyncOrgConfig("org1")
	org1Config.SetField(SettingEnabledSeverities, []string{"critical"}, false, false, "org")
	ldxCache.SetOrgConfig(org1Config)

	org2Config := NewLDXSyncOrgConfig("org2")
	org2Config.SetField(SettingEnabledSeverities, []string{"critical", "high"}, true, false, "group")
	ldxCache.SetOrgConfig(org2Config)

	folder1 := &FolderConfig{FolderPath: PathKey("/folder1"), PreferredOrg: "org1", OrgSetByUser: true}
	folder2 := &FolderConfig{FolderPath: PathKey("/folder2"), PreferredOrg: "org2", OrgSetByUser: true}
	configProvider := newMockConfigProvider(map[FilePath]*FolderConfig{folder1.FolderPath: folder1, folder2.FolderPath: folder2})
	resolver := NewConfigResolver(ldxCache, globalSettings, configProvider, &logger)

	t.Run("uses correct org config based on folder", func(t *testing.T) {
		value1, source1 := resolver.GetValue(SettingEnabledSeverities, folder1)
		value2, source2 := resolver.GetValue(SettingEnabledSeverities, folder2)

		assert.Equal(t, []string{"critical"}, value1)
		assert.Equal(t, ConfigSourceLDXSync, source1)

		assert.Equal(t, []string{"critical", "high"}, value2)
		assert.Equal(t, ConfigSourceLDXSyncLocked, source2)
	})
}

func TestConfigResolver_TypedAccessors(t *testing.T) {
	logger := zerolog.Nop()
	globalSettings := &Settings{
		Endpoint:            "https://api.snyk.io",
		ActivateSnykCode:    "true",
		EnableDeltaFindings: "true",
	}

	riskScore := 500
	globalSettings.RiskScoreThreshold = &riskScore

	resolver := NewConfigResolver(nil, globalSettings, nil, &logger)

	t.Run("GetString", func(t *testing.T) {
		value := resolver.GetString(SettingApiEndpoint, nil)
		assert.Equal(t, "https://api.snyk.io", value)
	})

	t.Run("GetBool with string true", func(t *testing.T) {
		value := resolver.GetBool(SettingScanNetNew, nil)
		assert.True(t, value)
	})

	t.Run("GetInt", func(t *testing.T) {
		value := resolver.GetInt(SettingRiskScoreThreshold, nil)
		assert.Equal(t, 500, value)
	})

	t.Run("GetStringSlice", func(t *testing.T) {
		folderConfig := &FolderConfig{
			FolderPath:           PathKey("/path"),
			AdditionalParameters: []string{"--debug", "--verbose"},
		}
		value := resolver.GetStringSlice(SettingAdditionalParameters, folderConfig)
		assert.Equal(t, []string{"--debug", "--verbose"}, value)
	})
}

func TestConfigResolver_IsLocked(t *testing.T) {
	logger := zerolog.Nop()

	ldxCache := NewLDXSyncConfigCache()
	orgConfig := NewLDXSyncOrgConfig("org1")
	orgConfig.SetField(SettingEnabledSeverities, []string{"critical"}, true, false, "group")
	orgConfig.SetField(SettingSnykCodeEnabled, true, false, false, "org")
	ldxCache.SetOrgConfig(orgConfig)

	folderConfig := &FolderConfig{
		FolderPath:   PathKey("/path"),
		PreferredOrg: "org1",
		OrgSetByUser: true,
	}
	configProvider := newMockConfigProvider(map[FilePath]*FolderConfig{folderConfig.FolderPath: folderConfig})
	resolver := NewConfigResolver(ldxCache, nil, configProvider, &logger)

	t.Run("returns true for locked setting", func(t *testing.T) {
		assert.True(t, resolver.IsLocked(SettingEnabledSeverities, folderConfig))
	})

	t.Run("returns false for unlocked setting", func(t *testing.T) {
		assert.False(t, resolver.IsLocked(SettingSnykCodeEnabled, folderConfig))
	})

	t.Run("returns false for missing setting", func(t *testing.T) {
		assert.False(t, resolver.IsLocked(SettingRiskScoreThreshold, folderConfig))
	})

	t.Run("returns false for nil folder config", func(t *testing.T) {
		assert.False(t, resolver.IsLocked(SettingEnabledSeverities, nil))
	})
}

func TestConfigResolver_IsEnforced(t *testing.T) {
	logger := zerolog.Nop()

	ldxCache := NewLDXSyncConfigCache()
	orgConfig := NewLDXSyncOrgConfig("org1")
	orgConfig.SetField(SettingEnabledSeverities, []string{"critical"}, false, true, "group")
	orgConfig.SetField(SettingSnykCodeEnabled, true, false, false, "org")
	ldxCache.SetOrgConfig(orgConfig)

	folderConfig := &FolderConfig{
		FolderPath:   PathKey("/path"),
		PreferredOrg: "org1",
		OrgSetByUser: true,
	}
	configProvider := newMockConfigProvider(map[FilePath]*FolderConfig{folderConfig.FolderPath: folderConfig})
	resolver := NewConfigResolver(ldxCache, nil, configProvider, &logger)

	t.Run("returns true for enforced setting", func(t *testing.T) {
		assert.True(t, resolver.IsEnforced(SettingEnabledSeverities, folderConfig))
	})

	t.Run("returns false for non-enforced setting", func(t *testing.T) {
		assert.False(t, resolver.IsEnforced(SettingSnykCodeEnabled, folderConfig))
	})
}

func TestConfigResolver_GetSource(t *testing.T) {
	logger := zerolog.Nop()
	globalSettings := &Settings{
		Endpoint: "https://api.snyk.io",
	}
	resolver := NewConfigResolver(nil, globalSettings, nil, &logger)

	source := resolver.GetSource(SettingApiEndpoint, nil)
	assert.Equal(t, ConfigSourceGlobal, source)
}

func TestStoredFolderConfig_UserOverrideMethods(t *testing.T) {
	t.Run("HasUserOverride returns false for nil config", func(t *testing.T) {
		var fc *FolderConfig
		assert.False(t, fc.HasUserOverride("test"))
	})

	t.Run("HasUserOverride returns false for nil map", func(t *testing.T) {
		fc := &FolderConfig{}
		assert.False(t, fc.HasUserOverride("test"))
	})

	t.Run("SetUserOverride creates map if nil", func(t *testing.T) {
		fc := &FolderConfig{}
		fc.SetUserOverride("test", "value")
		assert.NotNil(t, fc.UserOverrides)
		assert.Equal(t, "value", fc.UserOverrides["test"])
	})

	t.Run("GetUserOverride returns value and true when exists", func(t *testing.T) {
		fc := &FolderConfig{}
		fc.SetUserOverride("test", "value")

		val, exists := fc.GetUserOverride("test")
		assert.True(t, exists)
		assert.Equal(t, "value", val)
	})

	t.Run("GetUserOverride returns nil and false when not exists", func(t *testing.T) {
		fc := &FolderConfig{}

		val, exists := fc.GetUserOverride("test")
		assert.False(t, exists)
		assert.Nil(t, val)
	})

	t.Run("ResetToDefault removes override", func(t *testing.T) {
		fc := &FolderConfig{}
		fc.SetUserOverride("test", "value")
		assert.True(t, fc.HasUserOverride("test"))

		fc.ResetToDefault("test")
		assert.False(t, fc.HasUserOverride("test"))
	})

	t.Run("ResetToDefault does nothing for nil map", func(t *testing.T) {
		fc := &FolderConfig{}
		fc.ResetToDefault("test") // should not panic
	})
}

func TestStoredFolderConfig_Clone_WithUserOverrides(t *testing.T) {
	original := &FolderConfig{
		FolderPath:   PathKey("/path"),
		PreferredOrg: "org1",
		UserOverrides: map[string]any{
			"setting1": "value1",
			"setting2": 42,
		},
	}

	clone := original.Clone()

	t.Run("clones UserOverrides", func(t *testing.T) {
		assert.NotNil(t, clone.UserOverrides)
		assert.Equal(t, "value1", clone.UserOverrides["setting1"])
		assert.Equal(t, 42, clone.UserOverrides["setting2"])
	})

	t.Run("clone is independent", func(t *testing.T) {
		clone.UserOverrides["setting1"] = "modified"
		assert.Equal(t, "value1", original.UserOverrides["setting1"])
	})
}

func TestConfigResolver_GetEffectiveValue_IncludesOriginScope(t *testing.T) {
	logger := zerolog.Nop()
	globalSettings := &Settings{}

	ldxCache := NewLDXSyncConfigCache()
	orgConfig := NewLDXSyncOrgConfig("org1")
	orgConfig.SetField(SettingEnabledSeverities, []string{"critical"}, false, false, "tenant")
	orgConfig.SetField(SettingSnykCodeEnabled, true, true, false, "group")
	ldxCache.SetOrgConfig(orgConfig)

	folderConfig := &FolderConfig{
		FolderPath:   PathKey("/path/to/folder"),
		PreferredOrg: "org1",
		OrgSetByUser: true,
	}
	configProvider := newMockConfigProvider(map[FilePath]*FolderConfig{folderConfig.FolderPath: folderConfig})
	resolver := NewConfigResolver(ldxCache, globalSettings, configProvider, &logger)

	t.Run("includes OriginScope for LDX-Sync value", func(t *testing.T) {
		effectiveValue := resolver.GetEffectiveValue(SettingEnabledSeverities, folderConfig)

		assert.Equal(t, []string{"critical"}, effectiveValue.Value)
		assert.Equal(t, "ldx-sync", effectiveValue.Source)
		assert.Equal(t, "tenant", effectiveValue.OriginScope)
	})

	t.Run("includes OriginScope for locked LDX-Sync value", func(t *testing.T) {
		effectiveValue := resolver.GetEffectiveValue(SettingSnykCodeEnabled, folderConfig)

		assert.Equal(t, true, effectiveValue.Value)
		assert.Equal(t, "ldx-sync-locked", effectiveValue.Source)
		assert.Equal(t, "group", effectiveValue.OriginScope)
	})

	t.Run("OriginScope is empty for user override", func(t *testing.T) {
		folderConfigWithOverride := &FolderConfig{
			FolderPath:   PathKey("/path/to/folder"),
			PreferredOrg: "org1",
			OrgSetByUser: true,
		}
		folderConfigWithOverride.SetUserOverride(SettingEnabledSeverities, []string{"high"})

		effectiveValue := resolver.GetEffectiveValue(SettingEnabledSeverities, folderConfigWithOverride)

		assert.Equal(t, []string{"high"}, effectiveValue.Value)
		assert.Equal(t, "user-override", effectiveValue.Source)
		assert.Equal(t, "", effectiveValue.OriginScope)
	})

	t.Run("OriginScope is empty for global fallback", func(t *testing.T) {
		folderConfigNoOrg := &FolderConfig{
			FolderPath: PathKey("/path/to/folder"),
		}
		configProviderNoOrg := newMockConfigProvider(map[FilePath]*FolderConfig{folderConfigNoOrg.FolderPath: folderConfigNoOrg})
		resolverNoLdx := NewConfigResolver(nil, globalSettings, configProviderNoOrg, &logger)

		effectiveValue := resolverNoLdx.GetEffectiveValue(SettingEnabledSeverities, folderConfigNoOrg)

		assert.Equal(t, "", effectiveValue.OriginScope)
	})
}

func TestConfigResolver_EnforcedSource_OrgScope(t *testing.T) {
	logger := zerolog.Nop()
	globalSettings := &Settings{}

	ldxCache := NewLDXSyncConfigCache()
	orgConfig := NewLDXSyncOrgConfig("org1")
	orgConfig.SetField(SettingEnabledSeverities, []string{"critical"}, false, true, "group")
	orgConfig.SetField(SettingSnykCodeEnabled, true, false, false, "org")
	ldxCache.SetOrgConfig(orgConfig)

	folderConfig := &FolderConfig{
		FolderPath:   PathKey("/path/to/folder"),
		PreferredOrg: "org1",
		OrgSetByUser: true,
	}
	configProvider := newMockConfigProvider(map[FilePath]*FolderConfig{folderConfig.FolderPath: folderConfig})
	resolver := NewConfigResolver(ldxCache, globalSettings, configProvider, &logger)

	t.Run("enforced field without user override returns ldx-sync-enforced source", func(t *testing.T) {
		value, source := resolver.GetValue(SettingEnabledSeverities, folderConfig)
		assert.Equal(t, []string{"critical"}, value)
		assert.Equal(t, ConfigSourceLDXSyncEnforced, source)
	})

	t.Run("non-enforced field returns ldx-sync source", func(t *testing.T) {
		value, source := resolver.GetValue(SettingSnykCodeEnabled, folderConfig)
		assert.Equal(t, true, value)
		assert.Equal(t, ConfigSourceLDXSync, source)
	})

	t.Run("user override wins over enforced field", func(t *testing.T) {
		folderConfigWithOverride := &FolderConfig{
			FolderPath:   PathKey("/path/to/folder"),
			PreferredOrg: "org1",
			OrgSetByUser: true,
		}
		folderConfigWithOverride.SetUserOverride(SettingEnabledSeverities, []string{"high"})

		value, source := resolver.GetValue(SettingEnabledSeverities, folderConfigWithOverride)
		assert.Equal(t, []string{"high"}, value)
		assert.Equal(t, ConfigSourceUserOverride, source)
	})
}

func TestConfigResolver_EnforcedSource_MachineScope(t *testing.T) {
	logger := zerolog.Nop()
	globalSettings := &Settings{}

	machineConfig := map[string]*LDXSyncField{
		SettingApiEndpoint: {Value: "https://enforced.snyk.io", IsLocked: false, IsEnforced: true},
		SettingCliPath:     {Value: "/usr/bin/snyk", IsLocked: false, IsEnforced: false},
	}
	resolver := NewConfigResolver(nil, globalSettings, nil, &logger)
	resolver.SetLDXSyncMachineConfig(machineConfig)

	t.Run("enforced machine field without global setting returns ldx-sync-enforced source", func(t *testing.T) {
		value, source := resolver.GetValue(SettingApiEndpoint, nil)
		assert.Equal(t, "https://enforced.snyk.io", value)
		assert.Equal(t, ConfigSourceLDXSyncEnforced, source)
	})

	t.Run("non-enforced machine field returns ldx-sync source", func(t *testing.T) {
		value, source := resolver.GetValue(SettingCliPath, nil)
		assert.Equal(t, "/usr/bin/snyk", value)
		assert.Equal(t, ConfigSourceLDXSync, source)
	})

	t.Run("global setting wins over enforced machine field", func(t *testing.T) {
		globalSettingsWithEndpoint := &Settings{
			Endpoint: "https://user.snyk.io",
		}
		resolverWithGlobal := NewConfigResolver(nil, globalSettingsWithEndpoint, nil, &logger)
		resolverWithGlobal.SetLDXSyncMachineConfig(machineConfig)

		value, source := resolverWithGlobal.GetValue(SettingApiEndpoint, nil)
		assert.Equal(t, "https://user.snyk.io", value)
		assert.Equal(t, ConfigSourceGlobal, source)
	})
}

func TestConfigResolver_GetEffectiveValue_EnforcedIncludesOriginScope(t *testing.T) {
	logger := zerolog.Nop()
	globalSettings := &Settings{}

	ldxCache := NewLDXSyncConfigCache()
	orgConfig := NewLDXSyncOrgConfig("org1")
	orgConfig.SetField(SettingEnabledSeverities, []string{"critical"}, false, true, "group")
	ldxCache.SetOrgConfig(orgConfig)

	folderConfig := &FolderConfig{
		FolderPath:   PathKey("/path/to/folder"),
		PreferredOrg: "org1",
		OrgSetByUser: true,
	}
	configProvider := newMockConfigProvider(map[FilePath]*FolderConfig{folderConfig.FolderPath: folderConfig})
	resolver := NewConfigResolver(ldxCache, globalSettings, configProvider, &logger)

	effectiveValue := resolver.GetEffectiveValue(SettingEnabledSeverities, folderConfig)

	assert.Equal(t, []string{"critical"}, effectiveValue.Value)
	assert.Equal(t, "ldx-sync-enforced", effectiveValue.Source)
	assert.Equal(t, "group", effectiveValue.OriginScope)
}

func TestStoredFolderConfig_ApplyLspUpdate(t *testing.T) {
	t.Run("returns false for nil receiver", func(t *testing.T) {
		var fc *FolderConfig
		update := &LspFolderConfig{FolderPath: PathKey("/path")}
		assert.False(t, fc.ApplyLspUpdate(update))
	})

	t.Run("returns false for nil update", func(t *testing.T) {
		fc := &FolderConfig{FolderPath: PathKey("/path")}
		assert.False(t, fc.ApplyLspUpdate(nil))
	})

	t.Run("applies folder-scope updates", func(t *testing.T) {
		fc := &FolderConfig{
			FolderPath: PathKey("/path/to/folder"),
			BaseBranch: "main",
		}

		newBranch := "develop"
		newEnv := "DEBUG=1"
		update := &LspFolderConfig{
			FolderPath:    PathKey("/path/to/folder"),
			BaseBranch:    &newBranch,
			AdditionalEnv: &newEnv,
		}

		changed := fc.ApplyLspUpdate(update)

		assert.True(t, changed)
		assert.Equal(t, "develop", fc.BaseBranch)
		assert.Equal(t, "DEBUG=1", fc.AdditionalEnv)
	})

	t.Run("does not change fields when nil in update", func(t *testing.T) {
		fc := &FolderConfig{
			FolderPath: PathKey("/path/to/folder"),
			BaseBranch: "main",
		}

		update := &LspFolderConfig{
			FolderPath: PathKey("/path/to/folder"),
			// BaseBranch is nil - should not change
		}

		changed := fc.ApplyLspUpdate(update)

		assert.False(t, changed)
		assert.Equal(t, "main", fc.BaseBranch)
	})

	t.Run("applies org-scope updates as user overrides", func(t *testing.T) {
		fc := &FolderConfig{
			FolderPath: PathKey("/path/to/folder"),
		}

		update := &LspFolderConfig{
			FolderPath:    PathKey("/path/to/folder"),
			ScanAutomatic: NullableField[bool]{Value: true, Present: true},
			ScanNetNew:    NullableField[bool]{Value: false, Present: true},
		}

		changed := fc.ApplyLspUpdate(update)

		assert.True(t, changed)
		assert.True(t, fc.HasUserOverride(SettingScanAutomatic))
		assert.True(t, fc.HasUserOverride(SettingScanNetNew))
		scanAutoVal, _ := fc.GetUserOverride(SettingScanAutomatic)
		scanNetNewVal, _ := fc.GetUserOverride(SettingScanNetNew)
		assert.Equal(t, true, scanAutoVal)
		assert.Equal(t, false, scanNetNewVal)
	})

	t.Run("sets OrgSetByUser when PreferredOrg is updated", func(t *testing.T) {
		fc := &FolderConfig{
			FolderPath:   PathKey("/path/to/folder"),
			OrgSetByUser: false,
		}

		newOrg := "my-org"
		update := &LspFolderConfig{
			FolderPath:   PathKey("/path/to/folder"),
			PreferredOrg: &newOrg,
		}

		changed := fc.ApplyLspUpdate(update)

		assert.True(t, changed)
		assert.Equal(t, "my-org", fc.PreferredOrg)
		assert.True(t, fc.OrgSetByUser)
	})

	t.Run("clears user overrides via explicit null", func(t *testing.T) {
		fc := &FolderConfig{
			FolderPath: PathKey("/path/to/folder"),
		}
		// Set some user overrides first
		fc.SetUserOverride(SettingScanAutomatic, true)
		fc.SetUserOverride(SettingScanNetNew, false)
		fc.SetUserOverride(SettingSnykCodeEnabled, true)

		// Clear only some of them using explicit null
		update := &LspFolderConfig{
			FolderPath:      PathKey("/path/to/folder"),
			ScanAutomatic:   NullableField[bool]{Present: true, Null: true}, // explicit null = clear
			SnykCodeEnabled: NullableField[bool]{Present: true, Null: true}, // explicit null = clear
			// ScanNetNew is omitted (Present: false) = don't change
		}

		changed := fc.ApplyLspUpdate(update)

		assert.True(t, changed)
		assert.False(t, fc.HasUserOverride(SettingScanAutomatic), "ScanAutomatic should be cleared")
		assert.False(t, fc.HasUserOverride(SettingSnykCodeEnabled), "SnykCodeEnabled should be cleared")
		assert.True(t, fc.HasUserOverride(SettingScanNetNew), "ScanNetNew should remain")
	})

	t.Run("null clears and value sets in same update", func(t *testing.T) {
		fc := &FolderConfig{
			FolderPath: PathKey("/path/to/folder"),
		}
		fc.SetUserOverride(SettingScanAutomatic, true)

		// Clear one setting (null) and set another (value)
		update := &LspFolderConfig{
			FolderPath:    PathKey("/path/to/folder"),
			ScanAutomatic: NullableField[bool]{Present: true, Null: true},  // null = clear
			ScanNetNew:    NullableField[bool]{Value: true, Present: true}, // value = set
		}

		changed := fc.ApplyLspUpdate(update)

		assert.True(t, changed)
		assert.False(t, fc.HasUserOverride(SettingScanAutomatic), "ScanAutomatic should be cleared")
		assert.True(t, fc.HasUserOverride(SettingScanNetNew), "ScanNetNew should be set")
	})

	t.Run("omitted fields are not changed", func(t *testing.T) {
		fc := &FolderConfig{
			FolderPath: PathKey("/path/to/folder"),
		}
		fc.SetUserOverride(SettingScanAutomatic, true)
		fc.SetUserOverride(SettingScanNetNew, false)

		// Update with all fields omitted (Present: false)
		update := &LspFolderConfig{
			FolderPath: PathKey("/path/to/folder"),
			// All NullableField fields are zero value (Present: false) = omitted
		}

		changed := fc.ApplyLspUpdate(update)

		assert.False(t, changed, "No changes should be made when all fields are omitted")
		assert.True(t, fc.HasUserOverride(SettingScanAutomatic), "ScanAutomatic should remain")
		assert.True(t, fc.HasUserOverride(SettingScanNetNew), "ScanNetNew should remain")
	})

	t.Run("applies cwe/cve/rule filter overrides", func(t *testing.T) {
		fc := &FolderConfig{FolderPath: PathKey("/path/to/folder")}

		update := &LspFolderConfig{
			FolderPath: PathKey("/path/to/folder"),
			CweIds:     NullableField[[]string]{Value: []string{"CWE-79", "CWE-89"}, Present: true},
			CveIds:     NullableField[[]string]{Value: []string{"CVE-2023-1234"}, Present: true},
			RuleIds:    NullableField[[]string]{Value: []string{"SNYK-JS-001"}, Present: true},
		}

		changed := fc.ApplyLspUpdate(update)

		assert.True(t, changed)
		assert.True(t, fc.HasUserOverride(SettingCweIds))
		assert.True(t, fc.HasUserOverride(SettingCveIds))
		assert.True(t, fc.HasUserOverride(SettingRuleIds))
		cweVal, _ := fc.GetUserOverride(SettingCweIds)
		assert.Equal(t, []string{"CWE-79", "CWE-89"}, cweVal)
	})

	t.Run("clears cwe/cve/rule filter overrides via null", func(t *testing.T) {
		fc := &FolderConfig{FolderPath: PathKey("/path/to/folder")}
		fc.SetUserOverride(SettingCweIds, []string{"CWE-79"})
		fc.SetUserOverride(SettingCveIds, []string{"CVE-2023-1234"})

		update := &LspFolderConfig{
			FolderPath: PathKey("/path/to/folder"),
			CweIds:     NullableField[[]string]{Present: true, Null: true},
			CveIds:     NullableField[[]string]{Present: true, Null: true},
		}

		changed := fc.ApplyLspUpdate(update)

		assert.True(t, changed)
		assert.False(t, fc.HasUserOverride(SettingCweIds), "CweIds should be cleared")
		assert.False(t, fc.HasUserOverride(SettingCveIds), "CveIds should be cleared")
	})
}

func TestStoredFolderConfig_ToLspFolderConfig(t *testing.T) {
	t.Run("returns nil for nil config", func(t *testing.T) {
		var fc *FolderConfig
		result := fc.ToLspFolderConfig(nil)
		assert.Nil(t, result)
	})

	t.Run("copies folder-scope settings without resolver", func(t *testing.T) {
		fc := &FolderConfig{
			FolderPath:           PathKey("/path/to/folder"),
			BaseBranch:           "main",
			LocalBranches:        []string{"main", "develop"},
			AdditionalParameters: []string{"--debug"},
			AdditionalEnv:        "DEBUG=1",
			ReferenceFolderPath:  PathKey("/ref/path"),
			PreferredOrg:         "org1",
			AutoDeterminedOrg:    "auto-org",
		}

		result := fc.ToLspFolderConfig(nil)

		assert.Equal(t, PathKey("/path/to/folder"), result.FolderPath)
		assert.Equal(t, "main", *result.BaseBranch)
		assert.Equal(t, []string{"main", "develop"}, result.LocalBranches)
		assert.Equal(t, []string{"--debug"}, result.AdditionalParameters)
		assert.Equal(t, "DEBUG=1", *result.AdditionalEnv)
		assert.Equal(t, PathKey("/ref/path"), *result.ReferenceFolderPath)
		assert.Equal(t, "org1", *result.PreferredOrg)
		assert.Equal(t, "auto-org", *result.AutoDeterminedOrg)

		// Org-scope settings should be omitted (not present) without resolver
		assert.True(t, result.EnabledSeverities.IsOmitted(), "EnabledSeverities should be omitted without resolver")
		assert.True(t, result.RiskScoreThreshold.IsOmitted(), "RiskScoreThreshold should be omitted without resolver")
		assert.True(t, result.ScanAutomatic.IsOmitted(), "ScanAutomatic should be omitted without resolver")
	})

	t.Run("omits empty folder-scope settings", func(t *testing.T) {
		fc := &FolderConfig{
			FolderPath: PathKey("/path/to/folder"),
			// All other fields are empty/zero
		}

		result := fc.ToLspFolderConfig(nil)

		assert.Equal(t, PathKey("/path/to/folder"), result.FolderPath)
		assert.Nil(t, result.BaseBranch)
		assert.Nil(t, result.LocalBranches)
		assert.Nil(t, result.AdditionalParameters)
		assert.Nil(t, result.AdditionalEnv)
		assert.Nil(t, result.ReferenceFolderPath)
		assert.Nil(t, result.PreferredOrg)
		assert.Nil(t, result.AutoDeterminedOrg)
	})

	t.Run("populates org-scope settings with resolver", func(t *testing.T) {
		logger := zerolog.Nop()
		globalSettings := &Settings{
			ActivateSnykCode:       "true",
			ActivateSnykOpenSource: "true",
			ActivateSnykIac:        "false",
			ScanningMode:           "true", // GetBool checks for "true" string
			EnableDeltaFindings:    "true",
		}

		fc := &FolderConfig{
			FolderPath:   PathKey("/path/to/folder"),
			PreferredOrg: "org1",
			OrgSetByUser: true,
		}
		configProvider := newMockConfigProvider(map[FilePath]*FolderConfig{fc.FolderPath: fc})
		resolver := NewConfigResolver(nil, globalSettings, configProvider, &logger)

		result := fc.ToLspFolderConfig(resolver)

		assert.Equal(t, PathKey("/path/to/folder"), result.FolderPath)
		assert.True(t, result.ScanAutomatic.HasValue())
		assert.True(t, result.ScanAutomatic.Value)
		assert.True(t, result.ScanNetNew.HasValue())
		assert.True(t, result.ScanNetNew.Value)
		assert.True(t, result.SnykCodeEnabled.HasValue())
		assert.True(t, result.SnykCodeEnabled.Value)
		assert.True(t, result.SnykOssEnabled.HasValue())
		assert.True(t, result.SnykOssEnabled.Value)
		assert.True(t, result.SnykIacEnabled.HasValue())
		assert.False(t, result.SnykIacEnabled.Value)
	})
}
