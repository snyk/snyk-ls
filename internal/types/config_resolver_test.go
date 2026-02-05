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
	folderConfigs map[FilePath]*StoredFolderConfig
}

func (m *mockConfigProvider) FolderOrganization(path FilePath) string {
	fc, ok := m.folderConfigs[path]
	if !ok || fc == nil {
		return ""
	}
	if fc.OrgSetByUser {
		return fc.PreferredOrg
	}
	return fc.AutoDeterminedOrg
}

func newMockConfigProvider(folderConfigs map[FilePath]*StoredFolderConfig) *mockConfigProvider {
	return &mockConfigProvider{folderConfigs: folderConfigs}
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

	folderConfig := &StoredFolderConfig{
		FolderPath:           "/path/to/folder",
		BaseBranch:           "main",
		ReferenceFolderPath:  "/path/to/reference",
		AdditionalParameters: []string{"--debug"},
	}

	t.Run("returns folder value for reference_branch", func(t *testing.T) {
		value, source := resolver.GetValue(SettingReferenceBranch, folderConfig)
		assert.Equal(t, "main", value)
		assert.Equal(t, ConfigSourceFolder, source)
	})

	t.Run("returns folder value for reference_folder", func(t *testing.T) {
		value, source := resolver.GetValue(SettingReferenceFolder, folderConfig)
		assert.Equal(t, "/path/to/reference", value)
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

	folderConfig := &StoredFolderConfig{
		FolderPath:   "/path/to/folder",
		PreferredOrg: "org1",
		OrgSetByUser: true,
	}
	configProvider := newMockConfigProvider(map[FilePath]*StoredFolderConfig{folderConfig.FolderPath: folderConfig})
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

	folderConfig := &StoredFolderConfig{
		FolderPath:   "/path/to/folder",
		PreferredOrg: "org1",
		OrgSetByUser: true,
	}
	configProvider := newMockConfigProvider(map[FilePath]*StoredFolderConfig{folderConfig.FolderPath: folderConfig})
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

	folderConfig := &StoredFolderConfig{
		FolderPath:   "/path/to/folder",
		PreferredOrg: "org1",
		OrgSetByUser: true,
	}
	configProvider := newMockConfigProvider(map[FilePath]*StoredFolderConfig{folderConfig.FolderPath: folderConfig})
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

	folder1 := &StoredFolderConfig{FolderPath: "/folder1", PreferredOrg: "org1", OrgSetByUser: true}
	folder2 := &StoredFolderConfig{FolderPath: "/folder2", PreferredOrg: "org2", OrgSetByUser: true}
	configProvider := newMockConfigProvider(map[FilePath]*StoredFolderConfig{folder1.FolderPath: folder1, folder2.FolderPath: folder2})
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
		folderConfig := &StoredFolderConfig{
			FolderPath:           "/path",
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

	folderConfig := &StoredFolderConfig{
		FolderPath:   "/path",
		PreferredOrg: "org1",
		OrgSetByUser: true,
	}
	configProvider := newMockConfigProvider(map[FilePath]*StoredFolderConfig{folderConfig.FolderPath: folderConfig})
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

	folderConfig := &StoredFolderConfig{
		FolderPath:   "/path",
		PreferredOrg: "org1",
		OrgSetByUser: true,
	}
	configProvider := newMockConfigProvider(map[FilePath]*StoredFolderConfig{folderConfig.FolderPath: folderConfig})
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
		var fc *StoredFolderConfig
		assert.False(t, fc.HasUserOverride("test"))
	})

	t.Run("HasUserOverride returns false for nil map", func(t *testing.T) {
		fc := &StoredFolderConfig{}
		assert.False(t, fc.HasUserOverride("test"))
	})

	t.Run("SetUserOverride creates map if nil", func(t *testing.T) {
		fc := &StoredFolderConfig{}
		fc.SetUserOverride("test", "value")
		assert.NotNil(t, fc.UserOverrides)
		assert.Equal(t, "value", fc.UserOverrides["test"])
	})

	t.Run("GetUserOverride returns value and true when exists", func(t *testing.T) {
		fc := &StoredFolderConfig{}
		fc.SetUserOverride("test", "value")

		val, exists := fc.GetUserOverride("test")
		assert.True(t, exists)
		assert.Equal(t, "value", val)
	})

	t.Run("GetUserOverride returns nil and false when not exists", func(t *testing.T) {
		fc := &StoredFolderConfig{}

		val, exists := fc.GetUserOverride("test")
		assert.False(t, exists)
		assert.Nil(t, val)
	})

	t.Run("ResetToDefault removes override", func(t *testing.T) {
		fc := &StoredFolderConfig{}
		fc.SetUserOverride("test", "value")
		assert.True(t, fc.HasUserOverride("test"))

		fc.ResetToDefault("test")
		assert.False(t, fc.HasUserOverride("test"))
	})

	t.Run("ResetToDefault does nothing for nil map", func(t *testing.T) {
		fc := &StoredFolderConfig{}
		fc.ResetToDefault("test") // should not panic
	})
}

func TestStoredFolderConfig_Clone_WithUserOverrides(t *testing.T) {
	original := &StoredFolderConfig{
		FolderPath:   "/path",
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

	folderConfig := &StoredFolderConfig{
		FolderPath:   "/path/to/folder",
		PreferredOrg: "org1",
		OrgSetByUser: true,
	}
	configProvider := newMockConfigProvider(map[FilePath]*StoredFolderConfig{folderConfig.FolderPath: folderConfig})
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
		folderConfigWithOverride := &StoredFolderConfig{
			FolderPath:   "/path/to/folder",
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
		folderConfigNoOrg := &StoredFolderConfig{
			FolderPath: "/path/to/folder",
		}
		configProviderNoOrg := newMockConfigProvider(map[FilePath]*StoredFolderConfig{folderConfigNoOrg.FolderPath: folderConfigNoOrg})
		resolverNoLdx := NewConfigResolver(nil, globalSettings, configProviderNoOrg, &logger)

		effectiveValue := resolverNoLdx.GetEffectiveValue(SettingEnabledSeverities, folderConfigNoOrg)

		assert.Equal(t, "", effectiveValue.OriginScope)
	})
}

func TestStoredFolderConfig_ToLspFolderConfig(t *testing.T) {
	t.Run("returns nil for nil config", func(t *testing.T) {
		var fc *StoredFolderConfig
		result := fc.ToLspFolderConfig(nil)
		assert.Nil(t, result)
	})

	t.Run("copies folder-scope settings without resolver", func(t *testing.T) {
		fc := &StoredFolderConfig{
			FolderPath:           "/path/to/folder",
			BaseBranch:           "main",
			LocalBranches:        []string{"main", "develop"},
			AdditionalParameters: []string{"--debug"},
			AdditionalEnv:        "DEBUG=1",
			ReferenceFolderPath:  "/ref/path",
			PreferredOrg:         "org1",
			AutoDeterminedOrg:    "auto-org",
		}

		result := fc.ToLspFolderConfig(nil)

		assert.Equal(t, FilePath("/path/to/folder"), result.FolderPath)
		assert.Equal(t, "main", *result.BaseBranch)
		assert.Equal(t, []string{"main", "develop"}, result.LocalBranches)
		assert.Equal(t, []string{"--debug"}, result.AdditionalParameters)
		assert.Equal(t, "DEBUG=1", *result.AdditionalEnv)
		assert.Equal(t, FilePath("/ref/path"), *result.ReferenceFolderPath)
		assert.Equal(t, "org1", *result.PreferredOrg)
		assert.Equal(t, "auto-org", *result.AutoDeterminedOrg)

		// Org-scope settings should be nil without resolver
		assert.Nil(t, result.EnabledSeverities)
		assert.Nil(t, result.RiskScoreThreshold)
		assert.Nil(t, result.ScanAutomatic)
	})

	t.Run("omits empty folder-scope settings", func(t *testing.T) {
		fc := &StoredFolderConfig{
			FolderPath: "/path/to/folder",
			// All other fields are empty/zero
		}

		result := fc.ToLspFolderConfig(nil)

		assert.Equal(t, FilePath("/path/to/folder"), result.FolderPath)
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

		fc := &StoredFolderConfig{
			FolderPath:   "/path/to/folder",
			PreferredOrg: "org1",
			OrgSetByUser: true,
		}
		configProvider := newMockConfigProvider(map[FilePath]*StoredFolderConfig{fc.FolderPath: fc})
		resolver := NewConfigResolver(nil, globalSettings, configProvider, &logger)

		result := fc.ToLspFolderConfig(resolver)

		assert.Equal(t, FilePath("/path/to/folder"), result.FolderPath)
		assert.NotNil(t, result.ScanAutomatic)
		assert.True(t, *result.ScanAutomatic)
		assert.NotNil(t, result.ScanNetNew)
		assert.True(t, *result.ScanNetNew)
		assert.NotNil(t, result.SnykCodeEnabled)
		assert.True(t, *result.SnykCodeEnabled)
		assert.NotNil(t, result.SnykOssEnabled)
		assert.True(t, *result.SnykOssEnabled)
		assert.NotNil(t, result.SnykIacEnabled)
		assert.False(t, *result.SnykIacEnabled)
	})
}
