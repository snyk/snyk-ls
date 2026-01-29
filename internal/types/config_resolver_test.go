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
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

// testOrgResolver is a simple org resolver for tests.
// It looks up the folder config and returns PreferredOrg (if OrgSetByUser) or AutoDeterminedOrg.
func testOrgResolver(folderConfigs map[FilePath]*FolderConfig) OrgResolverFunc {
	return func(folderPath FilePath) string {
		fc, ok := folderConfigs[folderPath]
		if !ok || fc == nil {
			return ""
		}
		if fc.OrgSetByUser {
			return fc.PreferredOrg
		}
		return fc.AutoDeterminedOrg
	}
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
}

func TestConfigResolver_GetValue_FolderScope(t *testing.T) {
	logger := zerolog.Nop()
	resolver := NewConfigResolver(nil, nil, nil, &logger)

	folderConfig := &FolderConfig{
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

	folderConfig := &FolderConfig{
		FolderPath:   "/path/to/folder",
		PreferredOrg: "org1",
		OrgSetByUser: true,
	}
	orgResolver := testOrgResolver(map[FilePath]*FolderConfig{folderConfig.FolderPath: folderConfig})
	resolver := NewConfigResolver(nil, globalSettings, orgResolver, &logger)

	t.Run("returns global value when no LDX-Sync cache", func(t *testing.T) {
		value, source := resolver.GetValue(SettingEnabledProducts, folderConfig)
		products := value.([]string)
		assert.Contains(t, products, "code")
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
		FolderPath:   "/path/to/folder",
		PreferredOrg: "org1",
		OrgSetByUser: true,
	}
	orgResolver := testOrgResolver(map[FilePath]*FolderConfig{folderConfig.FolderPath: folderConfig})
	resolver := NewConfigResolver(ldxCache, globalSettings, orgResolver, &logger)

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
		FolderPath:   "/path/to/folder",
		PreferredOrg: "org1",
		OrgSetByUser: true,
	}
	orgResolver := testOrgResolver(map[FilePath]*FolderConfig{folderConfig.FolderPath: folderConfig})
	resolver := NewConfigResolver(ldxCache, globalSettings, orgResolver, &logger)

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

	folder1 := &FolderConfig{FolderPath: "/folder1", PreferredOrg: "org1", OrgSetByUser: true}
	folder2 := &FolderConfig{FolderPath: "/folder2", PreferredOrg: "org2", OrgSetByUser: true}
	orgResolver := testOrgResolver(map[FilePath]*FolderConfig{folder1.FolderPath: folder1, folder2.FolderPath: folder2})
	resolver := NewConfigResolver(ldxCache, globalSettings, orgResolver, &logger)

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
	orgConfig.SetField(SettingEnabledProducts, []string{"code"}, false, false, "org")
	ldxCache.SetOrgConfig(orgConfig)

	folderConfig := &FolderConfig{
		FolderPath:   "/path",
		PreferredOrg: "org1",
		OrgSetByUser: true,
	}
	orgResolver := testOrgResolver(map[FilePath]*FolderConfig{folderConfig.FolderPath: folderConfig})
	resolver := NewConfigResolver(ldxCache, nil, orgResolver, &logger)

	t.Run("returns true for locked setting", func(t *testing.T) {
		assert.True(t, resolver.IsLocked(SettingEnabledSeverities, folderConfig))
	})

	t.Run("returns false for unlocked setting", func(t *testing.T) {
		assert.False(t, resolver.IsLocked(SettingEnabledProducts, folderConfig))
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
	orgConfig.SetField(SettingEnabledProducts, []string{"code"}, false, false, "org")
	ldxCache.SetOrgConfig(orgConfig)

	folderConfig := &FolderConfig{
		FolderPath:   "/path",
		PreferredOrg: "org1",
		OrgSetByUser: true,
	}
	orgResolver := testOrgResolver(map[FilePath]*FolderConfig{folderConfig.FolderPath: folderConfig})
	resolver := NewConfigResolver(ldxCache, nil, orgResolver, &logger)

	t.Run("returns true for enforced setting", func(t *testing.T) {
		assert.True(t, resolver.IsEnforced(SettingEnabledSeverities, folderConfig))
	})

	t.Run("returns false for non-enforced setting", func(t *testing.T) {
		assert.False(t, resolver.IsEnforced(SettingEnabledProducts, folderConfig))
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

func TestFolderConfig_UserOverrideMethods(t *testing.T) {
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

func TestFolderConfig_Clone_WithUserOverrides(t *testing.T) {
	original := &FolderConfig{
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
	orgConfig.SetField(SettingEnabledProducts, []string{"code"}, true, false, "group")
	ldxCache.SetOrgConfig(orgConfig)

	folderConfig := &FolderConfig{
		FolderPath:   "/path/to/folder",
		PreferredOrg: "org1",
		OrgSetByUser: true,
	}
	orgResolver := testOrgResolver(map[FilePath]*FolderConfig{folderConfig.FolderPath: folderConfig})
	resolver := NewConfigResolver(ldxCache, globalSettings, orgResolver, &logger)

	t.Run("includes OriginScope for LDX-Sync value", func(t *testing.T) {
		effectiveValue := resolver.GetEffectiveValue(SettingEnabledSeverities, folderConfig)

		assert.Equal(t, []string{"critical"}, effectiveValue.Value)
		assert.Equal(t, "ldx-sync", effectiveValue.Source)
		assert.Equal(t, "tenant", effectiveValue.OriginScope)
	})

	t.Run("includes OriginScope for locked LDX-Sync value", func(t *testing.T) {
		effectiveValue := resolver.GetEffectiveValue(SettingEnabledProducts, folderConfig)

		assert.Equal(t, []string{"code"}, effectiveValue.Value)
		assert.Equal(t, "ldx-sync-locked", effectiveValue.Source)
		assert.Equal(t, "group", effectiveValue.OriginScope)
	})

	t.Run("OriginScope is empty for user override", func(t *testing.T) {
		folderConfigWithOverride := &FolderConfig{
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
		folderConfigNoOrg := &FolderConfig{
			FolderPath: "/path/to/folder",
		}
		orgResolverNoOrg := testOrgResolver(map[FilePath]*FolderConfig{folderConfigNoOrg.FolderPath: folderConfigNoOrg})
		resolverNoLdx := NewConfigResolver(nil, globalSettings, orgResolverNoOrg, &logger)

		effectiveValue := resolverNoLdx.GetEffectiveValue(SettingEnabledSeverities, folderConfigNoOrg)

		assert.Equal(t, "", effectiveValue.OriginScope)
	})
}
