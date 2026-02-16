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

package types_test

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
)

// setupMockConfigProvider creates a gomock MockConfigProvider with common default expectations.
// folderOrgs maps folder paths to their org IDs for FolderOrganization calls.
func setupMockConfigProvider(ctrl *gomock.Controller, folderOrgs map[types.FilePath]string) *mock_types.MockConfigProvider {
	mockCP := mock_types.NewMockConfigProvider(ctrl)
	mockCP.EXPECT().FolderOrganization(gomock.Any()).DoAndReturn(func(path types.FilePath) string {
		if org, ok := folderOrgs[path]; ok {
			return org
		}
		return ""
	}).AnyTimes()
	mockCP.EXPECT().FilterSeverity().Return(types.SeverityFilter{Critical: true, High: true, Medium: true, Low: true}).AnyTimes()
	mockCP.EXPECT().RiskScoreThreshold().Return(0).AnyTimes()
	mockCP.EXPECT().IssueViewOptions().Return(types.IssueViewOptions{OpenIssues: true, IgnoredIssues: true}).AnyTimes()
	mockCP.EXPECT().IsAutoScanEnabled().Return(true).AnyTimes()
	mockCP.EXPECT().IsDeltaFindingsEnabled().Return(false).AnyTimes()
	mockCP.EXPECT().IsSnykCodeEnabled().Return(true).AnyTimes()
	mockCP.EXPECT().IsSnykOssEnabled().Return(true).AnyTimes()
	mockCP.EXPECT().IsSnykIacEnabled().Return(true).AnyTimes()
	return mockCP
}

func TestConfigResolver_GetValue_MachineScope(t *testing.T) {
	logger := zerolog.Nop()
	globalSettings := &types.Settings{
		Endpoint: "https://api.snyk.io",
	}
	resolver := types.NewConfigResolver(nil, globalSettings, nil, &logger)

	t.Run("returns global value for machine-scoped setting", func(t *testing.T) {
		value, source := resolver.GetValue(types.SettingApiEndpoint, nil)
		assert.Equal(t, "https://api.snyk.io", value)
		assert.Equal(t, types.ConfigSourceGlobal, source)
	})

	t.Run("returns default source when global value is nil", func(t *testing.T) {
		value, source := resolver.GetValue(types.SettingCodeEndpoint, nil)
		assert.Nil(t, value)
		assert.Equal(t, types.ConfigSourceDefault, source)
	})

	t.Run("returns default source when global string value is empty", func(t *testing.T) {
		emptySettings := &types.Settings{
			ActivateSnykCode: "",
		}
		emptyResolver := types.NewConfigResolver(nil, emptySettings, nil, &logger)

		value, source := emptyResolver.GetValue(types.SettingSnykCodeEnabled, nil)
		assert.Nil(t, value)
		assert.Equal(t, types.ConfigSourceDefault, source, "empty string should return ConfigSourceDefault, not ConfigSourceGlobal")
	})

	t.Run("returns global source when global string value is explicitly set", func(t *testing.T) {
		explicitSettings := &types.Settings{
			ActivateSnykCode: "true",
		}
		explicitResolver := types.NewConfigResolver(nil, explicitSettings, nil, &logger)

		value, source := explicitResolver.GetValue(types.SettingSnykCodeEnabled, nil)
		assert.Equal(t, "true", value)
		assert.Equal(t, types.ConfigSourceGlobal, source)
	})
}

func TestConfigResolver_UsesReconciledGlobalValues(t *testing.T) {
	logger := zerolog.Nop()

	t.Run("SnykCode uses reconciled value from ConfigProvider when user set raw setting", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		settings := &types.Settings{
			ActivateSnykCode: "true",
		}
		mockCP := setupMockConfigProvider(ctrl, nil)
		resolver := types.NewConfigResolver(nil, settings, mockCP, &logger)

		result := resolver.IsSnykCodeEnabledForFolder(nil)
		assert.True(t, result)
	})

	t.Run("org-scope global fallback returns reconciled bool value not raw string", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		settings := &types.Settings{
			ActivateSnykCode:       "true",
			ActivateSnykOpenSource: "false",
			EnableDeltaFindings:    "true",
			ScanningMode:           "auto",
		}
		mockCP := setupMockConfigProvider(ctrl, nil)
		resolver := types.NewConfigResolver(nil, settings, mockCP, &logger)
		folderConfig := &types.FolderConfig{FolderPath: "/folder"}

		val, source := resolver.GetValue(types.SettingSnykCodeEnabled, folderConfig)
		assert.Equal(t, types.ConfigSourceGlobal, source)
		_, isBool := val.(bool)
		assert.True(t, isBool, "expected bool from reconciled ConfigProvider, got %T: %v", val, val)
		assert.Equal(t, true, val)

		val, source = resolver.GetValue(types.SettingSnykOssEnabled, folderConfig)
		assert.Equal(t, types.ConfigSourceGlobal, source)
		_, isBool = val.(bool)
		assert.True(t, isBool, "expected bool from reconciled ConfigProvider, got %T: %v", val, val)
		assert.Equal(t, true, val)

		val, source = resolver.GetValue(types.SettingScanNetNew, folderConfig)
		assert.Equal(t, types.ConfigSourceGlobal, source)
		_, isBool = val.(bool)
		assert.True(t, isBool, "expected bool from reconciled ConfigProvider, got %T: %v", val, val)
		assert.Equal(t, false, val)
	})

	t.Run("machine-scope global fallback returns reconciled value", func(t *testing.T) {
		settings := &types.Settings{
			CliPath: "/usr/local/bin/snyk",
		}
		resolver := types.NewConfigResolver(nil, settings, nil, &logger)

		val, source := resolver.GetValue(types.SettingCliPath, nil)
		assert.Equal(t, types.ConfigSourceGlobal, source)
		assert.Equal(t, "/usr/local/bin/snyk", val)
	})
}

func TestConfigResolver_GetValue_FolderScope(t *testing.T) {
	logger := zerolog.Nop()
	resolver := types.NewConfigResolver(nil, nil, nil, &logger)

	folderConfig := &types.FolderConfig{
		FolderPath:           "/path/to/folder",
		BaseBranch:           "main",
		ReferenceFolderPath:  "/path/to/reference",
		AdditionalParameters: []string{"--debug"},
	}

	t.Run("returns folder value for reference_branch", func(t *testing.T) {
		value, source := resolver.GetValue(types.SettingReferenceBranch, folderConfig)
		assert.Equal(t, "main", value)
		assert.Equal(t, types.ConfigSourceFolder, source)
	})

	t.Run("returns folder value for reference_folder", func(t *testing.T) {
		value, source := resolver.GetValue(types.SettingReferenceFolder, folderConfig)
		assert.Equal(t, "/path/to/reference", value)
		assert.Equal(t, types.ConfigSourceFolder, source)
	})

	t.Run("returns folder value for additional_parameters", func(t *testing.T) {
		value, source := resolver.GetValue(types.SettingAdditionalParameters, folderConfig)
		assert.Equal(t, []string{"--debug"}, value)
		assert.Equal(t, types.ConfigSourceFolder, source)
	})
}

func TestConfigResolver_GetValue_OrgScope_NoLDXSync(t *testing.T) {
	ctrl := gomock.NewController(t)
	logger := zerolog.Nop()
	globalSettings := &types.Settings{
		ActivateSnykCode: "true",
	}

	folderConfig := &types.FolderConfig{
		FolderPath:   "/path/to/folder",
		PreferredOrg: "org1",
		OrgSetByUser: true,
	}
	mockCP := setupMockConfigProvider(ctrl, map[types.FilePath]string{"/path/to/folder": "org1"})
	resolver := types.NewConfigResolver(nil, globalSettings, mockCP, &logger)

	t.Run("returns reconciled global value when no LDX-Sync cache", func(t *testing.T) {
		value, source := resolver.GetValue(types.SettingSnykCodeEnabled, folderConfig)
		assert.Equal(t, true, value)
		assert.Equal(t, types.ConfigSourceGlobal, source)
	})

	t.Run("returns user override when set and no LDX-Sync", func(t *testing.T) {
		folderConfig.SetUserOverride(types.SettingEnabledSeverities, []string{"critical", "high"})

		value, source := resolver.GetValue(types.SettingEnabledSeverities, folderConfig)
		assert.Equal(t, []string{"critical", "high"}, value)
		assert.Equal(t, types.ConfigSourceUserOverride, source)
	})
}

func TestConfigResolver_GetValue_OrgScope_WithLDXSync(t *testing.T) {
	ctrl := gomock.NewController(t)
	logger := zerolog.Nop()
	globalSettings := &types.Settings{}

	ldxCache := types.NewLDXSyncConfigCache()
	orgConfig := types.NewLDXSyncOrgConfig("org1")
	orgConfig.SetField(types.SettingEnabledSeverities, []string{"critical"}, false, false, "org")
	ldxCache.SetOrgConfig(orgConfig)

	folderConfig := &types.FolderConfig{
		FolderPath:   "/path/to/folder",
		PreferredOrg: "org1",
		OrgSetByUser: true,
	}
	mockCP := setupMockConfigProvider(ctrl, map[types.FilePath]string{"/path/to/folder": "org1"})
	resolver := types.NewConfigResolver(ldxCache, globalSettings, mockCP, &logger)

	t.Run("returns LDX-Sync value when no user override", func(t *testing.T) {
		value, source := resolver.GetValue(types.SettingEnabledSeverities, folderConfig)
		assert.Equal(t, []string{"critical"}, value)
		assert.Equal(t, types.ConfigSourceLDXSync, source)
	})

	t.Run("returns user override when set", func(t *testing.T) {
		folderConfig.SetUserOverride(types.SettingEnabledSeverities, []string{"critical", "high"})

		value, source := resolver.GetValue(types.SettingEnabledSeverities, folderConfig)
		assert.Equal(t, []string{"critical", "high"}, value)
		assert.Equal(t, types.ConfigSourceUserOverride, source)
	})
}

func TestConfigResolver_GetValue_OrgScope_Locked(t *testing.T) {
	ctrl := gomock.NewController(t)
	logger := zerolog.Nop()
	globalSettings := &types.Settings{}

	ldxCache := types.NewLDXSyncConfigCache()
	orgConfig := types.NewLDXSyncOrgConfig("org1")
	orgConfig.SetField(types.SettingEnabledSeverities, []string{"critical"}, true, false, "group")
	ldxCache.SetOrgConfig(orgConfig)

	folderConfig := &types.FolderConfig{
		FolderPath:   "/path/to/folder",
		PreferredOrg: "org1",
		OrgSetByUser: true,
	}
	mockCP := setupMockConfigProvider(ctrl, map[types.FilePath]string{"/path/to/folder": "org1"})
	resolver := types.NewConfigResolver(ldxCache, globalSettings, mockCP, &logger)

	t.Run("returns LDX-Sync locked value even when user override exists", func(t *testing.T) {
		folderConfig.SetUserOverride(types.SettingEnabledSeverities, []string{"critical", "high", "medium"})

		value, source := resolver.GetValue(types.SettingEnabledSeverities, folderConfig)
		assert.Equal(t, []string{"critical"}, value)
		assert.Equal(t, types.ConfigSourceLDXSyncLocked, source)
	})
}

func TestConfigResolver_GetValue_OrgScope_DifferentOrgs(t *testing.T) {
	ctrl := gomock.NewController(t)
	logger := zerolog.Nop()
	globalSettings := &types.Settings{}

	ldxCache := types.NewLDXSyncConfigCache()

	org1Config := types.NewLDXSyncOrgConfig("org1")
	org1Config.SetField(types.SettingEnabledSeverities, []string{"critical"}, false, false, "org")
	ldxCache.SetOrgConfig(org1Config)

	org2Config := types.NewLDXSyncOrgConfig("org2")
	org2Config.SetField(types.SettingEnabledSeverities, []string{"critical", "high"}, true, false, "group")
	ldxCache.SetOrgConfig(org2Config)

	folder1 := &types.FolderConfig{FolderPath: "/folder1", PreferredOrg: "org1", OrgSetByUser: true}
	folder2 := &types.FolderConfig{FolderPath: "/folder2", PreferredOrg: "org2", OrgSetByUser: true}
	mockCP := setupMockConfigProvider(ctrl, map[types.FilePath]string{"/folder1": "org1", "/folder2": "org2"})
	resolver := types.NewConfigResolver(ldxCache, globalSettings, mockCP, &logger)

	t.Run("uses correct org config based on folder", func(t *testing.T) {
		value1, source1 := resolver.GetValue(types.SettingEnabledSeverities, folder1)
		value2, source2 := resolver.GetValue(types.SettingEnabledSeverities, folder2)

		assert.Equal(t, []string{"critical"}, value1)
		assert.Equal(t, types.ConfigSourceLDXSync, source1)

		assert.Equal(t, []string{"critical", "high"}, value2)
		assert.Equal(t, types.ConfigSourceLDXSyncLocked, source2)
	})
}

func TestConfigResolver_TypedAccessors(t *testing.T) {
	logger := zerolog.Nop()
	globalSettings := &types.Settings{
		Endpoint:            "https://api.snyk.io",
		ActivateSnykCode:    "true",
		EnableDeltaFindings: "true",
	}

	riskScore := 500
	globalSettings.RiskScoreThreshold = &riskScore

	resolver := types.NewConfigResolver(nil, globalSettings, nil, &logger)

	t.Run("GetString", func(t *testing.T) {
		value := resolver.GetString(types.SettingApiEndpoint, nil)
		assert.Equal(t, "https://api.snyk.io", value)
	})

	t.Run("GetBool with string true", func(t *testing.T) {
		value := resolver.GetBool(types.SettingScanNetNew, nil)
		assert.True(t, value)
	})

	t.Run("GetInt", func(t *testing.T) {
		value := resolver.GetInt(types.SettingRiskScoreThreshold, nil)
		assert.Equal(t, 500, value)
	})

	t.Run("GetStringSlice", func(t *testing.T) {
		folderConfig := &types.FolderConfig{
			FolderPath:           "/path",
			AdditionalParameters: []string{"--debug", "--verbose"},
		}
		value := resolver.GetStringSlice(types.SettingAdditionalParameters, folderConfig)
		assert.Equal(t, []string{"--debug", "--verbose"}, value)
	})
}

func TestConfigResolver_IsLocked(t *testing.T) {
	ctrl := gomock.NewController(t)
	logger := zerolog.Nop()

	ldxCache := types.NewLDXSyncConfigCache()
	orgConfig := types.NewLDXSyncOrgConfig("org1")
	orgConfig.SetField(types.SettingEnabledSeverities, []string{"critical"}, true, false, "group")
	orgConfig.SetField(types.SettingSnykCodeEnabled, true, false, false, "org")
	ldxCache.SetOrgConfig(orgConfig)

	folderConfig := &types.FolderConfig{
		FolderPath:   "/path",
		PreferredOrg: "org1",
		OrgSetByUser: true,
	}
	mockCP := setupMockConfigProvider(ctrl, map[types.FilePath]string{"/path": "org1"})
	resolver := types.NewConfigResolver(ldxCache, nil, mockCP, &logger)

	t.Run("returns true for locked setting", func(t *testing.T) {
		assert.True(t, resolver.IsLocked(types.SettingEnabledSeverities, folderConfig))
	})

	t.Run("returns false for unlocked setting", func(t *testing.T) {
		assert.False(t, resolver.IsLocked(types.SettingSnykCodeEnabled, folderConfig))
	})

	t.Run("returns false for missing setting", func(t *testing.T) {
		assert.False(t, resolver.IsLocked(types.SettingRiskScoreThreshold, folderConfig))
	})

	t.Run("returns false for nil folder config", func(t *testing.T) {
		assert.False(t, resolver.IsLocked(types.SettingEnabledSeverities, nil))
	})
}

func TestConfigResolver_IsEnforced(t *testing.T) {
	ctrl := gomock.NewController(t)
	logger := zerolog.Nop()

	ldxCache := types.NewLDXSyncConfigCache()
	orgConfig := types.NewLDXSyncOrgConfig("org1")
	orgConfig.SetField(types.SettingEnabledSeverities, []string{"critical"}, false, true, "group")
	orgConfig.SetField(types.SettingSnykCodeEnabled, true, false, false, "org")
	ldxCache.SetOrgConfig(orgConfig)

	folderConfig := &types.FolderConfig{
		FolderPath:   "/path",
		PreferredOrg: "org1",
		OrgSetByUser: true,
	}
	mockCP := setupMockConfigProvider(ctrl, map[types.FilePath]string{"/path": "org1"})
	resolver := types.NewConfigResolver(ldxCache, nil, mockCP, &logger)

	t.Run("returns true for enforced setting", func(t *testing.T) {
		assert.True(t, resolver.IsEnforced(types.SettingEnabledSeverities, folderConfig))
	})

	t.Run("returns false for non-enforced setting", func(t *testing.T) {
		assert.False(t, resolver.IsEnforced(types.SettingSnykCodeEnabled, folderConfig))
	})
}

func TestConfigResolver_GetSource(t *testing.T) {
	logger := zerolog.Nop()
	globalSettings := &types.Settings{
		Endpoint: "https://api.snyk.io",
	}
	resolver := types.NewConfigResolver(nil, globalSettings, nil, &logger)

	source := resolver.GetSource(types.SettingApiEndpoint, nil)
	assert.Equal(t, types.ConfigSourceGlobal, source)
}

func TestStoredFolderConfig_UserOverrideMethods(t *testing.T) {
	t.Run("HasUserOverride returns false for nil config", func(t *testing.T) {
		var fc *types.FolderConfig
		assert.False(t, fc.HasUserOverride("test"))
	})

	t.Run("HasUserOverride returns false for nil map", func(t *testing.T) {
		fc := &types.FolderConfig{}
		assert.False(t, fc.HasUserOverride("test"))
	})

	t.Run("SetUserOverride creates map if nil", func(t *testing.T) {
		fc := &types.FolderConfig{}
		fc.SetUserOverride("test", "value")
		assert.NotNil(t, fc.UserOverrides)
		assert.Equal(t, "value", fc.UserOverrides["test"])
	})

	t.Run("GetUserOverride returns value and true when exists", func(t *testing.T) {
		fc := &types.FolderConfig{}
		fc.SetUserOverride("test", "value")

		val, exists := fc.GetUserOverride("test")
		assert.True(t, exists)
		assert.Equal(t, "value", val)
	})

	t.Run("GetUserOverride returns nil and false when not exists", func(t *testing.T) {
		fc := &types.FolderConfig{}

		val, exists := fc.GetUserOverride("test")
		assert.False(t, exists)
		assert.Nil(t, val)
	})

	t.Run("ResetToDefault removes override", func(t *testing.T) {
		fc := &types.FolderConfig{}
		fc.SetUserOverride("test", "value")
		assert.True(t, fc.HasUserOverride("test"))

		fc.ResetToDefault("test")
		assert.False(t, fc.HasUserOverride("test"))
	})

	t.Run("ResetToDefault does nothing for nil map", func(t *testing.T) {
		fc := &types.FolderConfig{}
		fc.ResetToDefault("test") // should not panic
	})
}

func TestStoredFolderConfig_Clone_WithUserOverrides(t *testing.T) {
	original := &types.FolderConfig{
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
	ctrl := gomock.NewController(t)
	logger := zerolog.Nop()
	globalSettings := &types.Settings{}

	ldxCache := types.NewLDXSyncConfigCache()
	orgConfig := types.NewLDXSyncOrgConfig("org1")
	orgConfig.SetField(types.SettingEnabledSeverities, []string{"critical"}, false, false, "tenant")
	orgConfig.SetField(types.SettingSnykCodeEnabled, true, true, false, "group")
	ldxCache.SetOrgConfig(orgConfig)

	folderConfig := &types.FolderConfig{
		FolderPath:   "/path/to/folder",
		PreferredOrg: "org1",
		OrgSetByUser: true,
	}
	mockCP := setupMockConfigProvider(ctrl, map[types.FilePath]string{"/path/to/folder": "org1"})
	resolver := types.NewConfigResolver(ldxCache, globalSettings, mockCP, &logger)

	t.Run("includes OriginScope for LDX-Sync value", func(t *testing.T) {
		effectiveValue := resolver.GetEffectiveValue(types.SettingEnabledSeverities, folderConfig)

		assert.Equal(t, []string{"critical"}, effectiveValue.Value)
		assert.Equal(t, "ldx-sync", effectiveValue.Source)
		assert.Equal(t, "tenant", effectiveValue.OriginScope)
	})

	t.Run("includes OriginScope for locked LDX-Sync value", func(t *testing.T) {
		effectiveValue := resolver.GetEffectiveValue(types.SettingSnykCodeEnabled, folderConfig)

		assert.Equal(t, true, effectiveValue.Value)
		assert.Equal(t, "ldx-sync-locked", effectiveValue.Source)
		assert.Equal(t, "group", effectiveValue.OriginScope)
	})

	t.Run("OriginScope is empty for user override", func(t *testing.T) {
		folderConfigWithOverride := &types.FolderConfig{
			FolderPath:   "/path/to/folder",
			PreferredOrg: "org1",
			OrgSetByUser: true,
		}
		folderConfigWithOverride.SetUserOverride(types.SettingEnabledSeverities, []string{"high"})

		effectiveValue := resolver.GetEffectiveValue(types.SettingEnabledSeverities, folderConfigWithOverride)

		assert.Equal(t, []string{"high"}, effectiveValue.Value)
		assert.Equal(t, "user-override", effectiveValue.Source)
		assert.Equal(t, "", effectiveValue.OriginScope)
	})

	t.Run("OriginScope is empty for global fallback", func(t *testing.T) {
		ctrlInner := gomock.NewController(t)
		folderConfigNoOrg := &types.FolderConfig{
			FolderPath: "/path/to/folder",
		}
		mockCPNoOrg := setupMockConfigProvider(ctrlInner, nil)
		resolverNoLdx := types.NewConfigResolver(nil, globalSettings, mockCPNoOrg, &logger)

		effectiveValue := resolverNoLdx.GetEffectiveValue(types.SettingEnabledSeverities, folderConfigNoOrg)

		assert.Equal(t, "", effectiveValue.OriginScope)
	})
}

func TestConfigResolver_EnforcedSource_OrgScope(t *testing.T) {
	ctrl := gomock.NewController(t)
	logger := zerolog.Nop()
	globalSettings := &types.Settings{}

	ldxCache := types.NewLDXSyncConfigCache()
	orgConfig := types.NewLDXSyncOrgConfig("org1")
	orgConfig.SetField(types.SettingEnabledSeverities, []string{"critical"}, false, true, "group")
	orgConfig.SetField(types.SettingSnykCodeEnabled, true, false, false, "org")
	ldxCache.SetOrgConfig(orgConfig)

	folderConfig := &types.FolderConfig{
		FolderPath:   "/path/to/folder",
		PreferredOrg: "org1",
		OrgSetByUser: true,
	}
	mockCP := setupMockConfigProvider(ctrl, map[types.FilePath]string{"/path/to/folder": "org1"})
	resolver := types.NewConfigResolver(ldxCache, globalSettings, mockCP, &logger)

	t.Run("enforced field without user override returns ldx-sync-enforced source", func(t *testing.T) {
		value, source := resolver.GetValue(types.SettingEnabledSeverities, folderConfig)
		assert.Equal(t, []string{"critical"}, value)
		assert.Equal(t, types.ConfigSourceLDXSyncEnforced, source)
	})

	t.Run("non-enforced field returns ldx-sync source", func(t *testing.T) {
		value, source := resolver.GetValue(types.SettingSnykCodeEnabled, folderConfig)
		assert.Equal(t, true, value)
		assert.Equal(t, types.ConfigSourceLDXSync, source)
	})

	t.Run("user override wins over enforced field", func(t *testing.T) {
		folderConfigWithOverride := &types.FolderConfig{
			FolderPath:   "/path/to/folder",
			PreferredOrg: "org1",
			OrgSetByUser: true,
		}
		folderConfigWithOverride.SetUserOverride(types.SettingEnabledSeverities, []string{"high"})

		value, source := resolver.GetValue(types.SettingEnabledSeverities, folderConfigWithOverride)
		assert.Equal(t, []string{"high"}, value)
		assert.Equal(t, types.ConfigSourceUserOverride, source)
	})
}

func TestConfigResolver_EnforcedSource_MachineScope(t *testing.T) {
	logger := zerolog.Nop()
	globalSettings := &types.Settings{}

	machineConfig := map[string]*types.LDXSyncField{
		types.SettingApiEndpoint: {Value: "https://enforced.snyk.io", IsLocked: false, IsEnforced: true},
		types.SettingCliPath:     {Value: "/usr/bin/snyk", IsLocked: false, IsEnforced: false},
	}
	resolver := types.NewConfigResolver(nil, globalSettings, nil, &logger)
	resolver.SetLDXSyncMachineConfig(machineConfig)

	t.Run("enforced machine field without global setting returns ldx-sync-enforced source", func(t *testing.T) {
		value, source := resolver.GetValue(types.SettingApiEndpoint, nil)
		assert.Equal(t, "https://enforced.snyk.io", value)
		assert.Equal(t, types.ConfigSourceLDXSyncEnforced, source)
	})

	t.Run("non-enforced machine field returns ldx-sync source", func(t *testing.T) {
		value, source := resolver.GetValue(types.SettingCliPath, nil)
		assert.Equal(t, "/usr/bin/snyk", value)
		assert.Equal(t, types.ConfigSourceLDXSync, source)
	})

	t.Run("global setting wins over enforced machine field", func(t *testing.T) {
		globalSettingsWithEndpoint := &types.Settings{
			Endpoint: "https://user.snyk.io",
		}
		resolverWithGlobal := types.NewConfigResolver(nil, globalSettingsWithEndpoint, nil, &logger)
		resolverWithGlobal.SetLDXSyncMachineConfig(machineConfig)

		value, source := resolverWithGlobal.GetValue(types.SettingApiEndpoint, nil)
		assert.Equal(t, "https://user.snyk.io", value)
		assert.Equal(t, types.ConfigSourceGlobal, source)
	})
}

func TestConfigResolver_GetEffectiveValue_EnforcedIncludesOriginScope(t *testing.T) {
	ctrl := gomock.NewController(t)
	logger := zerolog.Nop()
	globalSettings := &types.Settings{}

	ldxCache := types.NewLDXSyncConfigCache()
	orgConfig := types.NewLDXSyncOrgConfig("org1")
	orgConfig.SetField(types.SettingEnabledSeverities, []string{"critical"}, false, true, "group")
	ldxCache.SetOrgConfig(orgConfig)

	folderConfig := &types.FolderConfig{
		FolderPath:   "/path/to/folder",
		PreferredOrg: "org1",
		OrgSetByUser: true,
	}
	mockCP := setupMockConfigProvider(ctrl, map[types.FilePath]string{"/path/to/folder": "org1"})
	resolver := types.NewConfigResolver(ldxCache, globalSettings, mockCP, &logger)

	effectiveValue := resolver.GetEffectiveValue(types.SettingEnabledSeverities, folderConfig)

	assert.Equal(t, []string{"critical"}, effectiveValue.Value)
	assert.Equal(t, "ldx-sync-enforced", effectiveValue.Source)
	assert.Equal(t, "group", effectiveValue.OriginScope)
}

func TestStoredFolderConfig_ApplyLspUpdate(t *testing.T) {
	t.Run("returns false for nil receiver", func(t *testing.T) {
		var fc *types.FolderConfig
		update := &types.LspFolderConfig{FolderPath: "/path"}
		assert.False(t, fc.ApplyLspUpdate(update))
	})

	t.Run("returns false for nil update", func(t *testing.T) {
		fc := &types.FolderConfig{FolderPath: "/path"}
		assert.False(t, fc.ApplyLspUpdate(nil))
	})

	t.Run("applies folder-scope updates", func(t *testing.T) {
		fc := &types.FolderConfig{
			FolderPath: "/path/to/folder",
			BaseBranch: "main",
		}

		newBranch := "develop"
		newEnv := "DEBUG=1"
		update := &types.LspFolderConfig{
			FolderPath:    "/path/to/folder",
			BaseBranch:    &newBranch,
			AdditionalEnv: &newEnv,
		}

		changed := fc.ApplyLspUpdate(update)

		assert.True(t, changed)
		assert.Equal(t, "develop", fc.BaseBranch)
		assert.Equal(t, "DEBUG=1", fc.AdditionalEnv)
	})

	t.Run("does not change fields when nil in update", func(t *testing.T) {
		fc := &types.FolderConfig{
			FolderPath: "/path/to/folder",
			BaseBranch: "main",
		}

		update := &types.LspFolderConfig{
			FolderPath: "/path/to/folder",
			// BaseBranch is nil - should not change
		}

		changed := fc.ApplyLspUpdate(update)

		assert.False(t, changed)
		assert.Equal(t, "main", fc.BaseBranch)
	})

	t.Run("applies org-scope updates as user overrides", func(t *testing.T) {
		fc := &types.FolderConfig{
			FolderPath: "/path/to/folder",
		}

		update := &types.LspFolderConfig{
			FolderPath:    "/path/to/folder",
			ScanAutomatic: types.NullableField[bool]{Value: true, Present: true},
			ScanNetNew:    types.NullableField[bool]{Value: false, Present: true},
		}

		changed := fc.ApplyLspUpdate(update)

		assert.True(t, changed)
		assert.True(t, fc.HasUserOverride(types.SettingScanAutomatic))
		assert.True(t, fc.HasUserOverride(types.SettingScanNetNew))
		scanAutoVal, _ := fc.GetUserOverride(types.SettingScanAutomatic)
		scanNetNewVal, _ := fc.GetUserOverride(types.SettingScanNetNew)
		assert.Equal(t, true, scanAutoVal)
		assert.Equal(t, false, scanNetNewVal)
	})

	t.Run("sets OrgSetByUser when PreferredOrg is updated", func(t *testing.T) {
		fc := &types.FolderConfig{
			FolderPath:   "/path/to/folder",
			OrgSetByUser: false,
		}

		newOrg := "my-org"
		update := &types.LspFolderConfig{
			FolderPath:   "/path/to/folder",
			PreferredOrg: &newOrg,
		}

		changed := fc.ApplyLspUpdate(update)

		assert.True(t, changed)
		assert.Equal(t, "my-org", fc.PreferredOrg)
		assert.True(t, fc.OrgSetByUser)
	})

	t.Run("clears user overrides via explicit null", func(t *testing.T) {
		fc := &types.FolderConfig{
			FolderPath: "/path/to/folder",
		}
		// Set some user overrides first
		fc.SetUserOverride(types.SettingScanAutomatic, true)
		fc.SetUserOverride(types.SettingScanNetNew, false)
		fc.SetUserOverride(types.SettingSnykCodeEnabled, true)

		// Clear only some of them using explicit null
		update := &types.LspFolderConfig{
			FolderPath:      "/path/to/folder",
			ScanAutomatic:   types.NullableField[bool]{Present: true, Null: true}, // explicit null = clear
			SnykCodeEnabled: types.NullableField[bool]{Present: true, Null: true}, // explicit null = clear
			// ScanNetNew is omitted (Present: false) = don't change
		}

		changed := fc.ApplyLspUpdate(update)

		assert.True(t, changed)
		assert.False(t, fc.HasUserOverride(types.SettingScanAutomatic), "ScanAutomatic should be cleared")
		assert.False(t, fc.HasUserOverride(types.SettingSnykCodeEnabled), "SnykCodeEnabled should be cleared")
		assert.True(t, fc.HasUserOverride(types.SettingScanNetNew), "ScanNetNew should remain")
	})

	t.Run("null clears and value sets in same update", func(t *testing.T) {
		fc := &types.FolderConfig{
			FolderPath: "/path/to/folder",
		}
		fc.SetUserOverride(types.SettingScanAutomatic, true)

		// Clear one setting (null) and set another (value)
		update := &types.LspFolderConfig{
			FolderPath:    "/path/to/folder",
			ScanAutomatic: types.NullableField[bool]{Present: true, Null: true},  // null = clear
			ScanNetNew:    types.NullableField[bool]{Value: true, Present: true}, // value = set
		}

		changed := fc.ApplyLspUpdate(update)

		assert.True(t, changed)
		assert.False(t, fc.HasUserOverride(types.SettingScanAutomatic), "ScanAutomatic should be cleared")
		assert.True(t, fc.HasUserOverride(types.SettingScanNetNew), "ScanNetNew should be set")
	})

	t.Run("omitted fields are not changed", func(t *testing.T) {
		fc := &types.FolderConfig{
			FolderPath: "/path/to/folder",
		}
		fc.SetUserOverride(types.SettingScanAutomatic, true)
		fc.SetUserOverride(types.SettingScanNetNew, false)

		// Update with all fields omitted (Present: false)
		update := &types.LspFolderConfig{
			FolderPath: "/path/to/folder",
			// All NullableField fields are zero value (Present: false) = omitted
		}

		changed := fc.ApplyLspUpdate(update)

		assert.False(t, changed, "No changes should be made when all fields are omitted")
		assert.True(t, fc.HasUserOverride(types.SettingScanAutomatic), "ScanAutomatic should remain")
		assert.True(t, fc.HasUserOverride(types.SettingScanNetNew), "ScanNetNew should remain")
	})

	t.Run("applies cwe/cve/rule filter overrides", func(t *testing.T) {
		fc := &types.FolderConfig{FolderPath: "/path/to/folder"}

		update := &types.LspFolderConfig{
			FolderPath: "/path/to/folder",
			CweIds:     types.NullableField[[]string]{Value: []string{"CWE-79", "CWE-89"}, Present: true},
			CveIds:     types.NullableField[[]string]{Value: []string{"CVE-2023-1234"}, Present: true},
			RuleIds:    types.NullableField[[]string]{Value: []string{"SNYK-JS-001"}, Present: true},
		}

		changed := fc.ApplyLspUpdate(update)

		assert.True(t, changed)
		assert.True(t, fc.HasUserOverride(types.SettingCweIds))
		assert.True(t, fc.HasUserOverride(types.SettingCveIds))
		assert.True(t, fc.HasUserOverride(types.SettingRuleIds))
		cweVal, _ := fc.GetUserOverride(types.SettingCweIds)
		assert.Equal(t, []string{"CWE-79", "CWE-89"}, cweVal)
	})

	t.Run("clears cwe/cve/rule filter overrides via null", func(t *testing.T) {
		fc := &types.FolderConfig{FolderPath: "/path/to/folder"}
		fc.SetUserOverride(types.SettingCweIds, []string{"CWE-79"})
		fc.SetUserOverride(types.SettingCveIds, []string{"CVE-2023-1234"})

		update := &types.LspFolderConfig{
			FolderPath: "/path/to/folder",
			CweIds:     types.NullableField[[]string]{Present: true, Null: true},
			CveIds:     types.NullableField[[]string]{Present: true, Null: true},
		}

		changed := fc.ApplyLspUpdate(update)

		assert.True(t, changed)
		assert.False(t, fc.HasUserOverride(types.SettingCweIds), "CweIds should be cleared")
		assert.False(t, fc.HasUserOverride(types.SettingCveIds), "CveIds should be cleared")
	})
}

func TestStoredFolderConfig_ToLspFolderConfig(t *testing.T) {
	t.Run("returns nil for nil config", func(t *testing.T) {
		var fc *types.FolderConfig
		result := fc.ToLspFolderConfig(nil)
		assert.Nil(t, result)
	})

	t.Run("copies folder-scope settings without resolver", func(t *testing.T) {
		fc := &types.FolderConfig{
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

		assert.Equal(t, types.FilePath("/path/to/folder"), result.FolderPath)
		assert.Equal(t, "main", *result.BaseBranch)
		assert.Equal(t, []string{"main", "develop"}, result.LocalBranches)
		assert.Equal(t, []string{"--debug"}, result.AdditionalParameters)
		assert.Equal(t, "DEBUG=1", *result.AdditionalEnv)
		assert.Equal(t, types.FilePath("/ref/path"), *result.ReferenceFolderPath)
		assert.Equal(t, "org1", *result.PreferredOrg)
		assert.Equal(t, "auto-org", *result.AutoDeterminedOrg)

		// Org-scope settings should be omitted (not present) without resolver
		assert.True(t, result.EnabledSeverities.IsOmitted(), "EnabledSeverities should be omitted without resolver")
		assert.True(t, result.RiskScoreThreshold.IsOmitted(), "RiskScoreThreshold should be omitted without resolver")
		assert.True(t, result.ScanAutomatic.IsOmitted(), "ScanAutomatic should be omitted without resolver")
	})

	t.Run("omits empty folder-scope settings", func(t *testing.T) {
		fc := &types.FolderConfig{
			FolderPath: "/path/to/folder",
			// All other fields are empty/zero
		}

		result := fc.ToLspFolderConfig(nil)

		assert.Equal(t, types.FilePath("/path/to/folder"), result.FolderPath)
		assert.Nil(t, result.BaseBranch)
		assert.Nil(t, result.LocalBranches)
		assert.Nil(t, result.AdditionalParameters)
		assert.Nil(t, result.AdditionalEnv)
		assert.Nil(t, result.ReferenceFolderPath)
		assert.Nil(t, result.PreferredOrg)
		assert.Nil(t, result.AutoDeterminedOrg)
	})

	t.Run("populates org-scope settings with resolver", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		logger := zerolog.Nop()
		globalSettings := &types.Settings{
			ActivateSnykCode:       "true",
			ActivateSnykOpenSource: "true",
			ActivateSnykIac:        "false",
			ScanningMode:           "true",
			EnableDeltaFindings:    "true",
		}

		fc := &types.FolderConfig{
			FolderPath:   "/path/to/folder",
			PreferredOrg: "org1",
			OrgSetByUser: true,
		}
		mockCP := mock_types.NewMockConfigProvider(ctrl)
		mockCP.EXPECT().FolderOrganization(gomock.Any()).Return("org1").AnyTimes()
		mockCP.EXPECT().FilterSeverity().Return(types.SeverityFilter{Critical: true, High: true, Medium: true, Low: true}).AnyTimes()
		mockCP.EXPECT().RiskScoreThreshold().Return(0).AnyTimes()
		mockCP.EXPECT().IssueViewOptions().Return(types.IssueViewOptions{OpenIssues: true, IgnoredIssues: true}).AnyTimes()
		mockCP.EXPECT().IsAutoScanEnabled().Return(true).AnyTimes()
		mockCP.EXPECT().IsDeltaFindingsEnabled().Return(true).AnyTimes()
		mockCP.EXPECT().IsSnykCodeEnabled().Return(true).AnyTimes()
		mockCP.EXPECT().IsSnykOssEnabled().Return(true).AnyTimes()
		mockCP.EXPECT().IsSnykIacEnabled().Return(false).AnyTimes()
		resolver := types.NewConfigResolver(nil, globalSettings, mockCP, &logger)

		result := fc.ToLspFolderConfig(resolver)

		assert.Equal(t, types.FilePath("/path/to/folder"), result.FolderPath)
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
