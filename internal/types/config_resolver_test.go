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
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
)

// setupMockConfigProvider creates a gomock MockConfigProvider with common default expectations.
func setupMockConfigProvider(ctrl *gomock.Controller) *mock_types.MockConfigProvider {
	mockCP := mock_types.NewMockConfigProvider(ctrl)
	mockCP.EXPECT().FilterSeverity().Return(types.SeverityFilter{Critical: true, High: true, Medium: true, Low: true}).AnyTimes()
	mockCP.EXPECT().RiskScoreThreshold().Return(0).AnyTimes()
	mockCP.EXPECT().IssueViewOptions().Return(types.IssueViewOptions{OpenIssues: true, IgnoredIssues: true}).AnyTimes()
	mockCP.EXPECT().IsAutoScanEnabled().Return(true).AnyTimes()
	mockCP.EXPECT().IsDeltaFindingsEnabled().Return(false).AnyTimes()
	mockCP.EXPECT().IsSnykCodeEnabled().Return(true).AnyTimes()
	mockCP.EXPECT().IsSnykOssEnabled().Return(true).AnyTimes()
	mockCP.EXPECT().IsSnykIacEnabled().Return(true).AnyTimes()
	mockCP.EXPECT().IsSnykSecretsEnabled().Return(true).AnyTimes()
	return mockCP
}

// newResolverWithGAF creates a ConfigResolver with GAF resolver wired (required for tests after 2.4.4).
// Pass mockCP when globalSettings contains settings that need reconciliation (e.g. ActivateSnykCode).
func newResolverWithGAF(t *testing.T, cache *types.LDXSyncConfigCache, globalSettings *types.Settings, mockCP *mock_types.MockConfigProvider) (*types.ConfigResolver, configuration.Configuration) {
	t.Helper()
	conf := configuration.NewWithOpts()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	require.NoError(t, conf.AddFlagSet(fs))
	gafResolver := configuration.NewConfigResolver(conf)
	logger := zerolog.Nop()
	resolver := types.NewConfigResolver(cache, globalSettings, mockCP, &logger)
	resolver.SetGAFResolver(gafResolver, conf)
	if globalSettings != nil {
		resolver.SetGlobalSettings(globalSettings)
		resolver.SyncGlobalSettingsToConfiguration()
	}
	return resolver, conf
}

func TestConfigResolver_GetValue_MachineScope(t *testing.T) {
	globalSettings := &types.Settings{
		Endpoint: "https://api.snyk.io",
	}
	resolver, _ := newResolverWithGAF(t, nil, globalSettings, nil)

	t.Run("returns global value for machine-scoped setting", func(t *testing.T) {
		value, source := resolver.GetValue(types.SettingApiEndpoint, nil)
		assert.Equal(t, "https://api.snyk.io", value)
		assert.Equal(t, types.ConfigSourceGlobal, source)
	})

	t.Run("returns default source when global value is nil", func(t *testing.T) {
		value, source := resolver.GetValue(types.SettingCodeEndpoint, nil)
		assert.Equal(t, types.ConfigSourceDefault, source)
		assert.True(t, value == nil || value == "", "default value should be nil or empty")
	})

	t.Run("returns default source when global string value is empty", func(t *testing.T) {
		emptySettings := &types.Settings{
			ActivateSnykCode: "",
		}
		emptyResolver, _ := newResolverWithGAF(t, nil, emptySettings, nil)

		value, source := emptyResolver.GetValue(types.SettingSnykCodeEnabled, nil)
		assert.Equal(t, types.ConfigSourceDefault, source, "empty string should return ConfigSourceDefault, not ConfigSourceGlobal")
		assert.True(t, value == nil || value == false || value == "", "default value when unset")
	})

	t.Run("returns global source when global string value is explicitly set", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		explicitSettings := &types.Settings{
			ActivateSnykCode: "true",
		}
		mockCP := setupMockConfigProvider(ctrl)
		explicitResolver, _ := newResolverWithGAF(t, nil, explicitSettings, mockCP)

		value, source := explicitResolver.GetValue(types.SettingSnykCodeEnabled, nil)
		assert.Equal(t, true, value)
		assert.Equal(t, types.ConfigSourceGlobal, source)
	})
}

func TestConfigResolver_UsesReconciledGlobalValues(t *testing.T) {
	t.Run("SnykCode uses reconciled value from ConfigProvider when user set raw setting", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		settings := &types.Settings{
			ActivateSnykCode: "true",
		}
		mockCP := setupMockConfigProvider(ctrl)
		resolver, _ := newResolverWithGAF(t, nil, settings, mockCP)

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
		mockCP := setupMockConfigProvider(ctrl)
		resolver, _ := newResolverWithGAF(t, nil, settings, mockCP)
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
		resolver, _ := newResolverWithGAF(t, nil, settings, nil)

		val, source := resolver.GetValue(types.SettingCliPath, nil)
		assert.Equal(t, types.ConfigSourceGlobal, source)
		assert.Equal(t, "/usr/local/bin/snyk", val)
	})
}

func TestConfigResolver_IsSnykSecretsEnabledForFolder(t *testing.T) {
	t.Run("returns false when no setting and default fallback", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockCP := mock_types.NewMockConfigProvider(ctrl)
		mockCP.EXPECT().IsSnykSecretsEnabled().Return(false).AnyTimes()
		mockCP.EXPECT().FilterSeverity().Return(types.SeverityFilter{}).AnyTimes()
		mockCP.EXPECT().RiskScoreThreshold().Return(0).AnyTimes()
		mockCP.EXPECT().IssueViewOptions().Return(types.IssueViewOptions{}).AnyTimes()
		mockCP.EXPECT().IsAutoScanEnabled().Return(true).AnyTimes()
		mockCP.EXPECT().IsDeltaFindingsEnabled().Return(false).AnyTimes()
		mockCP.EXPECT().IsSnykCodeEnabled().Return(true).AnyTimes()
		mockCP.EXPECT().IsSnykOssEnabled().Return(true).AnyTimes()
		mockCP.EXPECT().IsSnykIacEnabled().Return(true).AnyTimes()
		resolver, _ := newResolverWithGAF(t, nil, &types.Settings{}, mockCP)
		assert.False(t, resolver.IsSnykSecretsEnabledForFolder(nil))
	})

	t.Run("uses reconciled value from ConfigProvider when user set global setting", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		settings := &types.Settings{ActivateSnykSecrets: "true"}
		mockCP := setupMockConfigProvider(ctrl)
		resolver, _ := newResolverWithGAF(t, nil, settings, mockCP)
		assert.True(t, resolver.IsSnykSecretsEnabledForFolder(nil))
	})

	t.Run("respects user override over global", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		settings := &types.Settings{ActivateSnykSecrets: "true"}
		mockCP := setupMockConfigProvider(ctrl)
		resolver, conf := newResolverWithGAF(t, nil, settings, mockCP)
		folderConfig := &types.FolderConfig{FolderPath: "/folder"}
		folderConfig.SetConf(conf)
		folderConfig.SyncToConfiguration()
		folderConfig.SetUserOverride(types.SettingSnykSecretsEnabled, false)
		assert.False(t, resolver.IsSnykSecretsEnabledForFolder(folderConfig))
	})

	t.Run("respects LDX-Sync locked value over user override", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		ldxCache := types.NewLDXSyncConfigCache()
		orgConfig := types.NewLDXSyncOrgConfig("org1")
		orgConfig.SetField(types.SettingSnykSecretsEnabled, true, true, "group")
		ldxCache.SetOrgConfig(orgConfig)
		settings := &types.Settings{}
		mockCP := setupMockConfigProvider(ctrl)
		resolver, conf := newResolverWithGAF(t, ldxCache, settings, mockCP)
		folderConfig := &types.FolderConfig{FolderPath: "/folder", PreferredOrg: "org1", OrgSetByUser: true}
		folderConfig.SetConf(conf)
		folderConfig.SyncToConfiguration()
		types.WriteOrgConfigToConfiguration(conf, orgConfig)
		folderConfig.SetUserOverride(types.SettingSnykSecretsEnabled, false)
		assert.True(t, resolver.IsSnykSecretsEnabledForFolder(folderConfig))
	})

	t.Run("falls back to global when no override and no LDX-Sync", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		settings := &types.Settings{ActivateSnykSecrets: "false"}
		mockCP := mock_types.NewMockConfigProvider(ctrl)
		mockCP.EXPECT().FilterSeverity().Return(types.SeverityFilter{}).AnyTimes()
		mockCP.EXPECT().RiskScoreThreshold().Return(0).AnyTimes()
		mockCP.EXPECT().IssueViewOptions().Return(types.IssueViewOptions{}).AnyTimes()
		mockCP.EXPECT().IsAutoScanEnabled().Return(true).AnyTimes()
		mockCP.EXPECT().IsDeltaFindingsEnabled().Return(false).AnyTimes()
		mockCP.EXPECT().IsSnykCodeEnabled().Return(true).AnyTimes()
		mockCP.EXPECT().IsSnykOssEnabled().Return(true).AnyTimes()
		mockCP.EXPECT().IsSnykIacEnabled().Return(true).AnyTimes()
		mockCP.EXPECT().IsSnykSecretsEnabled().Return(false).AnyTimes()
		resolver, _ := newResolverWithGAF(t, nil, settings, mockCP)
		folderConfig := &types.FolderConfig{FolderPath: "/folder"}
		assert.False(t, resolver.IsSnykSecretsEnabledForFolder(folderConfig))
	})
}

func TestConfigResolver_GetValue_FolderScope(t *testing.T) {
	resolver, conf := newResolverWithGAF(t, nil, nil, nil)

	folderConfig := &types.FolderConfig{
		FolderPath:           "/path/to/folder",
		BaseBranch:           "main",
		ReferenceFolderPath:  "/path/to/reference",
		AdditionalParameters: []string{"--debug"},
	}
	folderConfig.SetConf(conf)
	folderConfig.SyncToConfiguration()

	t.Run("returns folder value for reference_branch", func(t *testing.T) {
		// ReferenceBranch and BaseBranch share the same value; set both for GAF
		conf.Set(configuration.UserFolderKey(string(types.PathKey(folderConfig.GetFolderPath())), types.SettingReferenceBranch), &configuration.LocalConfigField{Value: "main", Changed: true})
		value, source := resolver.GetValue(types.SettingReferenceBranch, folderConfig)
		assert.Equal(t, "main", value)
		assert.Equal(t, types.ConfigSourceFolder, source)
	})

	t.Run("returns folder value for reference_folder", func(t *testing.T) {
		value, source := resolver.GetValue(types.SettingReferenceFolder, folderConfig)
		assert.Equal(t, types.ConfigSourceFolder, source)
		assert.True(t, value == "/path/to/reference" || value == types.FilePath("/path/to/reference"))
	})

	t.Run("returns folder value for additional_parameters", func(t *testing.T) {
		value, source := resolver.GetValue(types.SettingAdditionalParameters, folderConfig)
		assert.Equal(t, []string{"--debug"}, value)
		assert.Equal(t, types.ConfigSourceFolder, source)
	})

	t.Run("returns folder value for base_branch", func(t *testing.T) {
		value, source := resolver.GetValue(types.SettingBaseBranch, folderConfig)
		assert.Equal(t, "main", value)
		assert.Equal(t, types.ConfigSourceFolder, source)
	})

	t.Run("returns folder value for local_branches", func(t *testing.T) {
		fc := &types.FolderConfig{
			FolderPath:    "/path/to/folder",
			LocalBranches: []string{"main", "develop"},
		}
		fc.SetConf(conf)
		fc.SyncToConfiguration()
		value, source := resolver.GetValue(types.SettingLocalBranches, fc)
		assert.Equal(t, []string{"main", "develop"}, value)
		assert.Equal(t, types.ConfigSourceFolder, source)
	})

	t.Run("returns folder value for preferred_org", func(t *testing.T) {
		fc := &types.FolderConfig{
			FolderPath:   "/path/to/folder",
			PreferredOrg: "my-org",
			OrgSetByUser: true,
		}
		fc.SetConf(conf)
		fc.SyncToConfiguration()
		value, source := resolver.GetValue(types.SettingPreferredOrg, fc)
		assert.Equal(t, "my-org", value)
		assert.Equal(t, types.ConfigSourceFolder, source)
	})

	t.Run("returns folder value for auto_determined_org", func(t *testing.T) {
		fc := &types.FolderConfig{
			FolderPath:        "/path/to/folder",
			AutoDeterminedOrg: "auto-org",
		}
		fc.SetConf(conf)
		fc.SyncToConfiguration()
		value, source := resolver.GetValue(types.SettingAutoDeterminedOrg, fc)
		assert.Equal(t, "auto-org", value)
		assert.Equal(t, types.ConfigSourceFolder, source)
	})

	t.Run("returns folder value for org_set_by_user", func(t *testing.T) {
		fc := &types.FolderConfig{
			FolderPath:   "/path/to/folder",
			OrgSetByUser: true,
		}
		fc.SetConf(conf)
		fc.SyncToConfiguration()
		value, source := resolver.GetValue(types.SettingOrgSetByUser, fc)
		assert.Equal(t, true, value)
		assert.Equal(t, types.ConfigSourceFolder, source)
	})

	t.Run("returns folder value for scan_command_config", func(t *testing.T) {
		scanConfig := map[product.Product]types.ScanCommandConfig{
			product.ProductCode: {PreScanCommand: "/bin/ls"},
		}
		fc := &types.FolderConfig{
			FolderPath:        "/path/to/folder",
			ScanCommandConfig: scanConfig,
		}
		fc.SetConf(conf)
		fc.SyncToConfiguration()
		value, source := resolver.GetValue(types.SettingScanCommandConfig, fc)
		assert.Equal(t, scanConfig, value)
		assert.Equal(t, types.ConfigSourceFolder, source)
	})
}

func TestConfigResolver_GetValue_OrgScope_NoLDXSync(t *testing.T) {
	ctrl := gomock.NewController(t)
	globalSettings := &types.Settings{
		ActivateSnykCode: "true",
	}

	folderConfig := &types.FolderConfig{
		FolderPath:   "/path/to/folder",
		PreferredOrg: "org1",
		OrgSetByUser: true,
	}
	mockCP := setupMockConfigProvider(ctrl)
	resolver, conf := newResolverWithGAF(t, nil, globalSettings, mockCP)
	folderConfig.SetConf(conf)

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
	globalSettings := &types.Settings{}

	ldxCache := types.NewLDXSyncConfigCache()
	orgConfig := types.NewLDXSyncOrgConfig("org1")
	orgConfig.SetField(types.SettingEnabledSeverities, []string{"critical"}, false, "org")
	ldxCache.SetOrgConfig(orgConfig)

	folderConfig := &types.FolderConfig{
		FolderPath:   "/path/to/folder",
		PreferredOrg: "org1",
		OrgSetByUser: true,
	}
	mockCP := setupMockConfigProvider(ctrl)
	resolver, conf := newResolverWithGAF(t, ldxCache, globalSettings, mockCP)
	folderConfig.SetConf(conf)
	folderConfig.SyncToConfiguration()
	types.WriteOrgConfigToConfiguration(conf, orgConfig)

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

func TestConfigResolver_GetValue_OrgScope_GlobalOverridesLDXSync(t *testing.T) {
	ctrl := gomock.NewController(t)

	t.Run("global setting overrides non-locked LDX-Sync value", func(t *testing.T) {
		ldxCache := types.NewLDXSyncConfigCache()
		orgConfig := types.NewLDXSyncOrgConfig("org1")
		orgConfig.SetField(types.SettingSnykCodeEnabled, true, false, "org")
		ldxCache.SetOrgConfig(orgConfig)

		globalSettings := &types.Settings{
			ActivateSnykCode: "false",
		}

		folderConfig := &types.FolderConfig{
			FolderPath:   "/path/to/folder",
			PreferredOrg: "org1",
			OrgSetByUser: true,
		}
		innerCtrl := gomock.NewController(t)
		mockCP := mock_types.NewMockConfigProvider(innerCtrl)
		mockCP.EXPECT().IsSnykCodeEnabled().Return(false).AnyTimes()
		mockCP.EXPECT().IsSnykOssEnabled().Return(true).AnyTimes()
		mockCP.EXPECT().IsSnykIacEnabled().Return(true).AnyTimes()
		mockCP.EXPECT().IsSnykSecretsEnabled().Return(true).AnyTimes()
		mockCP.EXPECT().FilterSeverity().Return(types.SeverityFilter{}).AnyTimes()
		mockCP.EXPECT().RiskScoreThreshold().Return(0).AnyTimes()
		mockCP.EXPECT().IssueViewOptions().Return(types.IssueViewOptions{}).AnyTimes()
		mockCP.EXPECT().IsAutoScanEnabled().Return(true).AnyTimes()
		mockCP.EXPECT().IsDeltaFindingsEnabled().Return(false).AnyTimes()
		resolver, conf := newResolverWithGAF(t, ldxCache, globalSettings, mockCP)
		folderConfig.SetConf(conf)
		folderConfig.SyncToConfiguration()
		types.WriteOrgConfigToConfiguration(conf, orgConfig)

		value, source := resolver.GetValue(types.SettingSnykCodeEnabled, folderConfig)
		assert.Equal(t, false, value)
		assert.Equal(t, types.ConfigSourceGlobal, source)
	})

	t.Run("global setting does NOT override locked LDX-Sync value", func(t *testing.T) {
		ldxCache := types.NewLDXSyncConfigCache()
		orgConfig := types.NewLDXSyncOrgConfig("org1")
		orgConfig.SetField(types.SettingSnykCodeEnabled, true, true, "group")
		ldxCache.SetOrgConfig(orgConfig)

		globalSettings := &types.Settings{
			ActivateSnykCode: "false",
		}

		folderConfig := &types.FolderConfig{
			FolderPath:   "/path/to/folder",
			PreferredOrg: "org1",
			OrgSetByUser: true,
		}
		mockCP := setupMockConfigProvider(ctrl)
		resolver, conf := newResolverWithGAF(t, ldxCache, globalSettings, mockCP)
		folderConfig.SetConf(conf)
		folderConfig.SyncToConfiguration()
		types.WriteOrgConfigToConfiguration(conf, orgConfig)

		value, source := resolver.GetValue(types.SettingSnykCodeEnabled, folderConfig)
		assert.Equal(t, true, value)
		assert.Equal(t, types.ConfigSourceLDXSyncLocked, source)
	})

	t.Run("user override still wins over global when LDX-Sync present", func(t *testing.T) {
		ldxCache := types.NewLDXSyncConfigCache()
		orgConfig := types.NewLDXSyncOrgConfig("org1")
		orgConfig.SetField(types.SettingSnykCodeEnabled, true, false, "org")
		ldxCache.SetOrgConfig(orgConfig)

		globalSettings := &types.Settings{
			ActivateSnykCode: "false",
		}

		folderConfig := &types.FolderConfig{
			FolderPath:   "/path/to/folder",
			PreferredOrg: "org1",
			OrgSetByUser: true,
		}
		folderConfig.SetUserOverride(types.SettingSnykCodeEnabled, true)

		mockCP := setupMockConfigProvider(ctrl)
		resolver, conf := newResolverWithGAF(t, ldxCache, globalSettings, mockCP)
		folderConfig.SetConf(conf)
		folderConfig.SyncToConfiguration()
		types.WriteOrgConfigToConfiguration(conf, orgConfig)

		value, source := resolver.GetValue(types.SettingSnykCodeEnabled, folderConfig)
		assert.Equal(t, true, value)
		assert.Equal(t, types.ConfigSourceUserOverride, source)
	})

	t.Run("LDX-Sync default value used when no global and no override", func(t *testing.T) {
		ldxCache := types.NewLDXSyncConfigCache()
		orgConfig := types.NewLDXSyncOrgConfig("org1")
		orgConfig.SetField(types.SettingSnykCodeEnabled, true, false, "org")
		ldxCache.SetOrgConfig(orgConfig)

		globalSettings := &types.Settings{}

		folderConfig := &types.FolderConfig{
			FolderPath:   "/path/to/folder",
			PreferredOrg: "org1",
			OrgSetByUser: true,
		}
		mockCP := setupMockConfigProvider(ctrl)
		resolver, conf := newResolverWithGAF(t, ldxCache, globalSettings, mockCP)
		folderConfig.SetConf(conf)
		folderConfig.SyncToConfiguration()
		types.WriteOrgConfigToConfiguration(conf, orgConfig)

		value, source := resolver.GetValue(types.SettingSnykCodeEnabled, folderConfig)
		assert.Equal(t, true, value)
		assert.Equal(t, types.ConfigSourceLDXSync, source)
	})
}

func TestConfigResolver_GetValue_OrgScope_Locked(t *testing.T) {
	ctrl := gomock.NewController(t)
	globalSettings := &types.Settings{}

	ldxCache := types.NewLDXSyncConfigCache()
	orgConfig := types.NewLDXSyncOrgConfig("org1")
	orgConfig.SetField(types.SettingEnabledSeverities, []string{"critical"}, true, "group")
	ldxCache.SetOrgConfig(orgConfig)

	folderConfig := &types.FolderConfig{
		FolderPath:   "/path/to/folder",
		PreferredOrg: "org1",
		OrgSetByUser: true,
	}
	mockCP := setupMockConfigProvider(ctrl)
	resolver, conf := newResolverWithGAF(t, ldxCache, globalSettings, mockCP)
	folderConfig.SetConf(conf)
	folderConfig.SyncToConfiguration()
	types.WriteOrgConfigToConfiguration(conf, orgConfig)

	t.Run("returns LDX-Sync locked value even when user override exists", func(t *testing.T) {
		folderConfig.SetUserOverride(types.SettingEnabledSeverities, []string{"critical", "high", "medium"})

		value, source := resolver.GetValue(types.SettingEnabledSeverities, folderConfig)
		assert.Equal(t, []string{"critical"}, value)
		assert.Equal(t, types.ConfigSourceLDXSyncLocked, source)
	})
}

func TestConfigResolver_GetValue_OrgScope_DifferentOrgs(t *testing.T) {
	ctrl := gomock.NewController(t)
	globalSettings := &types.Settings{}

	ldxCache := types.NewLDXSyncConfigCache()

	org1Config := types.NewLDXSyncOrgConfig("org1")
	org1Config.SetField(types.SettingEnabledSeverities, []string{"critical"}, false, "org")
	ldxCache.SetOrgConfig(org1Config)

	org2Config := types.NewLDXSyncOrgConfig("org2")
	org2Config.SetField(types.SettingEnabledSeverities, []string{"critical", "high"}, true, "group")
	ldxCache.SetOrgConfig(org2Config)

	folder1 := &types.FolderConfig{FolderPath: "/folder1", PreferredOrg: "org1", OrgSetByUser: true}
	folder2 := &types.FolderConfig{FolderPath: "/folder2", PreferredOrg: "org2", OrgSetByUser: true}
	mockCP := setupMockConfigProvider(ctrl)
	resolver, conf := newResolverWithGAF(t, ldxCache, globalSettings, mockCP)
	folder1.SetConf(conf)
	folder2.SetConf(conf)
	folder1.SyncToConfiguration()
	folder2.SyncToConfiguration()
	types.WriteOrgConfigToConfiguration(conf, org1Config)
	types.WriteOrgConfigToConfiguration(conf, org2Config)

	t.Run("uses correct org config based on folder", func(t *testing.T) {
		value1, source1 := resolver.GetValue(types.SettingEnabledSeverities, folder1)
		value2, source2 := resolver.GetValue(types.SettingEnabledSeverities, folder2)

		assert.Equal(t, []string{"critical"}, value1)
		assert.Equal(t, types.ConfigSourceLDXSync, source1)

		assert.Equal(t, []string{"critical", "high"}, value2)
		assert.Equal(t, types.ConfigSourceLDXSyncLocked, source2)
	})
}

func TestConfigResolver_EffectiveOrgResolution(t *testing.T) {
	t.Run("uses PreferredOrg when OrgSetByUser is true", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		ldxCache := types.NewLDXSyncConfigCache()
		orgConfig := types.NewLDXSyncOrgConfig("user-org")
		orgConfig.SetField(types.SettingEnabledSeverities, []string{"critical"}, false, "org")
		ldxCache.SetOrgConfig(orgConfig)

		folderConfig := &types.FolderConfig{
			FolderPath:   "/path",
			PreferredOrg: "user-org",
			OrgSetByUser: true,
		}
		mockCP := setupMockConfigProvider(ctrl)
		resolver, conf := newResolverWithGAF(t, ldxCache, &types.Settings{}, mockCP)
		folderConfig.SetConf(conf)
		folderConfig.SyncToConfiguration()
		types.WriteOrgConfigToConfiguration(conf, orgConfig)

		value, source := resolver.GetValue(types.SettingEnabledSeverities, folderConfig)
		assert.Equal(t, []string{"critical"}, value)
		assert.Equal(t, types.ConfigSourceLDXSync, source)
	})

	t.Run("falls back to global org when OrgSetByUser is true but PreferredOrg is empty", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		ldxCache := types.NewLDXSyncConfigCache()
		globalOrg := "global-org"
		orgConfig := types.NewLDXSyncOrgConfig(globalOrg)
		orgConfig.SetField(types.SettingEnabledSeverities, []string{"high"}, false, "org")
		ldxCache.SetOrgConfig(orgConfig)

		folderConfig := &types.FolderConfig{
			FolderPath:   "/path",
			PreferredOrg: "",
			OrgSetByUser: true,
		}
		mockCP := setupMockConfigProvider(ctrl)
		resolver, conf := newResolverWithGAF(t, ldxCache, &types.Settings{Organization: &globalOrg}, mockCP)
		folderConfig.SetConf(conf)
		folderConfig.SyncToConfiguration()
		types.WriteOrgConfigToConfiguration(conf, orgConfig)

		value, source := resolver.GetValue(types.SettingEnabledSeverities, folderConfig)
		assert.Equal(t, []string{"high"}, value)
		assert.Equal(t, types.ConfigSourceLDXSync, source)
	})

	t.Run("uses AutoDeterminedOrg when OrgSetByUser is false", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		ldxCache := types.NewLDXSyncConfigCache()
		orgConfig := types.NewLDXSyncOrgConfig("auto-org")
		orgConfig.SetField(types.SettingEnabledSeverities, []string{"medium"}, false, "org")
		ldxCache.SetOrgConfig(orgConfig)

		folderConfig := &types.FolderConfig{
			FolderPath:        "/path",
			AutoDeterminedOrg: "auto-org",
			OrgSetByUser:      false,
		}
		mockCP := setupMockConfigProvider(ctrl)
		resolver, conf := newResolverWithGAF(t, ldxCache, &types.Settings{}, mockCP)
		folderConfig.SetConf(conf)
		folderConfig.SyncToConfiguration()
		types.WriteOrgConfigToConfiguration(conf, orgConfig)

		value, source := resolver.GetValue(types.SettingEnabledSeverities, folderConfig)
		assert.Equal(t, []string{"medium"}, value)
		assert.Equal(t, types.ConfigSourceLDXSync, source)
	})

	t.Run("falls back to global org when AutoDeterminedOrg is empty and OrgSetByUser is false", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		ldxCache := types.NewLDXSyncConfigCache()
		globalOrg := "global-org"
		orgConfig := types.NewLDXSyncOrgConfig(globalOrg)
		orgConfig.SetField(types.SettingEnabledSeverities, []string{"low"}, false, "org")
		ldxCache.SetOrgConfig(orgConfig)

		folderConfig := &types.FolderConfig{
			FolderPath:        "/path",
			AutoDeterminedOrg: "",
			OrgSetByUser:      false,
		}
		mockCP := setupMockConfigProvider(ctrl)
		resolver, conf := newResolverWithGAF(t, ldxCache, &types.Settings{Organization: &globalOrg}, mockCP)
		folderConfig.SetConf(conf)
		folderConfig.SyncToConfiguration()
		types.WriteOrgConfigToConfiguration(conf, orgConfig)

		value, source := resolver.GetValue(types.SettingEnabledSeverities, folderConfig)
		assert.Equal(t, []string{"low"}, value)
		assert.Equal(t, types.ConfigSourceLDXSync, source)
	})

	t.Run("returns default when folderConfig is nil", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		ldxCache := types.NewLDXSyncConfigCache()
		orgConfig := types.NewLDXSyncOrgConfig("org1")
		orgConfig.SetField(types.SettingEnabledSeverities, []string{"critical"}, false, "org")
		ldxCache.SetOrgConfig(orgConfig)

		mockCP := setupMockConfigProvider(ctrl)
		resolver, _ := newResolverWithGAF(t, ldxCache, &types.Settings{}, mockCP)

		_, source := resolver.GetValue(types.SettingEnabledSeverities, nil)
		assert.Equal(t, types.ConfigSourceDefault, source)
	})

	t.Run("returns default when no org can be determined and no global setting", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		ldxCache := types.NewLDXSyncConfigCache()
		orgConfig := types.NewLDXSyncOrgConfig("some-org")
		orgConfig.SetField(types.SettingEnabledSeverities, []string{"critical"}, false, "org")
		ldxCache.SetOrgConfig(orgConfig)

		folderConfig := &types.FolderConfig{
			FolderPath:        "/path",
			AutoDeterminedOrg: "",
			OrgSetByUser:      false,
		}
		mockCP := setupMockConfigProvider(ctrl)
		resolver, conf := newResolverWithGAF(t, ldxCache, &types.Settings{}, mockCP)
		folderConfig.SetConf(conf)
		folderConfig.SyncToConfiguration()
		types.WriteOrgConfigToConfiguration(conf, orgConfig)

		_, source := resolver.GetValue(types.SettingEnabledSeverities, folderConfig)
		assert.Equal(t, types.ConfigSourceDefault, source)
	})
}

func TestConfigResolver_TypedAccessors(t *testing.T) {
	ctrl := gomock.NewController(t)
	globalSettings := &types.Settings{
		Endpoint:            "https://api.snyk.io",
		ActivateSnykCode:    "true",
		EnableDeltaFindings: "true",
	}
	riskScore := 500
	globalSettings.RiskScoreThreshold = &riskScore

	mockCP := mock_types.NewMockConfigProvider(ctrl)
	mockCP.EXPECT().FilterSeverity().Return(types.SeverityFilter{}).AnyTimes()
	mockCP.EXPECT().RiskScoreThreshold().Return(500).AnyTimes()
	mockCP.EXPECT().IssueViewOptions().Return(types.IssueViewOptions{}).AnyTimes()
	mockCP.EXPECT().IsAutoScanEnabled().Return(true).AnyTimes()
	mockCP.EXPECT().IsDeltaFindingsEnabled().Return(true).AnyTimes()
	mockCP.EXPECT().IsSnykCodeEnabled().Return(true).AnyTimes()
	mockCP.EXPECT().IsSnykOssEnabled().Return(true).AnyTimes()
	mockCP.EXPECT().IsSnykIacEnabled().Return(true).AnyTimes()
	mockCP.EXPECT().IsSnykSecretsEnabled().Return(true).AnyTimes()
	resolver, conf := newResolverWithGAF(t, nil, globalSettings, mockCP)

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
		folderConfig.SetConf(conf)
		folderConfig.SyncToConfiguration()
		value := resolver.GetStringSlice(types.SettingAdditionalParameters, folderConfig)
		assert.Equal(t, []string{"--debug", "--verbose"}, value)
	})
}

func TestConfigResolver_IsLocked(t *testing.T) {
	ctrl := gomock.NewController(t)

	ldxCache := types.NewLDXSyncConfigCache()
	orgConfig := types.NewLDXSyncOrgConfig("org1")
	orgConfig.SetField(types.SettingEnabledSeverities, []string{"critical"}, true, "group")
	orgConfig.SetField(types.SettingSnykCodeEnabled, true, false, "org")
	ldxCache.SetOrgConfig(orgConfig)

	folderConfig := &types.FolderConfig{
		FolderPath:   "/path",
		PreferredOrg: "org1",
		OrgSetByUser: true,
	}
	mockCP := setupMockConfigProvider(ctrl)
	resolver, conf := newResolverWithGAF(t, ldxCache, nil, mockCP)
	folderConfig.SetConf(conf)
	folderConfig.SyncToConfiguration()
	types.WriteOrgConfigToConfiguration(conf, orgConfig)

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

func TestConfigResolver_GetSource(t *testing.T) {
	globalSettings := &types.Settings{
		Endpoint: "https://api.snyk.io",
	}
	resolver, _ := newResolverWithGAF(t, nil, globalSettings, nil)

	source := resolver.GetSource(types.SettingApiEndpoint, nil)
	assert.Equal(t, types.ConfigSourceGlobal, source)
}

func TestFolderConfig_UserOverrideMethods(t *testing.T) {
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

func TestFolderConfig_Clone_WithUserOverrides(t *testing.T) {
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
	globalSettings := &types.Settings{}

	ldxCache := types.NewLDXSyncConfigCache()
	orgConfig := types.NewLDXSyncOrgConfig("org1")
	orgConfig.SetField(types.SettingEnabledSeverities, []string{"critical"}, false, "tenant")
	orgConfig.SetField(types.SettingSnykCodeEnabled, true, true, "group")
	ldxCache.SetOrgConfig(orgConfig)

	folderConfig := &types.FolderConfig{
		FolderPath:   "/path/to/folder",
		PreferredOrg: "org1",
		OrgSetByUser: true,
	}
	mockCP := setupMockConfigProvider(ctrl)
	resolver, conf := newResolverWithGAF(t, ldxCache, globalSettings, mockCP)
	folderConfig.SetConf(conf)
	folderConfig.SyncToConfiguration()
	types.WriteOrgConfigToConfiguration(conf, orgConfig)

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
		folderConfigWithOverride.SetConf(conf)
		folderConfigWithOverride.SyncToConfiguration()
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
		mockCPNoOrg := setupMockConfigProvider(ctrlInner)
		resolverNoLdx, _ := newResolverWithGAF(t, nil, globalSettings, mockCPNoOrg)

		effectiveValue := resolverNoLdx.GetEffectiveValue(types.SettingEnabledSeverities, folderConfigNoOrg)

		assert.Equal(t, "", effectiveValue.OriginScope)
	})
}

func TestFolderConfig_ApplyLspUpdate(t *testing.T) {
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

		update := &types.LspFolderConfig{
			FolderPath: "/path/to/folder",
			Settings: map[string]*types.ConfigSetting{
				types.SettingBaseBranch:            {Value: "develop"},
				types.SettingAdditionalEnvironment: {Value: "DEBUG=1"},
			},
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
			Settings:   nil,
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
			FolderPath: "/path/to/folder",
			Settings: map[string]*types.ConfigSetting{
				types.SettingScanAutomatic: {Value: true, Changed: true},
				types.SettingScanNetNew:    {Value: false, Changed: true},
			},
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

		update := &types.LspFolderConfig{
			FolderPath: "/path/to/folder",
			Settings: map[string]*types.ConfigSetting{
				types.SettingPreferredOrg: {Value: "my-org"},
			},
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
		fc.SetUserOverride(types.SettingScanAutomatic, true)
		fc.SetUserOverride(types.SettingScanNetNew, false)
		fc.SetUserOverride(types.SettingSnykCodeEnabled, true)

		update := &types.LspFolderConfig{
			FolderPath: "/path/to/folder",
			Settings: map[string]*types.ConfigSetting{
				types.SettingScanAutomatic:   {Value: nil, Changed: true},
				types.SettingSnykCodeEnabled: {Value: nil, Changed: true},
			},
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

		update := &types.LspFolderConfig{
			FolderPath: "/path/to/folder",
			Settings: map[string]*types.ConfigSetting{
				types.SettingScanAutomatic: {Value: nil, Changed: true},
				types.SettingScanNetNew:    {Value: true, Changed: true},
			},
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

		update := &types.LspFolderConfig{
			FolderPath: "/path/to/folder",
			Settings:   map[string]*types.ConfigSetting{},
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
			Settings: map[string]*types.ConfigSetting{
				types.SettingCweIds:  {Value: []string{"CWE-79", "CWE-89"}, Changed: true},
				types.SettingCveIds:  {Value: []string{"CVE-2023-1234"}, Changed: true},
				types.SettingRuleIds: {Value: []string{"SNYK-JS-001"}, Changed: true},
			},
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
			Settings: map[string]*types.ConfigSetting{
				types.SettingCweIds: {Value: nil, Changed: true},
				types.SettingCveIds: {Value: nil, Changed: true},
			},
		}

		changed := fc.ApplyLspUpdate(update)

		assert.True(t, changed)
		assert.False(t, fc.HasUserOverride(types.SettingCweIds), "CweIds should be cleared")
		assert.False(t, fc.HasUserOverride(types.SettingCveIds), "CveIds should be cleared")
	})
}

func TestFolderConfig_ToLspFolderConfig(t *testing.T) {
	t.Run("returns nil for nil config", func(t *testing.T) {
		var fc *types.FolderConfig
		result := fc.ToLspFolderConfig(nil)
		assert.Nil(t, result)
	})

	t.Run("copies folder-scope settings via resolver and GAF", func(t *testing.T) {
		conf := configuration.NewWithOpts()
		fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
		types.RegisterAllConfigurations(fs)
		require.NoError(t, conf.AddFlagSet(fs))

		gafResolver := configuration.NewConfigResolver(conf)
		cache := types.NewLDXSyncConfigCache()
		logger := zerolog.Nop()
		resolver := types.NewConfigResolver(cache, nil, nil, &logger)
		resolver.SetGAFResolver(gafResolver, conf)

		fc := &types.FolderConfig{
			FolderPath:           "/path/to/folder",
			BaseBranch:           "main",
			LocalBranches:        []string{"main", "develop"},
			AdditionalParameters: []string{"--debug"},
			AdditionalEnv:        "DEBUG=1",
			ReferenceFolderPath:  "/ref/path",
			PreferredOrg:         "org1",
			OrgSetByUser:         true, // required for SyncToConfiguration to write PreferredOrg to UserFolderKey
			AutoDeterminedOrg:    "auto-org",
		}
		fc.SetConf(conf)
		fc.SyncToConfiguration()

		result := fc.ToLspFolderConfig(resolver)

		assert.Equal(t, types.FilePath("/path/to/folder"), result.FolderPath)
		require.NotNil(t, result.Settings[types.SettingBaseBranch])
		assert.Equal(t, "main", result.Settings[types.SettingBaseBranch].Value)
		require.NotNil(t, result.Settings[types.SettingLocalBranches])
		assert.Equal(t, []string{"main", "develop"}, result.Settings[types.SettingLocalBranches].Value)
		require.NotNil(t, result.Settings[types.SettingAdditionalParameters])
		assert.Equal(t, []string{"--debug"}, result.Settings[types.SettingAdditionalParameters].Value)
		require.NotNil(t, result.Settings[types.SettingAdditionalEnvironment])
		assert.Equal(t, "DEBUG=1", result.Settings[types.SettingAdditionalEnvironment].Value)
		require.NotNil(t, result.Settings[types.SettingReferenceFolder])
		assert.Equal(t, types.FilePath("/ref/path"), result.Settings[types.SettingReferenceFolder].Value)
		require.NotNil(t, result.Settings[types.SettingPreferredOrg])
		assert.Equal(t, "org1", result.Settings[types.SettingPreferredOrg].Value)
		require.NotNil(t, result.Settings[types.SettingAutoDeterminedOrg])
		assert.Equal(t, "auto-org", result.Settings[types.SettingAutoDeterminedOrg].Value)
		assert.Nil(t, result.Settings[types.SettingEnabledSeverities])
		assert.Nil(t, result.Settings[types.SettingRiskScoreThreshold])
		assert.Nil(t, result.Settings[types.SettingScanAutomatic])
	})

	t.Run("omits empty folder-scope settings", func(t *testing.T) {
		fc := &types.FolderConfig{
			FolderPath: "/path/to/folder",
		}

		result := fc.ToLspFolderConfig(nil)

		assert.Equal(t, types.FilePath("/path/to/folder"), result.FolderPath)
		assert.Nil(t, result.Settings[types.SettingBaseBranch])
		assert.Nil(t, result.Settings[types.SettingLocalBranches])
		assert.Nil(t, result.Settings[types.SettingPreferredOrg])
		assert.Nil(t, result.Settings[types.SettingAutoDeterminedOrg])
	})

	t.Run("populates org-scope settings with resolver", func(t *testing.T) {
		ctrl := gomock.NewController(t)
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
		mockCP.EXPECT().FilterSeverity().Return(types.SeverityFilter{Critical: true, High: true, Medium: true, Low: true}).AnyTimes()
		mockCP.EXPECT().RiskScoreThreshold().Return(0).AnyTimes()
		mockCP.EXPECT().IssueViewOptions().Return(types.IssueViewOptions{OpenIssues: true, IgnoredIssues: true}).AnyTimes()
		mockCP.EXPECT().IsAutoScanEnabled().Return(true).AnyTimes()
		mockCP.EXPECT().IsDeltaFindingsEnabled().Return(true).AnyTimes()
		mockCP.EXPECT().IsSnykCodeEnabled().Return(true).AnyTimes()
		mockCP.EXPECT().IsSnykOssEnabled().Return(true).AnyTimes()
		mockCP.EXPECT().IsSnykIacEnabled().Return(false).AnyTimes()
		resolver, conf := newResolverWithGAF(t, nil, globalSettings, mockCP)
		fc.SetConf(conf)
		fc.SyncToConfiguration()

		result := fc.ToLspFolderConfig(resolver)

		assert.Equal(t, types.FilePath("/path/to/folder"), result.FolderPath)
		require.NotNil(t, result.Settings[types.SettingScanAutomatic])
		assert.False(t, result.Settings[types.SettingScanAutomatic].Changed, "Changed should not be set for LS→IDE")
		assert.True(t, result.Settings[types.SettingScanAutomatic].Value.(bool))
		require.NotNil(t, result.Settings[types.SettingScanNetNew])
		assert.False(t, result.Settings[types.SettingScanNetNew].Changed, "Changed should not be set for LS→IDE")
		assert.True(t, result.Settings[types.SettingScanNetNew].Value.(bool))
		require.NotNil(t, result.Settings[types.SettingSnykCodeEnabled])
		assert.True(t, result.Settings[types.SettingSnykCodeEnabled].Value.(bool))
		require.NotNil(t, result.Settings[types.SettingSnykOssEnabled])
		assert.True(t, result.Settings[types.SettingSnykOssEnabled].Value.(bool))
		require.NotNil(t, result.Settings[types.SettingSnykIacEnabled])
		assert.False(t, result.Settings[types.SettingSnykIacEnabled].Value.(bool))
	})

	t.Run("populates Source OriginScope IsLocked for org-scope settings from LDX-Sync", func(t *testing.T) {
		cache := types.NewLDXSyncConfigCache()
		orgConfig := types.NewLDXSyncOrgConfig("org1")
		orgConfig.SetField(types.SettingSnykCodeEnabled, false, true, "organization")
		cache.SetOrgConfig(orgConfig)
		cache.SetFolderOrg(types.FilePath("/path/to/folder"), "org1")

		globalSettings := &types.Settings{ActivateSnykCode: "true"}
		ctrl := gomock.NewController(t)
		mockCP := mock_types.NewMockConfigProvider(ctrl)
		mockCP.EXPECT().FilterSeverity().Return(types.SeverityFilter{}).AnyTimes()
		mockCP.EXPECT().RiskScoreThreshold().Return(0).AnyTimes()
		mockCP.EXPECT().IssueViewOptions().Return(types.IssueViewOptions{}).AnyTimes()
		mockCP.EXPECT().IsAutoScanEnabled().Return(true).AnyTimes()
		mockCP.EXPECT().IsDeltaFindingsEnabled().Return(true).AnyTimes()
		mockCP.EXPECT().IsSnykOssEnabled().Return(true).AnyTimes()
		mockCP.EXPECT().IsSnykIacEnabled().Return(false).AnyTimes()
		mockCP.EXPECT().IsSnykSecretsEnabled().Return(false).AnyTimes()
		mockCP.EXPECT().IsSnykCodeEnabled().Return(true).AnyTimes()
		resolver, conf := newResolverWithGAF(t, cache, globalSettings, mockCP)

		fc := &types.FolderConfig{
			FolderPath:   "/path/to/folder",
			PreferredOrg: "org1",
			OrgSetByUser: true,
		}
		fc.SetConf(conf)
		fc.SyncToConfiguration()
		types.WriteOrgConfigToConfiguration(conf, orgConfig)

		result := fc.ToLspFolderConfig(resolver)

		require.NotNil(t, result.Settings[types.SettingSnykCodeEnabled])
		assert.False(t, result.Settings[types.SettingSnykCodeEnabled].Value.(bool))
		assert.Equal(t, "ldx-sync-locked", result.Settings[types.SettingSnykCodeEnabled].Source)
		assert.Equal(t, "organization", result.Settings[types.SettingSnykCodeEnabled].OriginScope)
		assert.True(t, result.Settings[types.SettingSnykCodeEnabled].IsLocked)
	})
}
