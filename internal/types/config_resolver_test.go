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
	return mockCP
}

// newResolverWithConfig creates a ConfigResolver with configuration resolver wired (required for tests after 2.4.4).
// Callers write global settings directly to conf via conf.Set(configuration.UserGlobalKey(types.SettingXxx), value).
func newResolverWithConfig(t *testing.T, cache *types.LDXSyncConfigCache, mockCP *mock_types.MockConfigProvider) (*types.ConfigResolver, configuration.Configuration) {
	t.Helper()
	conf := configuration.NewWithOpts()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	require.NoError(t, conf.AddFlagSet(fs))
	prefixKeyResolver := configuration.NewConfigResolver(conf)
	logger := zerolog.Nop()
	resolver := types.NewConfigResolver(cache, mockCP, &logger)
	resolver.SetPrefixKeyResolver(prefixKeyResolver, conf)
	return resolver, conf
}

func TestConfigResolver_GetValue_MachineScope(t *testing.T) {
	resolver, conf := newResolverWithConfig(t, nil, nil)
	conf.Set(configuration.UserGlobalKey(types.SettingApiEndpoint), "https://api.snyk.io")

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
		emptyResolver, _ := newResolverWithConfig(t, nil, nil)
		// No conf.Set for SnykCodeEnabled — expect default

		value, source := emptyResolver.GetValue(types.SettingSnykCodeEnabled, nil)
		assert.Equal(t, types.ConfigSourceDefault, source, "empty string should return ConfigSourceDefault, not ConfigSourceGlobal")
		assert.True(t, value == nil || value == false || value == "", "default value when unset")
	})

	t.Run("returns global source when global string value is explicitly set", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockCP := setupMockConfigProvider(ctrl)
		explicitResolver, conf := newResolverWithConfig(t, nil, mockCP)
		conf.Set(configuration.UserGlobalKey(types.SettingSnykCodeEnabled), true)

		value, source := explicitResolver.GetValue(types.SettingSnykCodeEnabled, nil)
		assert.Equal(t, true, value)
		assert.Equal(t, types.ConfigSourceGlobal, source)
	})
}

func TestConfigResolver_UsesReconciledGlobalValues(t *testing.T) {
	t.Run("SnykCode uses reconciled value from ConfigProvider when user set raw setting", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockCP := setupMockConfigProvider(ctrl)
		resolver, conf := newResolverWithConfig(t, nil, mockCP)
		conf.Set(configuration.UserGlobalKey(types.SettingSnykCodeEnabled), true)

		result := resolver.IsSnykCodeEnabledForFolder(nil)
		assert.True(t, result)
	})

	t.Run("org-scope global fallback returns reconciled bool value not raw string", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockCP := setupMockConfigProvider(ctrl)
		resolver, conf := newResolverWithConfig(t, nil, mockCP)
		conf.Set(configuration.UserGlobalKey(types.SettingSnykCodeEnabled), true)
		conf.Set(configuration.UserGlobalKey(types.SettingSnykOssEnabled), true)
		conf.Set(configuration.UserGlobalKey(types.SettingScanNetNew), false)
		conf.Set(configuration.UserGlobalKey(types.SettingScanAutomatic), true)
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
		resolver, conf := newResolverWithConfig(t, nil, nil)
		conf.Set(configuration.UserGlobalKey(types.SettingCliPath), "/usr/local/bin/snyk")

		val, source := resolver.GetValue(types.SettingCliPath, nil)
		assert.Equal(t, types.ConfigSourceGlobal, source)
		assert.Equal(t, "/usr/local/bin/snyk", val)
	})
}

func TestConfigResolver_IsSnykSecretsEnabledForFolder(t *testing.T) {
	t.Run("returns false when no setting and default fallback", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockCP := mock_types.NewMockConfigProvider(ctrl)
		resolver, _ := newResolverWithConfig(t, nil, mockCP)
		assert.False(t, resolver.IsSnykSecretsEnabledForFolder(nil))
	})

	t.Run("uses reconciled value from ConfigProvider when user set global setting", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockCP := setupMockConfigProvider(ctrl)
		resolver, conf := newResolverWithConfig(t, nil, mockCP)
		conf.Set(configuration.UserGlobalKey(types.SettingSnykSecretsEnabled), true)
		assert.True(t, resolver.IsSnykSecretsEnabledForFolder(nil))
	})

	t.Run("respects user override over global", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockCP := setupMockConfigProvider(ctrl)
		resolver, conf := newResolverWithConfig(t, nil, mockCP)
		conf.Set(configuration.UserGlobalKey(types.SettingSnykSecretsEnabled), true)
		folderConfig := &types.FolderConfig{FolderPath: "/folder"}
		folderConfig.SetConf(conf)
		conf.Set(configuration.UserFolderKey(string(types.PathKey(folderConfig.FolderPath)), types.SettingSnykSecretsEnabled), &configuration.LocalConfigField{Value: false, Changed: true})
		assert.False(t, resolver.IsSnykSecretsEnabledForFolder(folderConfig))
	})

	t.Run("respects LDX-Sync locked value over user override", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		ldxCache := types.NewLDXSyncConfigCache()
		orgConfig := types.NewLDXSyncOrgConfig("org1")
		orgConfig.SetField(types.SettingSnykSecretsEnabled, true, true, "group")
		ldxCache.SetOrgConfig(orgConfig)
		mockCP := setupMockConfigProvider(ctrl)
		resolver, conf := newResolverWithConfig(t, ldxCache, mockCP)
		folderConfig := &types.FolderConfig{FolderPath: "/folder"}
		folderConfig.SetConf(conf)
		folderPath := string(types.PathKey(folderConfig.FolderPath))
		types.SetPreferredOrgAndOrgSetByUser(conf, folderConfig.FolderPath, "org1", true)
		types.WriteOrgConfigToConfiguration(conf, orgConfig)
		conf.Set(configuration.UserFolderKey(folderPath, types.SettingSnykSecretsEnabled), &configuration.LocalConfigField{Value: false, Changed: true})
		assert.True(t, resolver.IsSnykSecretsEnabledForFolder(folderConfig))
	})

	t.Run("falls back to global when no override and no LDX-Sync", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockCP := mock_types.NewMockConfigProvider(ctrl)
		_ = ctrl // keep gomock controller alive
		resolver, conf := newResolverWithConfig(t, nil, mockCP)
		conf.Set(configuration.UserGlobalKey(types.SettingSnykSecretsEnabled), false)
		folderConfig := &types.FolderConfig{FolderPath: "/folder"}
		assert.False(t, resolver.IsSnykSecretsEnabledForFolder(folderConfig))
	})
}

func TestConfigResolver_GetValue_FolderScope(t *testing.T) {
	resolver, conf := newResolverWithConfig(t, nil, nil)

	folderConfig := &types.FolderConfig{FolderPath: "/path/to/folder"}
	folderConfig.SetConf(conf)
	folderPath := string(types.PathKey(folderConfig.FolderPath))
	conf.Set(configuration.UserFolderKey(folderPath, types.SettingBaseBranch), &configuration.LocalConfigField{Value: "main", Changed: true})
	conf.Set(configuration.UserFolderKey(folderPath, types.SettingReferenceBranch), &configuration.LocalConfigField{Value: "main", Changed: true})
	conf.Set(configuration.UserFolderKey(folderPath, types.SettingAdditionalParameters), &configuration.LocalConfigField{Value: []string{"--debug"}, Changed: true})
	conf.Set(configuration.UserFolderKey(folderPath, types.SettingReferenceFolder), &configuration.LocalConfigField{Value: "/path/to/reference", Changed: true})

	t.Run("returns folder value for reference_branch", func(t *testing.T) {
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
		fc := &types.FolderConfig{FolderPath: "/path/to/folder"}
		fc.SetConf(conf)
		conf.Set(configuration.FolderMetadataKey(string(types.PathKey(fc.FolderPath)), types.SettingLocalBranches), []string{"main", "develop"})
		value, source := resolver.GetValue(types.SettingLocalBranches, fc)
		assert.Equal(t, []string{"main", "develop"}, value)
		assert.Equal(t, types.ConfigSourceFolder, source)
	})

	t.Run("returns folder value for preferred_org", func(t *testing.T) {
		fc := &types.FolderConfig{FolderPath: "/path/to/folder"}
		fc.SetConf(conf)
		types.SetPreferredOrgAndOrgSetByUser(conf, fc.FolderPath, "my-org", true)
		value, source := resolver.GetValue(types.SettingPreferredOrg, fc)
		assert.Equal(t, "my-org", value)
		assert.Equal(t, types.ConfigSourceFolder, source)
	})

	t.Run("returns folder value for auto_determined_org", func(t *testing.T) {
		fc := &types.FolderConfig{FolderPath: "/path/to/folder"}
		fc.SetConf(conf)
		conf.Set(configuration.FolderMetadataKey(string(types.PathKey(fc.FolderPath)), types.SettingAutoDeterminedOrg), "auto-org")
		value, source := resolver.GetValue(types.SettingAutoDeterminedOrg, fc)
		assert.Equal(t, "auto-org", value)
		assert.Equal(t, types.ConfigSourceFolder, source)
	})

	t.Run("returns folder value for org_set_by_user", func(t *testing.T) {
		fc := &types.FolderConfig{FolderPath: "/path/to/folder"}
		fc.SetConf(conf)
		types.SetPreferredOrgAndOrgSetByUser(conf, fc.FolderPath, "", true)
		value, source := resolver.GetValue(types.SettingOrgSetByUser, fc)
		assert.Equal(t, true, value)
		assert.Equal(t, types.ConfigSourceFolder, source)
	})

	t.Run("returns folder value for scan_command_config", func(t *testing.T) {
		scanConfig := map[product.Product]types.ScanCommandConfig{
			product.ProductCode: {PreScanCommand: "/bin/ls"},
		}
		fc := &types.FolderConfig{FolderPath: "/path/to/folder"}
		fc.SetConf(conf)
		conf.Set(configuration.UserFolderKey(string(types.PathKey(fc.FolderPath)), types.SettingScanCommandConfig), &configuration.LocalConfigField{Value: scanConfig, Changed: true})
		value, source := resolver.GetValue(types.SettingScanCommandConfig, fc)
		assert.Equal(t, scanConfig, value)
		assert.Equal(t, types.ConfigSourceFolder, source)
	})
}

func TestConfigResolver_GetValue_OrgScope_NoLDXSync(t *testing.T) {
	ctrl := gomock.NewController(t)
	folderConfig := &types.FolderConfig{FolderPath: "/path/to/folder"}
	mockCP := setupMockConfigProvider(ctrl)
	resolver, conf := newResolverWithConfig(t, nil, mockCP)
	conf.Set(configuration.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	folderConfig.SetConf(conf)
	types.SetPreferredOrgAndOrgSetByUser(conf, folderConfig.FolderPath, "org1", true)

	t.Run("returns reconciled global value when no LDX-Sync cache", func(t *testing.T) {
		value, source := resolver.GetValue(types.SettingSnykCodeEnabled, folderConfig)
		assert.Equal(t, true, value)
		assert.Equal(t, types.ConfigSourceGlobal, source)
	})

	t.Run("returns user override when set and no LDX-Sync", func(t *testing.T) {
		conf.Set(configuration.UserFolderKey(string(types.PathKey(folderConfig.FolderPath)), types.SettingEnabledSeverities), &configuration.LocalConfigField{Value: []string{"critical", "high"}, Changed: true})

		value, source := resolver.GetValue(types.SettingEnabledSeverities, folderConfig)
		assert.Equal(t, []string{"critical", "high"}, value)
		assert.Equal(t, types.ConfigSourceUserOverride, source)
	})
}

func TestConfigResolver_GetValue_OrgScope_WithLDXSync(t *testing.T) {
	ctrl := gomock.NewController(t)
	ldxCache := types.NewLDXSyncConfigCache()
	orgConfig := types.NewLDXSyncOrgConfig("org1")
	orgConfig.SetField(types.SettingEnabledSeverities, []string{"critical"}, false, "org")
	ldxCache.SetOrgConfig(orgConfig)

	folderConfig := &types.FolderConfig{FolderPath: "/path/to/folder"}
	mockCP := setupMockConfigProvider(ctrl)
	resolver, conf := newResolverWithConfig(t, ldxCache, mockCP)
	folderConfig.SetConf(conf)
	types.SetPreferredOrgAndOrgSetByUser(conf, folderConfig.FolderPath, "org1", true)
	types.WriteOrgConfigToConfiguration(conf, orgConfig)

	t.Run("returns LDX-Sync value when no user override", func(t *testing.T) {
		value, source := resolver.GetValue(types.SettingEnabledSeverities, folderConfig)
		assert.Equal(t, []string{"critical"}, value)
		assert.Equal(t, types.ConfigSourceLDXSync, source)
	})

	t.Run("returns user override when set", func(t *testing.T) {
		conf.Set(configuration.UserFolderKey(string(types.PathKey(folderConfig.FolderPath)), types.SettingEnabledSeverities), &configuration.LocalConfigField{Value: []string{"critical", "high"}, Changed: true})

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

		folderConfig := &types.FolderConfig{FolderPath: "/path/to/folder"}
		innerCtrl := gomock.NewController(t)
		mockCP := mock_types.NewMockConfigProvider(innerCtrl)
		resolver, conf := newResolverWithConfig(t, ldxCache, mockCP)
		conf.Set(configuration.UserGlobalKey(types.SettingSnykCodeEnabled), false)
		folderConfig.SetConf(conf)
		types.SetPreferredOrgAndOrgSetByUser(conf, folderConfig.FolderPath, "org1", true)
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

		folderConfig := &types.FolderConfig{FolderPath: "/path/to/folder"}
		mockCP := setupMockConfigProvider(ctrl)
		resolver, conf := newResolverWithConfig(t, ldxCache, mockCP)
		conf.Set(configuration.UserGlobalKey(types.SettingSnykCodeEnabled), false)
		folderConfig.SetConf(conf)
		types.SetPreferredOrgAndOrgSetByUser(conf, folderConfig.FolderPath, "org1", true)
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

		folderConfig := &types.FolderConfig{FolderPath: "/path/to/folder"}

		mockCP := setupMockConfigProvider(ctrl)
		resolver, conf := newResolverWithConfig(t, ldxCache, mockCP)
		conf.Set(configuration.UserGlobalKey(types.SettingSnykCodeEnabled), false)
		folderConfig.SetConf(conf)
		types.SetPreferredOrgAndOrgSetByUser(conf, folderConfig.FolderPath, "org1", true)
		types.WriteOrgConfigToConfiguration(conf, orgConfig)
		conf.Set(configuration.UserFolderKey(string(types.PathKey(folderConfig.FolderPath)), types.SettingSnykCodeEnabled), &configuration.LocalConfigField{Value: true, Changed: true})

		value, source := resolver.GetValue(types.SettingSnykCodeEnabled, folderConfig)
		assert.Equal(t, true, value)
		assert.Equal(t, types.ConfigSourceUserOverride, source)
	})

	t.Run("LDX-Sync default value used when no global and no override", func(t *testing.T) {
		ldxCache := types.NewLDXSyncConfigCache()
		orgConfig := types.NewLDXSyncOrgConfig("org1")
		orgConfig.SetField(types.SettingSnykCodeEnabled, true, false, "org")
		ldxCache.SetOrgConfig(orgConfig)

		folderConfig := &types.FolderConfig{FolderPath: "/path/to/folder"}
		mockCP := setupMockConfigProvider(ctrl)
		resolver, conf := newResolverWithConfig(t, ldxCache, mockCP)
		folderConfig.SetConf(conf)
		types.SetPreferredOrgAndOrgSetByUser(conf, folderConfig.FolderPath, "org1", true)
		types.WriteOrgConfigToConfiguration(conf, orgConfig)

		value, source := resolver.GetValue(types.SettingSnykCodeEnabled, folderConfig)
		assert.Equal(t, true, value)
		assert.Equal(t, types.ConfigSourceLDXSync, source)
	})
}

func TestConfigResolver_GetValue_OrgScope_Locked(t *testing.T) {
	ctrl := gomock.NewController(t)
	ldxCache := types.NewLDXSyncConfigCache()
	orgConfig := types.NewLDXSyncOrgConfig("org1")
	orgConfig.SetField(types.SettingEnabledSeverities, []string{"critical"}, true, "group")
	ldxCache.SetOrgConfig(orgConfig)

	folderConfig := &types.FolderConfig{FolderPath: "/path/to/folder"}
	mockCP := setupMockConfigProvider(ctrl)
	resolver, conf := newResolverWithConfig(t, ldxCache, mockCP)
	folderConfig.SetConf(conf)
	types.SetPreferredOrgAndOrgSetByUser(conf, folderConfig.FolderPath, "org1", true)
	types.WriteOrgConfigToConfiguration(conf, orgConfig)

	t.Run("returns LDX-Sync locked value even when user override exists", func(t *testing.T) {
		conf.Set(configuration.UserFolderKey(string(types.PathKey(folderConfig.FolderPath)), types.SettingEnabledSeverities), &configuration.LocalConfigField{Value: []string{"critical", "high", "medium"}, Changed: true})

		value, source := resolver.GetValue(types.SettingEnabledSeverities, folderConfig)
		assert.Equal(t, []string{"critical"}, value)
		assert.Equal(t, types.ConfigSourceLDXSyncLocked, source)
	})
}

func TestConfigResolver_GetValue_OrgScope_DifferentOrgs(t *testing.T) {
	ctrl := gomock.NewController(t)
	ldxCache := types.NewLDXSyncConfigCache()

	org1Config := types.NewLDXSyncOrgConfig("org1")
	org1Config.SetField(types.SettingEnabledSeverities, []string{"critical"}, false, "org")
	ldxCache.SetOrgConfig(org1Config)

	org2Config := types.NewLDXSyncOrgConfig("org2")
	org2Config.SetField(types.SettingEnabledSeverities, []string{"critical", "high"}, true, "group")
	ldxCache.SetOrgConfig(org2Config)

	folder1 := &types.FolderConfig{FolderPath: "/folder1"}
	folder2 := &types.FolderConfig{FolderPath: "/folder2"}
	mockCP := setupMockConfigProvider(ctrl)
	resolver, conf := newResolverWithConfig(t, ldxCache, mockCP)
	folder1.SetConf(conf)
	folder2.SetConf(conf)
	types.SetPreferredOrgAndOrgSetByUser(conf, folder1.FolderPath, "org1", true)
	types.SetPreferredOrgAndOrgSetByUser(conf, folder2.FolderPath, "org2", true)
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

		folderConfig := &types.FolderConfig{FolderPath: "/path"}
		mockCP := setupMockConfigProvider(ctrl)
		resolver, conf := newResolverWithConfig(t, ldxCache, mockCP)
		folderConfig.SetConf(conf)
		types.SetPreferredOrgAndOrgSetByUser(conf, folderConfig.FolderPath, "user-org", true)
		types.WriteOrgConfigToConfiguration(conf, orgConfig)

		value, source := resolver.GetValue(types.SettingEnabledSeverities, folderConfig)
		assert.Equal(t, []string{"critical"}, value)
		assert.Equal(t, types.ConfigSourceLDXSync, source)
	})

	orgFallbackCases := []struct {
		name              string
		orgForConfig      string
		globalOrg         string
		preferredOrg      string
		autoDeterminedOrg string
		orgSetByUser      bool
		expectedSev       []string
	}{
		{"falls back to global org when OrgSetByUser is true but PreferredOrg is empty", "global-org", "global-org", "", "", true, []string{"high"}},
		{"uses AutoDeterminedOrg when OrgSetByUser is false", "auto-org", "", "", "auto-org", false, []string{"medium"}},
		{"falls back to global org when AutoDeterminedOrg is empty and OrgSetByUser is false", "global-org", "global-org", "", "", false, []string{"low"}},
	}
	for _, tc := range orgFallbackCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			ldxCache := types.NewLDXSyncConfigCache()
			orgConfig := types.NewLDXSyncOrgConfig(tc.orgForConfig)
			orgConfig.SetField(types.SettingEnabledSeverities, tc.expectedSev, false, "org")
			ldxCache.SetOrgConfig(orgConfig)

			folderConfig := &types.FolderConfig{FolderPath: "/path"}
			mockCP := setupMockConfigProvider(ctrl)
			resolver, conf := newResolverWithConfig(t, ldxCache, mockCP)
			if tc.globalOrg != "" {
				conf.Set(configuration.UserGlobalKey(types.SettingOrganization), tc.globalOrg)
			}
			folderConfig.SetConf(conf)
			types.SetPreferredOrgAndOrgSetByUser(conf, folderConfig.FolderPath, tc.preferredOrg, tc.orgSetByUser)
			if tc.autoDeterminedOrg != "" {
				types.SetAutoDeterminedOrg(conf, folderConfig.FolderPath, tc.autoDeterminedOrg)
			}
			types.WriteOrgConfigToConfiguration(conf, orgConfig)

			value, source := resolver.GetValue(types.SettingEnabledSeverities, folderConfig)
			assert.Equal(t, tc.expectedSev, value)
			assert.Equal(t, types.ConfigSourceLDXSync, source)
		})
	}

	t.Run("returns default when folderConfig is nil", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		ldxCache := types.NewLDXSyncConfigCache()
		orgConfig := types.NewLDXSyncOrgConfig("org1")
		orgConfig.SetField(types.SettingEnabledSeverities, []string{"critical"}, false, "org")
		ldxCache.SetOrgConfig(orgConfig)

		mockCP := setupMockConfigProvider(ctrl)
		resolver, _ := newResolverWithConfig(t, ldxCache, mockCP)

		_, source := resolver.GetValue(types.SettingEnabledSeverities, nil)
		assert.Equal(t, types.ConfigSourceDefault, source)
	})

	t.Run("returns default when no org can be determined and no global setting", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		ldxCache := types.NewLDXSyncConfigCache()
		orgConfig := types.NewLDXSyncOrgConfig("some-org")
		orgConfig.SetField(types.SettingEnabledSeverities, []string{"critical"}, false, "org")
		ldxCache.SetOrgConfig(orgConfig)

		folderConfig := &types.FolderConfig{FolderPath: "/path"}
		mockCP := setupMockConfigProvider(ctrl)
		resolver, conf := newResolverWithConfig(t, ldxCache, mockCP)
		folderConfig.SetConf(conf)
		types.SetPreferredOrgAndOrgSetByUser(conf, folderConfig.FolderPath, "", false)
		types.WriteOrgConfigToConfiguration(conf, orgConfig)

		_, source := resolver.GetValue(types.SettingEnabledSeverities, folderConfig)
		assert.Equal(t, types.ConfigSourceDefault, source)
	})
}

func TestConfigResolver_TypedAccessors(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockCP := mock_types.NewMockConfigProvider(ctrl)
	_ = ctrl
	resolver, conf := newResolverWithConfig(t, nil, mockCP)
	conf.Set(configuration.UserGlobalKey(types.SettingApiEndpoint), "https://api.snyk.io")
	conf.Set(configuration.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	conf.Set(configuration.UserGlobalKey(types.SettingScanNetNew), true)
	conf.Set(configuration.UserGlobalKey(types.SettingRiskScoreThreshold), 500)

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
		folderConfig := &types.FolderConfig{FolderPath: "/path"}
		folderConfig.SetConf(conf)
		conf.Set(configuration.UserFolderKey(string(types.PathKey(folderConfig.FolderPath)), types.SettingAdditionalParameters), &configuration.LocalConfigField{Value: []string{"--debug", "--verbose"}, Changed: true})
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

	folderConfig := &types.FolderConfig{FolderPath: "/path"}
	mockCP := setupMockConfigProvider(ctrl)
	resolver, conf := newResolverWithConfig(t, ldxCache, mockCP)
	folderConfig.SetConf(conf)
	types.SetPreferredOrgAndOrgSetByUser(conf, folderConfig.FolderPath, "org1", true)
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
	resolver, conf := newResolverWithConfig(t, nil, nil)
	conf.Set(configuration.UserGlobalKey(types.SettingApiEndpoint), "https://api.snyk.io")

	source := resolver.GetSource(types.SettingApiEndpoint, nil)
	assert.Equal(t, types.ConfigSourceGlobal, source)
}

func TestFolderConfig_UserOverrideMethods(t *testing.T) {
	t.Run("HasUserOverride returns false for nil config", func(t *testing.T) {
		assert.False(t, types.HasUserOverride(nil, "/path", "test"))
	})

	t.Run("HasUserOverride returns false when not set", func(t *testing.T) {
		conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		assert.False(t, types.HasUserOverride(conf, "/path", "test"))
	})

	t.Run("HasUserOverride returns true when set in configuration", func(t *testing.T) {
		conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		fp := string(types.PathKey("/path"))
		conf.Set(configuration.UserFolderKey(fp, types.SettingEnabledSeverities), &configuration.LocalConfigField{Value: []string{"critical"}, Changed: true})
		assert.True(t, types.HasUserOverride(conf, "/path", types.SettingEnabledSeverities))
	})

	t.Run("ReadFolderConfigSnapshot returns value when set via getUser", func(t *testing.T) {
		conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		fp := string(types.PathKey("/path"))
		conf.Set(configuration.UserFolderKey(fp, types.SettingBaseBranch), &configuration.LocalConfigField{Value: "main", Changed: true})
		snap := types.ReadFolderConfigSnapshot(conf, "/path")
		assert.Equal(t, "main", snap.BaseBranch)
	})

	t.Run("ReadFolderConfigSnapshot returns empty when not set", func(t *testing.T) {
		conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		snap := types.ReadFolderConfigSnapshot(conf, "/path")
		assert.Empty(t, snap.BaseBranch)
	})

	t.Run("Unset removes override from configuration", func(t *testing.T) {
		conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		fp := string(types.PathKey("/path"))
		key := configuration.UserFolderKey(fp, types.SettingEnabledSeverities)
		conf.Set(key, &configuration.LocalConfigField{Value: []string{"critical"}, Changed: true})
		assert.True(t, types.HasUserOverride(conf, "/path", types.SettingEnabledSeverities))

		conf.Unset(key)
		assert.False(t, types.HasUserOverride(conf, "/path", types.SettingEnabledSeverities))
	})
}

func TestFolderConfig_Clone(t *testing.T) {
	original := &types.FolderConfig{
		FolderPath: "/path",
	}

	clone := original.Clone()

	t.Run("clones FolderPath", func(t *testing.T) {
		assert.Equal(t, original.FolderPath, clone.FolderPath)
	})

	t.Run("clone is non-nil", func(t *testing.T) {
		assert.NotNil(t, clone)
	})
}

func TestConfigResolver_GetEffectiveValue_IncludesOriginScope(t *testing.T) {
	ctrl := gomock.NewController(t)
	ldxCache := types.NewLDXSyncConfigCache()
	orgConfig := types.NewLDXSyncOrgConfig("org1")
	orgConfig.SetField(types.SettingEnabledSeverities, []string{"critical"}, false, "tenant")
	orgConfig.SetField(types.SettingSnykCodeEnabled, true, true, "group")
	ldxCache.SetOrgConfig(orgConfig)

	folderConfig := &types.FolderConfig{FolderPath: "/path/to/folder"}
	mockCP := setupMockConfigProvider(ctrl)
	resolver, conf := newResolverWithConfig(t, ldxCache, mockCP)
	folderConfig.SetConf(conf)
	types.SetPreferredOrgAndOrgSetByUser(conf, folderConfig.FolderPath, "org1", true)
	fp := string(types.PathKey(folderConfig.FolderPath))
	conf.Set(configuration.UserFolderKey(fp, types.SettingPreferredOrg), &configuration.LocalConfigField{Value: "org1", Changed: true})
	conf.Set(configuration.UserFolderKey(fp, types.SettingOrgSetByUser), &configuration.LocalConfigField{Value: true, Changed: true})
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
		folderConfigWithOverride := &types.FolderConfig{FolderPath: "/path/to/folder"}
		folderConfigWithOverride.SetConf(conf)
		types.SetPreferredOrgAndOrgSetByUser(conf, folderConfigWithOverride.FolderPath, "org1", true)
		types.WriteOrgConfigToConfiguration(conf, orgConfig)
		fp := string(types.PathKey(folderConfigWithOverride.FolderPath))
		conf.Set(configuration.UserFolderKey(fp, types.SettingEnabledSeverities), &configuration.LocalConfigField{Value: []string{"high"}, Changed: true})

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
		resolverNoLdx, _ := newResolverWithConfig(t, nil, mockCPNoOrg)

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
		conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		fc := &types.FolderConfig{FolderPath: "/path/to/folder"}
		fc.SetConf(conf)
		fp := string(types.PathKey(fc.FolderPath))
		conf.Set(configuration.UserFolderKey(fp, types.SettingBaseBranch), &configuration.LocalConfigField{Value: "main", Changed: true})
		conf.Set(configuration.UserFolderKey(fp, types.SettingReferenceBranch), &configuration.LocalConfigField{Value: "main", Changed: true})

		update := &types.LspFolderConfig{
			FolderPath: "/path/to/folder",
			Settings: map[string]*types.ConfigSetting{
				types.SettingBaseBranch:            {Value: "develop"},
				types.SettingAdditionalEnvironment: {Value: "DEBUG=1"},
			},
		}

		changed := fc.ApplyLspUpdate(update)

		assert.True(t, changed)
		assert.Equal(t, "develop", fc.BaseBranch())
		assert.Equal(t, "DEBUG=1", fc.AdditionalEnv())
	})

	t.Run("does not change fields when nil in update", func(t *testing.T) {
		conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		fc := &types.FolderConfig{FolderPath: "/path/to/folder"}
		fc.SetConf(conf)
		fp := string(types.PathKey(fc.FolderPath))
		conf.Set(configuration.UserFolderKey(fp, types.SettingBaseBranch), &configuration.LocalConfigField{Value: "main", Changed: true})
		conf.Set(configuration.UserFolderKey(fp, types.SettingReferenceBranch), &configuration.LocalConfigField{Value: "main", Changed: true})

		update := &types.LspFolderConfig{
			FolderPath: "/path/to/folder",
			Settings:   nil,
		}

		changed := fc.ApplyLspUpdate(update)

		assert.False(t, changed)
		assert.Equal(t, "main", fc.BaseBranch())
	})

	t.Run("applies org-scope updates as user overrides", func(t *testing.T) {
		conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
		types.RegisterAllConfigurations(fs)
		_ = conf.AddFlagSet(fs)
		fc := &types.FolderConfig{FolderPath: "/path/to/folder"}
		fc.SetConf(conf)

		update := &types.LspFolderConfig{
			FolderPath: "/path/to/folder",
			Settings: map[string]*types.ConfigSetting{
				types.SettingScanAutomatic: {Value: true, Changed: true},
				types.SettingScanNetNew:    {Value: false, Changed: true},
			},
		}

		changed := fc.ApplyLspUpdate(update)

		assert.True(t, changed)
		assert.True(t, types.HasUserOverride(fc.Conf(), fc.FolderPath, types.SettingScanAutomatic))
		assert.True(t, types.HasUserOverride(fc.Conf(), fc.FolderPath, types.SettingScanNetNew))
		snap := types.ReadFolderConfigSnapshot(fc.Conf(), fc.FolderPath)
		scanAutoVal, ok1 := snap.UserOverrides[types.SettingScanAutomatic]
		scanNetNewVal, ok2 := snap.UserOverrides[types.SettingScanNetNew]
		assert.True(t, ok1)
		assert.True(t, ok2)
		assert.Equal(t, true, scanAutoVal)
		assert.Equal(t, false, scanNetNewVal)
	})

	t.Run("sets OrgSetByUser when PreferredOrg is updated", func(t *testing.T) {
		conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		fc := &types.FolderConfig{FolderPath: "/path/to/folder"}
		fc.SetConf(conf)
		types.SetPreferredOrgAndOrgSetByUser(conf, fc.FolderPath, "", false)

		update := &types.LspFolderConfig{
			FolderPath: "/path/to/folder",
			Settings: map[string]*types.ConfigSetting{
				types.SettingPreferredOrg: {Value: "my-org"},
			},
		}

		changed := fc.ApplyLspUpdate(update)

		assert.True(t, changed)
		assert.Equal(t, "my-org", fc.PreferredOrg())
		assert.True(t, fc.OrgSetByUser())
	})

	t.Run("clears user overrides via explicit null", func(t *testing.T) {
		conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
		types.RegisterAllConfigurations(fs)
		_ = conf.AddFlagSet(fs)
		fc := &types.FolderConfig{FolderPath: "/path/to/folder"}
		fc.SetConf(conf)
		fp := string(types.PathKey(fc.FolderPath))
		conf.Set(configuration.UserFolderKey(fp, types.SettingScanAutomatic), &configuration.LocalConfigField{Value: true, Changed: true})
		conf.Set(configuration.UserFolderKey(fp, types.SettingScanNetNew), &configuration.LocalConfigField{Value: false, Changed: true})
		conf.Set(configuration.UserFolderKey(fp, types.SettingSnykCodeEnabled), &configuration.LocalConfigField{Value: true, Changed: true})

		update := &types.LspFolderConfig{
			FolderPath: "/path/to/folder",
			Settings: map[string]*types.ConfigSetting{
				types.SettingScanAutomatic:   {Value: nil, Changed: true},
				types.SettingSnykCodeEnabled: {Value: nil, Changed: true},
			},
		}

		changed := fc.ApplyLspUpdate(update)

		assert.True(t, changed)
		assert.False(t, types.HasUserOverride(fc.Conf(), fc.FolderPath, types.SettingScanAutomatic), "ScanAutomatic should be cleared")
		assert.False(t, types.HasUserOverride(fc.Conf(), fc.FolderPath, types.SettingSnykCodeEnabled), "SnykCodeEnabled should be cleared")
		assert.True(t, types.HasUserOverride(fc.Conf(), fc.FolderPath, types.SettingScanNetNew), "ScanNetNew should remain")
	})

	t.Run("null clears and value sets in same update", func(t *testing.T) {
		conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
		types.RegisterAllConfigurations(fs)
		_ = conf.AddFlagSet(fs)
		fc := &types.FolderConfig{FolderPath: "/path/to/folder"}
		fc.SetConf(conf)
		fp := string(types.PathKey(fc.FolderPath))
		conf.Set(configuration.UserFolderKey(fp, types.SettingScanAutomatic), &configuration.LocalConfigField{Value: true, Changed: true})

		update := &types.LspFolderConfig{
			FolderPath: "/path/to/folder",
			Settings: map[string]*types.ConfigSetting{
				types.SettingScanAutomatic: {Value: nil, Changed: true},
				types.SettingScanNetNew:    {Value: true, Changed: true},
			},
		}

		changed := fc.ApplyLspUpdate(update)

		assert.True(t, changed)
		assert.False(t, types.HasUserOverride(fc.Conf(), fc.FolderPath, types.SettingScanAutomatic), "ScanAutomatic should be cleared")
		assert.True(t, types.HasUserOverride(fc.Conf(), fc.FolderPath, types.SettingScanNetNew), "ScanNetNew should be set")
	})

	t.Run("omitted fields are not changed", func(t *testing.T) {
		conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
		types.RegisterAllConfigurations(fs)
		_ = conf.AddFlagSet(fs)
		fc := &types.FolderConfig{FolderPath: "/path/to/folder"}
		fc.SetConf(conf)
		fp := string(types.PathKey(fc.FolderPath))
		conf.Set(configuration.UserFolderKey(fp, types.SettingScanAutomatic), &configuration.LocalConfigField{Value: true, Changed: true})
		conf.Set(configuration.UserFolderKey(fp, types.SettingScanNetNew), &configuration.LocalConfigField{Value: false, Changed: true})

		update := &types.LspFolderConfig{
			FolderPath: "/path/to/folder",
			Settings:   map[string]*types.ConfigSetting{},
		}

		changed := fc.ApplyLspUpdate(update)

		assert.False(t, changed, "No changes should be made when all fields are omitted")
		assert.True(t, types.HasUserOverride(fc.Conf(), fc.FolderPath, types.SettingScanAutomatic), "ScanAutomatic should remain")
		assert.True(t, types.HasUserOverride(fc.Conf(), fc.FolderPath, types.SettingScanNetNew), "ScanNetNew should remain")
	})

	t.Run("applies cwe/cve/rule filter overrides", func(t *testing.T) {
		conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
		types.RegisterAllConfigurations(fs)
		_ = conf.AddFlagSet(fs)
		fc := &types.FolderConfig{FolderPath: "/path/to/folder"}
		fc.SetConf(conf)

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
		assert.True(t, types.HasUserOverride(fc.Conf(), fc.FolderPath, types.SettingCweIds))
		assert.True(t, types.HasUserOverride(fc.Conf(), fc.FolderPath, types.SettingCveIds))
		assert.True(t, types.HasUserOverride(fc.Conf(), fc.FolderPath, types.SettingRuleIds))
		fp := string(types.PathKey(fc.FolderPath))
		cweVal := conf.Get(configuration.UserFolderKey(fp, types.SettingCweIds))
		lf, ok := cweVal.(*configuration.LocalConfigField)
		require.True(t, ok && lf != nil)
		assert.Equal(t, []string{"CWE-79", "CWE-89"}, lf.Value)
	})

	t.Run("clears cwe/cve/rule filter overrides via null", func(t *testing.T) {
		conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
		types.RegisterAllConfigurations(fs)
		_ = conf.AddFlagSet(fs)
		fc := &types.FolderConfig{FolderPath: "/path/to/folder"}
		fc.SetConf(conf)
		fp := string(types.PathKey(fc.FolderPath))
		conf.Set(configuration.UserFolderKey(fp, types.SettingCweIds), &configuration.LocalConfigField{Value: []string{"CWE-79"}, Changed: true})
		conf.Set(configuration.UserFolderKey(fp, types.SettingCveIds), &configuration.LocalConfigField{Value: []string{"CVE-2023-1234"}, Changed: true})

		update := &types.LspFolderConfig{
			FolderPath: "/path/to/folder",
			Settings: map[string]*types.ConfigSetting{
				types.SettingCweIds: {Value: nil, Changed: true},
				types.SettingCveIds: {Value: nil, Changed: true},
			},
		}

		changed := fc.ApplyLspUpdate(update)

		assert.True(t, changed)
		assert.False(t, types.HasUserOverride(fc.Conf(), fc.FolderPath, types.SettingCweIds), "CweIds should be cleared")
		assert.False(t, types.HasUserOverride(fc.Conf(), fc.FolderPath, types.SettingCveIds), "CveIds should be cleared")
	})

	t.Run("applies ScanCommandConfig from JSON-deserialized map[string]interface{}", func(t *testing.T) {
		conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
		types.RegisterAllConfigurations(fs)
		_ = conf.AddFlagSet(fs)
		fc := &types.FolderConfig{FolderPath: "/path/to/folder"}
		fc.SetConf(conf)
		update := &types.LspFolderConfig{
			FolderPath: "/path/to/folder",
			Settings: map[string]*types.ConfigSetting{
				types.SettingScanCommandConfig: {Value: map[string]interface{}{
					"Snyk Open Source": map[string]interface{}{
						"preScanCommand":             "/path/to/script",
						"preScanOnlyReferenceFolder": true,
					},
				}},
			},
		}

		changed := fc.ApplyLspUpdate(update)

		assert.True(t, changed)
		scanConfig := fc.ScanCommandConfig()
		require.NotNil(t, scanConfig)
		ossConfig, ok := scanConfig[product.ProductOpenSource]
		require.True(t, ok)
		assert.Equal(t, "/path/to/script", ossConfig.PreScanCommand)
		assert.True(t, ossConfig.PreScanOnlyReferenceFolder)
	})

	t.Run("applies ScanCommandConfig from typed Go value", func(t *testing.T) {
		conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
		types.RegisterAllConfigurations(fs)
		_ = conf.AddFlagSet(fs)
		fc := &types.FolderConfig{FolderPath: "/path/to/folder"}
		fc.SetConf(conf)
		update := &types.LspFolderConfig{
			FolderPath: "/path/to/folder",
			Settings: map[string]*types.ConfigSetting{
				types.SettingScanCommandConfig: {Value: map[product.Product]types.ScanCommandConfig{
					product.ProductOpenSource: {
						PreScanCommand: "/path/to/script",
					},
				}},
			},
		}

		changed := fc.ApplyLspUpdate(update)

		assert.True(t, changed)
		scanConfig := fc.ScanCommandConfig()
		require.NotNil(t, scanConfig)
		assert.Equal(t, "/path/to/script", scanConfig[product.ProductOpenSource].PreScanCommand)
	})
}

func TestFolderConfig_ToLspFolderConfig(t *testing.T) {
	t.Run("returns nil for nil config", func(t *testing.T) {
		var fc *types.FolderConfig
		result := fc.ToLspFolderConfig()
		assert.Nil(t, result)
	})

	t.Run("copies folder-scope settings via resolver and configuration", func(t *testing.T) {
		conf := configuration.NewWithOpts()
		fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
		types.RegisterAllConfigurations(fs)
		require.NoError(t, conf.AddFlagSet(fs))

		prefixKeyResolver := configuration.NewConfigResolver(conf)
		cache := types.NewLDXSyncConfigCache()
		logger := zerolog.Nop()
		resolver := types.NewConfigResolver(cache, nil, &logger)
		resolver.SetPrefixKeyResolver(prefixKeyResolver, conf)

		fc := &types.FolderConfig{FolderPath: "/path/to/folder"}
		fc.ConfigResolver = resolver
		fp := string(types.PathKey(fc.FolderPath))
		conf.Set(configuration.UserFolderKey(fp, types.SettingPreferredOrg), &configuration.LocalConfigField{Value: "org1", Changed: true})
		conf.Set(configuration.UserFolderKey(fp, types.SettingOrgSetByUser), &configuration.LocalConfigField{Value: true, Changed: true})
		conf.Set(configuration.UserFolderKey(fp, types.SettingBaseBranch), &configuration.LocalConfigField{Value: "main", Changed: true})
		conf.Set(configuration.UserFolderKey(fp, types.SettingReferenceBranch), &configuration.LocalConfigField{Value: "main", Changed: true})
		conf.Set(configuration.UserFolderKey(fp, types.SettingAdditionalParameters), &configuration.LocalConfigField{Value: []string{"--debug"}, Changed: true})
		conf.Set(configuration.UserFolderKey(fp, types.SettingAdditionalEnvironment), &configuration.LocalConfigField{Value: "DEBUG=1", Changed: true})
		conf.Set(configuration.UserFolderKey(fp, types.SettingReferenceFolder), &configuration.LocalConfigField{Value: "/ref/path", Changed: true})
		conf.Set(configuration.FolderMetadataKey(fp, types.SettingLocalBranches), []string{"main", "develop"})
		conf.Set(configuration.FolderMetadataKey(fp, types.SettingAutoDeterminedOrg), "auto-org")

		result := fc.ToLspFolderConfig()

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
		assert.Equal(t, "/ref/path", result.Settings[types.SettingReferenceFolder].Value)
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

		result := fc.ToLspFolderConfig()

		assert.Equal(t, types.FilePath("/path/to/folder"), result.FolderPath)
		assert.Nil(t, result.Settings[types.SettingBaseBranch])
		assert.Nil(t, result.Settings[types.SettingLocalBranches])
		assert.Nil(t, result.Settings[types.SettingPreferredOrg])
		assert.Nil(t, result.Settings[types.SettingAutoDeterminedOrg])
	})

	t.Run("populates org-scope settings with resolver", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		fc := &types.FolderConfig{FolderPath: "/path/to/folder"}

		mockCP := mock_types.NewMockConfigProvider(ctrl)
		resolver, conf := newResolverWithConfig(t, nil, mockCP)
		conf.Set(configuration.UserGlobalKey(types.SettingSnykCodeEnabled), true)
		conf.Set(configuration.UserGlobalKey(types.SettingSnykOssEnabled), true)
		conf.Set(configuration.UserGlobalKey(types.SettingSnykIacEnabled), false)
		conf.Set(configuration.UserGlobalKey(types.SettingScanAutomatic), true)
		conf.Set(configuration.UserGlobalKey(types.SettingScanNetNew), true)
		fc.ConfigResolver = resolver
		fp := string(types.PathKey(fc.FolderPath))
		conf.Set(configuration.UserFolderKey(fp, types.SettingPreferredOrg), &configuration.LocalConfigField{Value: "org1", Changed: true})
		conf.Set(configuration.UserFolderKey(fp, types.SettingOrgSetByUser), &configuration.LocalConfigField{Value: true, Changed: true})

		result := fc.ToLspFolderConfig()

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

		ctrl := gomock.NewController(t)
		mockCP := mock_types.NewMockConfigProvider(ctrl)
		resolver, conf := newResolverWithConfig(t, cache, mockCP)
		conf.Set(configuration.UserGlobalKey(types.SettingSnykCodeEnabled), true)

		fc := &types.FolderConfig{FolderPath: "/path/to/folder"}
		fc.ConfigResolver = resolver
		types.SetPreferredOrgAndOrgSetByUser(conf, fc.FolderPath, "org1", true)
		types.WriteOrgConfigToConfiguration(conf, orgConfig)

		result := fc.ToLspFolderConfig()

		require.NotNil(t, result.Settings[types.SettingSnykCodeEnabled])
		assert.False(t, result.Settings[types.SettingSnykCodeEnabled].Value.(bool))
		assert.Equal(t, "ldx-sync-locked", result.Settings[types.SettingSnykCodeEnabled].Source)
		assert.Equal(t, "organization", result.Settings[types.SettingSnykCodeEnabled].OriginScope)
		assert.True(t, result.Settings[types.SettingSnykCodeEnabled].IsLocked)
	})
}

// FC-104: ToLspFolderConfig and ApplyLspUpdate work correctly with thin FolderConfig wrapper (round-trip)
func Test_FC104_LspFolderConfig_RoundTrip_ToLspFolderConfig_ApplyLspUpdate(t *testing.T) {
	conf := configuration.NewWithOpts()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	require.NoError(t, conf.AddFlagSet(fs))

	prefixKeyResolver := configuration.NewConfigResolver(conf)
	cache := types.NewLDXSyncConfigCache()
	logger := zerolog.Nop()
	resolver := types.NewConfigResolver(cache, nil, &logger)
	resolver.SetPrefixKeyResolver(prefixKeyResolver, conf)

	folderPath := types.FilePath("/path/to/folder")
	fc := &types.FolderConfig{FolderPath: folderPath}
	fc.ConfigResolver = resolver
	fp := string(types.PathKey(fc.FolderPath))
	types.SetPreferredOrgAndOrgSetByUser(conf, fc.FolderPath, "org-fc104", true)
	conf.Set(configuration.UserFolderKey(fp, types.SettingBaseBranch), &configuration.LocalConfigField{Value: "main", Changed: true})
	conf.Set(configuration.UserFolderKey(fp, types.SettingReferenceBranch), &configuration.LocalConfigField{Value: "main", Changed: true})
	conf.Set(configuration.UserFolderKey(fp, types.SettingAdditionalParameters), &configuration.LocalConfigField{Value: []string{"--extra"}, Changed: true})
	types.SetAutoDeterminedOrg(conf, fc.FolderPath, "auto-org")

	lsp := fc.ToLspFolderConfig()
	require.NotNil(t, lsp)

	// Thin wrapper: only FolderPath and ConfigResolver set (as processSingleLspFolderConfig would load)
	fc2 := &types.FolderConfig{FolderPath: folderPath, ConfigResolver: resolver}
	changed := fc2.ApplyLspUpdate(lsp)
	require.True(t, changed)

	assert.Equal(t, fc.BaseBranch(), fc2.BaseBranch())
	assert.Equal(t, fc.PreferredOrg(), fc2.PreferredOrg())
	assert.True(t, fc2.OrgSetByUser())
	// AutoDeterminedOrg is LS-enriched (e.g. from LDX-Sync), not applied from IDE via ApplyLspUpdate
	assert.Equal(t, fc.AdditionalParameters(), fc2.AdditionalParameters())

	// Second round-trip: fc2 -> Lsp -> fc3
	lsp2 := fc2.ToLspFolderConfig()
	require.NotNil(t, lsp2)
	assert.Equal(t, fc2.BaseBranch(), lsp2.Settings[types.SettingBaseBranch].Value)
	assert.Equal(t, fc2.PreferredOrg(), lsp2.Settings[types.SettingPreferredOrg].Value)
}
