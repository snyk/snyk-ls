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
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

// newResolverWithConfig creates a ConfigResolver with configuration resolver wired (required for tests after 2.4.4).
// Callers write global settings directly to conf via conf.Set(configresolver.UserGlobalKey(types.SettingXxx), value).
func newResolverWithConfig(t *testing.T) (*types.ConfigResolver, configuration.Configuration) {
	t.Helper()
	conf := configuration.NewWithOpts()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	require.NoError(t, conf.AddFlagSet(fs))
	fm := workflow.ConfigurationOptionsFromFlagset(fs)
	prefixKeyResolver := configresolver.New(conf, fm)
	logger := zerolog.Nop()
	resolver := types.NewConfigResolver(&logger)
	resolver.SetPrefixKeyResolver(prefixKeyResolver, conf, fm)
	return resolver, conf
}

func TestConfigResolver_GetValue_MachineScope(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)
	conf.Set(configresolver.UserGlobalKey(types.SettingApiEndpoint), "https://api.snyk.io")

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
		emptyResolver, _ := newResolverWithConfig(t)
		// No conf.Set for SnykCodeEnabled — expect default

		value, source := emptyResolver.GetValue(types.SettingSnykCodeEnabled, nil)
		assert.Equal(t, types.ConfigSourceDefault, source, "empty string should return ConfigSourceDefault, not ConfigSourceGlobal")
		assert.True(t, value == nil || value == false || value == "", "default value when unset")
	})

	t.Run("returns global source when global string value is explicitly set", func(t *testing.T) {
		explicitResolver, conf := newResolverWithConfig(t)
		conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)

		value, source := explicitResolver.GetValue(types.SettingSnykCodeEnabled, nil)
		assert.Equal(t, true, value)
		assert.Equal(t, types.ConfigSourceGlobal, source)
	})
}

func TestConfigResolver_UsesReconciledGlobalValues(t *testing.T) {
	t.Run("SnykCode uses reconciled value from ConfigProvider when user set raw setting", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		_ = ctrl
		resolver, conf := newResolverWithConfig(t)
		conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)

		result := resolver.IsSnykCodeEnabledForFolder(nil)
		assert.True(t, result)
	})

	t.Run("org-scope global fallback returns reconciled bool value not raw string", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		_ = ctrl
		resolver, conf := newResolverWithConfig(t)
		conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
		conf.Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), true)
		conf.Set(configresolver.UserGlobalKey(types.SettingScanNetNew), false)
		conf.Set(configresolver.UserGlobalKey(types.SettingScanAutomatic), true)
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
		resolver, conf := newResolverWithConfig(t)
		conf.Set(configresolver.UserGlobalKey(types.SettingCliPath), "/usr/local/bin/snyk")

		val, source := resolver.GetValue(types.SettingCliPath, nil)
		assert.Equal(t, types.ConfigSourceGlobal, source)
		assert.Equal(t, "/usr/local/bin/snyk", val)
	})
}

func TestConfigResolver_IsSnykSecretsEnabledForFolder(t *testing.T) {
	t.Run("returns false when no setting and default fallback", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		_ = ctrl
		resolver, _ := newResolverWithConfig(t)
		assert.False(t, resolver.IsSnykSecretsEnabledForFolder(nil))
	})

	t.Run("uses reconciled value from ConfigProvider when user set global setting", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		_ = ctrl
		resolver, conf := newResolverWithConfig(t)
		conf.Set(configresolver.UserGlobalKey(types.SettingSnykSecretsEnabled), true)
		assert.True(t, resolver.IsSnykSecretsEnabledForFolder(nil))
	})

	t.Run("respects user override over global", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		_ = ctrl
		resolver, conf := newResolverWithConfig(t)
		conf.Set(configresolver.UserGlobalKey(types.SettingSnykSecretsEnabled), true)
		folderConfig := &types.FolderConfig{FolderPath: "/folder"}
		folderConfig.ConfigResolver = types.NewMinimalConfigResolver(conf)
		conf.Set(configresolver.UserFolderKey(string(types.PathKey(folderConfig.FolderPath)), types.SettingSnykSecretsEnabled), &configresolver.LocalConfigField{Value: false, Changed: true})
		assert.False(t, resolver.IsSnykSecretsEnabledForFolder(folderConfig))
	})

	t.Run("respects LDX-Sync locked value over user override", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		_ = ctrl
		orgConfig := types.NewLDXSyncOrgConfig("org1")
		orgConfig.SetField(types.SettingSnykSecretsEnabled, true, true, "group")
		resolver, conf := newResolverWithConfig(t)
		folderConfig := &types.FolderConfig{FolderPath: "/folder"}
		folderConfig.ConfigResolver = types.NewMinimalConfigResolver(conf)
		folderPath := string(types.PathKey(folderConfig.FolderPath))
		types.SetPreferredOrgAndOrgSetByUser(conf, folderConfig.FolderPath, "org1", true)
		types.WriteOrgConfigToConfiguration(conf, orgConfig)
		conf.Set(configresolver.UserFolderKey(folderPath, types.SettingSnykSecretsEnabled), &configresolver.LocalConfigField{Value: false, Changed: true})
		assert.True(t, resolver.IsSnykSecretsEnabledForFolder(folderConfig))
	})

	t.Run("falls back to global when no override and no LDX-Sync", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		_ = ctrl
		resolver, conf := newResolverWithConfig(t)
		conf.Set(configresolver.UserGlobalKey(types.SettingSnykSecretsEnabled), false)
		folderConfig := &types.FolderConfig{FolderPath: "/folder"}
		assert.False(t, resolver.IsSnykSecretsEnabledForFolder(folderConfig))
	})
}

func TestConfigResolver_GetValue_FolderScope(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)

	folderConfig := &types.FolderConfig{FolderPath: "/path/to/folder"}
	folderConfig.ConfigResolver = types.NewMinimalConfigResolver(conf)
	folderPath := string(types.PathKey(folderConfig.FolderPath))
	conf.Set(configresolver.UserFolderKey(folderPath, types.SettingBaseBranch), &configresolver.LocalConfigField{Value: "main", Changed: true})
	conf.Set(configresolver.UserFolderKey(folderPath, types.SettingReferenceBranch), &configresolver.LocalConfigField{Value: "main", Changed: true})
	conf.Set(configresolver.UserFolderKey(folderPath, types.SettingAdditionalParameters), &configresolver.LocalConfigField{Value: []string{"--debug"}, Changed: true})
	conf.Set(configresolver.UserFolderKey(folderPath, types.SettingReferenceFolder), &configresolver.LocalConfigField{Value: "/path/to/reference", Changed: true})

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
		fc.ConfigResolver = types.NewMinimalConfigResolver(conf)
		conf.Set(configresolver.FolderMetadataKey(string(types.PathKey(fc.FolderPath)), types.SettingLocalBranches), []string{"main", "develop"})
		value, source := resolver.GetValue(types.SettingLocalBranches, fc)
		assert.Equal(t, []string{"main", "develop"}, value)
		assert.Equal(t, types.ConfigSourceFolder, source)
	})

	t.Run("returns folder value for preferred_org", func(t *testing.T) {
		fc := &types.FolderConfig{FolderPath: "/path/to/folder"}
		fc.ConfigResolver = types.NewMinimalConfigResolver(conf)
		types.SetPreferredOrgAndOrgSetByUser(conf, fc.FolderPath, "my-org", true)
		value, source := resolver.GetValue(types.SettingPreferredOrg, fc)
		assert.Equal(t, "my-org", value)
		assert.Equal(t, types.ConfigSourceFolder, source)
	})

	t.Run("returns folder value for auto_determined_org", func(t *testing.T) {
		fc := &types.FolderConfig{FolderPath: "/path/to/folder"}
		fc.ConfigResolver = types.NewMinimalConfigResolver(conf)
		conf.Set(configresolver.FolderMetadataKey(string(types.PathKey(fc.FolderPath)), types.SettingAutoDeterminedOrg), "auto-org")
		value, source := resolver.GetValue(types.SettingAutoDeterminedOrg, fc)
		assert.Equal(t, "auto-org", value)
		assert.Equal(t, types.ConfigSourceFolder, source)
	})

	t.Run("returns folder value for org_set_by_user", func(t *testing.T) {
		fc := &types.FolderConfig{FolderPath: "/path/to/folder"}
		fc.ConfigResolver = types.NewMinimalConfigResolver(conf)
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
		fc.ConfigResolver = types.NewMinimalConfigResolver(conf)
		conf.Set(configresolver.UserFolderKey(string(types.PathKey(fc.FolderPath)), types.SettingScanCommandConfig), &configresolver.LocalConfigField{Value: scanConfig, Changed: true})
		value, source := resolver.GetValue(types.SettingScanCommandConfig, fc)
		assert.Equal(t, scanConfig, value)
		assert.Equal(t, types.ConfigSourceFolder, source)
	})
}

func TestConfigResolver_GetValue_OrgScope_NoLDXSync(t *testing.T) {
	ctrl := gomock.NewController(t)
	_ = ctrl
	folderConfig := &types.FolderConfig{FolderPath: "/path/to/folder"}
	resolver, conf := newResolverWithConfig(t)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	folderConfig.ConfigResolver = types.NewMinimalConfigResolver(conf)
	types.SetPreferredOrgAndOrgSetByUser(conf, folderConfig.FolderPath, "org1", true)

	t.Run("returns reconciled global value when no LDX-Sync cache", func(t *testing.T) {
		value, source := resolver.GetValue(types.SettingSnykCodeEnabled, folderConfig)
		assert.Equal(t, true, value)
		assert.Equal(t, types.ConfigSourceGlobal, source)
	})

	t.Run("returns user override when set and no LDX-Sync", func(t *testing.T) {
		conf.Set(configresolver.UserFolderKey(string(types.PathKey(folderConfig.FolderPath)), types.SettingEnabledSeverities), &configresolver.LocalConfigField{Value: []string{"critical", "high"}, Changed: true})

		value, source := resolver.GetValue(types.SettingEnabledSeverities, folderConfig)
		assert.Equal(t, []string{"critical", "high"}, value)
		assert.Equal(t, types.ConfigSourceUserOverride, source)
	})
}

func TestConfigResolver_GetValue_OrgScope_WithLDXSync(t *testing.T) {
	ctrl := gomock.NewController(t)
	_ = ctrl
	orgConfig := types.NewLDXSyncOrgConfig("org1")
	orgConfig.SetField(types.SettingEnabledSeverities, []string{"critical"}, false, "org")

	folderConfig := &types.FolderConfig{FolderPath: "/path/to/folder"}
	resolver, conf := newResolverWithConfig(t)
	folderConfig.ConfigResolver = types.NewMinimalConfigResolver(conf)
	types.SetPreferredOrgAndOrgSetByUser(conf, folderConfig.FolderPath, "org1", true)
	types.WriteOrgConfigToConfiguration(conf, orgConfig)

	t.Run("returns LDX-Sync value when no user override", func(t *testing.T) {
		value, source := resolver.GetValue(types.SettingEnabledSeverities, folderConfig)
		assert.Equal(t, []string{"critical"}, value)
		assert.Equal(t, types.ConfigSourceLDXSync, source)
	})

	t.Run("returns user override when set", func(t *testing.T) {
		conf.Set(configresolver.UserFolderKey(string(types.PathKey(folderConfig.FolderPath)), types.SettingEnabledSeverities), &configresolver.LocalConfigField{Value: []string{"critical", "high"}, Changed: true})

		value, source := resolver.GetValue(types.SettingEnabledSeverities, folderConfig)
		assert.Equal(t, []string{"critical", "high"}, value)
		assert.Equal(t, types.ConfigSourceUserOverride, source)
	})
}

func TestConfigResolver_GetValue_OrgScope_GlobalOverridesLDXSync(t *testing.T) {
	ctrl := gomock.NewController(t)
	_ = ctrl

	t.Run("global setting overrides non-locked LDX-Sync value", func(t *testing.T) {
		orgConfig := types.NewLDXSyncOrgConfig("org1")
		orgConfig.SetField(types.SettingSnykCodeEnabled, true, false, "org")

		folderConfig := &types.FolderConfig{FolderPath: "/path/to/folder"}
		innerCtrl := gomock.NewController(t)
		_ = innerCtrl
		resolver, conf := newResolverWithConfig(t)
		conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), false)
		folderConfig.ConfigResolver = types.NewMinimalConfigResolver(conf)
		types.SetPreferredOrgAndOrgSetByUser(conf, folderConfig.FolderPath, "org1", true)
		types.WriteOrgConfigToConfiguration(conf, orgConfig)

		value, source := resolver.GetValue(types.SettingSnykCodeEnabled, folderConfig)
		assert.Equal(t, false, value)
		assert.Equal(t, types.ConfigSourceGlobal, source)
	})

	t.Run("global setting does NOT override locked LDX-Sync value", func(t *testing.T) {
		orgConfig := types.NewLDXSyncOrgConfig("org1")
		orgConfig.SetField(types.SettingSnykCodeEnabled, true, true, "group")

		folderConfig := &types.FolderConfig{FolderPath: "/path/to/folder"}
		resolver, conf := newResolverWithConfig(t)
		conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), false)
		folderConfig.ConfigResolver = types.NewMinimalConfigResolver(conf)
		types.SetPreferredOrgAndOrgSetByUser(conf, folderConfig.FolderPath, "org1", true)
		types.WriteOrgConfigToConfiguration(conf, orgConfig)

		value, source := resolver.GetValue(types.SettingSnykCodeEnabled, folderConfig)
		assert.Equal(t, true, value)
		assert.Equal(t, types.ConfigSourceLDXSyncLocked, source)
	})

	t.Run("user override still wins over global when LDX-Sync present", func(t *testing.T) {
		orgConfig := types.NewLDXSyncOrgConfig("org1")
		orgConfig.SetField(types.SettingSnykCodeEnabled, true, false, "org")

		folderConfig := &types.FolderConfig{FolderPath: "/path/to/folder"}

		resolver, conf := newResolverWithConfig(t)
		conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), false)
		folderConfig.ConfigResolver = types.NewMinimalConfigResolver(conf)
		types.SetPreferredOrgAndOrgSetByUser(conf, folderConfig.FolderPath, "org1", true)
		types.WriteOrgConfigToConfiguration(conf, orgConfig)
		conf.Set(configresolver.UserFolderKey(string(types.PathKey(folderConfig.FolderPath)), types.SettingSnykCodeEnabled), &configresolver.LocalConfigField{Value: true, Changed: true})

		value, source := resolver.GetValue(types.SettingSnykCodeEnabled, folderConfig)
		assert.Equal(t, true, value)
		assert.Equal(t, types.ConfigSourceUserOverride, source)
	})

	t.Run("LDX-Sync default value used when no global and no override", func(t *testing.T) {
		orgConfig := types.NewLDXSyncOrgConfig("org1")
		orgConfig.SetField(types.SettingSnykCodeEnabled, true, false, "org")

		folderConfig := &types.FolderConfig{FolderPath: "/path/to/folder"}
		resolver, conf := newResolverWithConfig(t)
		folderConfig.ConfigResolver = types.NewMinimalConfigResolver(conf)
		types.SetPreferredOrgAndOrgSetByUser(conf, folderConfig.FolderPath, "org1", true)
		types.WriteOrgConfigToConfiguration(conf, orgConfig)

		value, source := resolver.GetValue(types.SettingSnykCodeEnabled, folderConfig)
		assert.Equal(t, true, value)
		assert.Equal(t, types.ConfigSourceLDXSync, source)
	})
}

func TestConfigResolver_GetValue_OrgScope_Locked(t *testing.T) {
	ctrl := gomock.NewController(t)
	_ = ctrl
	orgConfig := types.NewLDXSyncOrgConfig("org1")
	orgConfig.SetField(types.SettingEnabledSeverities, []string{"critical"}, true, "group")

	folderConfig := &types.FolderConfig{FolderPath: "/path/to/folder"}
	resolver, conf := newResolverWithConfig(t)
	folderConfig.ConfigResolver = types.NewMinimalConfigResolver(conf)
	types.SetPreferredOrgAndOrgSetByUser(conf, folderConfig.FolderPath, "org1", true)
	types.WriteOrgConfigToConfiguration(conf, orgConfig)

	t.Run("returns LDX-Sync locked value even when user override exists", func(t *testing.T) {
		conf.Set(configresolver.UserFolderKey(string(types.PathKey(folderConfig.FolderPath)), types.SettingEnabledSeverities), &configresolver.LocalConfigField{Value: []string{"critical", "high", "medium"}, Changed: true})

		value, source := resolver.GetValue(types.SettingEnabledSeverities, folderConfig)
		assert.Equal(t, []string{"critical"}, value)
		assert.Equal(t, types.ConfigSourceLDXSyncLocked, source)
	})
}

func TestConfigResolver_GetValue_OrgScope_DifferentOrgs(t *testing.T) {
	ctrl := gomock.NewController(t)
	_ = ctrl

	org1Config := types.NewLDXSyncOrgConfig("org1")
	org1Config.SetField(types.SettingEnabledSeverities, []string{"critical"}, false, "org")

	org2Config := types.NewLDXSyncOrgConfig("org2")
	org2Config.SetField(types.SettingEnabledSeverities, []string{"critical", "high"}, true, "group")

	folder1 := &types.FolderConfig{FolderPath: "/folder1"}
	folder2 := &types.FolderConfig{FolderPath: "/folder2"}
	resolver, conf := newResolverWithConfig(t)
	folder1.ConfigResolver = types.NewMinimalConfigResolver(conf)
	folder2.ConfigResolver = types.NewMinimalConfigResolver(conf)
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
		_ = ctrl
		orgConfig := types.NewLDXSyncOrgConfig("user-org")
		orgConfig.SetField(types.SettingEnabledSeverities, []string{"critical"}, false, "org")

		folderConfig := &types.FolderConfig{FolderPath: "/path"}
		resolver, conf := newResolverWithConfig(t)
		folderConfig.ConfigResolver = types.NewMinimalConfigResolver(conf)
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
			_ = ctrl
			orgConfig := types.NewLDXSyncOrgConfig(tc.orgForConfig)
			orgConfig.SetField(types.SettingEnabledSeverities, tc.expectedSev, false, "org")

			folderConfig := &types.FolderConfig{FolderPath: "/path"}
			resolver, conf := newResolverWithConfig(t)
			if tc.globalOrg != "" {
				conf.Set(configresolver.UserGlobalKey(types.SettingOrganization), tc.globalOrg)
			}
			folderConfig.ConfigResolver = types.NewMinimalConfigResolver(conf)
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
		_ = ctrl
		orgConfig := types.NewLDXSyncOrgConfig("org1")
		orgConfig.SetField(types.SettingEnabledSeverities, []string{"critical"}, false, "org")

		resolver, _ := newResolverWithConfig(t)

		_, source := resolver.GetValue(types.SettingEnabledSeverities, nil)
		assert.Equal(t, types.ConfigSourceDefault, source)
	})

	t.Run("returns default when no org can be determined and no global setting", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		_ = ctrl
		orgConfig := types.NewLDXSyncOrgConfig("some-org")
		orgConfig.SetField(types.SettingEnabledSeverities, []string{"critical"}, false, "org")

		folderConfig := &types.FolderConfig{FolderPath: "/path"}
		resolver, conf := newResolverWithConfig(t)
		folderConfig.ConfigResolver = types.NewMinimalConfigResolver(conf)
		types.SetPreferredOrgAndOrgSetByUser(conf, folderConfig.FolderPath, "", false)
		types.WriteOrgConfigToConfiguration(conf, orgConfig)

		_, source := resolver.GetValue(types.SettingEnabledSeverities, folderConfig)
		assert.Equal(t, types.ConfigSourceDefault, source)
	})
}

func TestConfigResolver_TypedAccessors(t *testing.T) {
	ctrl := gomock.NewController(t)
	_ = ctrl
	resolver, conf := newResolverWithConfig(t)
	conf.Set(configresolver.UserGlobalKey(types.SettingApiEndpoint), "https://api.snyk.io")
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingScanNetNew), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingRiskScoreThreshold), 500)

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
		folderConfig.ConfigResolver = types.NewMinimalConfigResolver(conf)
		conf.Set(configresolver.UserFolderKey(string(types.PathKey(folderConfig.FolderPath)), types.SettingAdditionalParameters), &configresolver.LocalConfigField{Value: []string{"--debug", "--verbose"}, Changed: true})
		value := resolver.GetStringSlice(types.SettingAdditionalParameters, folderConfig)
		assert.Equal(t, []string{"--debug", "--verbose"}, value)
	})
}

func TestConfigResolver_IsLocked(t *testing.T) {
	ctrl := gomock.NewController(t)
	_ = ctrl

	orgConfig := types.NewLDXSyncOrgConfig("org1")
	orgConfig.SetField(types.SettingEnabledSeverities, []string{"critical"}, true, "group")
	orgConfig.SetField(types.SettingSnykCodeEnabled, true, false, "org")

	folderConfig := &types.FolderConfig{FolderPath: "/path"}
	resolver, conf := newResolverWithConfig(t)
	folderConfig.ConfigResolver = types.NewMinimalConfigResolver(conf)
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

func TestConfigResolver_IsLocked_FolderLevelRemote(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)

	orgId := "org-folder-lock"
	folderPath := "/workspace/project"
	folderConfig := &types.FolderConfig{FolderPath: types.FilePath(folderPath)}
	folderConfig.ConfigResolver = types.NewMinimalConfigResolver(conf)
	types.SetPreferredOrgAndOrgSetByUser(conf, types.FilePath(folderPath), orgId, true)

	t.Run("returns true when folder-level remote is locked", func(t *testing.T) {
		key := configresolver.RemoteOrgFolderKey(orgId, folderPath, types.SettingSnykCodeEnabled)
		conf.Set(key, &configresolver.RemoteConfigField{Value: true, IsLocked: true})

		assert.True(t, resolver.IsLocked(types.SettingSnykCodeEnabled, folderConfig),
			"IsLocked should check RemoteOrgFolderKey for folder-level locks")
	})

	t.Run("returns false when only org-level is not locked", func(t *testing.T) {
		conf.Unset(configresolver.RemoteOrgFolderKey(orgId, folderPath, types.SettingScanAutomatic))
		conf.Set(configresolver.RemoteOrgKey(orgId, types.SettingScanAutomatic), &configresolver.RemoteConfigField{Value: false, IsLocked: false})

		assert.False(t, resolver.IsLocked(types.SettingScanAutomatic, folderConfig))
	})
}

func TestConfigResolver_Resolve_FolderLevelRemoteOverride(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)

	orgId := "org-resolve"
	folderPath := "/workspace/project"
	folderConfig := &types.FolderConfig{FolderPath: types.FilePath(folderPath)}
	folderConfig.ConfigResolver = types.NewMinimalConfigResolver(conf)
	types.SetPreferredOrgAndOrgSetByUser(conf, types.FilePath(folderPath), orgId, true)

	t.Run("folder-level remote overrides org-level remote", func(t *testing.T) {
		conf.Set(configresolver.RemoteOrgKey(orgId, types.SettingSnykCodeEnabled), &configresolver.RemoteConfigField{Value: false})
		conf.Set(configresolver.RemoteOrgFolderKey(orgId, folderPath, types.SettingSnykCodeEnabled), &configresolver.RemoteConfigField{Value: true})

		val, source := resolver.GetValue(types.SettingSnykCodeEnabled, folderConfig)
		assert.Equal(t, true, val, "folder-level remote should override org-level remote")
		assert.Equal(t, types.ConfigSourceLDXSync, source)
	})

	t.Run("folder-level locked remote overrides user override", func(t *testing.T) {
		conf.Set(configresolver.UserFolderKey(folderPath, types.SettingSnykCodeEnabled), &configresolver.LocalConfigField{Value: false, Changed: true})
		conf.Set(configresolver.RemoteOrgFolderKey(orgId, folderPath, types.SettingSnykCodeEnabled), &configresolver.RemoteConfigField{Value: true, IsLocked: true})

		val, source := resolver.GetValue(types.SettingSnykCodeEnabled, folderConfig)
		assert.Equal(t, true, val, "locked folder-level remote should override user override")
		assert.Equal(t, types.ConfigSourceLDXSyncLocked, source)
	})
}

func TestConfigResolver_GetSource(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)
	conf.Set(configresolver.UserGlobalKey(types.SettingApiEndpoint), "https://api.snyk.io")

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
		conf.Set(configresolver.UserFolderKey(fp, types.SettingEnabledSeverities), &configresolver.LocalConfigField{Value: []string{"critical"}, Changed: true})
		assert.True(t, types.HasUserOverride(conf, "/path", types.SettingEnabledSeverities))
	})

	t.Run("ReadFolderConfigSnapshot returns value when set via getUser", func(t *testing.T) {
		conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		fp := string(types.PathKey("/path"))
		conf.Set(configresolver.UserFolderKey(fp, types.SettingBaseBranch), &configresolver.LocalConfigField{Value: "main", Changed: true})
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
		key := configresolver.UserFolderKey(fp, types.SettingEnabledSeverities)
		conf.Set(key, &configresolver.LocalConfigField{Value: []string{"critical"}, Changed: true})
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
	_ = ctrl
	orgConfig := types.NewLDXSyncOrgConfig("org1")
	orgConfig.SetField(types.SettingEnabledSeverities, []string{"critical"}, false, "tenant")
	orgConfig.SetField(types.SettingSnykCodeEnabled, true, true, "group")

	folderConfig := &types.FolderConfig{FolderPath: "/path/to/folder"}
	resolver, conf := newResolverWithConfig(t)
	folderConfig.ConfigResolver = types.NewMinimalConfigResolver(conf)
	types.SetPreferredOrgAndOrgSetByUser(conf, folderConfig.FolderPath, "org1", true)
	fp := string(types.PathKey(folderConfig.FolderPath))
	conf.Set(configresolver.UserFolderKey(fp, types.SettingPreferredOrg), &configresolver.LocalConfigField{Value: "org1", Changed: true})
	conf.Set(configresolver.UserFolderKey(fp, types.SettingOrgSetByUser), &configresolver.LocalConfigField{Value: true, Changed: true})
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
		ctrl := gomock.NewController(t)
		_ = ctrl
		folderConfigWithOverride := &types.FolderConfig{FolderPath: "/path/to/folder"}
		folderConfigWithOverride.ConfigResolver = types.NewMinimalConfigResolver(conf)
		types.SetPreferredOrgAndOrgSetByUser(conf, folderConfigWithOverride.FolderPath, "org1", true)
		types.WriteOrgConfigToConfiguration(conf, orgConfig)
		fp := string(types.PathKey(folderConfigWithOverride.FolderPath))
		conf.Set(configresolver.UserFolderKey(fp, types.SettingEnabledSeverities), &configresolver.LocalConfigField{Value: []string{"high"}, Changed: true})

		effectiveValue := resolver.GetEffectiveValue(types.SettingEnabledSeverities, folderConfigWithOverride)

		assert.Equal(t, []string{"high"}, effectiveValue.Value)
		assert.Equal(t, "user-override", effectiveValue.Source)
		assert.Equal(t, "", effectiveValue.OriginScope)
	})

	t.Run("OriginScope is empty for global fallback", func(t *testing.T) {
		ctrlInner := gomock.NewController(t)
		_ = ctrlInner
		folderConfigNoOrg := &types.FolderConfig{
			FolderPath: "/path/to/folder",
		}
		resolverNoLdx, _ := newResolverWithConfig(t)

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
		fc.ConfigResolver = types.NewMinimalConfigResolver(conf)
		fp := string(types.PathKey(fc.FolderPath))
		conf.Set(configresolver.UserFolderKey(fp, types.SettingBaseBranch), &configresolver.LocalConfigField{Value: "main", Changed: true})
		conf.Set(configresolver.UserFolderKey(fp, types.SettingReferenceBranch), &configresolver.LocalConfigField{Value: "main", Changed: true})

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
		fc.ConfigResolver = types.NewMinimalConfigResolver(conf)
		fp := string(types.PathKey(fc.FolderPath))
		conf.Set(configresolver.UserFolderKey(fp, types.SettingBaseBranch), &configresolver.LocalConfigField{Value: "main", Changed: true})
		conf.Set(configresolver.UserFolderKey(fp, types.SettingReferenceBranch), &configresolver.LocalConfigField{Value: "main", Changed: true})

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
		fm := workflow.ConfigurationOptionsFromFlagset(fs)
		fc := &types.FolderConfig{FolderPath: "/path/to/folder"}
		fc.ConfigResolver = types.NewMinimalConfigResolver(conf)

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
		snap := types.ReadFolderConfigSnapshot(fc.Conf(), fc.FolderPath, fm)
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
		fc.ConfigResolver = types.NewMinimalConfigResolver(conf)
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
		fc.ConfigResolver = types.NewMinimalConfigResolver(conf)
		fp := string(types.PathKey(fc.FolderPath))
		conf.Set(configresolver.UserFolderKey(fp, types.SettingScanAutomatic), &configresolver.LocalConfigField{Value: true, Changed: true})
		conf.Set(configresolver.UserFolderKey(fp, types.SettingScanNetNew), &configresolver.LocalConfigField{Value: false, Changed: true})
		conf.Set(configresolver.UserFolderKey(fp, types.SettingSnykCodeEnabled), &configresolver.LocalConfigField{Value: true, Changed: true})

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
		fc.ConfigResolver = types.NewMinimalConfigResolver(conf)
		fp := string(types.PathKey(fc.FolderPath))
		conf.Set(configresolver.UserFolderKey(fp, types.SettingScanAutomatic), &configresolver.LocalConfigField{Value: true, Changed: true})

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
		fc.ConfigResolver = types.NewMinimalConfigResolver(conf)
		fp := string(types.PathKey(fc.FolderPath))
		conf.Set(configresolver.UserFolderKey(fp, types.SettingScanAutomatic), &configresolver.LocalConfigField{Value: true, Changed: true})
		conf.Set(configresolver.UserFolderKey(fp, types.SettingScanNetNew), &configresolver.LocalConfigField{Value: false, Changed: true})

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
		fc.ConfigResolver = types.NewMinimalConfigResolver(conf)

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
		cweVal := conf.Get(configresolver.UserFolderKey(fp, types.SettingCweIds))
		lf, ok := cweVal.(*configresolver.LocalConfigField)
		require.True(t, ok && lf != nil)
		assert.Equal(t, []string{"CWE-79", "CWE-89"}, lf.Value)
	})

	t.Run("clears cwe/cve/rule filter overrides via null", func(t *testing.T) {
		conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
		types.RegisterAllConfigurations(fs)
		_ = conf.AddFlagSet(fs)
		fc := &types.FolderConfig{FolderPath: "/path/to/folder"}
		fc.ConfigResolver = types.NewMinimalConfigResolver(conf)
		fp := string(types.PathKey(fc.FolderPath))
		conf.Set(configresolver.UserFolderKey(fp, types.SettingCweIds), &configresolver.LocalConfigField{Value: []string{"CWE-79"}, Changed: true})
		conf.Set(configresolver.UserFolderKey(fp, types.SettingCveIds), &configresolver.LocalConfigField{Value: []string{"CVE-2023-1234"}, Changed: true})

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
		fc.ConfigResolver = types.NewMinimalConfigResolver(conf)
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
		fc.ConfigResolver = types.NewMinimalConfigResolver(conf)
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
		fm := workflow.ConfigurationOptionsFromFlagset(fs)

		prefixKeyResolver := configresolver.New(conf, fm)
		logger := zerolog.Nop()
		resolver := types.NewConfigResolver(&logger)
		resolver.SetPrefixKeyResolver(prefixKeyResolver, conf, fm)

		fc := &types.FolderConfig{FolderPath: "/path/to/folder"}
		fc.ConfigResolver = resolver
		fp := string(types.PathKey(fc.FolderPath))
		conf.Set(configresolver.UserFolderKey(fp, types.SettingPreferredOrg), &configresolver.LocalConfigField{Value: "org1", Changed: true})
		conf.Set(configresolver.UserFolderKey(fp, types.SettingOrgSetByUser), &configresolver.LocalConfigField{Value: true, Changed: true})
		conf.Set(configresolver.UserFolderKey(fp, types.SettingBaseBranch), &configresolver.LocalConfigField{Value: "main", Changed: true})
		conf.Set(configresolver.UserFolderKey(fp, types.SettingReferenceBranch), &configresolver.LocalConfigField{Value: "main", Changed: true})
		conf.Set(configresolver.UserFolderKey(fp, types.SettingAdditionalParameters), &configresolver.LocalConfigField{Value: []string{"--debug"}, Changed: true})
		conf.Set(configresolver.UserFolderKey(fp, types.SettingAdditionalEnvironment), &configresolver.LocalConfigField{Value: "DEBUG=1", Changed: true})
		conf.Set(configresolver.UserFolderKey(fp, types.SettingReferenceFolder), &configresolver.LocalConfigField{Value: "/ref/path", Changed: true})
		conf.Set(configresolver.FolderMetadataKey(fp, types.SettingLocalBranches), []string{"main", "develop"})
		conf.Set(configresolver.FolderMetadataKey(fp, types.SettingAutoDeterminedOrg), "auto-org")

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
		_ = ctrl
		fc := &types.FolderConfig{FolderPath: "/path/to/folder"}

		resolver, conf := newResolverWithConfig(t)
		conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
		conf.Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), true)
		conf.Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), false)
		conf.Set(configresolver.UserGlobalKey(types.SettingScanAutomatic), true)
		conf.Set(configresolver.UserGlobalKey(types.SettingScanNetNew), true)
		fc.ConfigResolver = resolver
		fp := string(types.PathKey(fc.FolderPath))
		conf.Set(configresolver.UserFolderKey(fp, types.SettingPreferredOrg), &configresolver.LocalConfigField{Value: "org1", Changed: true})
		conf.Set(configresolver.UserFolderKey(fp, types.SettingOrgSetByUser), &configresolver.LocalConfigField{Value: true, Changed: true})

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
		orgConfig := types.NewLDXSyncOrgConfig("org1")
		orgConfig.SetField(types.SettingSnykCodeEnabled, false, true, "organization")

		ctrl := gomock.NewController(t)
		_ = ctrl
		resolver, conf := newResolverWithConfig(t)
		conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)

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
	fm := workflow.ConfigurationOptionsFromFlagset(fs)

	prefixKeyResolver := configresolver.New(conf, fm)
	logger := zerolog.Nop()
	resolver := types.NewConfigResolver(&logger)
	resolver.SetPrefixKeyResolver(prefixKeyResolver, conf, fm)

	folderPath := types.FilePath("/path/to/folder")
	fc := &types.FolderConfig{FolderPath: folderPath}
	fc.ConfigResolver = resolver
	fp := string(types.PathKey(fc.FolderPath))
	types.SetPreferredOrgAndOrgSetByUser(conf, fc.FolderPath, "org-fc104", true)
	conf.Set(configresolver.UserFolderKey(fp, types.SettingBaseBranch), &configresolver.LocalConfigField{Value: "main", Changed: true})
	conf.Set(configresolver.UserFolderKey(fp, types.SettingReferenceBranch), &configresolver.LocalConfigField{Value: "main", Changed: true})
	conf.Set(configresolver.UserFolderKey(fp, types.SettingAdditionalParameters), &configresolver.LocalConfigField{Value: []string{"--extra"}, Changed: true})
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

// Integration tests: full config resolution pipeline
// These test the config resolution with all layers (GAF resolver, prefix keys, scopes)
// using a real Configuration instance, not mocks.

func TestInteg_ConfigResolution_FolderLevelRemotePrecedence(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)

	orgId := "integ-org"
	folderPath := "/integ/workspace/project"
	fc := &types.FolderConfig{FolderPath: types.FilePath(folderPath), ConfigResolver: resolver}
	types.SetPreferredOrgAndOrgSetByUser(conf, types.FilePath(folderPath), orgId, true)

	t.Run("default value when no remote config", func(t *testing.T) {
		val, source := resolver.GetValue(types.SettingSnykCodeEnabled, fc)
		assert.Equal(t, false, val)
		assert.Equal(t, types.ConfigSourceDefault, source)
	})

	t.Run("org-level remote value applied", func(t *testing.T) {
		conf.Set(configresolver.RemoteOrgKey(orgId, types.SettingSnykCodeEnabled), &configresolver.RemoteConfigField{Value: true})
		val, source := resolver.GetValue(types.SettingSnykCodeEnabled, fc)
		assert.Equal(t, true, val)
		assert.Equal(t, types.ConfigSourceLDXSync, source)
	})

	t.Run("folder-level remote overrides org-level remote", func(t *testing.T) {
		conf.Set(configresolver.RemoteOrgFolderKey(orgId, folderPath, types.SettingSnykCodeEnabled), &configresolver.RemoteConfigField{Value: false})
		val, source := resolver.GetValue(types.SettingSnykCodeEnabled, fc)
		assert.Equal(t, false, val, "folder-level remote should override org-level")
		assert.Equal(t, types.ConfigSourceLDXSync, source)
	})

	t.Run("non-locked remote folder takes precedence over user global", func(t *testing.T) {
		// GAF folder-scope chain: remote folder > user global > remote org
		conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
		val, source := resolver.GetValue(types.SettingSnykCodeEnabled, fc)
		assert.Equal(t, false, val)
		assert.Equal(t, types.ConfigSourceLDXSync, source)
	})

	t.Run("user folder override takes precedence over user global", func(t *testing.T) {
		conf.Set(configresolver.UserFolderKey(folderPath, types.SettingSnykCodeEnabled), &configresolver.LocalConfigField{Value: false, Changed: true})
		val, source := resolver.GetValue(types.SettingSnykCodeEnabled, fc)
		assert.Equal(t, false, val)
		assert.Equal(t, types.ConfigSourceUserOverride, source)
	})

	t.Run("folder-level locked remote overrides everything", func(t *testing.T) {
		conf.Set(configresolver.RemoteOrgFolderKey(orgId, folderPath, types.SettingSnykCodeEnabled), &configresolver.RemoteConfigField{Value: true, IsLocked: true})
		val, source := resolver.GetValue(types.SettingSnykCodeEnabled, fc)
		assert.Equal(t, true, val, "locked folder remote should override all user settings")
		assert.Equal(t, types.ConfigSourceLDXSyncLocked, source)
		assert.True(t, resolver.IsLocked(types.SettingSnykCodeEnabled, fc))
	})
}

func TestInteg_ConfigResolution_MultiFolderDifferentRemoteLevels(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)

	orgId := "shared-org"
	folder1 := "/integ/folder1"
	folder2 := "/integ/folder2"

	fc1 := &types.FolderConfig{FolderPath: types.FilePath(folder1), ConfigResolver: resolver}
	fc2 := &types.FolderConfig{FolderPath: types.FilePath(folder2), ConfigResolver: resolver}
	types.SetPreferredOrgAndOrgSetByUser(conf, types.FilePath(folder1), orgId, true)
	types.SetPreferredOrgAndOrgSetByUser(conf, types.FilePath(folder2), orgId, true)

	// Org-level remote: code enabled
	conf.Set(configresolver.RemoteOrgKey(orgId, types.SettingSnykCodeEnabled), &configresolver.RemoteConfigField{Value: true})

	// Folder1: folder-level remote overrides to disabled
	conf.Set(configresolver.RemoteOrgFolderKey(orgId, folder1, types.SettingSnykCodeEnabled), &configresolver.RemoteConfigField{Value: false})

	// Folder2: no folder-level override, uses org-level
	val1, _ := resolver.GetValue(types.SettingSnykCodeEnabled, fc1)
	val2, _ := resolver.GetValue(types.SettingSnykCodeEnabled, fc2)

	assert.Equal(t, false, val1, "folder1 should use folder-level remote override (disabled)")
	assert.Equal(t, true, val2, "folder2 should use org-level remote (enabled)")
}

func TestInteg_ConfigResolution_WriteFolderConfig_RoundTrip(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)

	orgId := "roundtrip-org"
	folderPath := "/integ/roundtrip"
	fc := &types.FolderConfig{FolderPath: types.FilePath(folderPath), ConfigResolver: resolver}
	types.SetPreferredOrgAndOrgSetByUser(conf, types.FilePath(folderPath), orgId, true)

	// Simulate LDX-Sync writing folder-level settings
	folderSettings := map[string]*types.LDXSyncField{
		types.SettingSnykCodeEnabled: {Value: true, IsLocked: true, OriginScope: "org"},
		types.SettingScanAutomatic:   {Value: false, IsLocked: false, OriginScope: "group"},
	}
	types.WriteFolderConfigToConfiguration(conf, orgId, types.FilePath(folderPath), folderSettings)

	// Verify through resolver
	val, source := resolver.GetValue(types.SettingSnykCodeEnabled, fc)
	assert.Equal(t, true, val)
	assert.Equal(t, types.ConfigSourceLDXSyncLocked, source)
	assert.True(t, resolver.IsLocked(types.SettingSnykCodeEnabled, fc))

	val2, source2 := resolver.GetValue(types.SettingScanAutomatic, fc)
	assert.Equal(t, false, val2)
	assert.Equal(t, types.ConfigSourceLDXSync, source2)
	assert.False(t, resolver.IsLocked(types.SettingScanAutomatic, fc))
}

func TestInteg_ConfigResolution_MachineScopePrecedence(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)

	fc := &types.FolderConfig{FolderPath: "/integ/machine"}

	t.Run("default value", func(t *testing.T) {
		val, source := resolver.GetValue(types.SettingApiEndpoint, fc)
		assert.Equal(t, "", val)
		assert.Equal(t, types.ConfigSourceDefault, source)
	})

	t.Run("remote machine value", func(t *testing.T) {
		conf.Set(configresolver.RemoteMachineKey(types.SettingApiEndpoint), &configresolver.RemoteConfigField{Value: "https://remote.api"})
		val, source := resolver.GetValue(types.SettingApiEndpoint, fc)
		assert.Equal(t, "https://remote.api", val)
		assert.Equal(t, types.ConfigSourceLDXSync, source)
	})

	t.Run("user global overrides remote", func(t *testing.T) {
		conf.Set(configresolver.UserGlobalKey(types.SettingApiEndpoint), "https://user.api")
		val, source := resolver.GetValue(types.SettingApiEndpoint, fc)
		assert.Equal(t, "https://user.api", val)
		assert.Equal(t, types.ConfigSourceGlobal, source)
	})

	t.Run("locked remote overrides user global", func(t *testing.T) {
		conf.Set(configresolver.RemoteMachineKey(types.SettingApiEndpoint), &configresolver.RemoteConfigField{Value: "https://locked.api", IsLocked: true})
		val, source := resolver.GetValue(types.SettingApiEndpoint, fc)
		assert.Equal(t, "https://locked.api", val)
		assert.Equal(t, types.ConfigSourceLDXSyncLocked, source)
		assert.True(t, resolver.IsLocked(types.SettingApiEndpoint, fc))
	})
}

func TestInteg_ConfigResolution_FolderScopePrecedence(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)

	orgId := "folder-scope-org"
	folderPath := "/integ/folder-scope"
	fc := &types.FolderConfig{FolderPath: types.FilePath(folderPath), ConfigResolver: resolver}
	types.SetPreferredOrgAndOrgSetByUser(conf, types.FilePath(folderPath), orgId, true)

	t.Run("default value", func(t *testing.T) {
		val, source := resolver.GetValue(types.SettingReferenceBranch, fc)
		assert.Equal(t, "", val)
		assert.Equal(t, types.ConfigSourceDefault, source)
	})

	t.Run("user global overrides default", func(t *testing.T) {
		conf.Set(configresolver.UserGlobalKey(types.SettingReferenceBranch), "global-branch")
		val, source := resolver.GetValue(types.SettingReferenceBranch, fc)
		assert.Equal(t, "global-branch", val)
		assert.Equal(t, types.ConfigSourceGlobal, source)
	})

	t.Run("user global takes precedence over non-locked remote org", func(t *testing.T) {
		// GAF folder-scope chain: remote folder > user global > remote org (when no remote folder set)
		conf.Set(configresolver.RemoteOrgKey(orgId, types.SettingReferenceBranch), &configresolver.RemoteConfigField{Value: "remote-org-branch"})
		val, source := resolver.GetValue(types.SettingReferenceBranch, fc)
		assert.Equal(t, "global-branch", val)
		assert.Equal(t, types.ConfigSourceGlobal, source)
	})

	t.Run("remote folder overrides remote org", func(t *testing.T) {
		conf.Set(configresolver.RemoteOrgFolderKey(orgId, folderPath, types.SettingReferenceBranch), &configresolver.RemoteConfigField{Value: "remote-folder-branch"})
		val, source := resolver.GetValue(types.SettingReferenceBranch, fc)
		assert.Equal(t, "remote-folder-branch", val)
		assert.Equal(t, types.ConfigSourceLDXSync, source)
	})

	t.Run("folder value overrides remote folder", func(t *testing.T) {
		conf.Set(configresolver.UserFolderKey(folderPath, types.SettingReferenceBranch), &configresolver.LocalConfigField{Value: "main", Changed: true})
		val, source := resolver.GetValue(types.SettingReferenceBranch, fc)
		assert.Equal(t, "main", val)
		assert.Equal(t, types.ConfigSourceFolder, source)
	})

	t.Run("locked remote overrides folder value", func(t *testing.T) {
		conf.Set(configresolver.RemoteOrgFolderKey(orgId, folderPath, types.SettingReferenceBranch), &configresolver.RemoteConfigField{Value: "locked-branch", IsLocked: true})
		val, source := resolver.GetValue(types.SettingReferenceBranch, fc)
		assert.Equal(t, "locked-branch", val)
		assert.Equal(t, types.ConfigSourceLDXSyncLocked, source)
		assert.True(t, resolver.IsLocked(types.SettingReferenceBranch, fc))
	})
}

// --- Exhaustive precedence coverage ---

// Machine scope: locked remote > user global > remote > default
func TestInteg_MachinePrecedence_RemoteOnlyOverridesDefault(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)
	fc := &types.FolderConfig{FolderPath: "/m/1"}

	conf.Set(configresolver.RemoteMachineKey(types.SettingCodeEndpoint), &configresolver.RemoteConfigField{Value: "https://remote.code"})
	val, source := resolver.GetValue(types.SettingCodeEndpoint, fc)
	assert.Equal(t, "https://remote.code", val)
	assert.Equal(t, types.ConfigSourceLDXSync, source)
}

func TestInteg_MachinePrecedence_LockedRemoteOnlyOverridesDefault(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)
	fc := &types.FolderConfig{FolderPath: "/m/2"}

	conf.Set(configresolver.RemoteMachineKey(types.SettingCodeEndpoint), &configresolver.RemoteConfigField{Value: "https://locked.code", IsLocked: true})
	val, source := resolver.GetValue(types.SettingCodeEndpoint, fc)
	assert.Equal(t, "https://locked.code", val)
	assert.Equal(t, types.ConfigSourceLDXSyncLocked, source)
	assert.True(t, resolver.IsLocked(types.SettingCodeEndpoint, fc))
}

func TestInteg_MachinePrecedence_UserGlobalOnlyOverridesDefault(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)
	fc := &types.FolderConfig{FolderPath: "/m/3"}

	conf.Set(configresolver.UserGlobalKey(types.SettingCodeEndpoint), "https://user.code")
	val, source := resolver.GetValue(types.SettingCodeEndpoint, fc)
	assert.Equal(t, "https://user.code", val)
	assert.Equal(t, types.ConfigSourceGlobal, source)
}

func TestInteg_MachinePrecedence_UserGlobalDoesNotOverrideLocked(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)
	fc := &types.FolderConfig{FolderPath: "/m/4"}

	conf.Set(configresolver.UserGlobalKey(types.SettingCodeEndpoint), "https://user.code")
	conf.Set(configresolver.RemoteMachineKey(types.SettingCodeEndpoint), &configresolver.RemoteConfigField{Value: "https://locked.code", IsLocked: true})
	val, source := resolver.GetValue(types.SettingCodeEndpoint, fc)
	assert.Equal(t, "https://locked.code", val)
	assert.Equal(t, types.ConfigSourceLDXSyncLocked, source)
}

func TestInteg_MachinePrecedence_NilFolderConfig(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)

	conf.Set(configresolver.UserGlobalKey(types.SettingApiEndpoint), "https://api.test")
	val, source := resolver.GetValue(types.SettingApiEndpoint, nil)
	assert.Equal(t, "https://api.test", val)
	assert.Equal(t, types.ConfigSourceGlobal, source)
}

// Org scope: locked remote [folder then org] > user folder override > user global > remote [folder then org] > default
func TestInteg_OrgPrecedence_OrgLevelLockedOverridesUserOverride(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)

	orgId := "org-locked-test"
	folderPath := "/org/locked"
	fc := &types.FolderConfig{FolderPath: types.FilePath(folderPath), ConfigResolver: resolver}
	types.SetPreferredOrgAndOrgSetByUser(conf, types.FilePath(folderPath), orgId, true)

	conf.Set(configresolver.UserFolderKey(folderPath, types.SettingSnykOssEnabled), &configresolver.LocalConfigField{Value: true, Changed: true})
	conf.Set(configresolver.RemoteOrgKey(orgId, types.SettingSnykOssEnabled), &configresolver.RemoteConfigField{Value: false, IsLocked: true})

	val, source := resolver.GetValue(types.SettingSnykOssEnabled, fc)
	assert.Equal(t, false, val, "org-level locked should override user folder override")
	assert.Equal(t, types.ConfigSourceLDXSyncLocked, source)
	assert.True(t, resolver.IsLocked(types.SettingSnykOssEnabled, fc))
}

func TestInteg_OrgPrecedence_RemoteOrgOnlyOverridesDefault(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)

	orgId := "org-remote-only"
	folderPath := "/org/remote-only"
	fc := &types.FolderConfig{FolderPath: types.FilePath(folderPath), ConfigResolver: resolver}
	types.SetPreferredOrgAndOrgSetByUser(conf, types.FilePath(folderPath), orgId, true)

	conf.Set(configresolver.RemoteOrgKey(orgId, types.SettingSnykIacEnabled), &configresolver.RemoteConfigField{Value: true})
	val, source := resolver.GetValue(types.SettingSnykIacEnabled, fc)
	assert.Equal(t, true, val)
	assert.Equal(t, types.ConfigSourceLDXSync, source)
}

func TestInteg_OrgPrecedence_UserGlobalOnlyOverridesDefault(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)

	folderPath := "/org/global-only"
	fc := &types.FolderConfig{FolderPath: types.FilePath(folderPath), ConfigResolver: resolver}

	conf.Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), true)
	val, source := resolver.GetValue(types.SettingSnykIacEnabled, fc)
	assert.Equal(t, true, val)
	assert.Equal(t, types.ConfigSourceGlobal, source)
}

func TestInteg_OrgPrecedence_UserFolderOverrideOnlyOverridesDefault(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)

	folderPath := "/org/user-override-only"
	fc := &types.FolderConfig{FolderPath: types.FilePath(folderPath), ConfigResolver: resolver}

	conf.Set(configresolver.UserFolderKey(folderPath, types.SettingScanAutomatic), &configresolver.LocalConfigField{Value: true, Changed: true})
	val, source := resolver.GetValue(types.SettingScanAutomatic, fc)
	assert.Equal(t, true, val)
	assert.Equal(t, types.ConfigSourceUserOverride, source)
}

func TestInteg_OrgPrecedence_FolderLockedTakesPrecedenceOverOrgLocked(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)

	orgId := "org-both-locked"
	folderPath := "/org/both-locked"
	fc := &types.FolderConfig{FolderPath: types.FilePath(folderPath), ConfigResolver: resolver}
	types.SetPreferredOrgAndOrgSetByUser(conf, types.FilePath(folderPath), orgId, true)

	conf.Set(configresolver.RemoteOrgKey(orgId, types.SettingScanAutomatic), &configresolver.RemoteConfigField{Value: true, IsLocked: true})
	conf.Set(configresolver.RemoteOrgFolderKey(orgId, folderPath, types.SettingScanAutomatic), &configresolver.RemoteConfigField{Value: false, IsLocked: true})

	val, source := resolver.GetValue(types.SettingScanAutomatic, fc)
	assert.Equal(t, false, val, "folder-level locked should take precedence over org-level locked")
	assert.Equal(t, types.ConfigSourceLDXSyncLocked, source)
}

func TestInteg_OrgPrecedence_RemoteFolderOnlyOverridesDefault(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)

	orgId := "org-remote-folder-only"
	folderPath := "/org/remote-folder-only"
	fc := &types.FolderConfig{FolderPath: types.FilePath(folderPath), ConfigResolver: resolver}
	types.SetPreferredOrgAndOrgSetByUser(conf, types.FilePath(folderPath), orgId, true)

	conf.Set(configresolver.RemoteOrgFolderKey(orgId, folderPath, types.SettingSnykSecretsEnabled), &configresolver.RemoteConfigField{Value: true})
	val, source := resolver.GetValue(types.SettingSnykSecretsEnabled, fc)
	assert.Equal(t, true, val)
	assert.Equal(t, types.ConfigSourceLDXSync, source)
}

func TestInteg_OrgPrecedence_RemoteFolderTakesPrecedenceOverUserGlobal(t *testing.T) {
	// GAF folder-scope chain: remote folder > user global > remote org
	resolver, conf := newResolverWithConfig(t)

	orgId := "org-user-global-over-remote"
	folderPath := "/org/user-global-over-remote"
	fc := &types.FolderConfig{FolderPath: types.FilePath(folderPath), ConfigResolver: resolver}
	types.SetPreferredOrgAndOrgSetByUser(conf, types.FilePath(folderPath), orgId, true)

	conf.Set(configresolver.RemoteOrgKey(orgId, types.SettingSnykCodeEnabled), &configresolver.RemoteConfigField{Value: false})
	conf.Set(configresolver.RemoteOrgFolderKey(orgId, folderPath, types.SettingSnykCodeEnabled), &configresolver.RemoteConfigField{Value: false})
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)

	val, source := resolver.GetValue(types.SettingSnykCodeEnabled, fc)
	assert.Equal(t, false, val, "non-locked remote folder takes precedence over user global in folder-scope chain")
	assert.Equal(t, types.ConfigSourceLDXSync, source)
}

// Folder scope: locked remote [folder then org] > folder value > remote [folder then org] > user global > default
func TestInteg_FolderPrecedence_OrgLevelLockedOverridesFolderValue(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)

	orgId := "folder-org-locked"
	folderPath := "/folder/org-locked"
	fc := &types.FolderConfig{FolderPath: types.FilePath(folderPath), ConfigResolver: resolver}
	types.SetPreferredOrgAndOrgSetByUser(conf, types.FilePath(folderPath), orgId, true)

	conf.Set(configresolver.UserFolderKey(folderPath, types.SettingAdditionalEnvironment), &configresolver.LocalConfigField{Value: "USER_VAR=1", Changed: true})
	conf.Set(configresolver.RemoteOrgKey(orgId, types.SettingAdditionalEnvironment), &configresolver.RemoteConfigField{Value: "LOCKED_VAR=1", IsLocked: true})

	val, source := resolver.GetValue(types.SettingAdditionalEnvironment, fc)
	assert.Equal(t, "LOCKED_VAR=1", val, "org-level locked should override folder value")
	assert.Equal(t, types.ConfigSourceLDXSyncLocked, source)
	assert.True(t, resolver.IsLocked(types.SettingAdditionalEnvironment, fc))
}

func TestInteg_FolderPrecedence_FolderLockedTakesPrecedenceOverOrgLocked(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)

	orgId := "folder-both-locked"
	folderPath := "/folder/both-locked"
	fc := &types.FolderConfig{FolderPath: types.FilePath(folderPath), ConfigResolver: resolver}
	types.SetPreferredOrgAndOrgSetByUser(conf, types.FilePath(folderPath), orgId, true)

	conf.Set(configresolver.RemoteOrgKey(orgId, types.SettingAdditionalEnvironment), &configresolver.RemoteConfigField{Value: "ORG_LOCKED=1", IsLocked: true})
	conf.Set(configresolver.RemoteOrgFolderKey(orgId, folderPath, types.SettingAdditionalEnvironment), &configresolver.RemoteConfigField{Value: "FOLDER_LOCKED=1", IsLocked: true})

	val, source := resolver.GetValue(types.SettingAdditionalEnvironment, fc)
	assert.Equal(t, "FOLDER_LOCKED=1", val, "folder-level locked should take precedence over org-level locked")
	assert.Equal(t, types.ConfigSourceLDXSyncLocked, source)
}

func TestInteg_FolderPrecedence_UserGlobalTakesPrecedenceOverRemoteOrg(t *testing.T) {
	// GAF folder-scope chain: remote folder > user global > remote org (when no remote folder)
	resolver, conf := newResolverWithConfig(t)

	orgId := "folder-remote-org-only"
	folderPath := "/folder/remote-org-only"
	fc := &types.FolderConfig{FolderPath: types.FilePath(folderPath), ConfigResolver: resolver}
	types.SetPreferredOrgAndOrgSetByUser(conf, types.FilePath(folderPath), orgId, true)

	conf.Set(configresolver.UserGlobalKey(types.SettingAdditionalEnvironment), "GLOBAL=1")
	conf.Set(configresolver.RemoteOrgKey(orgId, types.SettingAdditionalEnvironment), &configresolver.RemoteConfigField{Value: "REMOTE_ORG=1"})

	val, source := resolver.GetValue(types.SettingAdditionalEnvironment, fc)
	assert.Equal(t, "GLOBAL=1", val, "user global takes precedence over non-locked remote org in folder-scope chain")
	assert.Equal(t, types.ConfigSourceGlobal, source)
}

func TestInteg_FolderPrecedence_FolderValueOverridesRemoteOrg(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)

	orgId := "folder-value-over-org"
	folderPath := "/folder/value-over-org"
	fc := &types.FolderConfig{FolderPath: types.FilePath(folderPath), ConfigResolver: resolver}
	types.SetPreferredOrgAndOrgSetByUser(conf, types.FilePath(folderPath), orgId, true)

	conf.Set(configresolver.RemoteOrgKey(orgId, types.SettingAdditionalEnvironment), &configresolver.RemoteConfigField{Value: "REMOTE=1"})
	conf.Set(configresolver.UserFolderKey(folderPath, types.SettingAdditionalEnvironment), &configresolver.LocalConfigField{Value: "LOCAL=1", Changed: true})

	val, source := resolver.GetValue(types.SettingAdditionalEnvironment, fc)
	assert.Equal(t, "LOCAL=1", val, "folder value should override non-locked remote org")
	assert.Equal(t, types.ConfigSourceFolder, source)
}

// Isolated adjacent-pair tests that the cumulative chains cover only transitively

func TestInteg_FolderPrecedence_FolderValueOverridesUserGlobal(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)

	orgId := "folder-val-vs-global"
	folderPath := "/folder/val-vs-global"
	fc := &types.FolderConfig{FolderPath: types.FilePath(folderPath), ConfigResolver: resolver}
	types.SetPreferredOrgAndOrgSetByUser(conf, types.FilePath(folderPath), orgId, true)

	conf.Set(configresolver.UserGlobalKey(types.SettingAdditionalEnvironment), "GLOBAL=1")
	conf.Set(configresolver.UserFolderKey(folderPath, types.SettingAdditionalEnvironment), &configresolver.LocalConfigField{Value: "FOLDER=1", Changed: true})

	val, source := resolver.GetValue(types.SettingAdditionalEnvironment, fc)
	assert.Equal(t, "FOLDER=1", val, "folder value should override user global when no remote is set")
	assert.Equal(t, types.ConfigSourceFolder, source)
}

func TestInteg_FolderPrecedence_RemoteFolderOverridesUserGlobal(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)

	orgId := "folder-remote-vs-global"
	folderPath := "/folder/remote-vs-global"
	fc := &types.FolderConfig{FolderPath: types.FilePath(folderPath), ConfigResolver: resolver}
	types.SetPreferredOrgAndOrgSetByUser(conf, types.FilePath(folderPath), orgId, true)

	conf.Set(configresolver.UserGlobalKey(types.SettingAdditionalEnvironment), "GLOBAL=1")
	conf.Set(configresolver.RemoteOrgFolderKey(orgId, folderPath, types.SettingAdditionalEnvironment), &configresolver.RemoteConfigField{Value: "REMOTE_FOLDER=1"})

	val, source := resolver.GetValue(types.SettingAdditionalEnvironment, fc)
	assert.Equal(t, "REMOTE_FOLDER=1", val, "remote folder should override user global when no folder value is set")
	assert.Equal(t, types.ConfigSourceLDXSync, source)
}

func TestInteg_OrgPrecedence_UserFolderOverrideOverridesRemoteFolder(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)

	orgId := "org-override-vs-remote"
	folderPath := "/org/override-vs-remote"
	fc := &types.FolderConfig{FolderPath: types.FilePath(folderPath), ConfigResolver: resolver}
	types.SetPreferredOrgAndOrgSetByUser(conf, types.FilePath(folderPath), orgId, true)

	conf.Set(configresolver.RemoteOrgFolderKey(orgId, folderPath, types.SettingSnykCodeEnabled), &configresolver.RemoteConfigField{Value: false})
	conf.Set(configresolver.RemoteOrgKey(orgId, types.SettingSnykCodeEnabled), &configresolver.RemoteConfigField{Value: false})
	conf.Set(configresolver.UserFolderKey(folderPath, types.SettingSnykCodeEnabled), &configresolver.LocalConfigField{Value: true, Changed: true})

	val, source := resolver.GetValue(types.SettingSnykCodeEnabled, fc)
	assert.Equal(t, true, val, "user folder override should beat non-locked folder-level and org-level remote")
	assert.Equal(t, types.ConfigSourceUserOverride, source)
}

func TestInteg_FolderPrecedence_FolderValueOverridesRemoteFolder(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)

	orgId := "folder-val-vs-remote-folder"
	folderPath := "/folder/val-vs-remote-folder"
	fc := &types.FolderConfig{FolderPath: types.FilePath(folderPath), ConfigResolver: resolver}
	types.SetPreferredOrgAndOrgSetByUser(conf, types.FilePath(folderPath), orgId, true)

	conf.Set(configresolver.RemoteOrgFolderKey(orgId, folderPath, types.SettingBaseBranch), &configresolver.RemoteConfigField{Value: "remote-branch"})
	conf.Set(configresolver.UserFolderKey(folderPath, types.SettingBaseBranch), &configresolver.LocalConfigField{Value: "local-branch", Changed: true})

	val, source := resolver.GetValue(types.SettingBaseBranch, fc)
	assert.Equal(t, "local-branch", val, "folder value should override non-locked remote folder")
	assert.Equal(t, types.ConfigSourceFolder, source)
}

func TestInteg_FolderPrecedence_RemoteFolderOverridesRemoteOrg(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)

	orgId := "folder-remote-vs-org-remote"
	folderPath := "/folder/remote-vs-org"
	fc := &types.FolderConfig{FolderPath: types.FilePath(folderPath), ConfigResolver: resolver}
	types.SetPreferredOrgAndOrgSetByUser(conf, types.FilePath(folderPath), orgId, true)

	conf.Set(configresolver.RemoteOrgKey(orgId, types.SettingBaseBranch), &configresolver.RemoteConfigField{Value: "org-branch"})
	conf.Set(configresolver.RemoteOrgFolderKey(orgId, folderPath, types.SettingBaseBranch), &configresolver.RemoteConfigField{Value: "folder-branch"})

	val, source := resolver.GetValue(types.SettingBaseBranch, fc)
	assert.Equal(t, "folder-branch", val, "remote folder should override remote org")
	assert.Equal(t, types.ConfigSourceLDXSync, source)
}

func TestInteg_FolderPrecedence_UserGlobalOverridesDefault(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)

	orgId := "folder-global-vs-default"
	folderPath := "/folder/global-vs-default"
	fc := &types.FolderConfig{FolderPath: types.FilePath(folderPath), ConfigResolver: resolver}
	types.SetPreferredOrgAndOrgSetByUser(conf, types.FilePath(folderPath), orgId, true)

	conf.Set(configresolver.UserGlobalKey(types.SettingBaseBranch), "global-branch")

	val, source := resolver.GetValue(types.SettingBaseBranch, fc)
	assert.Equal(t, "global-branch", val, "user global should override default for folder-scope setting")
	assert.Equal(t, types.ConfigSourceGlobal, source)
}

func TestInteg_OrgPrecedence_UserFolderOverrideOverridesUserGlobal(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)

	orgId := "org-override-vs-global"
	folderPath := "/org/override-vs-global"
	fc := &types.FolderConfig{FolderPath: types.FilePath(folderPath), ConfigResolver: resolver}
	types.SetPreferredOrgAndOrgSetByUser(conf, types.FilePath(folderPath), orgId, true)

	conf.Set(configresolver.UserGlobalKey(types.SettingScanAutomatic), false)
	conf.Set(configresolver.UserFolderKey(folderPath, types.SettingScanAutomatic), &configresolver.LocalConfigField{Value: true, Changed: true})

	val, source := resolver.GetValue(types.SettingScanAutomatic, fc)
	assert.Equal(t, true, val, "user folder override should beat user global")
	assert.Equal(t, types.ConfigSourceUserOverride, source)
}

func TestInteg_OrgPrecedence_RemoteFolderOverridesRemoteOrg(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)

	orgId := "org-remote-folder-vs-org"
	folderPath := "/org/remote-folder-vs-org"
	fc := &types.FolderConfig{FolderPath: types.FilePath(folderPath), ConfigResolver: resolver}
	types.SetPreferredOrgAndOrgSetByUser(conf, types.FilePath(folderPath), orgId, true)

	conf.Set(configresolver.RemoteOrgKey(orgId, types.SettingScanNetNew), &configresolver.RemoteConfigField{Value: true})
	conf.Set(configresolver.RemoteOrgFolderKey(orgId, folderPath, types.SettingScanNetNew), &configresolver.RemoteConfigField{Value: false})

	val, source := resolver.GetValue(types.SettingScanNetNew, fc)
	assert.Equal(t, false, val, "remote folder should override remote org in org scope")
	assert.Equal(t, types.ConfigSourceLDXSync, source)
}

// Multi-folder isolation tests
func TestInteg_OrgPrecedence_MultiFolderDifferentOrgs_IndependentResolution(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)

	org1, org2 := "org-alpha", "org-beta"
	f1, f2 := "/multi/folder1", "/multi/folder2"
	fc1 := &types.FolderConfig{FolderPath: types.FilePath(f1), ConfigResolver: resolver}
	fc2 := &types.FolderConfig{FolderPath: types.FilePath(f2), ConfigResolver: resolver}
	types.SetPreferredOrgAndOrgSetByUser(conf, types.FilePath(f1), org1, true)
	types.SetPreferredOrgAndOrgSetByUser(conf, types.FilePath(f2), org2, true)

	// Org1: code enabled via remote, Org2: code disabled via locked remote
	conf.Set(configresolver.RemoteOrgKey(org1, types.SettingSnykCodeEnabled), &configresolver.RemoteConfigField{Value: true})
	conf.Set(configresolver.RemoteOrgKey(org2, types.SettingSnykCodeEnabled), &configresolver.RemoteConfigField{Value: false, IsLocked: true})
	// Folder2 user override should be blocked by locked
	conf.Set(configresolver.UserFolderKey(f2, types.SettingSnykCodeEnabled), &configresolver.LocalConfigField{Value: true, Changed: true})

	val1, src1 := resolver.GetValue(types.SettingSnykCodeEnabled, fc1)
	val2, src2 := resolver.GetValue(types.SettingSnykCodeEnabled, fc2)

	assert.Equal(t, true, val1)
	assert.Equal(t, types.ConfigSourceLDXSync, src1)
	assert.Equal(t, false, val2, "locked org remote should block user override in folder2")
	assert.Equal(t, types.ConfigSourceLDXSyncLocked, src2)
}

func TestInteg_FolderPrecedence_MultiFolderIsolation(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)

	orgId := "shared-org-folder"
	f1, f2 := "/multi-f/project-a", "/multi-f/project-b"
	fc1 := &types.FolderConfig{FolderPath: types.FilePath(f1), ConfigResolver: resolver}
	fc2 := &types.FolderConfig{FolderPath: types.FilePath(f2), ConfigResolver: resolver}
	types.SetPreferredOrgAndOrgSetByUser(conf, types.FilePath(f1), orgId, true)
	types.SetPreferredOrgAndOrgSetByUser(conf, types.FilePath(f2), orgId, true)

	// Folder1: explicit value, Folder2: falls back to user global
	conf.Set(configresolver.UserFolderKey(f1, types.SettingBaseBranch), &configresolver.LocalConfigField{Value: "release", Changed: true})
	conf.Set(configresolver.UserGlobalKey(types.SettingBaseBranch), "global-main")

	val1, src1 := resolver.GetValue(types.SettingBaseBranch, fc1)
	val2, src2 := resolver.GetValue(types.SettingBaseBranch, fc2)

	assert.Equal(t, "release", val1)
	assert.Equal(t, types.ConfigSourceFolder, src1)
	assert.Equal(t, "global-main", val2, "folder2 should fall back to user global")
	assert.Equal(t, types.ConfigSourceGlobal, src2)
}

// Cross-scope: verify scope annotations are respected
func TestInteg_CrossScope_MachineSettingIgnoresOrgRemote(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)

	orgId := "cross-scope-org"
	folderPath := "/cross/scope"
	fc := &types.FolderConfig{FolderPath: types.FilePath(folderPath), ConfigResolver: resolver}
	types.SetPreferredOrgAndOrgSetByUser(conf, types.FilePath(folderPath), orgId, true)

	// Set org-level remote for a machine-scoped setting — should be ignored
	conf.Set(configresolver.RemoteOrgKey(orgId, types.SettingApiEndpoint), &configresolver.RemoteConfigField{Value: "https://wrong.api"})
	// Set the correct machine-level remote
	conf.Set(configresolver.RemoteMachineKey(types.SettingApiEndpoint), &configresolver.RemoteConfigField{Value: "https://correct.api"})

	val, source := resolver.GetValue(types.SettingApiEndpoint, fc)
	assert.Equal(t, "https://correct.api", val, "machine-scoped setting should use RemoteMachineKey, not RemoteOrgKey")
	assert.Equal(t, types.ConfigSourceLDXSync, source)
}

func TestInteg_CrossScope_OrgSettingIgnoresMachineRemote(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)

	orgId := "cross-scope-org2"
	folderPath := "/cross/scope2"
	fc := &types.FolderConfig{FolderPath: types.FilePath(folderPath), ConfigResolver: resolver}
	types.SetPreferredOrgAndOrgSetByUser(conf, types.FilePath(folderPath), orgId, true)

	// Set machine-level remote for an org-scoped setting — should be ignored
	conf.Set(configresolver.RemoteMachineKey(types.SettingSnykCodeEnabled), &configresolver.RemoteConfigField{Value: true})

	val, source := resolver.GetValue(types.SettingSnykCodeEnabled, fc)
	assert.Equal(t, false, val, "org-scoped setting should not pick up machine-level remote")
	assert.Equal(t, types.ConfigSourceDefault, source)
}

// Edge cases: empty folder path, no org set
func TestInteg_OrgPrecedence_EmptyFolderPath_FallsBackToGlobalOrRemote(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)

	// FolderConfig with no FolderPath — should still resolve via global org
	fc := &types.FolderConfig{FolderPath: "", ConfigResolver: resolver}

	conf.Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), true)
	val, source := resolver.GetValue(types.SettingSnykOssEnabled, fc)
	assert.Equal(t, true, val)
	assert.Equal(t, types.ConfigSourceGlobal, source)
}

func TestInteg_FolderPrecedence_NoOrgSet_RemoteIgnored_FallsToUserGlobal(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)

	folderPath := "/folder/no-org"
	fc := &types.FolderConfig{FolderPath: types.FilePath(folderPath), ConfigResolver: resolver}
	// No org set — remote keys with any org won't match

	conf.Set(configresolver.RemoteOrgKey("some-org", types.SettingReferenceBranch), &configresolver.RemoteConfigField{Value: "remote-branch"})
	conf.Set(configresolver.UserGlobalKey(types.SettingReferenceBranch), "global-branch")

	val, source := resolver.GetValue(types.SettingReferenceBranch, fc)
	assert.Equal(t, "global-branch", val, "without matching org, remote should not resolve; should fall back to user global")
	assert.Equal(t, types.ConfigSourceGlobal, source)
}

// IsLocked coverage
func TestInteg_IsLocked_OrgScope_FolderLevelLockedVsOrgLevel(t *testing.T) {
	resolver, conf := newResolverWithConfig(t)

	orgId := "locked-check-org"
	folderPath := "/locked/check"
	fc := &types.FolderConfig{FolderPath: types.FilePath(folderPath), ConfigResolver: resolver}
	types.SetPreferredOrgAndOrgSetByUser(conf, types.FilePath(folderPath), orgId, true)

	t.Run("not locked when no remote", func(t *testing.T) {
		assert.False(t, resolver.IsLocked(types.SettingScanAutomatic, fc))
	})

	t.Run("not locked with non-locked remote", func(t *testing.T) {
		conf.Set(configresolver.RemoteOrgKey(orgId, types.SettingScanAutomatic), &configresolver.RemoteConfigField{Value: true})
		assert.False(t, resolver.IsLocked(types.SettingScanAutomatic, fc))
	})

	t.Run("locked with org-level locked remote", func(t *testing.T) {
		conf.Set(configresolver.RemoteOrgKey(orgId, types.SettingScanAutomatic), &configresolver.RemoteConfigField{Value: true, IsLocked: true})
		assert.True(t, resolver.IsLocked(types.SettingScanAutomatic, fc))
	})

	t.Run("locked with folder-level locked remote", func(t *testing.T) {
		conf.Set(configresolver.RemoteOrgKey(orgId, types.SettingScanAutomatic), &configresolver.RemoteConfigField{Value: true})
		conf.Set(configresolver.RemoteOrgFolderKey(orgId, folderPath, types.SettingScanAutomatic), &configresolver.RemoteConfigField{Value: false, IsLocked: true})
		assert.True(t, resolver.IsLocked(types.SettingScanAutomatic, fc))
	})
}
