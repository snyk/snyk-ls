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

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"

	"github.com/snyk/snyk-ls/internal/types"
)

// FC-046: Golden test — ConfigResolver.GetValue behavior preserved when delegating to configuration resolver
func TestConfigResolver_FC046_GoldenTest_Delegation(t *testing.T) {
	conf := configuration.NewWithOpts()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	require.NoError(t, conf.AddFlagSet(fs))
	fm := workflow.ConfigurationOptionsFromFlagset(fs)

	prefixKeyResolver := configresolver.New(conf, fm)

	logger := zerolog.Nop()
	resolver := types.NewConfigResolver(&logger)
	resolver.SetPrefixKeyResolver(prefixKeyResolver, conf, fm)

	t.Run("machine-scope with remote locked", func(t *testing.T) {
		conf.Set(configresolver.RemoteMachineKey(types.SettingApiEndpoint), &configresolver.RemoteConfigField{
			Value: "https://locked.api", IsLocked: true,
		})
		fc := &types.FolderConfig{FolderPath: "/test/folder"}
		val, source := resolver.GetValue(types.SettingApiEndpoint, fc)
		assert.Equal(t, "https://locked.api", val)
		assert.Equal(t, configresolver.ConfigSourceRemoteLocked, source)
	})

	t.Run("org-scope with user override", func(t *testing.T) {
		conf.Set(configresolver.UserFolderKey("/test/folder", types.SettingSnykCodeEnabled), &configresolver.LocalConfigField{
			Value: true, Changed: true,
		})
		fc := &types.FolderConfig{FolderPath: "/test/folder"}
		val, source := resolver.GetValue(types.SettingSnykCodeEnabled, fc)
		assert.Equal(t, true, val)
		assert.Equal(t, configresolver.ConfigSourceUserFolderOverride, source)
	})

	t.Run("user global", func(t *testing.T) {
		conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
		fc2 := &types.FolderConfig{FolderPath: "/other/folder"}
		val, source := resolver.GetValue(types.SettingSnykCodeEnabled, fc2)
		assert.Equal(t, true, val)
		assert.Equal(t, configresolver.ConfigSourceUserGlobal, source)
	})

	t.Run("default", func(t *testing.T) {
		fc2 := &types.FolderConfig{FolderPath: "/other/folder"}
		val, source := resolver.GetValue(types.SettingSnykIacEnabled, fc2)
		assert.Equal(t, true, val)
		assert.Equal(t, configresolver.ConfigSourceDefault, source)
	})
}

// newOrgConfigForTest creates an LDXSyncOrgConfig with the given fields for testing.
func newOrgConfigForTest(orgId string, fields map[string]*types.LDXSyncField) *types.LDXSyncOrgConfig {
	oc := types.NewLDXSyncOrgConfig(orgId)
	for name, field := range fields {
		if field != nil {
			oc.SetField(name, field.Value, field.IsLocked, field.OriginScope)
		}
	}
	return oc
}

// TestConfigResolver_DualWriteTiming_SyncAfterConfigUpdate verifies that writing directly to configuration
// via conf.Set(UserGlobalKey(...)) is correctly resolved by the ConfigResolver.
func TestConfigResolver_DualWriteTiming_SyncAfterConfigUpdate(t *testing.T) {
	conf := configuration.NewWithOpts()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	require.NoError(t, conf.AddFlagSet(fs))
	fm := workflow.ConfigurationOptionsFromFlagset(fs)

	prefixKeyResolver := configresolver.New(conf, fm)
	logger := zerolog.Nop()

	resolver := types.NewConfigResolver(&logger)
	resolver.SetPrefixKeyResolver(prefixKeyResolver, conf, fm)

	conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)

	fc := &types.FolderConfig{FolderPath: "/test/folder"}
	assert.True(t, resolver.GetBool(types.SettingSnykCodeEnabled, fc), "snyk_code_enabled should be true when written to configuration")
	_, source := resolver.GetValue(types.SettingSnykCodeEnabled, fc)
	assert.Equal(t, configresolver.ConfigSourceUserGlobal, source)
}

// FC-056: UserGlobalKey values written directly to conf are resolved by ConfigResolver
func TestConfigResolver_FC056_SetGlobalSettings_WritesUserGlobalKeys(t *testing.T) {
	conf := configuration.NewWithOpts()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	require.NoError(t, conf.AddFlagSet(fs))
	fm := workflow.ConfigurationOptionsFromFlagset(fs)

	prefixKeyResolver := configresolver.New(conf, fm)
	logger := zerolog.Nop()
	resolver := types.NewConfigResolver(&logger)
	resolver.SetPrefixKeyResolver(prefixKeyResolver, conf, fm)

	conf.Set(configresolver.UserGlobalKey(types.SettingApiEndpoint), "https://api.snyk.io")
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingScanAutomatic), true)

	assert.Equal(t, "https://api.snyk.io", conf.Get(configresolver.UserGlobalKey(types.SettingApiEndpoint)))
	snykCodeVal := conf.Get(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled))
	assert.True(t, snykCodeVal == "true" || snykCodeVal == true, "snyk_code_enabled should be set")
	assert.Equal(t, true, conf.Get(configresolver.UserGlobalKey(types.SettingScanAutomatic)))

	fc := &types.FolderConfig{FolderPath: "/test/folder"}
	val, source := resolver.GetValue(types.SettingApiEndpoint, fc)
	assert.Equal(t, "https://api.snyk.io", val)
	assert.Equal(t, configresolver.ConfigSourceUserGlobal, source)
}

// FC-057: FolderConfig SetUserOverride writes to UserFolderKey (verify through resolver)
func TestConfigResolver_FC057_FolderOverride_ResolvedViaPrefixKey(t *testing.T) {
	conf := configuration.NewWithOpts()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	require.NoError(t, conf.AddFlagSet(fs))
	fm := workflow.ConfigurationOptionsFromFlagset(fs)

	prefixKeyResolver := configresolver.New(conf, fm)
	logger := zerolog.Nop()
	resolver := types.NewConfigResolver(&logger)
	resolver.SetPrefixKeyResolver(prefixKeyResolver, conf, fm)

	conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)

	fc := &types.FolderConfig{FolderPath: "/test/folder"}
	fc.ConfigResolver = types.NewMinimalConfigResolver(conf)
	conf.Set(configresolver.UserFolderKey(string(types.PathKey(fc.FolderPath)), types.SettingSnykCodeEnabled), &configresolver.LocalConfigField{Value: false, Changed: true})

	val, source := resolver.GetValue(types.SettingSnykCodeEnabled, fc)
	assert.Equal(t, false, val)
	assert.Equal(t, configresolver.ConfigSourceUserFolderOverride, source)

	fc2 := &types.FolderConfig{FolderPath: "/other/folder"}
	val2, source2 := resolver.GetValue(types.SettingSnykCodeEnabled, fc2)
	assert.Equal(t, true, val2)
	assert.Equal(t, configresolver.ConfigSourceUserGlobal, source2)
}

// TestConfigResolver_SmokeLegacyRouting_OSSEnabledAfterSync reproduces the scenario from
// Test_SmokeLegacyRoutingUnmanagedWithRiskScore: Config has SetSnykOssEnabled(true), settings
// have ActivateSnykOpenSource="true". Writing directly to configuration, IsSnykOssEnabledForFolder must return true.
func TestConfigResolver_SmokeLegacyRouting_OSSEnabledAfterSync(t *testing.T) {
	conf := configuration.NewWithOpts()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	require.NoError(t, conf.AddFlagSet(fs))
	fm := workflow.ConfigurationOptionsFromFlagset(fs)

	prefixKeyResolver := configresolver.New(conf, fm)
	logger := zerolog.Nop()

	resolver := types.NewConfigResolver(&logger)
	resolver.SetPrefixKeyResolver(prefixKeyResolver, conf, fm)

	conf.Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), true)

	userGlobalKey := configresolver.UserGlobalKey(types.SettingSnykOssEnabled)
	assert.True(t, conf.IsSet(userGlobalKey), "user:global:snyk_oss_enabled should be set in configuration")
	assert.Equal(t, true, conf.Get(userGlobalKey), "user:global:snyk_oss_enabled should be true")

	fc := &types.FolderConfig{FolderPath: "/test/folder"}
	assert.True(t, resolver.IsSnykOssEnabledForFolder(fc),
		"IsSnykOssEnabledForFolder must return true when written to configuration")
	val, source := resolver.GetValue(types.SettingSnykOssEnabled, fc)
	assert.Equal(t, true, val)
	assert.Equal(t, configresolver.ConfigSourceUserGlobal, source)
}

// FC-047: Golden test — full end-to-end resolution chain
func TestConfigResolver_FC047_GoldenTest_FullResolutionChain(t *testing.T) {
	conf := configuration.NewWithOpts()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	require.NoError(t, conf.AddFlagSet(fs))
	fm := workflow.ConfigurationOptionsFromFlagset(fs)

	prefixKeyResolver := configresolver.New(conf, fm)
	logger := zerolog.Nop()
	resolver := types.NewConfigResolver(&logger)
	resolver.SetPrefixKeyResolver(prefixKeyResolver, conf, fm)

	conf.Set(configresolver.UserGlobalKey(types.SettingApiEndpoint), "https://user.api")
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	// SnykOssEnabled not set — comes from LDX-Sync (non-locked)

	orgId := "org-123"
	orgConfig := newOrgConfigForTest(orgId, map[string]*types.LDXSyncField{
		types.SettingSnykCodeEnabled: {Value: false, IsLocked: true, OriginScope: "org"},
		types.SettingSnykOssEnabled:  {Value: true, IsLocked: false, OriginScope: "group"},
	})
	types.WriteOrgConfigToConfiguration(conf, orgConfig)

	types.WriteMachineConfigToConfiguration(conf, map[string]*types.LDXSyncField{
		types.SettingApiEndpoint: {Value: "https://remote.api", IsLocked: false, OriginScope: ""},
	})

	fc := &types.FolderConfig{FolderPath: "/project"}
	fc.ConfigResolver = types.NewMinimalConfigResolver(conf)
	types.SetPreferredOrgAndOrgSetByUser(conf, fc.FolderPath, orgId, true)

	val, source := resolver.GetValue(types.SettingApiEndpoint, fc)
	assert.Equal(t, "https://user.api", val)
	assert.Equal(t, configresolver.ConfigSourceUserGlobal, source)

	val, source = resolver.GetValue(types.SettingSnykCodeEnabled, fc)
	assert.Equal(t, false, val)
	assert.Equal(t, configresolver.ConfigSourceRemoteLocked, source)

	val, source = resolver.GetValue(types.SettingSnykOssEnabled, fc)
	assert.Equal(t, true, val)
	assert.Equal(t, configresolver.ConfigSourceRemote, source)

	val, source = resolver.GetValue(types.SettingReferenceBranch, fc)
	assert.Equal(t, "", val)
	assert.Equal(t, configresolver.ConfigSourceDefault, source)
}

// FC-058: Metadata settings (local_branches, auto_determined_org) are read from FolderMetadataKey
func TestConfigResolver_FC058_MetadataFromFolderMetadataKey(t *testing.T) {
	conf := configuration.NewWithOpts()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	require.NoError(t, conf.AddFlagSet(fs))
	fm := workflow.ConfigurationOptionsFromFlagset(fs)

	prefixKeyResolver := configresolver.New(conf, fm)
	logger := zerolog.Nop()
	resolver := types.NewConfigResolver(&logger)
	resolver.SetPrefixKeyResolver(prefixKeyResolver, conf, fm)

	folderPath := string(types.PathKey("/test/folder"))
	fc := &types.FolderConfig{FolderPath: "/test/folder"}

	t.Run("GetValue(SettingLocalBranches) returns value from FolderMetadataKey", func(t *testing.T) {
		conf.Set(configresolver.FolderMetadataKey(folderPath, types.SettingLocalBranches), []string{"main", "develop"})
		val, source := resolver.GetValue(types.SettingLocalBranches, fc)
		assert.Equal(t, []string{"main", "develop"}, val)
		assert.Equal(t, configresolver.ConfigSourceLocal, source)
	})

	t.Run("GetValue(SettingAutoDeterminedOrg) returns value from FolderMetadataKey", func(t *testing.T) {
		conf.Set(configresolver.FolderMetadataKey(folderPath, types.SettingAutoDeterminedOrg), "org-456")
		val, source := resolver.GetValue(types.SettingAutoDeterminedOrg, fc)
		assert.Equal(t, "org-456", val)
		assert.Equal(t, configresolver.ConfigSourceLocal, source)
	})

	t.Run("GetValue(SettingBaseBranch) returns value from UserFolderKey via configuration resolver", func(t *testing.T) {
		conf.Set(configresolver.UserFolderKey(folderPath, types.SettingBaseBranch), &configresolver.LocalConfigField{
			Value: "main", Changed: true,
		})
		val, source := resolver.GetValue(types.SettingBaseBranch, fc)
		assert.Equal(t, "main", val)
		assert.Equal(t, configresolver.ConfigSourceUserFolderOverride, source)
	})
}

// FC-059: getEffectiveOrg reads from Configuration (UserFolderKey/FolderMetadataKey) when prefixKeyConf is set
func TestConfigResolver_FC059_GetEffectiveOrgFromConfiguration(t *testing.T) {
	conf := configuration.NewWithOpts()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	require.NoError(t, conf.AddFlagSet(fs))
	fm := workflow.ConfigurationOptionsFromFlagset(fs)

	prefixKeyResolver := configresolver.New(conf, fm)
	logger := zerolog.Nop()
	resolver := types.NewConfigResolver(&logger)
	resolver.SetPrefixKeyResolver(prefixKeyResolver, conf, fm)

	folderPath := string(types.PathKey("/test/folder"))

	t.Run("returns PreferredOrg from UserFolderKey when OrgSetByUser", func(t *testing.T) {
		conf.Set(configresolver.UserFolderKey(folderPath, types.SettingOrgSetByUser), &configresolver.LocalConfigField{Value: true, Changed: true})
		conf.Set(configresolver.UserFolderKey(folderPath, types.SettingPreferredOrg), &configresolver.LocalConfigField{Value: "user-org", Changed: true})
		fc := &types.FolderConfig{FolderPath: "/test/folder"}

		orgConfig := types.NewLDXSyncOrgConfig("user-org")
		orgConfig.SetField(types.SettingEnabledSeverities, []string{"critical"}, false, "org")
		types.WriteOrgConfigToConfiguration(conf, orgConfig)
		val, source := resolver.GetValue(types.SettingEnabledSeverities, fc)
		assert.Equal(t, []string{"critical"}, val)
		assert.Equal(t, configresolver.ConfigSourceRemote, source)
	})

	t.Run("returns AutoDeterminedOrg from FolderMetadataKey when OrgSetByUser is false", func(t *testing.T) {
		conf.Set(configresolver.UserFolderKey(folderPath, types.SettingOrgSetByUser), &configresolver.LocalConfigField{Value: false, Changed: true})
		conf.Set(configresolver.FolderMetadataKey(folderPath, types.SettingAutoDeterminedOrg), "auto-org")
		fc := &types.FolderConfig{FolderPath: "/test/folder"}

		orgConfig := types.NewLDXSyncOrgConfig("auto-org")
		orgConfig.SetField(types.SettingEnabledSeverities, []string{"high"}, false, "org")
		types.WriteOrgConfigToConfiguration(conf, orgConfig)
		val, source := resolver.GetValue(types.SettingEnabledSeverities, fc)
		assert.Equal(t, []string{"high"}, val)
		assert.Equal(t, configresolver.ConfigSourceRemote, source)
	})

	t.Run("falls back to global org when both are empty", func(t *testing.T) {
		conf.Set(configresolver.UserFolderKey(folderPath, types.SettingOrgSetByUser), &configresolver.LocalConfigField{Value: false, Changed: true})
		conf.Set(configresolver.FolderMetadataKey(folderPath, types.SettingAutoDeterminedOrg), nil)
		conf.Set(configresolver.UserGlobalKey(types.SettingOrganization), "global-org")
		fc := &types.FolderConfig{FolderPath: "/test/folder"}

		orgConfig := types.NewLDXSyncOrgConfig("global-org")
		orgConfig.SetField(types.SettingEnabledSeverities, []string{"low"}, false, "org")
		types.WriteOrgConfigToConfiguration(conf, orgConfig)
		val, source := resolver.GetValue(types.SettingEnabledSeverities, fc)
		assert.Equal(t, []string{"low"}, val)
		assert.Equal(t, configresolver.ConfigSourceRemote, source)
	})

	t.Run("falls back to configuration.ORGANIZATION when UserGlobalKey is empty", func(t *testing.T) {
		conf.Set(configresolver.UserFolderKey(folderPath, types.SettingOrgSetByUser), &configresolver.LocalConfigField{Value: false, Changed: true})
		conf.Set(configresolver.FolderMetadataKey(folderPath, types.SettingAutoDeterminedOrg), nil)
		conf.Set(configresolver.UserGlobalKey(types.SettingOrganization), "")
		conf.Set(configuration.ORGANIZATION, "gaf-global-org")
		fc := &types.FolderConfig{FolderPath: "/test/folder"}

		orgConfig := types.NewLDXSyncOrgConfig("gaf-global-org")
		orgConfig.SetField(types.SettingEnabledSeverities, []string{"medium"}, false, "org")
		types.WriteOrgConfigToConfiguration(conf, orgConfig)
		val, source := resolver.GetValue(types.SettingEnabledSeverities, fc)
		assert.Equal(t, []string{"medium"}, val)
		assert.Equal(t, configresolver.ConfigSourceRemote, source)
	})
}
