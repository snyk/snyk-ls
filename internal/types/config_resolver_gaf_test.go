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
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/spf13/pflag"

	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
)

// FC-046: Golden test — ConfigResolver.GetValue behavior preserved when delegating to GAF resolver
func TestConfigResolver_FC046_GoldenTest_GAFDelegation(t *testing.T) {
	conf := configuration.NewWithOpts()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	require.NoError(t, conf.AddFlagSet(fs))

	gafResolver := configuration.NewConfigResolver(conf)

	logger := zerolog.Nop()
	cache := types.NewLDXSyncConfigCache()
	resolver := types.NewConfigResolver(cache, nil, nil, &logger)
	resolver.SetGAFResolver(gafResolver, conf)

	t.Run("machine-scope with remote locked", func(t *testing.T) {
		conf.Set(configuration.RemoteMachineKey(types.SettingApiEndpoint), &configuration.RemoteConfigField{
			Value: "https://locked.api", IsLocked: true,
		})
		fc := &types.FolderConfig{FolderPath: "/test/folder"}
		val, source := resolver.GetValue(types.SettingApiEndpoint, fc)
		assert.Equal(t, "https://locked.api", val)
		assert.Equal(t, types.ConfigSourceLDXSyncLocked, source)
	})

	t.Run("org-scope with user override", func(t *testing.T) {
		conf.Set(configuration.UserFolderKey("/test/folder", types.SettingSnykCodeEnabled), &configuration.LocalConfigField{
			Value: true, Changed: true,
		})
		fc := &types.FolderConfig{FolderPath: "/test/folder"}
		val, source := resolver.GetValue(types.SettingSnykCodeEnabled, fc)
		assert.Equal(t, true, val)
		assert.Equal(t, types.ConfigSourceUserOverride, source)
	})

	t.Run("user global", func(t *testing.T) {
		conf.Set(configuration.UserGlobalKey(types.SettingSnykCodeEnabled), true)
		fc2 := &types.FolderConfig{FolderPath: "/other/folder"}
		val, source := resolver.GetValue(types.SettingSnykCodeEnabled, fc2)
		assert.Equal(t, true, val)
		assert.Equal(t, types.ConfigSourceGlobal, source)
	})

	t.Run("default", func(t *testing.T) {
		fc2 := &types.FolderConfig{FolderPath: "/other/folder"}
		val, source := resolver.GetValue(types.SettingSnykIacEnabled, fc2)
		assert.Equal(t, false, val)
		assert.Equal(t, types.ConfigSourceDefault, source)
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

// TestConfigResolver_GAFDualWriteTiming verifies that SyncGlobalSettingsToConfiguration is called
// AFTER ConfigProvider (e.g. updateProductEnablement) has run, so reconciled values like
// IsSnykCodeEnabled() are correct when written to GAF. Without this, SetGlobalSettings would
// write eagerly before Config is updated, causing snyk_code_enabled=false to be written.
func TestConfigResolver_GAFDualWriteTiming_SyncAfterConfigUpdate(t *testing.T) {
	conf := configuration.NewWithOpts()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	require.NoError(t, conf.AddFlagSet(fs))

	gafResolver := configuration.NewConfigResolver(conf)
	cache := types.NewLDXSyncConfigCache()
	logger := zerolog.Nop()

	ctrl := gomock.NewController(t)
	mockCP := mock_types.NewMockConfigProvider(ctrl)
	// Simulate ConfigProvider returning true AFTER updateProductEnablement has run.
	// SyncGlobalSettingsToConfiguration must be called after update* calls, so at sync time
	// Config.IsSnykCodeEnabled() returns the correct reconciled value.
	mockCP.EXPECT().IsSnykCodeEnabled().Return(true).Times(1)
	mockCP.EXPECT().IsSnykOssEnabled().Return(false).AnyTimes()
	mockCP.EXPECT().IsSnykIacEnabled().Return(false).AnyTimes()
	mockCP.EXPECT().IsSnykSecretsEnabled().Return(false).AnyTimes()
	mockCP.EXPECT().IsAutoScanEnabled().Return(true).AnyTimes()
	mockCP.EXPECT().IsDeltaFindingsEnabled().Return(false).AnyTimes()
	mockCP.EXPECT().FilterSeverity().Return(types.SeverityFilter{}).AnyTimes()
	mockCP.EXPECT().RiskScoreThreshold().Return(0).AnyTimes()
	mockCP.EXPECT().IssueViewOptions().Return(types.IssueViewOptions{}).AnyTimes()

	resolver := types.NewConfigResolver(cache, nil, mockCP, &logger)
	resolver.SetGAFResolver(gafResolver, conf)

	settings := &types.Settings{
		ActivateSnykCode: "true",
	}
	resolver.SetGlobalSettings(settings)
	// Sync must be called AFTER updateProductEnablement (and other update* calls) have run.
	// This ensures reconciled values from ConfigProvider are correct when written to GAF.
	resolver.SyncGlobalSettingsToConfiguration()

	fc := &types.FolderConfig{FolderPath: "/test/folder"}
	assert.True(t, resolver.GetBool(types.SettingSnykCodeEnabled, fc), "snyk_code_enabled should be true after SyncGlobalSettingsToConfiguration")
	_, source := resolver.GetValue(types.SettingSnykCodeEnabled, fc)
	assert.Equal(t, types.ConfigSourceGlobal, source)
}

// FC-056: writeSettings populates UserGlobalKey via SetGlobalSettings + SyncGlobalSettingsToConfiguration
func TestConfigResolver_FC056_SetGlobalSettings_WritesUserGlobalKeys(t *testing.T) {
	conf := configuration.NewWithOpts()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	require.NoError(t, conf.AddFlagSet(fs))

	gafResolver := configuration.NewConfigResolver(conf)
	cache := types.NewLDXSyncConfigCache()
	logger := zerolog.Nop()
	resolver := types.NewConfigResolver(cache, nil, nil, &logger)
	resolver.SetGAFResolver(gafResolver, conf)

	settings := &types.Settings{
		Endpoint:               "https://api.snyk.io",
		ActivateSnykCode:       "true",
		ActivateSnykOpenSource: "true",
		ScanningMode:           "automatic",
	}
	resolver.SetGlobalSettings(settings)
	resolver.SyncGlobalSettingsToConfiguration()

	assert.Equal(t, "https://api.snyk.io", conf.Get(configuration.UserGlobalKey(types.SettingApiEndpoint)))
	snykCodeVal := conf.Get(configuration.UserGlobalKey(types.SettingSnykCodeEnabled))
	assert.True(t, snykCodeVal == "true" || snykCodeVal == true, "snyk_code_enabled should be set")
	assert.Equal(t, "automatic", conf.Get(configuration.UserGlobalKey(types.SettingScanAutomatic)))

	fc := &types.FolderConfig{FolderPath: "/test/folder"}
	val, source := resolver.GetValue(types.SettingApiEndpoint, fc)
	assert.Equal(t, "https://api.snyk.io", val)
	assert.Equal(t, types.ConfigSourceGlobal, source)
}

// FC-057: FolderConfig SetUserOverride writes to UserFolderKey (verify through resolver)
func TestConfigResolver_FC057_FolderOverride_ResolvedViaGAF(t *testing.T) {
	conf := configuration.NewWithOpts()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	require.NoError(t, conf.AddFlagSet(fs))

	gafResolver := configuration.NewConfigResolver(conf)
	cache := types.NewLDXSyncConfigCache()
	logger := zerolog.Nop()
	resolver := types.NewConfigResolver(cache, nil, nil, &logger)
	resolver.SetGAFResolver(gafResolver, conf)

	conf.Set(configuration.UserGlobalKey(types.SettingSnykCodeEnabled), true)

	fc := &types.FolderConfig{FolderPath: "/test/folder"}
	fc.SetConf(conf)
	fc.SetUserOverride(types.SettingSnykCodeEnabled, false)

	val, source := resolver.GetValue(types.SettingSnykCodeEnabled, fc)
	assert.Equal(t, false, val)
	assert.Equal(t, types.ConfigSourceUserOverride, source)

	fc2 := &types.FolderConfig{FolderPath: "/other/folder"}
	val2, source2 := resolver.GetValue(types.SettingSnykCodeEnabled, fc2)
	assert.Equal(t, true, val2)
	assert.Equal(t, types.ConfigSourceGlobal, source2)
}

// FC-047: Golden test — full end-to-end resolution chain
func TestConfigResolver_FC047_GoldenTest_FullResolutionChain(t *testing.T) {
	conf := configuration.NewWithOpts()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	require.NoError(t, conf.AddFlagSet(fs))

	gafResolver := configuration.NewConfigResolver(conf)
	cache := types.NewLDXSyncConfigCache()
	logger := zerolog.Nop()
	resolver := types.NewConfigResolver(cache, nil, nil, &logger)
	resolver.SetGAFResolver(gafResolver, conf)

	settings := &types.Settings{
		Endpoint:         "https://user.api",
		ActivateSnykCode: "true",
		// ActivateSnykOpenSource not set — SnykOssEnabled comes from LDX-Sync (non-locked)
	}
	resolver.SetGlobalSettings(settings)
	resolver.SyncGlobalSettingsToConfiguration()

	orgId := "org-123"
	orgConfig := newOrgConfigForTest(orgId, map[string]*types.LDXSyncField{
		types.SettingSnykCodeEnabled: {Value: false, IsLocked: true, OriginScope: "org"},
		types.SettingSnykOssEnabled:  {Value: true, IsLocked: false, OriginScope: "group"},
	})
	types.WriteOrgConfigToConfiguration(conf, orgConfig)

	types.WriteMachineConfigToConfiguration(conf, map[string]*types.LDXSyncField{
		types.SettingApiEndpoint: {Value: "https://remote.api", IsLocked: false, OriginScope: ""},
	})

	fc := &types.FolderConfig{
		FolderPath:   "/project",
		PreferredOrg: orgId,
		OrgSetByUser: true,
	}
	fc.SetConf(conf)
	fc.SyncToConfiguration()

	val, source := resolver.GetValue(types.SettingApiEndpoint, fc)
	assert.Equal(t, "https://user.api", val)
	assert.Equal(t, types.ConfigSourceGlobal, source)

	val, source = resolver.GetValue(types.SettingSnykCodeEnabled, fc)
	assert.Equal(t, false, val)
	assert.Equal(t, types.ConfigSourceLDXSyncLocked, source)

	val, source = resolver.GetValue(types.SettingSnykOssEnabled, fc)
	assert.Equal(t, true, val)
	assert.Equal(t, types.ConfigSourceLDXSync, source)

	val, source = resolver.GetValue(types.SettingReferenceBranch, fc)
	assert.Equal(t, "", val)
	assert.Equal(t, types.ConfigSourceDefault, source)
}
