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
	"sync"
	"testing"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

func TestConfigSourceString(t *testing.T) {
	tests := []struct {
		source      configresolver.ConfigSource
		settingName string
		expected    string
	}{
		{configresolver.ConfigSourceDefault, SettingApiEndpoint, "default"},
		{configresolver.ConfigSourceLocal, SettingApiEndpoint, "folder"},
		{configresolver.ConfigSourceUserGlobal, SettingApiEndpoint, "global"},
		{configresolver.ConfigSourceRemote, SettingApiEndpoint, "ldx-sync"},
		{configresolver.ConfigSourceRemoteLocked, SettingApiEndpoint, "ldx-sync-locked"},
		{configresolver.ConfigSourceUserFolderOverride, SettingSnykCodeEnabled, "user-override"},
		{configresolver.ConfigSourceUserFolderOverride, SettingPreferredOrg, "folder"},
		{configresolver.ConfigSourceUserFolderOverride, SettingOrgSetByUser, "folder"},
		{configresolver.ConfigSourceUserFolderOverride, SettingBaseBranch, "folder"},
		{configresolver.ConfigSource(99), SettingApiEndpoint, "default"},
	}

	for _, tt := range tests {
		t.Run(tt.expected+"_"+tt.settingName, func(t *testing.T) {
			assert.Equal(t, tt.expected, configSourceString(tt.source, tt.settingName))
		})
	}
}

func TestLDXSyncOrgConfig_GetField(t *testing.T) {
	t.Run("returns nil for nil config", func(t *testing.T) {
		var config *LDXSyncOrgConfig
		assert.Nil(t, config.GetField("test"))
	})

	t.Run("returns nil for nil fields", func(t *testing.T) {
		config := &LDXSyncOrgConfig{OrgId: "org1"}
		assert.Nil(t, config.GetField("test"))
	})

	t.Run("returns nil for missing field", func(t *testing.T) {
		config := NewLDXSyncOrgConfig("org1")
		assert.Nil(t, config.GetField("missing"))
	})

	t.Run("returns field when exists", func(t *testing.T) {
		config := NewLDXSyncOrgConfig("org1")
		config.SetField("test", "value", false, "org")

		field := config.GetField("test")
		assert.NotNil(t, field)
		assert.Equal(t, "value", field.Value)
		assert.False(t, field.IsLocked)
	})
}

func TestLDXSyncOrgConfig_SetField(t *testing.T) {
	t.Run("creates fields map if nil", func(t *testing.T) {
		config := &LDXSyncOrgConfig{OrgId: "org1"}
		config.SetField("test", "value", true, "group")

		assert.NotNil(t, config.Fields)
		field := config.Fields["test"]
		assert.Equal(t, "value", field.Value)
		assert.True(t, field.IsLocked)
		assert.Equal(t, "group", field.OriginScope)
	})
}

func TestConfigResolver_ConcurrentAccess(t *testing.T) {
	conf := configuration.NewWithOpts()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	RegisterAllConfigurations(fs)
	_ = conf.AddFlagSet(fs)
	fm := workflow.ConfigurationOptionsFromFlagset(fs)

	orgConfig := NewLDXSyncOrgConfig("org1")
	orgConfig.SetField(SettingSnykCodeEnabled, true, false, "")
	WriteOrgConfigToConfiguration(conf, orgConfig)
	SetPreferredOrgAndOrgSetByUser(conf, "/folder", "org1", true)

	logger := zerolog.Nop()
	resolver := NewConfigResolver(&logger)
	resolver.SetPrefixKeyResolver(configresolver.New(conf, fm), conf, fm)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fc := &FolderConfig{FolderPath: "/folder"}
			fc.ConfigResolver = NewMinimalConfigResolver(conf)
			_ = resolver.GetBool(SettingSnykCodeEnabled, fc)
		}()
	}
	wg.Wait()
}

func testFm(t *testing.T) workflow.ConfigurationOptionsMetaData {
	t.Helper()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	RegisterAllConfigurations(fs)
	return workflow.ConfigurationOptionsFromFlagset(fs)
}

func TestGetSettingScope(t *testing.T) {
	fm := testFm(t)

	t.Run("machine-scope settings", func(t *testing.T) {
		machineSettings := []string{
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
		}

		for _, setting := range machineSettings {
			assert.Equal(t, configresolver.MachineScope, GetSettingScope(fm, setting), "expected %s to be machine-scoped", setting)
			assert.True(t, IsMachineWideSetting(fm, setting), "expected IsMachineWideSetting(%s) to be true", setting)
			assert.False(t, IsFolderScopedSetting(fm, setting))
		}
	})

	t.Run("folder-scope settings (including former org-scope)", func(t *testing.T) {
		folderSettings := []string{
			// formerly org-scoped
			SettingEnabledSeverities,
			SettingRiskScoreThreshold,
			SettingCweIds,
			SettingCveIds,
			SettingRuleIds,
			SettingSnykCodeEnabled,
			SettingSnykOssEnabled,
			SettingSnykIacEnabled,
			SettingSnykContainerEnabled,
			SettingSnykSecretsEnabled,
			SettingScanAutomatic,
			SettingScanNetNew,
			SettingIssueViewOpenIssues,
			SettingIssueViewIgnoredIssues,
			// folder-scoped
			SettingReferenceFolder,
			SettingReferenceBranch,
			SettingAdditionalParameters,
			SettingAdditionalEnvironment,
			SettingSastSettings,
			SettingPreAssignedOrgId,
		}

		for _, setting := range folderSettings {
			assert.Equal(t, configresolver.FolderScope, GetSettingScope(fm, setting), "expected %s to be folder-scoped", setting)
			assert.True(t, IsFolderScopedSetting(fm, setting), "expected IsFolderScopedSetting(%s) to be true", setting)
			assert.False(t, IsMachineWideSetting(fm, setting))
		}
	})

	t.Run("unknown settings default to folder scope", func(t *testing.T) {
		assert.Equal(t, configresolver.FolderScope, GetSettingScope(fm, "unknown_setting"))
	})
}
