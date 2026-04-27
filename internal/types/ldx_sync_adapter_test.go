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

	v20241015 "github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config/ldx_sync/2024-10-15"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/util"
)

func adapterTestFm(t *testing.T) workflow.ConfigurationOptionsMetaData {
	t.Helper()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	RegisterAllConfigurations(fs)
	return workflow.ConfigurationOptionsFromFlagset(fs)
}

func TestConvertLDXSyncResponseToOrgConfig(t *testing.T) {
	fm := adapterTestFm(t)
	t.Run("returns nil for nil response", func(t *testing.T) {
		result := ConvertLDXSyncResponseToOrgConfig("org1", nil, fm)
		assert.Nil(t, result)
	})

	t.Run("converts settings with metadata", func(t *testing.T) {
		response := &v20241015.UserConfigResponse{}
		response.Data.Attributes.Settings = &map[string]v20241015.SettingMetadata{
			"severity_critical_enabled": {
				Value:  true,
				Locked: util.Ptr(true),
				Origin: v20241015.SettingMetadataOriginGroup,
			},
			"scan_automatic": {
				Value:  true,
				Locked: util.Ptr(false),
				Origin: v20241015.SettingMetadataOriginOrg,
			},
		}

		result := ConvertLDXSyncResponseToOrgConfig("org1", response, fm)

		assert.NotNil(t, result)
		assert.Equal(t, "org1", result.OrgId)

		// Check severity_critical_enabled
		criticalField := result.GetField(SettingSeverityFilterCritical)
		assert.NotNil(t, criticalField)
		assert.Equal(t, true, criticalField.Value)
		assert.True(t, criticalField.IsLocked)
		assert.Equal(t, "group", criticalField.OriginScope)

		// Check scan_automatic
		autoField := result.GetField(SettingScanAutomatic)
		assert.NotNil(t, autoField)
		assert.Equal(t, true, autoField.Value)
		assert.False(t, autoField.IsLocked)
		assert.Equal(t, "org", autoField.OriginScope)
	})

	t.Run("handles nil locked pointers", func(t *testing.T) {
		response := &v20241015.UserConfigResponse{}
		response.Data.Attributes.Settings = &map[string]v20241015.SettingMetadata{
			"scan_net_new": {
				Value:  true,
				Origin: v20241015.SettingMetadataOriginUser,
			},
		}

		result := ConvertLDXSyncResponseToOrgConfig("org1", response, fm)

		field := result.GetField(SettingScanNetNew)
		assert.NotNil(t, field)
		assert.False(t, field.IsLocked)
	})

	t.Run("ignores unknown settings", func(t *testing.T) {
		response := &v20241015.UserConfigResponse{}
		response.Data.Attributes.Settings = &map[string]v20241015.SettingMetadata{
			"unknown_setting": {
				Value:  "test",
				Origin: v20241015.SettingMetadataOriginOrg,
			},
		}

		result := ConvertLDXSyncResponseToOrgConfig("org1", response, fm)

		assert.NotNil(t, result)
		assert.Empty(t, result.Fields)
	})
}

func TestExtractFolderSettings(t *testing.T) {
	t.Run("extracts folder-specific settings", func(t *testing.T) {
		locked := true
		response := &v20241015.UserConfigResponse{}
		response.Data.Attributes.FolderSettings = &map[string]map[string]v20241015.SettingMetadata{
			"git@github.com:snyk/test-repo.git": {
				"scan_automatic": {
					Value:  false,
					Origin: v20241015.SettingMetadataOriginOrg,
					Locked: &locked,
				},
			},
		}

		result := ExtractFolderSettings(response, "git@github.com:snyk/test-repo.git")

		assert.NotNil(t, result)
		autoField := result[SettingScanAutomatic]
		assert.NotNil(t, autoField)
		assert.Equal(t, false, autoField.Value)
		assert.True(t, autoField.IsLocked)
	})

	t.Run("returns nil for missing remote URL", func(t *testing.T) {
		response := &v20241015.UserConfigResponse{}
		response.Data.Attributes.FolderSettings = &map[string]map[string]v20241015.SettingMetadata{
			"git@github.com:snyk/test-repo.git": {
				"reference_branch": {
					Value:  "develop",
					Origin: v20241015.SettingMetadataOriginOrg,
				},
			},
		}

		result := ExtractFolderSettings(response, "git@github.com:snyk/other-repo.git")
		assert.Nil(t, result)
	})

	t.Run("returns nil for nil response", func(t *testing.T) {
		result := ExtractFolderSettings(nil, "git@github.com:snyk/test-repo.git")
		assert.Nil(t, result)
	})

	t.Run("returns nil for empty remote URL", func(t *testing.T) {
		response := &v20241015.UserConfigResponse{}
		response.Data.Attributes.FolderSettings = &map[string]map[string]v20241015.SettingMetadata{
			"git@github.com:snyk/test-repo.git": {
				"reference_branch": {
					Value:  "develop",
					Origin: v20241015.SettingMetadataOriginOrg,
				},
			},
		}

		result := ExtractFolderSettings(response, "")
		assert.Nil(t, result)
	})

	t.Run("returns nil for nil folder settings", func(t *testing.T) {
		response := &v20241015.UserConfigResponse{}
		result := ExtractFolderSettings(response, "git@github.com:snyk/test-repo.git")
		assert.Nil(t, result)
	})

	t.Run("matches normalized URL from API response when caller normalizes raw SSH URL", func(t *testing.T) {
		locked := true
		normalizedURL := "https://github.com/snyk/test-repo"
		response := &v20241015.UserConfigResponse{}
		response.Data.Attributes.FolderSettings = &map[string]map[string]v20241015.SettingMetadata{
			normalizedURL: {
				"issue_view_open_issues": {
					Value:  true,
					Origin: v20241015.SettingMetadataOriginOrg,
					Locked: &locked,
				},
			},
		}

		rawSSHUrl := "git@github.com:snyk/test-repo.git"
		normalized, err := util.NormalizeGitURL(rawSSHUrl)
		require.NoError(t, err)

		result := ExtractFolderSettings(response, normalized)
		assert.NotNil(t, result)
		issueField := result[SettingIssueViewOpenIssues]
		assert.NotNil(t, issueField)
		assert.Equal(t, true, issueField.Value)
		assert.True(t, issueField.IsLocked)
	})

	t.Run("matches normalized URL from API response when caller normalizes HTTPS URL with credentials", func(t *testing.T) {
		normalizedURL := "https://github.com/snyk/test-repo"
		response := &v20241015.UserConfigResponse{}
		response.Data.Attributes.FolderSettings = &map[string]map[string]v20241015.SettingMetadata{
			normalizedURL: {
				"issue_view_ignored_issues": {
					Value:  false,
					Origin: v20241015.SettingMetadataOriginOrg,
				},
			},
		}

		rawHTTPSUrl := "https://user:token@github.com/snyk/test-repo.git"
		normalized, err := util.NormalizeGitURL(rawHTTPSUrl)
		require.NoError(t, err)

		result := ExtractFolderSettings(response, normalized)
		assert.NotNil(t, result)
		ignoredField := result[SettingIssueViewIgnoredIssues]
		assert.NotNil(t, ignoredField)
		assert.Equal(t, false, ignoredField.Value)
	})
}

func TestExtractMachineSettings(t *testing.T) {
	fm := adapterTestFm(t)
	t.Run("extracts machine-scope settings only", func(t *testing.T) {
		locked := true
		response := &v20241015.UserConfigResponse{}
		response.Data.Attributes.Settings = &map[string]v20241015.SettingMetadata{
			// Machine-scope setting
			"cli_release_channel": {
				Value:  "stable",
				Origin: v20241015.SettingMetadataOriginOrg,
				Locked: &locked,
			},
			// Org-scope setting (should be excluded)
			"scan_automatic": {
				Value:  true,
				Origin: v20241015.SettingMetadataOriginOrg,
			},
		}

		result := ExtractMachineSettings(response, fm)

		assert.NotNil(t, result)
		// Should have machine-scope setting
		channelField := result[SettingCliReleaseChannel]
		assert.NotNil(t, channelField)
		assert.Equal(t, "stable", channelField.Value)
		assert.True(t, channelField.IsLocked)

		// Should NOT have org-scope setting
		_, hasAuto := result[SettingScanAutomatic]
		assert.False(t, hasAuto)
	})

	t.Run("returns nil for nil response", func(t *testing.T) {
		result := ExtractMachineSettings(nil, fm)
		assert.Nil(t, result)
	})

	t.Run("returns nil for nil settings", func(t *testing.T) {
		response := &v20241015.UserConfigResponse{}
		result := ExtractMachineSettings(response, fm)
		assert.Nil(t, result)
	})

	t.Run("returns nil when no machine-scope settings present", func(t *testing.T) {
		response := &v20241015.UserConfigResponse{}
		response.Data.Attributes.Settings = &map[string]v20241015.SettingMetadata{
			// Only org-scope setting
			"scan_automatic": {
				Value:  true,
				Origin: v20241015.SettingMetadataOriginOrg,
			},
		}

		result := ExtractMachineSettings(response, fm)
		assert.Nil(t, result)
	})

	t.Run("ignores removed settings and accepts valid ones [IDE-1920]", func(t *testing.T) {
		response := &v20241015.UserConfigResponse{}
		response.Data.Attributes.Settings = &map[string]v20241015.SettingMetadata{
			// Removed settings (commented out in ldxSyncSettingKeyMap)
			"proxy_no_proxy": {
				Value:  "localhost,127.0.0.1",
				Origin: v20241015.SettingMetadataOriginOrg,
			},
			"api_endpoint": {
				Value:  "https://api.evil.com",
				Origin: v20241015.SettingMetadataOriginOrg,
			},
			"authentication_method": {
				Value:  "token",
				Origin: v20241015.SettingMetadataOriginOrg,
			},
			"cwe_ids": {
				Value:  "123,456",
				Origin: v20241015.SettingMetadataOriginOrg,
			},
			// Valid machine-scope setting
			"cli_release_channel": {
				Value:  "stable",
				Origin: v20241015.SettingMetadataOriginOrg,
			},
		}

		result := ExtractMachineSettings(response, fm)

		// Should have the valid setting
		assert.NotNil(t, result)
		channelField := result[SettingCliReleaseChannel]
		assert.NotNil(t, channelField)
		assert.Equal(t, "stable", channelField.Value)

		// Should NOT have any of the removed settings
		_, hasProxyNoProxy := result[SettingProxyNoProxy]
		assert.False(t, hasProxyNoProxy, "proxy_no_proxy should be ignored")

		_, hasApiEndpoint := result[SettingApiEndpoint]
		assert.False(t, hasApiEndpoint, "api_endpoint should be ignored")

		_, hasAuthMethod := result[SettingAuthenticationMethod]
		assert.False(t, hasAuthMethod, "authentication_method should be ignored")

		_, hasCweIds := result[SettingCweIds]
		assert.False(t, hasCweIds, "cwe_ids should be ignored")
	})
}

func TestExtractOrgIdFromResponse(t *testing.T) {
	t.Run("returns empty for nil response", func(t *testing.T) {
		result := ExtractOrgIdFromResponse(nil)
		assert.Empty(t, result)
	})

	t.Run("returns empty for nil organizations", func(t *testing.T) {
		response := &v20241015.UserConfigResponse{}
		result := ExtractOrgIdFromResponse(response)
		assert.Empty(t, result)
	})

	t.Run("returns preferred organization", func(t *testing.T) {
		response := &v20241015.UserConfigResponse{}
		response.Data.Attributes.Organizations = &[]v20241015.Organization{
			{Id: "org1", Name: "Org 1", Slug: "org1", IsDefault: util.Ptr(true)},
			{Id: "org2", Name: "Org 2", Slug: "org2", PreferredByAlgorithm: util.Ptr(true)},
		}

		result := ExtractOrgIdFromResponse(response)
		assert.Equal(t, "org2", result)
	})

	t.Run("falls back to default organization", func(t *testing.T) {
		response := &v20241015.UserConfigResponse{}
		response.Data.Attributes.Organizations = &[]v20241015.Organization{
			{Id: "org1", Name: "Org 1", Slug: "org1", IsDefault: util.Ptr(true)},
			{Id: "org2", Name: "Org 2", Slug: "org2"},
		}

		result := ExtractOrgIdFromResponse(response)
		assert.Equal(t, "org1", result)
	})

	t.Run("falls back to first organization", func(t *testing.T) {
		response := &v20241015.UserConfigResponse{}
		response.Data.Attributes.Organizations = &[]v20241015.Organization{
			{Id: "org1", Name: "Org 1", Slug: "org1"},
			{Id: "org2", Name: "Org 2", Slug: "org2"},
		}

		result := ExtractOrgIdFromResponse(response)
		assert.Equal(t, "org1", result)
	})
}

func TestGetLDXSyncKey(t *testing.T) {
	t.Run("returns correct mapping", func(t *testing.T) {
		assert.Equal(t, "scan_automatic", GetLDXSyncKey(SettingScanAutomatic))
		assert.Equal(t, "issue_view_open_issues", GetLDXSyncKey(SettingIssueViewOpenIssues))
		assert.Equal(t, "severity_critical_enabled", GetLDXSyncKey(SettingSeverityFilterCritical))
	})

	t.Run("returns empty for removed settings [IDE-1920]", func(t *testing.T) {
		assert.Empty(t, GetLDXSyncKey(SettingRiskScoreThreshold))
		assert.Empty(t, GetLDXSyncKey(SettingReferenceBranch))
		assert.Empty(t, GetLDXSyncKey(SettingProxyNoProxy))
	})

	t.Run("returns empty for unknown setting", func(t *testing.T) {
		assert.Empty(t, GetLDXSyncKey("unknown_setting"))
	})
}

func TestPtrToBool(t *testing.T) {
	t.Run("returns false for nil", func(t *testing.T) {
		assert.False(t, util.PtrToBool(nil))
	})

	t.Run("returns true for true pointer", func(t *testing.T) {
		assert.True(t, util.PtrToBool(util.Ptr(true)))
	})

	t.Run("returns false for false pointer", func(t *testing.T) {
		assert.False(t, util.PtrToBool(util.Ptr(false)))
	})
}

// FC-053: LDX-Sync adapter writes RemoteConfigField to RemoteOrgKey prefix keys
func TestWriteOrgConfigToConfiguration_FC053(t *testing.T) {
	t.Run("writes org config to configuration", func(t *testing.T) {
		conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())

		orgId := "test-org-123"
		orgConfig := NewLDXSyncOrgConfig(orgId)
		orgConfig.SetField(SettingSnykCodeEnabled, true, true, "org")
		orgConfig.SetField(SettingScanAutomatic, false, false, "group")

		WriteOrgConfigToConfiguration(conf, orgConfig)

		// Verify snyk_code_enabled
		key := configresolver.RemoteOrgKey(orgId, SettingSnykCodeEnabled)
		got := conf.Get(key)
		require.NotNil(t, got, "RemoteOrgKey %q should have a value", key)
		field, ok := got.(*configresolver.RemoteConfigField)
		require.True(t, ok, "Expected *RemoteConfigField, got %T", got)
		assert.Equal(t, true, field.Value)
		assert.True(t, field.IsLocked)
		assert.Equal(t, "org", field.Origin)

		// Verify scan_automatic
		key2 := configresolver.RemoteOrgKey(orgId, SettingScanAutomatic)
		got2 := conf.Get(key2)
		require.NotNil(t, got2, "RemoteOrgKey %q should have a value", key2)
		field2, ok2 := got2.(*configresolver.RemoteConfigField)
		require.True(t, ok2, "Expected *RemoteConfigField, got %T", got2)
		assert.Equal(t, false, field2.Value)
		assert.False(t, field2.IsLocked)
		assert.Equal(t, "group", field2.Origin)
	})

	t.Run("no-op for nil orgConfig", func(t *testing.T) {
		conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		WriteOrgConfigToConfiguration(conf, nil)
		// Should not panic; conf should remain empty for remote keys
	})

	t.Run("no-op for nil conf", func(t *testing.T) {
		orgConfig := NewLDXSyncOrgConfig("org1")
		orgConfig.SetField(SettingSnykCodeEnabled, true, false, "org")
		WriteOrgConfigToConfiguration(nil, orgConfig)
		// Should not panic
	})
}

// FC-054: LDX-Sync adapter writes machine settings to RemoteMachineKey prefix keys
func TestWriteMachineConfigToConfiguration_FC054(t *testing.T) {
	t.Run("writes machine config to configuration", func(t *testing.T) {
		conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())

		machineSettings := map[string]*LDXSyncField{
			SettingApiEndpoint: {
				Value:       "https://custom.endpoint.com",
				IsLocked:    true,
				OriginScope: "org",
			},
		}

		WriteMachineConfigToConfiguration(conf, machineSettings)

		key := configresolver.RemoteMachineKey(SettingApiEndpoint)
		got := conf.Get(key)
		require.NotNil(t, got, "RemoteMachineKey %q should have a value", key)
		field, ok := got.(*configresolver.RemoteConfigField)
		require.True(t, ok, "Expected *RemoteConfigField, got %T", got)
		assert.Equal(t, "https://custom.endpoint.com", field.Value)
		assert.True(t, field.IsLocked)
		assert.Equal(t, "org", field.Origin)
	})

	t.Run("no-op for nil conf", func(t *testing.T) {
		machineSettings := map[string]*LDXSyncField{
			SettingApiEndpoint: {Value: "https://x.com", IsLocked: true},
		}
		WriteMachineConfigToConfiguration(nil, machineSettings)
		// Should not panic
	})

	t.Run("no-op for nil machineSettings", func(t *testing.T) {
		conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		WriteMachineConfigToConfiguration(conf, nil)
		// Should not panic
	})
}

// FC-055: LDX-Sync adapter writes folder settings to RemoteOrgFolderKey prefix keys
func TestWriteFolderConfigToConfiguration_FC055(t *testing.T) {
	t.Run("writes folder settings to configuration", func(t *testing.T) {
		conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		orgId := "org-123"
		folderPath := string(PathKey(FilePath("/workspace/my-project")))

		folderSettings := map[string]*LDXSyncField{
			SettingSnykCodeEnabled: {
				Value:       true,
				IsLocked:    true,
				OriginScope: "org",
			},
			SettingScanAutomatic: {
				Value:       false,
				IsLocked:    false,
				OriginScope: "group",
			},
		}

		WriteFolderConfigToConfiguration(conf, orgId, FilePath(folderPath), folderSettings)

		key := configresolver.RemoteOrgFolderKey(orgId, folderPath, SettingSnykCodeEnabled)
		got := conf.Get(key)
		require.NotNil(t, got, "RemoteOrgFolderKey %q should have a value", key)
		field, ok := got.(*configresolver.RemoteConfigField)
		require.True(t, ok, "Expected *RemoteConfigField, got %T", got)
		assert.Equal(t, true, field.Value)
		assert.True(t, field.IsLocked)
		assert.Equal(t, "org", field.Origin)

		key2 := configresolver.RemoteOrgFolderKey(orgId, folderPath, SettingScanAutomatic)
		got2 := conf.Get(key2)
		require.NotNil(t, got2)
		field2, ok2 := got2.(*configresolver.RemoteConfigField)
		require.True(t, ok2)
		assert.Equal(t, false, field2.Value)
		assert.False(t, field2.IsLocked)
	})

	t.Run("no-op for nil conf", func(t *testing.T) {
		WriteFolderConfigToConfiguration(nil, "org1", "/path", map[string]*LDXSyncField{
			SettingSnykCodeEnabled: {Value: true},
		})
	})

	t.Run("no-op for nil settings", func(t *testing.T) {
		conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		WriteFolderConfigToConfiguration(conf, "org1", "/path", nil)
	})
}
