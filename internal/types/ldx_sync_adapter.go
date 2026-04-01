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
	v20241015 "github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config/ldx_sync/2024-10-15"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/internal/util"
)

// LDXSyncSettingKey maps our internal setting names to LDX-Sync API field names
var ldxSyncSettingKeyMap = map[string]string{
	SettingApiEndpoint:                     "api_endpoint",
	SettingCodeEndpoint:                    "code_endpoint",
	SettingAuthenticationMethod:            "authentication_method",
	SettingProxyHttp:                       "proxy_http",
	SettingProxyHttps:                      "proxy_https",
	SettingProxyNoProxy:                    "proxy_no_proxy",
	SettingProxyInsecure:                   "proxy_insecure",
	SettingAutoConfigureMcpServer:          "auto_configure_mcp_server",
	SettingPublishSecurityAtInceptionRules: "publish_security_at_inception_rules",
	SettingTrustEnabled:                    "trust_enabled",
	SettingBinaryBaseUrl:                   "binary_base_url",
	SettingCliPath:                         "cli_path",
	SettingAutomaticDownload:               "automatic_download",
	SettingCliReleaseChannel:               "cli_release_channel",
	SettingRiskScoreThreshold:              "risk_score_threshold",
	SettingCweIds:                          "cwe_ids",
	SettingCveIds:                          "cve_ids",
	SettingRuleIds:                         "rule_ids",
	SettingSnykCodeEnabled:                 "product_code_enabled",
	SettingSnykOssEnabled:                  "product_oss_enabled",
	SettingSnykIacEnabled:                  "product_iac_enabled",
	SettingSnykContainerEnabled:            "product_container_enabled",
	SettingSnykSecretsEnabled:              "product_secrets_enabled",
	SettingScanAutomatic:                   "scan_automatic",
	SettingScanNetNew:                      "scan_net_new",
	SettingIssueViewOpenIssues:             "issue_view_open_issues",
	SettingIssueViewIgnoredIssues:          "issue_view_ignored_issues",
	SettingReferenceFolder:                 "reference_folder",
	SettingReferenceBranch:                 "reference_branch",
	SettingAdditionalParameters:            "additional_parameters",
	SettingAdditionalEnvironment:           "additional_environment",
}

// severityAPIKeys maps LDX-Sync API field names for individual severity booleans
// These are not in ldxSyncSettingKeyMap because they merge into a single SettingEnabledSeverities
var severityAPIKeys = map[string]string{
	"severity_critical_enabled": "Critical",
	"severity_high_enabled":     "High",
	"severity_medium_enabled":   "Medium",
	"severity_low_enabled":      "Low",
}

// ConvertLDXSyncResponseToOrgConfig converts a UserConfigResponse to our LDXSyncOrgConfig format.
// Only extracts folder-scoped settings (not machine-scoped).
// fm is used to determine setting scope from GAF annotations.
func ConvertLDXSyncResponseToOrgConfig(orgId string, response *v20241015.UserConfigResponse, fm workflow.ConfigurationOptionsMetaData) *LDXSyncOrgConfig {
	if response == nil {
		return nil
	}

	orgConfig := NewLDXSyncOrgConfig(orgId)

	if response.Data.Attributes.Settings != nil {
		var sf *SeverityFilter
		var sfLocked bool
		var sfOrigin string

		for settingName, metadata := range *response.Data.Attributes.Settings {
			// Check if this is a severity boolean from the API
			if level, isSeverity := severityAPIKeys[settingName]; isSeverity {
				if sf == nil {
					sf = &SeverityFilter{}
				}
				bVal, _ := metadata.Value.(bool)
				switch level {
				case "Critical":
					sf.Critical = bVal
				case "High":
					sf.High = bVal
				case "Medium":
					sf.Medium = bVal
				case "Low":
					sf.Low = bVal
				}
				if util.PtrToBool(metadata.Locked) {
					sfLocked = true
				}
				if sfOrigin == "" {
					sfOrigin = string(metadata.Origin)
				}
				continue
			}

			// Standard setting mapping
			internalName := getInternalSettingName(settingName)
			if internalName != "" && IsFolderScopedSetting(fm, internalName) {
				orgConfig.SetField(
					internalName,
					metadata.Value,
					util.PtrToBool(metadata.Locked),
					string(metadata.Origin),
				)
			}
		}

		// Store merged severity filter as SettingEnabledSeverities
		if sf != nil {
			orgConfig.SetField(SettingEnabledSeverities, sf, sfLocked, sfOrigin)
		}
	}

	return orgConfig
}

// ExtractMachineSettings extracts machine-scoped settings from a UserConfigResponse.
// fm is used to determine setting scope from GAF annotations.
func ExtractMachineSettings(response *v20241015.UserConfigResponse, fm workflow.ConfigurationOptionsMetaData) map[string]*LDXSyncField {
	if response == nil || response.Data.Attributes.Settings == nil {
		return nil
	}

	result := make(map[string]*LDXSyncField)
	for settingName, metadata := range *response.Data.Attributes.Settings {
		internalName := getInternalSettingName(settingName)
		if internalName != "" && IsMachineWideSetting(fm, internalName) {
			result[internalName] = &LDXSyncField{
				Value:       metadata.Value,
				IsLocked:    util.PtrToBool(metadata.Locked),
				OriginScope: string(metadata.Origin),
			}
		}
	}

	if len(result) == 0 {
		return nil
	}
	return result
}

// ExtractFolderSettings extracts folder-specific settings from a UserConfigResponse for the given remote URL
// These settings should be stored per-folder, NOT merged into the org config cache
// Returns nil if no folder-specific settings are found
func ExtractFolderSettings(response *v20241015.UserConfigResponse, remoteUrl string) map[string]*LDXSyncField {
	if response == nil || response.Data.Attributes.FolderSettings == nil || remoteUrl == "" {
		return nil
	}

	folderSettings, ok := (*response.Data.Attributes.FolderSettings)[remoteUrl]
	if !ok || len(folderSettings) == 0 {
		return nil
	}

	result := make(map[string]*LDXSyncField)
	for settingName, metadata := range folderSettings {
		internalName := getInternalSettingName(settingName)
		if internalName != "" {
			result[internalName] = &LDXSyncField{
				Value:       metadata.Value,
				IsLocked:    util.PtrToBool(metadata.Locked),
				OriginScope: string(metadata.Origin),
			}
		}
	}

	if len(result) == 0 {
		return nil
	}
	return result
}

// getInternalSettingName maps an LDX-Sync API field name to our internal setting name
func getInternalSettingName(ldxSyncKey string) string {
	for internal, ldx := range ldxSyncSettingKeyMap {
		if ldx == ldxSyncKey {
			return internal
		}
	}
	return ""
}

// GetLDXSyncKey returns the LDX-Sync API field name for an internal setting name
func GetLDXSyncKey(internalName string) string {
	return ldxSyncSettingKeyMap[internalName]
}

// WriteOrgConfigToConfiguration writes org-scope LDX-Sync config to configuration
// using RemoteOrgKey prefix keys. Each field is stored as a *RemoteConfigField.
func WriteOrgConfigToConfiguration(conf configuration.Configuration, orgConfig *LDXSyncOrgConfig) {
	if orgConfig == nil || conf == nil {
		return
	}
	for settingName, field := range orgConfig.Fields {
		if field == nil {
			continue
		}
		key := configresolver.RemoteOrgKey(orgConfig.OrgId, settingName)
		conf.Set(key, &configresolver.RemoteConfigField{
			Value:    field.Value,
			IsLocked: field.IsLocked,
			Origin:   field.OriginScope,
		})
	}
}

// WriteMachineConfigToConfiguration writes machine-scope LDX-Sync config to configuration
// using RemoteMachineKey prefix keys. Each field is stored as a *RemoteConfigField.
func WriteMachineConfigToConfiguration(conf configuration.Configuration, machineSettings map[string]*LDXSyncField) {
	if conf == nil {
		return
	}
	for settingName, field := range machineSettings {
		if field == nil {
			continue
		}
		key := configresolver.RemoteMachineKey(settingName)
		conf.Set(key, &configresolver.RemoteConfigField{
			Value:    field.Value,
			IsLocked: field.IsLocked,
			Origin:   field.OriginScope,
		})
	}
}

// WriteFolderConfigToConfiguration writes folder-level remote config to configuration
// using RemoteOrgFolderKey prefix keys. Each field is stored as a *RemoteConfigField.
func WriteFolderConfigToConfiguration(conf configuration.Configuration, orgId string, folderPath FilePath, settings map[string]*LDXSyncField) {
	if conf == nil || settings == nil {
		return
	}
	fp := string(PathKey(folderPath))
	if fp == "" {
		return
	}
	for settingName, field := range settings {
		if field == nil {
			continue
		}
		key := configresolver.RemoteOrgFolderKey(orgId, fp, settingName)
		conf.Set(key, &configresolver.RemoteConfigField{
			Value:    field.Value,
			IsLocked: field.IsLocked,
			Origin:   field.OriginScope,
		})
	}
}

// ExtractOrgIdFromResponse extracts the preferred organization ID from a UserConfigResponse
func ExtractOrgIdFromResponse(response *v20241015.UserConfigResponse) string {
	if response == nil || response.Data.Attributes.Organizations == nil {
		return ""
	}

	// First try to find the preferred organization
	for _, org := range *response.Data.Attributes.Organizations {
		if org.PreferredByAlgorithm != nil && *org.PreferredByAlgorithm {
			return org.Id
		}
	}

	// Fall back to default organization
	for _, org := range *response.Data.Attributes.Organizations {
		if org.IsDefault != nil && *org.IsDefault {
			return org.Id
		}
	}

	// Return first org if available
	if len(*response.Data.Attributes.Organizations) > 0 {
		return (*response.Data.Attributes.Organizations)[0].Id
	}

	return ""
}
