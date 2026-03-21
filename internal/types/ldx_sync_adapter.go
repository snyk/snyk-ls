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
	SettingEnabledSeverities:               "severities",
	SettingRiskScoreThreshold:              "risk_score_threshold",
	SettingCweIds:                          "cwe",
	SettingCveIds:                          "cve",
	SettingRuleIds:                         "rule",
	SettingScanAutomatic:                   "automatic",
	SettingScanNetNew:                      "net_new",
	SettingIssueViewOpenIssues:             "open_issues",
	SettingIssueViewIgnoredIssues:          "ignored_issues",
	SettingReferenceFolder:                 "reference_folder",
	SettingReferenceBranch:                 "reference_branch",
	SettingAdditionalParameters:            "additional_parameters",
	SettingAdditionalEnvironment:           "additional_environment",
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
		for settingName, metadata := range *response.Data.Attributes.Settings {
			// Special handling for "products" - convert list to individual booleans
			if settingName == "products" {
				convertProductsToIndividualSettings(orgConfig, metadata)
				continue
			}

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
	}

	return orgConfig
}

// convertProductsToIndividualSettings converts a "products" list from LDX-Sync
// into individual boolean settings (snyk_code_enabled, snyk_oss_enabled, snyk_iac_enabled)
func convertProductsToIndividualSettings(orgConfig *LDXSyncOrgConfig, metadata v20241015.SettingMetadata) {
	isLocked := util.PtrToBool(metadata.Locked)
	originScope := string(metadata.Origin)

	// Parse the products list
	productsList := parseProductsList(metadata.Value)

	// Set individual boolean fields based on whether each product is in the list
	orgConfig.SetField(SettingSnykCodeEnabled, containsProduct(productsList, "code"), isLocked, originScope)
	orgConfig.SetField(SettingSnykOssEnabled, containsProduct(productsList, "oss"), isLocked, originScope)
	orgConfig.SetField(SettingSnykIacEnabled, containsProduct(productsList, "iac"), isLocked, originScope)
	orgConfig.SetField(SettingSnykSecretsEnabled, containsProduct(productsList, "secrets"), isLocked, originScope)
}

// parseProductsList extracts a []string from the products value
func parseProductsList(value any) []string {
	if value == nil {
		return nil
	}

	// Handle []interface{} (common from JSON unmarshaling)
	if arr, ok := value.([]interface{}); ok {
		result := make([]string, 0, len(arr))
		for _, v := range arr {
			if s, ok := v.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}

	// Handle []string directly
	if arr, ok := value.([]string); ok {
		return arr
	}

	return nil
}

// containsProduct checks if a product name is in the list
func containsProduct(products []string, product string) bool {
	for _, p := range products {
		if p == product {
			return true
		}
	}
	return false
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
