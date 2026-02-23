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
	"slices"

	v20241015 "github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config/ldx_sync/2024-10-15"

	"github.com/snyk/snyk-ls/internal/product"
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

// ConvertLDXSyncResponseToOrgConfig converts a UserConfigResponse to our LDXSyncOrgConfig format
// Only extracts org-scope settings (not machine-scope or folder-scope)
func ConvertLDXSyncResponseToOrgConfig(orgId string, response *v20241015.UserConfigResponse) *LDXSyncOrgConfig {
	if response == nil {
		return nil
	}

	orgConfig := NewLDXSyncOrgConfig(orgId)

	// Extract only org-scope settings from the response
	if response.Data.Attributes.Settings != nil {
		for settingName, metadata := range *response.Data.Attributes.Settings {
			// Special handling for "products" - convert list to individual booleans
			if settingName == "products" {
				convertProductsToIndividualSettings(orgConfig, metadata)
				continue
			}

			// Special handling for "enabled_severities" - convert array to SeverityFilter
			if settingName == "enabled_severities" {
				convertEnabledSeveritiesToFilter(orgConfig, metadata)
				continue
			}

			internalName := getInternalSettingName(settingName)
			if internalName != "" && GetSettingScope(internalName) == SettingScopeOrg {
				orgConfig.SetField(
					internalName,
					metadata.Value,
					util.PtrToBool(metadata.Locked),
					util.PtrToBool(metadata.Enforced),
					string(metadata.Origin),
				)
			}
		}
	}

	return orgConfig
}

// ldxProductToSetting maps Snyk products to their internal enabled-state setting keys
var ldxProductToSetting = map[product.Product]string{
	product.ProductCode:                 SettingSnykCodeEnabled,
	product.ProductOpenSource:           SettingSnykOssEnabled,
	product.ProductInfrastructureAsCode: SettingSnykIacEnabled,
}

// convertProductsToIndividualSettings converts a "products" list from LDX-Sync
// into individual boolean settings (snyk_code_enabled, snyk_oss_enabled, snyk_iac_enabled)
func convertProductsToIndividualSettings(orgConfig *LDXSyncOrgConfig, metadata v20241015.SettingMetadata) {
	isLocked := util.PtrToBool(metadata.Locked)
	isEnforced := util.PtrToBool(metadata.Enforced)
	originScope := string(metadata.Origin)

	// Parse the products list
	productsList := parseProductsList(metadata.Value)

	// Set individual boolean fields based on whether each product is in the list
	for p, setting := range ldxProductToSetting {
		orgConfig.SetField(setting, slices.Contains(productsList, p.ToProductCodename()), isLocked, isEnforced, originScope)
	}
}

// convertEnabledSeveritiesToFilter converts a "severities" array from LDX-Sync
// into a SeverityFilter object
func convertEnabledSeveritiesToFilter(orgConfig *LDXSyncOrgConfig, metadata v20241015.SettingMetadata) {
	isLocked := util.PtrToBool(metadata.Locked)
	isEnforced := util.PtrToBool(metadata.Enforced)
	originScope := string(metadata.Origin)

	// Parse the severities list
	severitiesList := parseProductsList(metadata.Value) // Reuse parseProductsList for string arrays

	filter := SeverityFilter{
		Critical: slices.Contains(severitiesList, "critical"),
		High:     slices.Contains(severitiesList, "high"),
		Medium:   slices.Contains(severitiesList, "medium"),
		Low:      slices.Contains(severitiesList, "low"),
	}

	orgConfig.SetField(SettingEnabledSeverities, filter, isLocked, isEnforced, originScope)
}

// parseProductsList extracts a []string from the products value
func parseProductsList(value any) []string {
	if value == nil {
		return nil
	}

	// Handle []any (common from JSON unmarshaling)
	if arr, ok := value.([]any); ok {
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

// ExtractMachineSettings extracts machine-scope settings from a UserConfigResponse
// These settings apply globally regardless of org
func ExtractMachineSettings(response *v20241015.UserConfigResponse) map[string]*LDXSyncField {
	if response == nil || response.Data.Attributes.Settings == nil {
		return nil
	}

	result := make(map[string]*LDXSyncField)
	for settingName, metadata := range *response.Data.Attributes.Settings {
		internalName := getInternalSettingName(settingName)
		if internalName != "" && GetSettingScope(internalName) == SettingScopeMachine {
			result[internalName] = &LDXSyncField{
				Value:       metadata.Value,
				IsLocked:    util.PtrToBool(metadata.Locked),
				IsEnforced:  util.PtrToBool(metadata.Enforced),
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
				IsEnforced:  util.PtrToBool(metadata.Enforced),
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
