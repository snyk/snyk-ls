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

	"github.com/snyk/snyk-ls/internal/util"
)

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
			// Special handling for "enabled_products" - convert list to individual booleans
			if settingName == SettingEnabledProducts {
				convertProductsToIndividualSettings(orgConfig, metadata)
				continue
			}

			// Special handling for "enabled_severities" - convert array to SeverityFilter
			if settingName == SettingEnabledSeverities {
				convertEnabledSeveritiesToFilter(orgConfig, metadata)
				continue
			}

			if scope, ok := settingScopeByName[settingName]; ok && scope == SettingScopeOrg {
				orgConfig.SetField(
					settingName,
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

// convertProductsToIndividualSettings converts a "products" list from LDX-Sync
// into individual boolean settings (snyk_code_enabled, snyk_oss_enabled, snyk_iac_enabled)
func convertProductsToIndividualSettings(orgConfig *LDXSyncOrgConfig, metadata v20241015.SettingMetadata) {
	isLocked := util.PtrToBool(metadata.Locked)
	isEnforced := util.PtrToBool(metadata.Enforced)
	originScope := string(metadata.Origin)

	productsList := parseProductsList(metadata.Value)

	for _, desc := range productRegistry {
		orgConfig.SetField(desc.settingName, slices.Contains(productsList, desc.codename), isLocked, isEnforced, originScope)
	}
}

// convertEnabledSeveritiesToFilter converts an "enabled_severities" array from LDX-Sync
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
		if scope, ok := settingScopeByName[settingName]; ok && scope == SettingScopeMachine {
			result[settingName] = &LDXSyncField{
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
		if _, ok := settingScopeByName[settingName]; ok {
			result[settingName] = &LDXSyncField{
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
