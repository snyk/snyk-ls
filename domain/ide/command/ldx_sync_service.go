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

// ABOUTME: LDX-Sync service provides configuration refresh from LDX-Sync API
// ABOUTME: Implements parallel fetching and caching of user config for workspace folders

package command

//go:generate go tool github.com/golang/mock/mockgen -source=ldx_sync_service.go -destination mock/ldx_sync_service_mock.go -package mock_command

import (
	"sync"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/types"
)

// LdxSyncApiClient abstracts the external LDX-Sync API calls for testability
type LdxSyncApiClient interface {
	GetUserConfigForProject(engine workflow.Engine, projectPath string, preferredOrg string) ldx_sync_config.LdxSyncConfigResult
}

// DefaultLdxSyncApiClient wraps the real GAF LDX-Sync functions
type DefaultLdxSyncApiClient struct{}

// GetUserConfigForProject calls the GAF ldx_sync_config package
func (a *DefaultLdxSyncApiClient) GetUserConfigForProject(engine workflow.Engine, projectPath string, preferredOrg string) ldx_sync_config.LdxSyncConfigResult {
	return ldx_sync_config.GetUserConfigForProject(engine, projectPath, preferredOrg)
}

// LdxSyncService provides LDX-Sync configuration refresh functionality
type LdxSyncService interface {
	RefreshConfigFromLdxSync(c *config.Config, workspaceFolders []types.Folder)
}

// DefaultLdxSyncService is the default implementation of LdxSyncService
type DefaultLdxSyncService struct {
	apiClient LdxSyncApiClient
}

// NewLdxSyncService creates a new LdxSyncService with the default API client
func NewLdxSyncService() LdxSyncService {
	return &DefaultLdxSyncService{
		apiClient: &DefaultLdxSyncApiClient{},
	}
}

// NewLdxSyncServiceWithApiClient creates a new LdxSyncService with a custom API client (for testing)
func NewLdxSyncServiceWithApiClient(apiClient LdxSyncApiClient) LdxSyncService {
	return &DefaultLdxSyncService{
		apiClient: apiClient,
	}
}

// RefreshConfigFromLdxSync refreshes the user configuration from LDX-Sync for all workspace folders in parallel.
// Results are stored in the LDXSyncConfigCache:
// - FolderToOrgMapping: maps folder paths to their resolved org IDs
// - OrgConfigs: maps org IDs to their org-level settings
func (s *DefaultLdxSyncService) RefreshConfigFromLdxSync(c *config.Config, workspaceFolders []types.Folder) {
	logger := c.Logger().With().Str("method", "RefreshConfigFromLdxSync").Logger()
	engine := c.Engine()
	gafConfig := engine.GetConfiguration()

	var wg sync.WaitGroup
	results := make(map[types.FilePath]*ldx_sync_config.LdxSyncConfigResult)
	resultsMutex := sync.Mutex{}

	for _, folder := range workspaceFolders {
		wg.Add(1)
		go func(f types.Folder) {
			defer wg.Done()

			// Get PreferredOrg from folder config (or empty string if missing)
			folderConfig, err := storedconfig.GetFolderConfigWithOptions(gafConfig, f.Path(), &logger, storedconfig.GetFolderConfigOptions{
				CreateIfNotExist: false,
				ReadOnly:         true,
				EnrichFromGit:    false,
			})
			preferredOrg := ""
			if err == nil && folderConfig != nil {
				preferredOrg = folderConfig.PreferredOrg
			}

			logger.Debug().
				Str("projectPath", string(f.Path())).
				Str("preferredOrg", preferredOrg).
				Msg("LDX-Sync API Request - calling GetUserConfigForProject")

			cfgResult := s.apiClient.GetUserConfigForProject(engine, string(f.Path()), preferredOrg)

			logger.Debug().
				Str("projectPath", string(f.Path())).
				Bool("hasError", cfgResult.Error != nil).
				Bool("hasConfig", cfgResult.Config != nil).
				Str("remoteUrl", cfgResult.RemoteUrl).
				Str("projectRoot", cfgResult.ProjectRoot).
				Interface("fullResult", cfgResult).
				Msg("LDX-Sync API Response - full result")

			// Fallback logic: If PreferredOrg fails, retry without it to allow auto-determination
			if cfgResult.Error != nil && preferredOrg != "" {
				logger.Warn().
					Str("folder", string(f.Path())).
					Str("preferredOrg", preferredOrg).
					Err(cfgResult.Error).
					Msg("PreferredOrg failed, retrying without it")

				// Retry without PreferredOrg to allow full auto-determination
				cfgResult = s.apiClient.GetUserConfigForProject(engine, string(f.Path()), "")

				logger.Debug().
					Str("projectPath", string(f.Path())).
					Bool("hasError", cfgResult.Error != nil).
					Bool("hasConfig", cfgResult.Config != nil).
					Msg("LDX-Sync fallback response")
			}

			// Store result in temporary map (even if there's an error)
			// This allows ResolveOrg to distinguish between "never attempted" and "attempted but failed"
			resultsMutex.Lock()
			results[f.Path()] = &cfgResult
			resultsMutex.Unlock()

			if cfgResult.Error != nil {
				logger.Err(cfgResult.Error).
					Str("folder", string(f.Path())).
					Msg("Failed to get user config from LDX-Sync")
				return
			}

			// Store result in temporary map
			resultsMutex.Lock()
			results[f.Path()] = &cfgResult
			resultsMutex.Unlock()

			logger.Debug().
				Str("folder", string(f.Path())).
				Msg("Retrieved user config from LDX-Sync")
		}(folder)
	}

	// Wait for all goroutines to complete
	wg.Wait()

	// Update the org config cache (including folder-to-org mapping) and machine config
	s.updateOrgConfigCache(c, results)
	s.updateMachineConfig(c, results)
}

// updateOrgConfigCache converts LDX-Sync results to org configs and updates the cache.
// This populates both:
// - FolderToOrgMapping: folder path → org ID (for callers to look up the resolved org)
// - OrgConfigs: org ID → org-level settings (for ConfigResolver to read settings)
//
// When a field from LDX-Sync is Locked or Enforced, we clear any user overrides for that field
// from FolderConfigs using that org. This ensures org policy takes precedence.
func (s *DefaultLdxSyncService) updateOrgConfigCache(c *config.Config, results map[types.FilePath]*ldx_sync_config.LdxSyncConfigResult) {
	logger := c.Logger().With().Str("method", "updateOrgConfigCache").Logger()
	cache := c.GetLdxSyncOrgConfigCache()

	// Track which orgs have locked/enforced fields that need override clearing
	orgLockedFields := make(map[string][]string) // orgId -> list of locked field names

	for folderPath, result := range results {
		if result == nil || result.Config == nil {
			continue
		}

		// Extract org ID from the response
		orgId := types.ExtractOrgIdFromResponse(result.Config)
		if orgId == "" {
			logger.Debug().
				Str("folder", string(folderPath)).
				Msg("No org ID found in LDX-Sync response, skipping org config cache update")
			continue
		}

		// Store folder → org mapping for callers to look up
		cache.SetFolderOrg(folderPath, orgId)

		// Convert to our org config format (org-level settings only)
		orgConfig := types.ConvertLDXSyncResponseToOrgConfig(orgId, result.Config)
		if orgConfig == nil {
			continue
		}

		// Collect locked/enforced fields for this org (only need to do once per org)
		if _, seen := orgLockedFields[orgId]; !seen {
			orgLockedFields[orgId] = []string{}
			for fieldName, field := range orgConfig.Fields {
				if field != nil && (field.IsLocked || field.IsEnforced) {
					orgLockedFields[orgId] = append(orgLockedFields[orgId], fieldName)
				}
			}
		}

		// Update the org config in cache
		c.UpdateLdxSyncOrgConfig(orgConfig)

		logger.Debug().
			Str("folder", string(folderPath)).
			Str("orgId", orgId).
			Int("fieldCount", len(orgConfig.Fields)).
			Msg("Updated org config cache from LDX-Sync")
	}

	// Clear user overrides for locked/enforced fields from FolderConfigs
	s.clearLockedOverridesFromFolderConfigs(c, orgLockedFields, &logger)
}

// updateMachineConfig extracts machine-scope settings from LDX-Sync results and applies them to Config.
// Machine settings are global and don't vary by org, so we take the first available result.
// For each setting:
// - If locked: always use LDX-Sync value (user cannot override)
// - If enforced: use LDX-Sync value (user can temporarily override between LDX-Sync runs)
// - Otherwise: use LDX-Sync value only if user hasn't set a non-default value
func (s *DefaultLdxSyncService) updateMachineConfig(c *config.Config, results map[types.FilePath]*ldx_sync_config.LdxSyncConfigResult) {
	logger := c.Logger().With().Str("method", "updateMachineConfig").Logger()

	var configUpdated = false
	for folderPath, result := range results {
		if result == nil || result.Config == nil {
			continue
		}

		// Extract machine-scope settings from the first valid response
		if !configUpdated {
			machineConfig := types.ExtractMachineSettings(result.Config)
			if len(machineConfig) > 0 {
				// Store metadata (locked/enforced status) for ConfigResolver
				c.UpdateLdxSyncMachineConfig(machineConfig)

				// Apply actual values to Config
				s.applyMachineConfigValues(c, machineConfig)

				logger.Debug().
					Str("folder", string(folderPath)).
					Int("fieldCount", len(machineConfig)).
					Msg("Updated machine config from LDX-Sync")
				configUpdated = true
			} else {
				logger.Debug().
					Str("folder", string(folderPath)).
					Msg("No machine config found in LDX-Sync response, skipping machine config update")
			}
		} else {
			logger.Debug().
				Str("folder", string(folderPath)).
				Msg("Machine config already applied from another folder, skipping")
		}
	}
}

// applyMachineConfigValues applies machine-scope setting values from LDX-Sync to Config.
// For locked/enforced settings, the LDX-Sync value is always applied.
// For non-locked/non-enforced settings, the value is only applied if the user hasn't set a custom value.
func (s *DefaultLdxSyncService) applyMachineConfigValues(c *config.Config, machineConfig map[string]*types.LDXSyncField) {
	logger := c.Logger().With().Str("method", "applyMachineConfigValues").Logger()

	for settingName, field := range machineConfig {
		if field == nil || field.Value == nil {
			continue
		}

		applied := s.applyMachineSetting(c, settingName, field)
		if applied {
			logger.Debug().
				Str("setting", settingName).
				Bool("locked", field.IsLocked).
				Bool("enforced", field.IsEnforced).
				Msg("Applied LDX-Sync value")
		}
	}
}

// applyMachineSetting applies a single machine-scope setting value to Config.
// Returns true if the value was applied.
func (s *DefaultLdxSyncService) applyMachineSetting(c *config.Config, settingName string, field *types.LDXSyncField) bool {
	shouldApply := field.IsLocked || field.IsEnforced

	switch settingName {
	case types.SettingApiEndpoint:
		return s.applyStringSettingIfNeeded(field, shouldApply, c.Endpoint() == config.DefaultSnykApiUrl, func(v string) { c.UpdateApiEndpoints(v) })
	case types.SettingCliPath:
		return s.applyStringSettingIfNeeded(field, shouldApply, c.CliSettings().Path() == "", func(v string) { c.CliSettings().SetPath(v) })
	case types.SettingBinaryBaseUrl:
		return s.applyStringSettingIfNeeded(field, shouldApply, c.CliBaseDownloadURL() == "", func(v string) { c.SetCliBaseDownloadURL(v) })
	case types.SettingAutomaticDownload:
		return s.applyBoolSettingIfNeeded(field, shouldApply, c.ManageBinariesAutomatically(), func(v bool) { c.SetManageBinariesAutomatically(v) })
	case types.SettingTrustEnabled:
		return s.applyBoolSettingIfNeeded(field, shouldApply, c.IsTrustedFolderFeatureEnabled(), func(v bool) { c.SetTrustedFolderFeatureEnabled(v) })
	case types.SettingAutoConfigureMcpServer:
		return s.applyBoolSettingIfNeeded(field, shouldApply, !c.IsAutoConfigureMcpEnabled(), func(v bool) { c.SetAutoConfigureMcpEnabled(v) })
	case types.SettingAuthenticationMethod:
		if strVal, ok := field.Value.(string); ok && strVal != "" {
			if shouldApply || c.AuthenticationMethod() == types.EmptyAuthenticationMethod {
				c.SetAuthenticationMethod(types.AuthenticationMethod(strVal))
				return true
			}
		}
	}
	return false
}

func (s *DefaultLdxSyncService) applyStringSettingIfNeeded(field *types.LDXSyncField, shouldApply, isDefault bool, setter func(string)) bool {
	if strVal, ok := field.Value.(string); ok && strVal != "" {
		if shouldApply || isDefault {
			setter(strVal)
			return true
		}
	}
	return false
}

func (s *DefaultLdxSyncService) applyBoolSettingIfNeeded(field *types.LDXSyncField, shouldApply, isDefault bool, setter func(bool)) bool {
	if boolVal, ok := field.Value.(bool); ok {
		if shouldApply || isDefault {
			setter(boolVal)
			return true
		}
	}
	return false
}

// clearLockedOverridesFromFolderConfigs clears user overrides for locked/enforced fields
// from all FolderConfigs that use the affected orgs.
// When LDX-Sync returns Enforced/Locked fields, we clear any user overrides
// from FolderConfigs that use that org. This ensures org policy takes precedence.
func (s *DefaultLdxSyncService) clearLockedOverridesFromFolderConfigs(c *config.Config, orgLockedFields map[string][]string, logger *zerolog.Logger) {
	if len(orgLockedFields) == 0 {
		return
	}

	gafConfig := c.Engine().GetConfiguration()
	sc, err := storedconfig.GetStoredConfig(gafConfig, logger, true)
	if err != nil {
		logger.Err(err).Msg("Failed to get stored config for clearing locked overrides")
		return
	}

	// Use the cache's FolderToOrgMapping to determine org for each folder
	// This is more accurate than FolderOrganization because the cache was just updated
	cache := c.GetLdxSyncOrgConfigCache()

	modified := false
	for folderPath, fc := range sc.FolderConfigs {
		if fc == nil || fc.UserOverrides == nil || len(fc.UserOverrides) == 0 {
			continue
		}

		// Get the org from the cache's FolderToOrgMapping (just updated by updateOrgConfigCache)
		effectiveOrg := cache.GetOrgIdForFolder(folderPath)
		if effectiveOrg == "" {
			continue
		}

		// Check if this org has any locked/enforced fields
		lockedFields, hasLockedFields := orgLockedFields[effectiveOrg]
		if !hasLockedFields || len(lockedFields) == 0 {
			continue
		}

		// Clear user overrides for locked/enforced fields
		for _, fieldName := range lockedFields {
			if _, hasOverride := fc.UserOverrides[fieldName]; hasOverride {
				delete(fc.UserOverrides, fieldName)
				modified = true
				logger.Debug().
					Str("folder", string(folderPath)).
					Str("org", effectiveOrg).
					Str("field", fieldName).
					Msg("Cleared user override for locked/enforced field")
			}
		}
	}

	// Save if any modifications were made
	if modified {
		if err := storedconfig.Save(gafConfig, sc); err != nil {
			logger.Err(err).Msg("Failed to save stored config after clearing locked overrides")
		} else {
			logger.Debug().Msg("Saved stored config after clearing locked overrides")
		}
	}
}
