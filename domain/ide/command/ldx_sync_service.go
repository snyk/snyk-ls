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
	"context"
	"sync"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/types"
)

// LdxSyncApiClient abstracts the external LDX-Sync API calls for testability
type LdxSyncApiClient interface {
	GetUserConfigForProject(ctx context.Context, engine workflow.Engine, projectPath string, preferredOrg string) ldx_sync_config.LdxSyncConfigResult
}

// DefaultLdxSyncApiClient wraps the real GAF LDX-Sync functions
type DefaultLdxSyncApiClient struct{}

// GetUserConfigForProject calls the GAF ldx_sync_config package
func (a *DefaultLdxSyncApiClient) GetUserConfigForProject(ctx context.Context, engine workflow.Engine, projectPath string, preferredOrg string) ldx_sync_config.LdxSyncConfigResult {
	// TODO: pass ctx to GAF GetUserConfigForProject once it supports context
	_ = ctx
	return ldx_sync_config.GetUserConfigForProject(engine, projectPath, preferredOrg)
}

// LdxSyncService provides LDX-Sync configuration refresh functionality
type LdxSyncService interface {
	RefreshConfigFromLdxSync(ctx context.Context, c *config.Config, workspaceFolders []types.Folder, notifier notification.Notifier)
}

// DefaultLdxSyncService is the default implementation of LdxSyncService
type DefaultLdxSyncService struct {
	apiClient      LdxSyncApiClient
	configResolver types.ConfigResolverInterface
}

// NewLdxSyncService creates a new LdxSyncService with the default API client
func NewLdxSyncService(configResolver types.ConfigResolverInterface) LdxSyncService {
	return &DefaultLdxSyncService{
		apiClient:      &DefaultLdxSyncApiClient{},
		configResolver: configResolver,
	}
}

// NewLdxSyncServiceWithApiClient creates a new LdxSyncService with a custom API client (for testing)
func NewLdxSyncServiceWithApiClient(apiClient LdxSyncApiClient, configResolver types.ConfigResolverInterface) LdxSyncService {
	return &DefaultLdxSyncService{
		apiClient:      apiClient,
		configResolver: configResolver,
	}
}

// RefreshConfigFromLdxSync refreshes the user configuration from LDX-Sync for all workspace folders in parallel.
// Results are stored in the LDXSyncConfigCache:
// - FolderToOrgMapping: maps folder paths to their resolved org IDs
// - OrgConfigs: maps org IDs to their org-level settings
// The notifier is used to send $/snyk.configuration when machine config is updated.
func (s *DefaultLdxSyncService) RefreshConfigFromLdxSync(ctx context.Context, c *config.Config, workspaceFolders []types.Folder, notifier notification.Notifier) {
	logger := c.Logger().With().Str("method", "RefreshConfigFromLdxSync").Logger()
	engine := c.Engine()
	gafConfig := engine.GetConfiguration()

	var wg sync.WaitGroup
	results := make(map[types.FilePath]*ldx_sync_config.LdxSyncConfigResult)
	resultsMutex := sync.Mutex{}

	for _, folder := range workspaceFolders {
		if ctx.Err() != nil {
			logger.Info().Msg("Context canceled, skipping remaining folders")
			break
		}
		wg.Add(1)
		go func(f types.Folder) {
			defer wg.Done()

			if ctx.Err() != nil {
				return
			}

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

			cfgResult := s.apiClient.GetUserConfigForProject(ctx, engine, string(f.Path()), preferredOrg)

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
				cfgResult = s.apiClient.GetUserConfigForProject(ctx, engine, string(f.Path()), "")

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

			logger.Debug().
				Str("folder", string(f.Path())).
				Msg("Retrieved user config from LDX-Sync")
		}(folder)
	}

	// Wait for all goroutines to complete
	wg.Wait()

	if ctx.Err() != nil {
		logger.Info().Msg("Context canceled after waiting for LDX-Sync results, skipping config update")
		return
	}

	// Update the org config cache (including folder-to-org mapping) and global config
	s.updateOrgConfigCache(c, results)
	s.updateGlobalConfig(c, results, notifier)
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

		// Store folder → org mapping for callers to look up (path normalization is handled internally by SetFolderOrg)
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

// updateGlobalConfig extracts global/machine-scope settings from LDX-Sync results and applies them to Config.
// Global settings don't vary by org, so we take the first available result.
// For each setting:
// - If locked: always use LDX-Sync value (user cannot override)
// - If enforced: use LDX-Sync value (user can temporarily override between LDX-Sync runs)
// - Otherwise: use LDX-Sync value only if user hasn't set a non-default value
// After updating, sends $/snyk.configuration notification so IDE can persist the changes.
func (s *DefaultLdxSyncService) updateGlobalConfig(c *config.Config, results map[types.FilePath]*ldx_sync_config.LdxSyncConfigResult, notifier notification.Notifier) {
	logger := c.Logger().With().Str("method", "updateGlobalConfig").Logger()

	var configUpdated = false
	for folderPath, result := range results {
		if result == nil || result.Config == nil {
			continue
		}

		// Extract global settings from the first valid response
		if !configUpdated {
			globalConfig := types.ExtractMachineSettings(result.Config)
			if len(globalConfig) > 0 {
				// Store metadata (locked/enforced status) for ConfigResolver
				if s.configResolver != nil {
					s.configResolver.SetLDXSyncMachineConfig(globalConfig)
				}

				// Apply actual values to Config
				s.applyGlobalConfigValues(c, globalConfig)

				logger.Debug().
					Str("folder", string(folderPath)).
					Int("fieldCount", len(globalConfig)).
					Msg("Updated global config from LDX-Sync")
				configUpdated = true
			} else {
				logger.Debug().
					Str("folder", string(folderPath)).
					Msg("No global config found in LDX-Sync response, skipping global config update")
			}
		} else {
			logger.Debug().
				Str("folder", string(folderPath)).
				Msg("Global config already applied from another folder, skipping")
		}
	}

	// Send $/snyk.configuration notification so IDE can persist the updated global config
	if configUpdated && notifier != nil {
		lspConfig := BuildLspConfiguration(c)
		notifier.Send(lspConfig)
		logger.Debug().Msg("Sent $/snyk.configuration notification after global config update")
	}
}

// applyGlobalConfigValues applies global/machine-scope setting values from LDX-Sync to Config.
// For locked/enforced settings, the LDX-Sync value is always applied.
// For non-locked/non-enforced settings, the value is only applied if the user hasn't set a custom value.
func (s *DefaultLdxSyncService) applyGlobalConfigValues(c *config.Config, globalConfig map[string]*types.LDXSyncField) {
	logger := c.Logger().With().Str("method", "applyGlobalConfigValues").Logger()

	for settingName, field := range globalConfig {
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

// machineStringSettingDef defines a string machine-scope setting: isDefault check and setter.
type machineStringSettingDef struct {
	isDefault func() bool
	setter    func(string)
}

// machineBoolSettingDef defines a bool machine-scope setting: isDefault check and setter.
type machineBoolSettingDef struct {
	isDefault func() bool
	setter    func(bool)
}

// applyMachineSetting applies a single machine-scope setting value to Config.
// Returns true if the value was applied.
func (s *DefaultLdxSyncService) applyMachineSetting(c *config.Config, settingName string, field *types.LDXSyncField) bool {
	shouldApply := field.IsLocked || field.IsEnforced

	// Special case: authentication method has unique logic
	if settingName == types.SettingAuthenticationMethod {
		if strVal, ok := field.Value.(string); ok && strVal != "" {
			if shouldApply || c.AuthenticationMethod() == types.EmptyAuthenticationMethod {
				c.SetAuthenticationMethod(types.AuthenticationMethod(strVal))
				return true
			}
		}
		return false
	}

	if def, ok := s.stringSettingDefs(c)[settingName]; ok {
		return s.applyStringSettingIfNeeded(field, shouldApply, def.isDefault(), def.setter)
	}
	if def, ok := s.boolSettingDefs(c)[settingName]; ok {
		return s.applyBoolSettingIfNeeded(field, shouldApply, def.isDefault(), def.setter)
	}
	return false
}

func (s *DefaultLdxSyncService) stringSettingDefs(c *config.Config) map[string]machineStringSettingDef {
	return map[string]machineStringSettingDef{
		types.SettingApiEndpoint:       {func() bool { return c.Endpoint() == config.DefaultSnykApiUrl }, func(v string) { c.UpdateApiEndpoints(v) }},
		types.SettingCliPath:           {func() bool { return c.CliSettings().Path() == "" }, func(v string) { c.CliSettings().SetPath(v) }},
		types.SettingBinaryBaseUrl:     {func() bool { return c.CliBaseDownloadURL() == "" }, func(v string) { c.SetCliBaseDownloadURL(v) }},
		types.SettingCodeEndpoint:      {func() bool { return c.CodeEndpoint() == "" }, func(v string) { c.SetCodeEndpoint(v) }},
		types.SettingProxyHttp:         {func() bool { return c.ProxyHttp() == "" }, func(v string) { c.SetProxyHttp(v) }},
		types.SettingProxyHttps:        {func() bool { return c.ProxyHttps() == "" }, func(v string) { c.SetProxyHttps(v) }},
		types.SettingProxyNoProxy:      {func() bool { return c.ProxyNoProxy() == "" }, func(v string) { c.SetProxyNoProxy(v) }},
		types.SettingCliReleaseChannel: {func() bool { return c.CliReleaseChannel() == "" }, func(v string) { c.SetCliReleaseChannel(v) }},
	}
}

func (s *DefaultLdxSyncService) boolSettingDefs(c *config.Config) map[string]machineBoolSettingDef {
	return map[string]machineBoolSettingDef{
		types.SettingAutomaticDownload:               {func() bool { return c.ManageBinariesAutomatically() }, func(v bool) { c.SetManageBinariesAutomatically(v) }},
		types.SettingTrustEnabled:                    {func() bool { return c.IsTrustedFolderFeatureEnabled() }, func(v bool) { c.SetTrustedFolderFeatureEnabled(v) }},
		types.SettingAutoConfigureMcpServer:          {func() bool { return !c.IsAutoConfigureMcpEnabled() }, func(v bool) { c.SetAutoConfigureMcpEnabled(v) }},
		types.SettingProxyInsecure:                   {func() bool { return !c.IsProxyInsecure() }, func(v bool) { c.SetProxyInsecure(v) }},
		types.SettingPublishSecurityAtInceptionRules: {func() bool { return !c.IsPublishSecurityAtInceptionRulesEnabled() }, func(v bool) { c.SetPublishSecurityAtInceptionRulesEnabled(v) }},
	}
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
