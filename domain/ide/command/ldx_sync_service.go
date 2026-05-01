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
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

// LdxSyncApiClient abstracts the external LDX-Sync API calls for testability
type LdxSyncApiClient interface {
	GetUserConfigForProject(ctx context.Context, engine workflow.Engine, projectPath string, preferredOrg string) ldx_sync_config.LdxSyncConfigResult
}

// DefaultLdxSyncApiClient wraps the real framework LDX-Sync functions
type DefaultLdxSyncApiClient struct{}

// GetUserConfigForProject calls the framework ldx_sync_config package
func (a *DefaultLdxSyncApiClient) GetUserConfigForProject(ctx context.Context, engine workflow.Engine, projectPath string, preferredOrg string) ldx_sync_config.LdxSyncConfigResult {
	// TODO: pass ctx to framework GetUserConfigForProject once it supports context
	_ = ctx
	return ldx_sync_config.GetUserConfigForProject(engine, projectPath, preferredOrg)
}

// LdxSyncService provides LDX-Sync configuration refresh functionality
type LdxSyncService interface {
	RefreshConfigFromLdxSync(ctx context.Context, conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, workspaceFolders []types.Folder, notifier notification.Notifier)
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
// Results are stored in GAF configuration via prefix keys:
// - RemoteOrgKey / RemoteMachineKey: org-level and machine-level settings
// - FolderMetadataKey(AutoDeterminedOrg): folder-to-org mapping
// The notifier is used to send $/snyk.configuration when machine config is updated.
func (s *DefaultLdxSyncService) RefreshConfigFromLdxSync(ctx context.Context, conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, workspaceFolders []types.Folder, notifier notification.Notifier) {
	log := logger.With().Str("method", "RefreshConfigFromLdxSync").Logger()

	var wg sync.WaitGroup
	results := make(map[types.FilePath]*ldx_sync_config.LdxSyncConfigResult)
	resultsMutex := sync.Mutex{}

	for _, folder := range workspaceFolders {
		if ctx.Err() != nil {
			log.Info().Msg("Context canceled, skipping remaining folders")
			break
		}
		wg.Add(1)
		go func(f types.Folder) {
			defer wg.Done()

			if ctx.Err() != nil {
				return
			}

			// Get PreferredOrg from folder config (or empty string if missing)
			folderConfig := config.GetUnenrichedFolderConfigFromEngine(engine, s.configResolver, f.Path(), logger)
			preferredOrg := ""
			if folderConfig != nil && folderConfig.OrgSetByUser() {
				preferredOrg = folderConfig.PreferredOrg()
			}

			log.Debug().
				Str("projectPath", string(f.Path())).
				Str("preferredOrg", preferredOrg).
				Msg("LDX-Sync API Request - calling GetUserConfigForProject")

			cfgResult := s.apiClient.GetUserConfigForProject(ctx, engine, string(f.Path()), preferredOrg)

			log.Debug().
				Str("projectPath", string(f.Path())).
				Bool("hasError", cfgResult.Error != nil).
				Bool("hasConfig", cfgResult.Config != nil).
				Str("remoteUrl", cfgResult.RemoteUrl).
				Str("projectRoot", cfgResult.ProjectRoot).
				Interface("fullResult", cfgResult).
				Msg("LDX-Sync API Response - full result")

			// Fallback logic: If PreferredOrg fails, retry without it to allow auto-determination
			if cfgResult.Error != nil && preferredOrg != "" {
				log.Warn().
					Str("folder", string(f.Path())).
					Str("preferredOrg", preferredOrg).
					Err(cfgResult.Error).
					Msg("PreferredOrg failed, retrying without it")

				// Retry without PreferredOrg to allow full auto-determination
				cfgResult = s.apiClient.GetUserConfigForProject(ctx, engine, string(f.Path()), "")

				log.Debug().
					Str("projectPath", string(f.Path())).
					Bool("hasError", cfgResult.Error != nil).
					Bool("hasConfig", cfgResult.Config != nil).
					Interface("fullResult", cfgResult).
					Msg("LDX-Sync fallback response")
			}

			// Store result in temporary map (even if there's an error)
			// This allows ResolveOrg to distinguish between "never attempted" and "attempted but failed"
			resultsMutex.Lock()
			results[f.Path()] = &cfgResult
			resultsMutex.Unlock()

			if cfgResult.Error != nil {
				log.Err(cfgResult.Error).
					Str("folder", string(f.Path())).
					Msg("Failed to get user config from LDX-Sync")
				return
			}

			log.Debug().
				Str("folder", string(f.Path())).
				Msg("Retrieved user config from LDX-Sync")
		}(folder)
	}

	// Wait for all goroutines to complete
	wg.Wait()

	if ctx.Err() != nil {
		log.Info().Msg("Context canceled after waiting for LDX-Sync results, skipping config update")
		return
	}

	// Update the org config cache (including folder-to-org mapping) and global config
	s.updateOrgConfigCache(conf, engine, &log, results)
	s.updateGlobalConfig(conf, engine, &log, results, notifier)
}

// updateOrgConfigCache converts LDX-Sync results to org configs, writes them to GAF configuration,
// and stores the folder→org mapping as AutoDeterminedOrg in FolderMetadataKey so all callers
// can read it directly from GAF without a separate in-memory cache.
//
// When a field from LDX-Sync is Locked, we clear any user overrides for that field
// from FolderConfigs using that org. This ensures org policy takes precedence.
func (s *DefaultLdxSyncService) updateOrgConfigCache(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, results map[types.FilePath]*ldx_sync_config.LdxSyncConfigResult) {
	// Track which orgs have locked fields that need override clearing
	orgLockedFields := make(map[string][]string) // orgId -> list of locked field names

	for folderPath, result := range results {
		if result == nil || result.Config == nil {
			continue
		}

		// Extract org ID from the response
		autoDeterminedOrgId := types.ExtractOrgIdFromResponse(result.Config)
		if autoDeterminedOrgId == "" {
			logger.Debug().
				Str("folder", string(folderPath)).
				Msg("No org ID found in LDX-Sync response, skipping org config update")
			continue
		}

		// Store folder → org mapping in GAF FolderMetadataKey so all callers can read it directly
		types.SetAutoDeterminedOrg(conf, folderPath, autoDeterminedOrgId)

		folderConfig := config.GetUnenrichedFolderConfigFromEngine(engine, s.configResolver, folderPath, logger)
		if folderConfig == nil {
			logger.Warn().Str("folder", string(folderPath)).Msg("no folder config; skipping LDX-Sync update")
			continue
		}
		orgForConfig := autoDeterminedOrgId
		if folderConfig.OrgSetByUser() {
			orgForConfig = folderConfig.PreferredOrg()
			if orgForConfig == "" {
				orgForConfig = s.configResolver.GlobalOrg()
			}
		}
		if orgForConfig == "" {
			logger.Warn().Str("folder", string(folderPath)).Msg("no org for LDX-Sync cache key; skipping folder")
			continue
		}

		// Convert to our org config format (folder-level settings only)
		orgConfig := types.ConvertLDXSyncResponseToOrgConfig(orgForConfig, result.Config, s.configResolver.ConfigurationOptionsMetaData())
		if orgConfig == nil {
			continue
		}

		// Collect locked fields for this org (only need to do once per org)
		if _, seen := orgLockedFields[orgForConfig]; !seen {
			orgLockedFields[orgForConfig] = []string{}
			for fieldName, field := range orgConfig.Fields {
				if field != nil && field.IsLocked {
					orgLockedFields[orgForConfig] = append(orgLockedFields[orgForConfig], fieldName)
				}
			}
		}

		// Write org config to GAF configuration prefix keys
		types.WriteOrgConfigToConfiguration(conf, orgConfig)

		logger.Debug().
			Str("folder", string(folderPath)).
			Str("orgId", orgForConfig).
			Int("fieldCount", len(orgConfig.Fields)).
			Msg("Updated org config from LDX-Sync")

		// Extract and write folder-specific settings from the FolderSettings map.
		// The API response keys FolderSettings by normalized URL; we normalize the
		// raw remote URL from git to match.
		s.extractAndWriteFolderSettings(conf, logger, result, orgForConfig, folderPath, orgLockedFields)
	}

	// Clear user overrides for locked fields from FolderConfigs
	s.clearLockedOverridesFromFolderConfigs(conf, engine, logger, orgLockedFields)
}

// extractAndWriteFolderSettings normalizes the remote URL from the LDX-Sync result,
// looks up folder-specific settings in the API response, and writes them to GAF configuration
// using RemoteOrgFolderKey prefix keys. Locked folder settings are tracked for override clearing.
func (s *DefaultLdxSyncService) extractAndWriteFolderSettings(
	conf configuration.Configuration,
	logger *zerolog.Logger,
	result *ldx_sync_config.LdxSyncConfigResult,
	orgId string,
	folderPath types.FilePath,
	orgLockedFields map[string][]string,
) {
	if result.RemoteUrl == "" {
		return
	}

	normalizedURL, err := util.NormalizeGitURL(result.RemoteUrl)
	if err != nil || normalizedURL == "" {
		logger.Debug().
			Str("folder", string(folderPath)).
			Str("remoteUrl", result.RemoteUrl).
			Err(err).
			Msg("Failed to normalize remote URL for folder settings lookup")
		return
	}

	folderSettings := types.ExtractFolderSettings(result.Config, normalizedURL)
	if folderSettings == nil {
		return
	}

	types.WriteFolderConfigToConfiguration(conf, orgId, folderPath, folderSettings)

	// Collect locked folder fields for override clearing
	for fieldName, field := range folderSettings {
		if field != nil && field.IsLocked {
			orgLockedFields[orgId] = append(orgLockedFields[orgId], fieldName)
		}
	}

	logger.Debug().
		Str("folder", string(folderPath)).
		Str("orgId", orgId).
		Str("normalizedUrl", normalizedURL).
		Int("folderSettingCount", len(folderSettings)).
		Msg("Applied folder-specific settings from LDX-Sync")
}

// updateGlobalConfig extracts global/machine-scope settings from LDX-Sync results and applies them to Config.
// Global settings don't vary by org, so we take the first available result.
// For each setting:
// - If locked: always use LDX-Sync value (user cannot override)
// - Otherwise: use LDX-Sync value only if user hasn't set a non-default value
// After updating, sends $/snyk.configuration notification so IDE can persist the changes.
func (s *DefaultLdxSyncService) updateGlobalConfig(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, results map[types.FilePath]*ldx_sync_config.LdxSyncConfigResult, notifier notification.Notifier) {
	var configUpdated = false
	for folderPath, result := range results {
		if result == nil || result.Config == nil {
			continue
		}

		// Extract global settings from the first valid response
		if !configUpdated {
			globalConfig := types.ExtractMachineSettings(result.Config, s.configResolver.ConfigurationOptionsMetaData())
			if len(globalConfig) > 0 {
				// Store in configuration prefix keys for ConfigResolver to read
				types.WriteMachineConfigToConfiguration(conf, globalConfig)

				// Apply actual values to Config
				s.applyGlobalConfigValues(conf, engine, logger, globalConfig)

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

	// Send unified $/snyk.configuration notification so IDE can persist the updated config
	if configUpdated && notifier != nil {
		lspConfig := BuildLspConfiguration(conf, engine, logger, nil, s.configResolver)
		notifier.Send(lspConfig)
		logger.Debug().Msg("Sent $/snyk.configuration notification after global config update")
	}
}

// applyGlobalConfigValues applies global/machine-scope setting values from LDX-Sync to Config.
// For locked settings, the LDX-Sync value is always applied.
// For non-locked settings, the value is only applied if the user hasn't set a custom value.
func (s *DefaultLdxSyncService) applyGlobalConfigValues(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, globalConfig map[string]*types.LDXSyncField) {
	for settingName, field := range globalConfig {
		if field == nil || field.Value == nil {
			continue
		}

		applied := s.applyMachineSetting(conf, engine, logger, settingName, field)
		if applied {
			logger.Debug().
				Str("setting", settingName).
				Bool("locked", field.IsLocked).
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
func (s *DefaultLdxSyncService) applyMachineSetting(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, settingName string, field *types.LDXSyncField) bool {
	shouldApply := field.IsLocked

	// Special case: authentication method has unique logic
	if settingName == types.SettingAuthenticationMethod {
		if strVal, ok := field.Value.(string); ok && strVal != "" {
			if shouldApply || config.GetAuthenticationMethodFromConfig(conf) == types.EmptyAuthenticationMethod {
				conf.Set(configresolver.UserGlobalKey(types.SettingAuthenticationMethod), strVal)
				return true
			}
		}
		return false
	}

	if def, ok := s.stringSettingDefs(conf)[settingName]; ok {
		return s.applyStringSettingIfNeeded(field, shouldApply, def.isDefault(), def.setter)
	}
	if def, ok := s.boolSettingDefs(conf)[settingName]; ok {
		return s.applyBoolSettingIfNeeded(field, shouldApply, def.isDefault(), def.setter)
	}
	return false
}

func (s *DefaultLdxSyncService) stringSettingDefs(conf configuration.Configuration) map[string]machineStringSettingDef {
	return map[string]machineStringSettingDef{
		types.SettingApiEndpoint: {func() bool {
			return types.GetGlobalString(conf, types.SettingApiEndpoint) == config.DefaultSnykApiUrl
		}, func(v string) { config.UpdateApiEndpointsOnConfig(conf, v) }},
		types.SettingCliPath:           {func() bool { return conf.GetString(configresolver.UserGlobalKey(types.SettingCliPath)) == "" }, func(v string) { conf.Set(configresolver.UserGlobalKey(types.SettingCliPath), v) }},
		types.SettingBinaryBaseUrl:     {func() bool { return conf.GetString(configresolver.UserGlobalKey(types.SettingBinaryBaseUrl)) == "" }, func(v string) { conf.Set(configresolver.UserGlobalKey(types.SettingBinaryBaseUrl), v) }},
		types.SettingCodeEndpoint:      {func() bool { return conf.GetString(configresolver.UserGlobalKey(types.SettingCodeEndpoint)) == "" }, func(v string) { conf.Set(configresolver.UserGlobalKey(types.SettingCodeEndpoint), v) }},
		types.SettingProxyHttp:         {func() bool { return conf.GetString(configresolver.UserGlobalKey(types.SettingProxyHttp)) == "" }, func(v string) { conf.Set(configresolver.UserGlobalKey(types.SettingProxyHttp), v) }},
		types.SettingProxyHttps:        {func() bool { return conf.GetString(configresolver.UserGlobalKey(types.SettingProxyHttps)) == "" }, func(v string) { conf.Set(configresolver.UserGlobalKey(types.SettingProxyHttps), v) }},
		types.SettingProxyNoProxy:      {func() bool { return conf.GetString(configresolver.UserGlobalKey(types.SettingProxyNoProxy)) == "" }, func(v string) { conf.Set(configresolver.UserGlobalKey(types.SettingProxyNoProxy), v) }},
		types.SettingCliReleaseChannel: {func() bool { return conf.GetString(configresolver.UserGlobalKey(types.SettingCliReleaseChannel)) == "" }, func(v string) { conf.Set(configresolver.UserGlobalKey(types.SettingCliReleaseChannel), v) }},
	}
}

func (s *DefaultLdxSyncService) boolSettingDefs(conf configuration.Configuration) map[string]machineBoolSettingDef {
	return map[string]machineBoolSettingDef{
		types.SettingAutomaticDownload:      {func() bool { return conf.GetBool(configresolver.UserGlobalKey(types.SettingAutomaticDownload)) }, func(v bool) { conf.Set(configresolver.UserGlobalKey(types.SettingAutomaticDownload), v) }},
		types.SettingTrustEnabled:           {func() bool { return conf.GetBool(configresolver.UserGlobalKey(types.SettingTrustEnabled)) }, func(v bool) { conf.Set(configresolver.UserGlobalKey(types.SettingTrustEnabled), v) }},
		types.SettingAutoConfigureMcpServer: {func() bool { return !conf.GetBool(configresolver.UserGlobalKey(types.SettingAutoConfigureMcpServer)) }, func(v bool) { conf.Set(configresolver.UserGlobalKey(types.SettingAutoConfigureMcpServer), v) }},
		types.SettingProxyInsecure: {func() bool { return !conf.GetBool(configresolver.UserGlobalKey(types.SettingProxyInsecure)) }, func(v bool) {
			conf.Set(configresolver.UserGlobalKey(types.SettingProxyInsecure), v)
		}},
		types.SettingPublishSecurityAtInceptionRules: {func() bool {
			return !conf.GetBool(configresolver.UserGlobalKey(types.SettingPublishSecurityAtInceptionRules))
		}, func(v bool) { conf.Set(configresolver.UserGlobalKey(types.SettingPublishSecurityAtInceptionRules), v) }},
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

// clearLockedOverridesFromFolderConfigs clears user overrides for locked fields
// from all FolderConfigs that use the affected orgs.
// When LDX-Sync returns locked fields, we clear any user overrides
// from FolderConfigs that use that org. This ensures org policy takes precedence.
// The folder→org mapping is read from FolderMetadataKey (written by updateOrgConfigCache).
func (s *DefaultLdxSyncService) clearLockedOverridesFromFolderConfigs(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, orgLockedFields map[string][]string) {
	if len(orgLockedFields) == 0 {
		return
	}

	ws := config.GetWorkspace(conf)
	if ws == nil {
		return
	}

	for _, folder := range ws.Folders() {
		folderPath := folder.Path()
		snapshot := types.ReadFolderConfigSnapshot(conf, folderPath)
		effectiveOrg := snapshot.AutoDeterminedOrg
		if effectiveOrg == "" {
			continue
		}

		lockedFields, hasLockedFields := orgLockedFields[effectiveOrg]
		if !hasLockedFields || len(lockedFields) == 0 {
			continue
		}

		for _, fieldName := range lockedFields {
			if types.HasUserOverride(conf, folderPath, fieldName) {
				key := configresolver.UserFolderKey(string(types.PathKey(folderPath)), fieldName)
				conf.Unset(key)
				logger.Debug().
					Str("folder", string(folderPath)).
					Str("org", effectiveOrg).
					Str("field", fieldName).
					Msg("Cleared user override for locked field")
			}
		}
	}
}
