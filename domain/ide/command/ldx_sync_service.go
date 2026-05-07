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
		// ExtractFolderSettings normalizes API keys and the raw git remote URL (GAF) for lookup.
		s.extractAndWriteFolderSettings(conf, logger, result, orgForConfig, folderPath, orgLockedFields)
	}

	// Clear user overrides for locked fields from FolderConfigs
	s.clearLockedOverridesFromFolderConfigs(conf, engine, logger, orgLockedFields)
}

// extractAndWriteFolderSettings looks up folder-specific settings in the LDX-Sync API response
// (using the raw git remote URL; normalization happens in types.ExtractFolderSettings) and writes
// them to GAF configuration using RemoteOrgFolderKey prefix keys. Locked folder settings are
// tracked for override clearing.
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

	folderSettings := types.ExtractFolderSettings(result.Config, result.RemoteUrl)
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
		Str("remoteUrl", result.RemoteUrl).
		Int("folderSettingCount", len(folderSettings)).
		Msg("Applied folder-specific settings from LDX-Sync")
}

// Writes only to RemoteMachineKey — UserGlobalKey is the IDE PATCH path; dual-writing there
// would make user vs LDX-Sync values indistinguishable to the resolver. Global settings are
// org-invariant, so the first non-empty result wins.
func (s *DefaultLdxSyncService) updateGlobalConfig(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, results map[types.FilePath]*ldx_sync_config.LdxSyncConfigResult, notifier notification.Notifier) {
	var configUpdated = false
	for folderPath, result := range results {
		if result == nil || result.Config == nil {
			continue
		}

		if !configUpdated {
			globalConfig := types.ExtractMachineSettings(result.Config, s.configResolver.ConfigurationOptionsMetaData())
			if len(globalConfig) > 0 {
				types.WriteMachineConfigToConfiguration(conf, globalConfig)
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

	if configUpdated && notifier != nil {
		lspConfig := BuildLspConfiguration(conf, engine, logger, nil, s.configResolver)
		notifier.Send(lspConfig)
		logger.Debug().Msg("Sent $/snyk.configuration notification after global config update")
	}
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
