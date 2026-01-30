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
// - FolderOrgMapping: maps folder paths to their resolved org IDs
// - Configs: maps org IDs to their org-level settings
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

			// Call GetUserConfigForProject with 3 params including preferredOrg
			cfgResult := s.apiClient.GetUserConfigForProject(engine, string(f.Path()), preferredOrg)

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
// - FolderOrgMapping: folder path → org ID (for callers to look up the resolved org)
// - Configs: org ID → org-level settings (for ConfigResolver to read settings)
func (s *DefaultLdxSyncService) updateOrgConfigCache(c *config.Config, results map[types.FilePath]*ldx_sync_config.LdxSyncConfigResult) {
	logger := c.Logger().With().Str("method", "updateOrgConfigCache").Logger()
	cache := c.GetLdxSyncOrgConfigCache()

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

		// Update the org config in cache
		c.UpdateLdxSyncOrgConfig(orgConfig)

		logger.Debug().
			Str("folder", string(folderPath)).
			Str("orgId", orgId).
			Int("fieldCount", len(orgConfig.Fields)).
			Msg("Updated org config cache from LDX-Sync")
	}
}

// updateMachineConfig extracts machine-scope settings from LDX-Sync results
// Machine settings are global and don't vary by org, so we take the first available result
// After updating, sends a notification to the IDE so it can persist the settings
func (s *DefaultLdxSyncService) updateMachineConfig(c *config.Config, results map[types.FilePath]*ldx_sync_config.LdxSyncConfigResult) {
	logger := c.Logger().With().Str("method", "updateMachineConfig").Logger()

	var configUpdated = false
	for folderPath, result := range results {
		if result == nil || result.Config == nil {
			continue
		}

		// Extract machine-scope settings from the first valid response
		// These are stored in LS memory only for metadata (locked/enforced status)
		// The actual values are configUpdated to Config via existing update functions
		if !configUpdated {
			machineConfig := types.ExtractMachineSettings(result.Config)
			if len(machineConfig) > 0 {
				c.UpdateLdxSyncMachineConfig(machineConfig)

				logger.Debug().
					Str("folder", string(folderPath)).
					Int("fieldCount", len(machineConfig)).
					Msg("Updated machine config metadata from LDX-Sync")
				configUpdated = true
			} else {
				logger.Debug().
					Str("folder", string(folderPath)).
					Msg("No machine config found in LDX-Sync response, skipping machine config cache update")
			}
		} else {
			logger.Debug().
				Str("folder", string(folderPath)).
				Msg("Machine config already applied from another folder, skipping machine config cache update")
		}
	}
}
