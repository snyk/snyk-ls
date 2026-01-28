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
	"errors"
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
	ResolveOrgFromUserConfig(engine workflow.Engine, result ldx_sync_config.LdxSyncConfigResult) (ldx_sync_config.Organization, error)
}

// DefaultLdxSyncApiClient wraps the real GAF LDX-Sync functions
type DefaultLdxSyncApiClient struct{}

// GetUserConfigForProject calls the GAF ldx_sync_config package
func (a *DefaultLdxSyncApiClient) GetUserConfigForProject(engine workflow.Engine, projectPath string, preferredOrg string) ldx_sync_config.LdxSyncConfigResult {
	return ldx_sync_config.GetUserConfigForProject(engine, projectPath, preferredOrg)
}

// ResolveOrgFromUserConfig calls the GAF ldx_sync_config package
func (a *DefaultLdxSyncApiClient) ResolveOrgFromUserConfig(engine workflow.Engine, result ldx_sync_config.LdxSyncConfigResult) (ldx_sync_config.Organization, error) {
	return ldx_sync_config.ResolveOrgFromUserConfig(engine, result)
}

// LdxSyncService provides LDX-Sync configuration refresh functionality
type LdxSyncService interface {
	RefreshConfigFromLdxSync(c *config.Config, workspaceFolders []types.Folder)
	ResolveOrg(c *config.Config, folderPath types.FilePath) (ldx_sync_config.Organization, error)
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

// RefreshConfigFromLdxSync refreshes the user configuration from LDX-Sync for all workspace folders in parallel
// Results are cached in memory for later use by ResolveOrg
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

	// Update cache with all results
	c.UpdateLdxSyncCache(results)
}

// ResolveOrg retrieves the organization from the cached LDX-Sync result for a folder
// Returns an error if no cache entry exists
func (s *DefaultLdxSyncService) ResolveOrg(c *config.Config, folderPath types.FilePath) (ldx_sync_config.Organization, error) {
	logger := c.Logger().With().Str("method", "ResolveOrg").Logger()

	// Get cached result
	cachedResult := c.GetLdxSyncResult(folderPath)

	// If we have a cached result, use it to resolve the org
	if cachedResult != nil {
		return s.apiClient.ResolveOrgFromUserConfig(c.Engine(), *cachedResult)
	}

	// Return error if no cache entry
	logger.Warn().
		Str("folder", string(folderPath)).
		Msg("No LDX-Sync cache entry found, falling back to global organization")
	return ldx_sync_config.Organization{}, errors.New("no organization was able to be determined for folder: " + string(folderPath))
}
