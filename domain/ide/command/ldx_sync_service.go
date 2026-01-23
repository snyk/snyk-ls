/*
 * © 2023 Snyk Limited
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

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/types"
)

// LdxSyncService provides LDX-Sync configuration refresh functionality
type LdxSyncService interface {
	RefreshConfigFromLdxSync(c *config.Config, workspaceFolders []types.Folder)
}

// DefaultLdxSyncService is the default implementation of LdxSyncService
type DefaultLdxSyncService struct{}

// NewLdxSyncService creates a new LdxSyncService
func NewLdxSyncService() LdxSyncService {
	return &DefaultLdxSyncService{}
}

// RefreshConfigFromLdxSync refreshes the user configuration from LDX-Sync for all workspace folders in parallel
// Results are cached in memory for later use by GetOrgFromCachedLdxSync
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
			cfgResult := ldx_sync_config.GetUserConfigForProject(engine, string(f.Path()), preferredOrg)

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
