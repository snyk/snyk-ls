/*
 * © 2025 Snyk Limited
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

package featureflag

import (
	"fmt"
	"sync"
	"testing"

	"github.com/snyk/go-application-framework/pkg/local_workflows/code_workflow/sast_contract"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// mockExternalCallsProvider is a mock implementation of ExternalCallsProvider for testing
type mockExternalCallsProvider struct {
	ignoreApproval bool
	ignoreErr      error
	featureFlags   map[string]bool
	flagErr        error
	sastSettings   *sast_contract.SastResponse
	sastErr        error
	folderOrg      string
}

func (m *mockExternalCallsProvider) getIgnoreApprovalEnabled(org string) (bool, error) {
	return m.ignoreApproval, m.ignoreErr
}

func (m *mockExternalCallsProvider) getFeatureFlag(flag string, org string) (bool, error) {
	if m.flagErr != nil {
		return false, m.flagErr
	}
	return m.featureFlags[flag], nil
}

func (m *mockExternalCallsProvider) getSastSettings(org string) (*sast_contract.SastResponse, error) {
	return m.sastSettings, m.sastErr
}

func (m *mockExternalCallsProvider) folderOrganization(path types.FilePath) string {
	return m.folderOrg
}

func setupMockProvider(t *testing.T) (*config.Config, *mockExternalCallsProvider) {
	t.Helper()
	c := testutil.UnitTest(t)

	mockProvider := &mockExternalCallsProvider{
		ignoreApproval: true,
		featureFlags: map[string]bool{
			SnykCodeConsistentIgnores: true,
			SnykCodeInlineIgnore:      false,
		},
		sastSettings: &sast_contract.SastResponse{
			SastEnabled: true,
			LocalCodeEngine: sast_contract.LocalCodeEngine{
				Enabled: true,
			},
		},
		folderOrg: "test-org",
	}

	return c, mockProvider
}

func TestFetch(t *testing.T) {
	t.Run("caches flags with mock provider", func(t *testing.T) {
		c, mockProvider := setupMockProvider(t)
		service := &serviceImpl{
			c:                 c,
			provider:          mockProvider,
			orgToFlag:         make(map[string]map[string]bool),
			orgToSastSettings: make(map[string]*sast_contract.SastResponse),
			mutex:             &sync.Mutex{},
		}
		org := "test-org-123"

		// First fetch populates cache
		flags1 := service.fetch(org)
		require.NotNil(t, flags1)
		assert.Contains(t, flags1, SnykCodeConsistentIgnores)
		assert.Contains(t, flags1, SnykCodeInlineIgnore)
		assert.Contains(t, flags1, IgnoreApprovalEnabled)

		// Second fetch returns cached flags (no provider calls)
		flags2 := service.fetch(org)
		assert.Equal(t, flags1, flags2)

		// Cache should contain the org
		assert.Contains(t, service.orgToFlag, org)
	})

	t.Run("different orgs have separate caches", func(t *testing.T) {
		c, mockProvider := setupMockProvider(t)
		service := &serviceImpl{
			c:                 c,
			provider:          mockProvider,
			orgToFlag:         make(map[string]map[string]bool),
			orgToSastSettings: make(map[string]*sast_contract.SastResponse),
			mutex:             &sync.Mutex{},
		}

		org1 := "org-1"
		org2 := "org-2"

		flags1 := service.fetch(org1)
		assert.NotNil(t, flags1)

		flags2 := service.fetch(org2)
		assert.NotNil(t, flags2)

		// Cache should have both orgs
		assert.Contains(t, service.orgToFlag, org1)
		assert.Contains(t, service.orgToFlag, org2)
		assert.Len(t, service.orgToFlag, 2)
	})

	t.Run("concurrent access is thread-safe", func(t *testing.T) {
		c, mockProvider := setupMockProvider(t)
		service := &serviceImpl{
			c:                 c,
			provider:          mockProvider,
			orgToFlag:         make(map[string]map[string]bool),
			orgToSastSettings: make(map[string]*sast_contract.SastResponse),
			mutex:             &sync.Mutex{},
		}
		org := "concurrent-org"

		// Launch multiple goroutines that fetch simultaneously
		var wg sync.WaitGroup
		numGoroutines := 10
		results := make([]map[string]bool, numGoroutines)

		for i := range numGoroutines {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				results[index] = service.fetch(org)
			}(i)
		}
		wg.Wait()

		// All goroutines should get results
		for _, flags := range results {
			assert.NotNil(t, flags)
		}

		// Should only have one cache entry for the org
		assert.Contains(t, service.orgToFlag, org)
		assert.Len(t, service.orgToFlag, 1)
	})

	t.Run("fetches IgnoreApprovalEnabled flag via provider", func(t *testing.T) {
		c, mockProvider := setupMockProvider(t)
		service := &serviceImpl{
			c:                 c,
			provider:          mockProvider,
			orgToFlag:         make(map[string]map[string]bool),
			orgToSastSettings: make(map[string]*sast_contract.SastResponse),
			mutex:             &sync.Mutex{},
		}

		flags := service.fetch("test-org")

		// Should contain the special IgnoreApprovalEnabled flag
		_, exists := flags[IgnoreApprovalEnabled]
		assert.True(t, exists, "IgnoreApprovalEnabled should be fetched")
	})

	t.Run("handles empty org string", func(t *testing.T) {
		c, mockProvider := setupMockProvider(t)
		service := &serviceImpl{
			c:                 c,
			provider:          mockProvider,
			orgToFlag:         make(map[string]map[string]bool),
			orgToSastSettings: make(map[string]*sast_contract.SastResponse),
			mutex:             &sync.Mutex{},
		}

		// Should not panic with empty org
		flags := service.fetch("")
		assert.NotNil(t, flags)
	})
}

func TestFlushCache(t *testing.T) {
	t.Run("clears all org feature flags", func(t *testing.T) {
		c, mockProvider := setupMockProvider(t)
		service := &serviceImpl{
			c:                 c,
			provider:          mockProvider,
			orgToFlag:         make(map[string]map[string]bool),
			orgToSastSettings: make(map[string]*sast_contract.SastResponse),
			mutex:             &sync.Mutex{},
		}

		org := "test-org"
		_ = service.fetch(org)
		assert.NotEmpty(t, service.orgToFlag)

		service.FlushCache()

		assert.Empty(t, service.orgToFlag)
	})

	t.Run("clears SAST settings", func(t *testing.T) {
		c, mockProvider := setupMockProvider(t)
		service := &serviceImpl{
			c:                 c,
			provider:          mockProvider,
			orgToFlag:         make(map[string]map[string]bool),
			orgToSastSettings: make(map[string]*sast_contract.SastResponse),
			mutex:             &sync.Mutex{},
		}

		org := "test-org-sast"
		_, _ = service.fetchSastSettings(org)
		assert.NotEmpty(t, service.orgToSastSettings)

		service.FlushCache()

		assert.Empty(t, service.orgToSastSettings)
	})

	t.Run("concurrent flush during fetch is thread-safe", func(t *testing.T) {
		c, mockProvider := setupMockProvider(t)
		service := &serviceImpl{
			c:                 c,
			provider:          mockProvider,
			orgToFlag:         make(map[string]map[string]bool),
			orgToSastSettings: make(map[string]*sast_contract.SastResponse),
			mutex:             &sync.Mutex{},
		}

		var wg sync.WaitGroup
		// Start multiple fetches
		for i := range 5 {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				_ = service.fetch("org-" + string(rune('A'+index)))
			}(i)
		}

		// Flush cache concurrently
		wg.Add(1)
		go func() {
			defer wg.Done()
			service.FlushCache()
		}()

		// Should not panic or deadlock
		wg.Wait()
	})
}

func TestGetFromFolderConfig(t *testing.T) {
	t.Run("returns correct flag value", func(t *testing.T) {
		c, mockProvider := setupMockProvider(t)
		service := &serviceImpl{
			c:                 c,
			provider:          mockProvider,
			orgToFlag:         make(map[string]map[string]bool),
			orgToSastSettings: make(map[string]*sast_contract.SastResponse),
			mutex:             &sync.Mutex{},
		}

		folderPath := types.FilePath("/test/folder")

		// Setup folder config with specific feature flags
		folderConfig := &types.FolderConfig{
			FolderPath: folderPath,
			FeatureFlags: map[string]bool{
				SnykCodeConsistentIgnores: true,
				SnykCodeInlineIgnore:      false,
			},
		}
		c.UpdateFolderConfig(folderConfig)

		// Test existing flags
		value1 := service.GetFromFolderConfig(folderPath, SnykCodeConsistentIgnores)
		assert.True(t, value1)

		value2 := service.GetFromFolderConfig(folderPath, SnykCodeInlineIgnore)
		assert.False(t, value2)
	})

	t.Run("returns false for non-existent flag", func(t *testing.T) {
		c, mockProvider := setupMockProvider(t)
		service := &serviceImpl{
			c:                 c,
			provider:          mockProvider,
			orgToFlag:         make(map[string]map[string]bool),
			orgToSastSettings: make(map[string]*sast_contract.SastResponse),
			mutex:             &sync.Mutex{},
		}

		folderPath := types.FilePath("/test/folder")
		folderConfig := &types.FolderConfig{
			FolderPath: folderPath,
			FeatureFlags: map[string]bool{
				SnykCodeConsistentIgnores: true,
			},
		}
		c.UpdateFolderConfig(folderConfig)

		// Test non-existent flag
		value := service.GetFromFolderConfig(folderPath, "nonExistentFlag")
		assert.False(t, value)
	})

	t.Run("handles multiple folders independently", func(t *testing.T) {
		c, mockProvider := setupMockProvider(t)
		service := &serviceImpl{
			c:                 c,
			provider:          mockProvider,
			orgToFlag:         make(map[string]map[string]bool),
			orgToSastSettings: make(map[string]*sast_contract.SastResponse),
			mutex:             &sync.Mutex{},
		}

		folder1 := types.FilePath("/folder1")
		folder2 := types.FilePath("/folder2")

		// Setup different flags for each folder
		config1 := &types.FolderConfig{
			FolderPath: folder1,
			FeatureFlags: map[string]bool{
				SnykCodeConsistentIgnores: true,
			},
		}
		config2 := &types.FolderConfig{
			FolderPath: folder2,
			FeatureFlags: map[string]bool{
				SnykCodeConsistentIgnores: false,
			},
		}
		c.UpdateFolderConfig(config1)
		c.UpdateFolderConfig(config2)

		// Each folder should have its own flags
		val1 := service.GetFromFolderConfig(folder1, SnykCodeConsistentIgnores)
		assert.True(t, val1)

		val2 := service.GetFromFolderConfig(folder2, SnykCodeConsistentIgnores)
		assert.False(t, val2)
	})

	t.Run("handles nil FeatureFlags map gracefully", func(t *testing.T) {
		c, mockProvider := setupMockProvider(t)
		service := &serviceImpl{
			c:                 c,
			provider:          mockProvider,
			orgToFlag:         make(map[string]map[string]bool),
			orgToSastSettings: make(map[string]*sast_contract.SastResponse),
			mutex:             &sync.Mutex{},
		}

		folderPath := types.FilePath("/test")
		folderConfig := &types.FolderConfig{
			FolderPath:   folderPath,
			FeatureFlags: nil, // nil map
		}
		c.UpdateFolderConfig(folderConfig)

		// Should not panic, should return false
		value := service.GetFromFolderConfig(folderPath, "anyFlag")
		assert.False(t, value)
	})

	t.Run("handles empty folder path", func(t *testing.T) {
		c, mockProvider := setupMockProvider(t)
		service := &serviceImpl{
			c:                 c,
			provider:          mockProvider,
			orgToFlag:         make(map[string]map[string]bool),
			orgToSastSettings: make(map[string]*sast_contract.SastResponse),
			mutex:             &sync.Mutex{},
		}

		// Should not panic with empty path
		value := service.GetFromFolderConfig("", "anyFlag")
		assert.False(t, value)
	})
}

func TestPopulateFolderConfig(t *testing.T) {
	t.Run("sets feature flags", func(t *testing.T) {
		c, mockProvider := setupMockProvider(t)
		service := &serviceImpl{
			c:                 c,
			provider:          mockProvider,
			orgToFlag:         make(map[string]map[string]bool),
			orgToSastSettings: make(map[string]*sast_contract.SastResponse),
			mutex:             &sync.Mutex{},
		}

		folderPath := types.FilePath("/test/folder")
		folderConfig := &types.FolderConfig{
			FolderPath: folderPath,
		}

		service.PopulateFolderConfig(folderConfig)

		assert.NotNil(t, folderConfig.FeatureFlags)
		assert.Contains(t, folderConfig.FeatureFlags, SnykCodeConsistentIgnores)
		assert.Contains(t, folderConfig.FeatureFlags, SnykCodeInlineIgnore)
	})

	t.Run("handles multiple folders", func(t *testing.T) {
		c, mockProvider := setupMockProvider(t)
		service := &serviceImpl{
			c:                 c,
			provider:          mockProvider,
			orgToFlag:         make(map[string]map[string]bool),
			orgToSastSettings: make(map[string]*sast_contract.SastResponse),
			mutex:             &sync.Mutex{},
		}

		folder1 := &types.FolderConfig{FolderPath: "/folder1"}
		folder2 := &types.FolderConfig{FolderPath: "/folder2"}

		// Populate both folders
		service.PopulateFolderConfig(folder1)
		service.PopulateFolderConfig(folder2)

		assert.NotNil(t, folder1.FeatureFlags)
		assert.NotNil(t, folder2.FeatureFlags)
	})

	t.Run("populates SAST settings", func(t *testing.T) {
		c, mockProvider := setupMockProvider(t)
		service := &serviceImpl{
			c:                 c,
			provider:          mockProvider,
			orgToFlag:         make(map[string]map[string]bool),
			orgToSastSettings: make(map[string]*sast_contract.SastResponse),
			mutex:             &sync.Mutex{},
		}

		folderPath := types.FilePath("/test/folder")
		folderConfig := &types.FolderConfig{
			FolderPath: folderPath,
		}

		service.PopulateFolderConfig(folderConfig)

		assert.NotNil(t, folderConfig.FeatureFlags)
		assert.NotNil(t, folderConfig.SastSettings)
	})

	t.Run("continues on SAST settings error", func(t *testing.T) {
		c, mockProviderWithError := setupMockProvider(t)
		// Override with error
		mockProviderWithError.sastErr = fmt.Errorf("mock error")
		service := &serviceImpl{
			c:                 c,
			provider:          mockProviderWithError,
			orgToFlag:         make(map[string]map[string]bool),
			orgToSastSettings: make(map[string]*sast_contract.SastResponse),
			mutex:             &sync.Mutex{},
		}

		folderPath := types.FilePath("/test/folder")
		folderConfig := &types.FolderConfig{
			FolderPath: folderPath,
		}

		// Even if SAST settings fetch fails, feature flags should still be populated
		service.PopulateFolderConfig(folderConfig)

		assert.NotNil(t, folderConfig.FeatureFlags)
	})

	t.Run("concurrent population is thread-safe", func(t *testing.T) {
		c, mockProvider := setupMockProvider(t)
		service := &serviceImpl{
			c:                 c,
			provider:          mockProvider,
			orgToFlag:         make(map[string]map[string]bool),
			orgToSastSettings: make(map[string]*sast_contract.SastResponse),
			mutex:             &sync.Mutex{},
		}

		var wg sync.WaitGroup
		numFolders := 10
		configs := make([]*types.FolderConfig, numFolders)

		for i := range numFolders {
			configs[i] = &types.FolderConfig{
				FolderPath: types.FilePath("/folder" + string(rune(i))),
			}
			wg.Add(1)
			go func(cfg *types.FolderConfig) {
				defer wg.Done()
				service.PopulateFolderConfig(cfg)
			}(configs[i])
		}
		wg.Wait()

		// All configs should be populated
		for _, cfg := range configs {
			assert.NotNil(t, cfg.FeatureFlags)
		}
	})
}

func TestFetchSastSettings(t *testing.T) {
	t.Run("caches SAST settings", func(t *testing.T) {
		c, mockProvider := setupMockProvider(t)
		service := &serviceImpl{
			c:                 c,
			provider:          mockProvider,
			orgToFlag:         make(map[string]map[string]bool),
			orgToSastSettings: make(map[string]*sast_contract.SastResponse),
			mutex:             &sync.Mutex{},
		}
		org := "test-org-sast"

		// First fetch populates cache
		settings1, err1 := service.fetchSastSettings(org)
		require.NoError(t, err1)
		require.NotNil(t, settings1)

		// Second fetch returns cached settings
		settings2, err2 := service.fetchSastSettings(org)
		require.NoError(t, err2)
		assert.Equal(t, settings1, settings2)

		// Cache should contain the org
		assert.Contains(t, service.orgToSastSettings, org)
	})

	t.Run("different orgs have separate caches", func(t *testing.T) {
		c, mockProvider := setupMockProvider(t)
		service := &serviceImpl{
			c:                 c,
			provider:          mockProvider,
			orgToFlag:         make(map[string]map[string]bool),
			orgToSastSettings: make(map[string]*sast_contract.SastResponse),
			mutex:             &sync.Mutex{},
		}

		org1 := "org-sast-1"
		org2 := "org-sast-2"

		settings1, err1 := service.fetchSastSettings(org1)
		require.NoError(t, err1)
		assert.NotNil(t, settings1)

		settings2, err2 := service.fetchSastSettings(org2)
		require.NoError(t, err2)
		assert.NotNil(t, settings2)

		// Cache should have both orgs
		assert.Contains(t, service.orgToSastSettings, org1)
		assert.Contains(t, service.orgToSastSettings, org2)
		assert.Len(t, service.orgToSastSettings, 2)
	})

	t.Run("concurrent SAST settings fetch is thread-safe", func(t *testing.T) {
		c, mockProvider := setupMockProvider(t)
		service := &serviceImpl{
			c:                 c,
			provider:          mockProvider,
			orgToFlag:         make(map[string]map[string]bool),
			orgToSastSettings: make(map[string]*sast_contract.SastResponse),
			mutex:             &sync.Mutex{},
		}
		org := "concurrent-sast-org"

		var wg sync.WaitGroup
		numGoroutines := 10
		errors := make([]error, numGoroutines)

		for i := range numGoroutines {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				_, errors[index] = service.fetchSastSettings(org)
			}(i)
		}
		wg.Wait()

		// Should only have one cache entry
		assert.Contains(t, service.orgToSastSettings, org)
		assert.Len(t, service.orgToSastSettings, 1)
	})
}

func TestGetSastSettings(t *testing.T) {
	t.Run("returns SAST settings from folder config", func(t *testing.T) {
		c, mockProvider := setupMockProvider(t)
		service := &serviceImpl{
			c:                 c,
			provider:          mockProvider,
			orgToFlag:         make(map[string]map[string]bool),
			orgToSastSettings: make(map[string]*sast_contract.SastResponse),
			mutex:             &sync.Mutex{},
		}

		folderPath := types.FilePath("/test/folder")

		// First populate folder config
		folderConfig := &types.FolderConfig{
			FolderPath: folderPath,
		}
		service.PopulateFolderConfig(folderConfig)
		c.UpdateFolderConfig(folderConfig)

		// Then get SAST settings
		settings := service.GetSastSettingsFromFolderConfig(folderPath)
		assert.NotNil(t, settings)
	})

	t.Run("returns default when not found", func(t *testing.T) {
		c, mockProvider := setupMockProvider(t)
		service := &serviceImpl{
			c:                 c,
			provider:          mockProvider,
			orgToFlag:         make(map[string]map[string]bool),
			orgToSastSettings: make(map[string]*sast_contract.SastResponse),
			mutex:             &sync.Mutex{},
		}

		folderPath := types.FilePath("/nonexistent/folder")

		settings := service.GetSastSettingsFromFolderConfig(folderPath)
		assert.NotNil(t, settings)
		// Should return default struct, not nil
		assert.Equal(t, &sast_contract.SastResponse{}, settings)
	})

	t.Run("handles nil SastSettings gracefully", func(t *testing.T) {
		c, mockProvider := setupMockProvider(t)
		service := &serviceImpl{
			c:                 c,
			provider:          mockProvider,
			orgToFlag:         make(map[string]map[string]bool),
			orgToSastSettings: make(map[string]*sast_contract.SastResponse),
			mutex:             &sync.Mutex{},
		}

		folderPath := types.FilePath("/test/folder")
		folderConfig := &types.FolderConfig{
			FolderPath:   folderPath,
			SastSettings: nil, // Explicitly nil
		}
		c.UpdateFolderConfig(folderConfig)

		// Should return default struct, not panic
		settings := service.GetSastSettingsFromFolderConfig(folderPath)
		assert.NotNil(t, settings)
		assert.Equal(t, &sast_contract.SastResponse{}, settings)
	})
}
