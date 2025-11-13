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
	ignoreApprovalByOrg map[string]bool
	ignoreErr           error
	featureFlagsByOrg   map[string]map[string]bool
	flagErr             error
	sastSettingsByOrg   map[string]*sast_contract.SastResponse
	sastErr             error
	folderOrg           string

	// Call counters to verify no unnecessary external calls
	ignoreApprovalCalls int
	featureFlagCalls    int
	sastSettingsCalls   int
	mu                  sync.Mutex
}

func (m *mockExternalCallsProvider) getIgnoreApprovalEnabled(org string) (bool, error) {
	m.mu.Lock()
	m.ignoreApprovalCalls++
	m.mu.Unlock()
	if m.ignoreErr != nil {
		return false, m.ignoreErr
	}
	if val, ok := m.ignoreApprovalByOrg[org]; ok {
		return val, nil
	}
	// Default value if org not specified
	return true, nil
}

func (m *mockExternalCallsProvider) getFeatureFlag(flag string, org string) (bool, error) {
	m.mu.Lock()
	m.featureFlagCalls++
	m.mu.Unlock()
	if m.flagErr != nil {
		return false, m.flagErr
	}
	if orgFlags, ok := m.featureFlagsByOrg[org]; ok {
		return orgFlags[flag], nil
	}
	// Default values if org not specified
	defaultFlags := map[string]bool{
		SnykCodeConsistentIgnores: true,
		SnykCodeInlineIgnore:      false,
	}
	return defaultFlags[flag], nil
}

func (m *mockExternalCallsProvider) getSastSettings(org string) (*sast_contract.SastResponse, error) {
	m.mu.Lock()
	m.sastSettingsCalls++
	m.mu.Unlock()
	if m.sastErr != nil {
		return nil, m.sastErr
	}
	if settings, ok := m.sastSettingsByOrg[org]; ok {
		return settings, nil
	}
	// Default settings if org not specified
	return &sast_contract.SastResponse{
		SastEnabled: true,
		LocalCodeEngine: sast_contract.LocalCodeEngine{
			Enabled: true,
		},
	}, nil
}

func (m *mockExternalCallsProvider) folderOrganization(path types.FilePath) string {
	return m.folderOrg
}

func setupMockProvider(t *testing.T) (*config.Config, *mockExternalCallsProvider) {
	t.Helper()
	c := testutil.UnitTest(t)

	mockProvider := &mockExternalCallsProvider{
		ignoreApprovalByOrg: make(map[string]bool),
		featureFlagsByOrg:   make(map[string]map[string]bool),
		sastSettingsByOrg:   make(map[string]*sast_contract.SastResponse),
		folderOrg:           "test-org",
	}

	return c, mockProvider
}

func TestFetch(t *testing.T) {
	t.Run("caches flags with mock provider", func(t *testing.T) {
		c, mockProvider := setupMockProvider(t)
		service := New(c, WithProvider(mockProvider))
		org := "test-org-123"

		// First fetch populates cache
		flags1 := service.fetch(org)
		require.NotNil(t, flags1)
		assert.Contains(t, flags1, SnykCodeConsistentIgnores)
		assert.Contains(t, flags1, SnykCodeInlineIgnore)
		assert.Contains(t, flags1, IgnoreApprovalEnabled)

		// Record call counts after first fetch
		mockProvider.mu.Lock()
		firstFetchIgnoreCalls := mockProvider.ignoreApprovalCalls
		firstFetchFlagCalls := mockProvider.featureFlagCalls
		mockProvider.mu.Unlock()

		// Second fetch returns cached flags (no provider calls)
		flags2 := service.fetch(org)
		assert.Equal(t, flags1, flags2)

		// Verify no additional calls were made (cache was used)
		mockProvider.mu.Lock()
		assert.Equal(t, firstFetchIgnoreCalls, mockProvider.ignoreApprovalCalls, "second fetch should not call getIgnoreApprovalEnabled")
		assert.Equal(t, firstFetchFlagCalls, mockProvider.featureFlagCalls, "second fetch should not call getFeatureFlag")
		mockProvider.mu.Unlock()

		// Cache should contain the org
		_, b := service.orgToFlag.Get(org)
		assert.True(t, b)
	})

	t.Run("different orgs have separate caches", func(t *testing.T) {
		c, mockProvider := setupMockProvider(t)

		org1 := "org-1"
		org2 := "org-2"

		// Configure different feature flags for each org
		mockProvider.featureFlagsByOrg[org1] = map[string]bool{
			SnykCodeConsistentIgnores: true,
			SnykCodeInlineIgnore:      false,
		}
		mockProvider.featureFlagsByOrg[org2] = map[string]bool{
			SnykCodeConsistentIgnores: false,
			SnykCodeInlineIgnore:      true,
		}

		service := New(c, WithProvider(mockProvider))

		flags1 := service.fetch(org1)
		assert.NotNil(t, flags1)

		flags2 := service.fetch(org2)
		assert.NotNil(t, flags2)

		// Cache should have both orgs
		flag := service.orgToFlag
		assert.Len(t, flag.GetAll(), 2)

		// Explicitly verify caches are distinct entries with different values
		org1Cache, b := flag.Get(org1)
		assert.True(t, b)
		org2Cache, b := flag.Get(org2)
		assert.True(t, b)
		assert.Equal(t, flags1, org1Cache, "org1 cache should match flags1")
		assert.Equal(t, flags2, org2Cache, "org2 cache should match flags2")

		// Verify that different orgs have different flag values
		assert.NotEqual(t, flags1[SnykCodeConsistentIgnores], flags2[SnykCodeConsistentIgnores], "org1 and org2 should have different SnykCodeConsistentIgnores values")
		assert.NotEqual(t, flags1[SnykCodeInlineIgnore], flags2[SnykCodeInlineIgnore], "org1 and org2 should have different SnykCodeInlineIgnore values")

		// Verify specific values
		assert.True(t, flags1[SnykCodeConsistentIgnores], "org-1 should have SnykCodeConsistentIgnores=true")
		assert.False(t, flags2[SnykCodeConsistentIgnores], "org-2 should have SnykCodeConsistentIgnores=false")
	})

	t.Run("concurrent access is thread-safe", func(t *testing.T) {
		c, mockProvider := setupMockProvider(t)
		service := New(c, WithProvider(mockProvider))
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
		_, b := service.orgToFlag.Get(org)
		assert.True(t, b)
		assert.Len(t, service.orgToFlag.GetAll(), 1)
	})

	t.Run("fetches IgnoreApprovalEnabled flag via provider", func(t *testing.T) {
		c, mockProvider := setupMockProvider(t)
		service := New(c, WithProvider(mockProvider))

		flags := service.fetch("test-org")

		// Should contain the special IgnoreApprovalEnabled flag
		_, exists := flags[IgnoreApprovalEnabled]
		assert.True(t, exists, "IgnoreApprovalEnabled should be fetched")
	})

	t.Run("handles empty org string", func(t *testing.T) {
		c, mockProvider := setupMockProvider(t)
		service := New(c, WithProvider(mockProvider))
		// Should not panic with empty org
		flags := service.fetch("")
		assert.NotNil(t, flags)
	})
}

func TestFlushCache(t *testing.T) {
	t.Run("clears all org feature flags", func(t *testing.T) {
		c, mockProvider := setupMockProvider(t)
		service := New(c, WithProvider(mockProvider))
		org := "test-org"
		_ = service.fetch(org)
		assert.NotEmpty(t, service.orgToFlag)

		service.FlushCache()

		assert.Empty(t, service.orgToFlag)
	})

	t.Run("clears SAST settings", func(t *testing.T) {
		c, mockProvider := setupMockProvider(t)
		service := New(c, WithProvider(mockProvider))

		org := "test-org-sast"
		_, _ = service.fetchSastSettings(org)
		assert.NotEmpty(t, service.orgToSastSettings)

		service.FlushCache()

		assert.Empty(t, service.orgToSastSettings)
	})

	t.Run("concurrent flush during fetch is thread-safe", func(t *testing.T) {
		c, mockProvider := setupMockProvider(t)
		service := New(c, WithProvider(mockProvider))

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
		service := New(c, WithProvider(mockProvider))
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
		service := New(c, WithProvider(mockProvider))

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
		service := New(c, WithProvider(mockProvider))

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
		service := New(c, WithProvider(mockProvider))

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
		service := New(c, WithProvider(mockProvider))

		// Should not panic with empty path
		value := service.GetFromFolderConfig("", "anyFlag")
		assert.False(t, value)
	})
}

func TestPopulateFolderConfig(t *testing.T) {
	t.Run("sets feature flags", func(t *testing.T) {
		c, mockProvider := setupMockProvider(t)
		service := New(c, WithProvider(mockProvider))

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
		service := New(c, WithProvider(mockProvider))

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
		service := New(c, WithProvider(mockProvider))

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
		service := New(c, WithProvider(mockProviderWithError))

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
		service := New(c, WithProvider(mockProvider))

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
		service := New(c, WithProvider(mockProvider))

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

		org1 := "org-sast-1"
		org2 := "org-sast-2"

		// Configure different SAST settings for each org
		mockProvider.sastSettingsByOrg[org1] = &sast_contract.SastResponse{
			SastEnabled: true,
			LocalCodeEngine: sast_contract.LocalCodeEngine{
				Enabled: true,
			},
		}
		mockProvider.sastSettingsByOrg[org2] = &sast_contract.SastResponse{
			SastEnabled: false,
			LocalCodeEngine: sast_contract.LocalCodeEngine{
				Enabled: false,
			},
		}

		service := New(c, WithProvider(mockProvider))

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

		actualOrg1, b := service.orgToSastSettings.Get(org1)
		assert.True(t, b)
		actualOrg2, b := service.orgToSastSettings.Get(org2)
		assert.True(t, b)

		// Explicitly verify caches are distinct entries with different values
		assert.Equal(t, settings1, actualOrg1, "org1 SAST cache should match settings1")
		assert.Equal(t, settings2, actualOrg2, "org2 SAST cache should match settings2")

		// Verify that different orgs have different SAST settings
		assert.NotEqual(t, settings1.SastEnabled, settings2.SastEnabled, "org1 and org2 should have different SastEnabled values")
		assert.NotEqual(t, settings1.LocalCodeEngine.Enabled, settings2.LocalCodeEngine.Enabled, "org1 and org2 should have different LocalCodeEngine.Enabled values")

		// Verify specific values
		assert.True(t, settings1.SastEnabled, "org-sast-1 should have SastEnabled=true")
		assert.False(t, settings2.SastEnabled, "org-sast-2 should have SastEnabled=false")
	})

	t.Run("concurrent SAST settings fetch is thread-safe", func(t *testing.T) {
		c, mockProvider := setupMockProvider(t)
		service := New(c, WithProvider(mockProvider))
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
