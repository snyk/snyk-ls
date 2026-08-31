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
	"time"

	"github.com/erni27/imcache"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/code-client-go/pkg/code/sast_contract"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/ignore_workflow"
	gafUtils "github.com/snyk/go-application-framework/pkg/utils"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// Configuration keys used to exercise getConfigValues independently of any particular flag. The tests
// register the resolver for them, so the names only have to be unique.
const (
	testConfigKeyA = "test_config_key_a"
	testConfigKeyB = "test_config_key_b"
)

// mockExternalCallsProvider is a mock implementation of externalCalls for testing
type mockExternalCallsProvider struct {
	ignoreApprovalByOrg map[string]bool
	ignoreErr           error
	featureFlagsByOrg   map[string]map[string]bool
	flagErr             error
	flagDelay           time.Duration // artificial latency injected into getFeatureFlag
	flagReadyCh         chan struct{} // signals when first getFeatureFlag call is mid-sleep
	sastSettingsByOrg   map[string]*sast_contract.SastResponse
	sastErr             error
	sastDelay           time.Duration // artificial latency injected into getSastSettings
	sastReadyCh         chan struct{} // closed when getSastSettings is mid-sleep
	folderOrg           string
	folderOrgByPath     map[string]string // Maps folder path to org for testing different folders

	// Call counters to verify no unnecessary external calls
	configValuesCalls int
	featureFlagCalls  int
	sastSettingsCalls int
	mu                sync.Mutex
}

func (m *mockExternalCallsProvider) getConfigValues(configKeys []string, org string) (map[string]bool, error) {
	m.mu.Lock()
	m.configValuesCalls++
	m.mu.Unlock()

	values := make(map[string]bool, len(configKeys))
	if m.ignoreErr != nil {
		for _, key := range configKeys {
			values[key] = false
		}
		return values, m.ignoreErr
	}

	// ignoreApprovalByOrg wins for its own key: a config key must not pick up a value staged for the
	// platform flag route, or the mock would answer for a key the real provider never resolves.
	for _, key := range configKeys {
		if key == ignore_workflow.ConfigIgnoreApprovalEnabled {
			if val, ok := m.ignoreApprovalByOrg[org]; ok {
				values[key] = val
			} else {
				// Default value if org not specified
				values[key] = true
			}
			continue
		}
		values[key] = m.featureFlagsByOrg[org][key]
	}

	return values, nil
}

func (m *mockExternalCallsProvider) getFeatureFlag(flag string, org string) (bool, error) {
	m.mu.Lock()
	m.featureFlagCalls++
	delay := m.flagDelay
	readyCh := m.flagReadyCh
	m.mu.Unlock()
	if readyCh != nil {
		select {
		case readyCh <- struct{}{}:
		default:
		}
	}
	if delay > 0 {
		time.Sleep(delay)
	}
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
	delay := m.sastDelay
	readyCh := m.sastReadyCh
	m.mu.Unlock()
	if readyCh != nil {
		select {
		case readyCh <- struct{}{}:
		default:
		}
	}
	if delay > 0 {
		time.Sleep(delay)
	}
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

func setupMockProvider(t *testing.T) (workflow.Engine, *mockExternalCallsProvider) {
	t.Helper()
	engine := testutil.UnitTest(t)

	mockProvider := &mockExternalCallsProvider{
		ignoreApprovalByOrg: make(map[string]bool),
		featureFlagsByOrg:   make(map[string]map[string]bool),
		sastSettingsByOrg:   make(map[string]*sast_contract.SastResponse),
		folderOrg:           "test-org",
	}

	return engine, mockProvider
}

func TestFetch(t *testing.T) {
	t.Run("caches flags with mock provider", func(t *testing.T) {
		engine, mockProvider := setupMockProvider(t)
		service := New(engine.GetConfiguration(), engine.GetLogger(), engine, testutil.DefaultConfigResolver(engine), withProvider(mockProvider))
		org := "test-org-123"

		// First fetch populates cache
		flags1 := service.fetch(org)
		require.NotNil(t, flags1)
		assert.Contains(t, flags1, SnykCodeConsistentIgnores)
		assert.Contains(t, flags1, SnykCodeInlineIgnore)
		assert.Contains(t, flags1, ignore_workflow.ConfigIgnoreApprovalEnabled)

		// Record call counts after first fetch
		mockProvider.mu.Lock()
		firstFetchIgnoreCalls := mockProvider.configValuesCalls
		firstFetchFlagCalls := mockProvider.featureFlagCalls
		mockProvider.mu.Unlock()

		// Second fetch returns cached flags (no provider calls)
		flags2 := service.fetch(org)
		assert.Equal(t, flags1, flags2)

		// Verify no additional calls were made (cache was used)
		mockProvider.mu.Lock()
		assert.Equal(t, firstFetchIgnoreCalls, mockProvider.configValuesCalls, "second fetch should not call getConfigValues")
		assert.Equal(t, firstFetchFlagCalls, mockProvider.featureFlagCalls, "second fetch should not call getFeatureFlag")
		mockProvider.mu.Unlock()

		// Cache should contain the org
		_, b := service.orgToFlag.Get(org)
		assert.True(t, b)
	})

	t.Run("different orgs have separate caches", func(t *testing.T) {
		engine, mockProvider := setupMockProvider(t)

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

		service := New(engine.GetConfiguration(), engine.GetLogger(), engine, testutil.DefaultConfigResolver(engine), withProvider(mockProvider))

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
		engine, mockProvider := setupMockProvider(t)
		service := New(engine.GetConfiguration(), engine.GetLogger(), engine, testutil.DefaultConfigResolver(engine), withProvider(mockProvider))
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

	t.Run("fetches ConfigIgnoreApprovalEnabled flag via provider", func(t *testing.T) {
		engine, mockProvider := setupMockProvider(t)
		service := New(engine.GetConfiguration(), engine.GetLogger(), engine, testutil.DefaultConfigResolver(engine), withProvider(mockProvider))

		flags := service.fetch("test-org")

		// Should contain the special ConfigIgnoreApprovalEnabled flag
		_, exists := flags[ignore_workflow.ConfigIgnoreApprovalEnabled]
		assert.True(t, exists, "ConfigIgnoreApprovalEnabled should be fetched")
	})

	t.Run("handles empty org string", func(t *testing.T) {
		engine, mockProvider := setupMockProvider(t)
		service := New(engine.GetConfiguration(), engine.GetLogger(), engine, testutil.DefaultConfigResolver(engine), withProvider(mockProvider))
		// Should not panic with empty org
		flags := service.fetch("")
		assert.NotNil(t, flags)
	})

	t.Run("concurrent FlushCache does not re-populate flag cache", func(t *testing.T) {
		// TOCTOU guard: if FlushCache() runs while flag goroutines are in-flight,
		// the stale results must not be written into the freshly-cleared cache.
		engine, mockProvider := setupMockProvider(t)
		mockProvider.flagDelay = 50 * time.Millisecond
		mockProvider.flagReadyCh = make(chan struct{}, 1)

		service := New(engine.GetConfiguration(), engine.GetLogger(), engine, testutil.DefaultConfigResolver(engine), withProvider(mockProvider))
		org := "toctou-flags-org"

		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = service.fetch(org)
		}()

		// Wait for the first flag goroutine to signal it's mid-fetch, then flush.
		testsupport.RequireEventuallyReceive(t, mockProvider.flagReadyCh, 5*time.Second, time.Millisecond, "flag fetch did not start in time")
		service.FlushCache()

		testsupport.RequireEventuallyClosed(t, done, 5*time.Second, time.Millisecond, "in-flight fetch goroutine did not finish in time")

		// The gen guard must have prevented stale flags from being written back.
		_, found := service.orgToFlag.Get(org)
		assert.False(t, found, "flag cache must not be re-populated after concurrent FlushCache (TOCTOU guard)")
	})
}

// configKeyOnlyProvider resolves GAF configuration keys for real and fails any attempt to look a flag
// up by platform name, so a key that stops being treated as a GAF configuration key is caught rather
// than silently answered as false by an unrelated route.
type configKeyOnlyProvider struct {
	*externalCallsProvider
}

func (p *configKeyOnlyProvider) getFeatureFlag(flag string, _ string) (bool, error) {
	return false, fmt.Errorf("%s must be resolved as a GAF configuration key, not by platform flag name", flag)
}

// Test_fetch_resolvesConfigKeysAsConfigKeys pins which route every entry of gafConfigResolvedFlags
// takes. Getting this wrong costs nothing at compile time and produces no error at runtime: the flag
// simply reads false forever and whatever it gates reaches nobody.
func Test_fetch_resolvesConfigKeysAsConfigKeys(t *testing.T) {
	const org = "00000000-0000-0000-0000-000000000001"

	// Fails rather than passing vacuously if the list is emptied.
	require.NotEmpty(t, gafConfigResolvedFlags)

	for _, configKey := range gafConfigResolvedFlags {
		t.Run(configKey, func(t *testing.T) {
			engine := testutil.UnitTest(t)
			conf := engine.GetConfiguration()
			conf.AddDefaultValue(configKey, func(_ configuration.Configuration, _ any) (any, error) {
				return true, nil
			})

			logger := engine.GetLogger()
			provider := &configKeyOnlyProvider{
				externalCallsProvider: &externalCallsProvider{conf: conf, logger: logger, engine: engine},
			}
			service := New(conf, logger, engine, testutil.DefaultConfigResolver(engine), withProvider(provider))

			flags := service.fetch(org)

			assert.True(t, flags[configKey])
		})
	}
}

// Test_gafConfigResolvedFlags_coversFileFilterKeys pins the membership file filtering depends on: a key
// dropped from this list is not a compile or runtime error, it just reads false forever.
func Test_gafConfigResolvedFlags_coversFileFilterKeys(t *testing.T) {
	assert.Contains(t, gafConfigResolvedFlags, gafUtils.FF_GITIGNORE_RESPECT_TRACKED_FILES)
	assert.Contains(t, gafConfigResolvedFlags, gafUtils.FF_FILE_FILTER_METACHARACTER_FIX)
}

// Test_getConfigValues_resolvesForTheGivenOrg covers the reason snyk-ls resolves GAF configuration
// keys itself instead of reading them off the engine configuration: a folder can belong to an
// organization other than the global one, and GAF's resolvers answer for whichever organization the
// configuration they are handed carries.
func Test_getConfigValues_resolvesForTheGivenOrg(t *testing.T) {
	const enabledOrg = "00000000-0000-0000-0000-000000000001"
	const disabledOrg = "00000000-0000-0000-0000-000000000002"

	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()
	conf.AddDefaultValue(testConfigKeyA,
		func(c configuration.Configuration, _ any) (any, error) {
			return c.GetString(configuration.ORGANIZATION) == enabledOrg, nil
		})

	provider := &externalCallsProvider{conf: conf, logger: engine.GetLogger(), engine: engine}

	enabled, err := provider.getConfigValues([]string{testConfigKeyA}, enabledOrg)
	require.NoError(t, err)
	assert.True(t, enabled[testConfigKeyA])

	disabled, err := provider.getConfigValues([]string{testConfigKeyA}, disabledOrg)
	require.NoError(t, err)
	assert.False(t, disabled[testConfigKeyA])
}

// Test_getConfigValues_sharesOneCloneAcrossKeys pins the reason the keys share a clone: GAF caches
// what it resolves on the configuration object it is handed, including one batched evaluation
// covering the keys it registers together. A clone per key would throw that cache away.
func Test_getConfigValues_sharesOneCloneAcrossKeys(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()

	var mu sync.Mutex
	var handed []configuration.Configuration
	record := func(c configuration.Configuration, _ any) (any, error) {
		mu.Lock()
		defer mu.Unlock()
		handed = append(handed, c)
		return false, nil
	}
	conf.AddDefaultValue(testConfigKeyA, record)
	conf.AddDefaultValue(testConfigKeyB, record)

	provider := &externalCallsProvider{conf: conf, logger: engine.GetLogger(), engine: engine}

	_, err := provider.getConfigValues([]string{testConfigKeyA, testConfigKeyB}, "00000000-0000-0000-0000-000000000001")
	require.NoError(t, err)

	require.Len(t, handed, 2)
	assert.Same(t, handed[0], handed[1], "both keys must resolve on the same configuration clone")
	assert.NotSame(t, conf, handed[0], "the engine configuration must not be the one carrying the folder's organization")
}

// Test_getConfigValues_reportsErrorsWithoutLosingValues covers the fail-closed contract: a key that
// cannot be resolved is false rather than absent, so a caller reading the map cannot mistake a failed
// lookup for an enabled flag.
func Test_getConfigValues_reportsErrorsWithoutLosingValues(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()
	conf.AddDefaultValue(testConfigKeyA,
		func(_ configuration.Configuration, _ any) (any, error) {
			return true, fmt.Errorf("gateway unavailable")
		})
	conf.AddDefaultValue(testConfigKeyB,
		func(_ configuration.Configuration, _ any) (any, error) {
			return true, nil
		})

	provider := &externalCallsProvider{conf: conf, logger: engine.GetLogger(), engine: engine}

	values, err := provider.getConfigValues([]string{testConfigKeyA, testConfigKeyB}, "00000000-0000-0000-0000-000000000001")

	require.Error(t, err)
	assert.False(t, values[testConfigKeyA], "a failed lookup must be false")
	assert.True(t, values[testConfigKeyB], "one failing key must not discard the others")
}

func TestFlushCache(t *testing.T) {
	t.Run("clears all org feature flags", func(t *testing.T) {
		engine, mockProvider := setupMockProvider(t)
		service := New(engine.GetConfiguration(), engine.GetLogger(), engine, testutil.DefaultConfigResolver(engine), withProvider(mockProvider))
		org := "test-org"
		_ = service.fetch(org)
		assert.NotEmpty(t, service.orgToFlag)

		service.FlushCache()

		assert.Len(t, service.orgToFlag.GetAll(), 0)
	})

	t.Run("clears SAST settings", func(t *testing.T) {
		engine, mockProvider := setupMockProvider(t)
		service := New(engine.GetConfiguration(), engine.GetLogger(), engine, testutil.DefaultConfigResolver(engine), withProvider(mockProvider))

		org := "test-org-sast"
		_, _ = service.fetchSastSettings(org)
		assert.NotEmpty(t, service.orgToSastSettings)

		service.FlushCache()

		assert.Len(t, service.orgToSastSettings.GetAll(), 0)
	})

	t.Run("concurrent flush during fetch is thread-safe", func(t *testing.T) {
		engine, mockProvider := setupMockProvider(t)
		service := New(engine.GetConfiguration(), engine.GetLogger(), engine, testutil.DefaultConfigResolver(engine), withProvider(mockProvider))

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
		engine, mockProvider := setupMockProvider(t)
		service := New(engine.GetConfiguration(), engine.GetLogger(), engine, testutil.DefaultConfigResolver(engine), withProvider(mockProvider))
		folderPath := types.FilePath("/test/folder")

		// Setup folder config with specific feature flags via configuration
		folderConfig := &types.FolderConfig{
			FolderPath:     folderPath,
			ConfigResolver: testutil.DefaultConfigResolver(engine),
		}
		folderConfig.SetFeatureFlag(SnykCodeConsistentIgnores, true)
		folderConfig.SetFeatureFlag(SnykCodeInlineIgnore, false)

		// Test existing flags
		value1 := service.GetFromFolderConfig(folderPath, SnykCodeConsistentIgnores)
		assert.True(t, value1)

		value2 := service.GetFromFolderConfig(folderPath, SnykCodeInlineIgnore)
		assert.False(t, value2)
	})

	t.Run("returns false for non-existent flag", func(t *testing.T) {
		engine, mockProvider := setupMockProvider(t)
		service := New(engine.GetConfiguration(), engine.GetLogger(), engine, testutil.DefaultConfigResolver(engine), withProvider(mockProvider))

		folderPath := types.FilePath("/test/folder")
		folderConfig := &types.FolderConfig{
			FolderPath:     folderPath,
			ConfigResolver: testutil.DefaultConfigResolver(engine),
		}
		folderConfig.SetFeatureFlag(SnykCodeConsistentIgnores, true)

		// Test non-existent flag
		value := service.GetFromFolderConfig(folderPath, "nonExistentFlag")
		assert.False(t, value)
	})

	t.Run("handles multiple folders independently", func(t *testing.T) {
		engine, mockProvider := setupMockProvider(t)
		service := New(engine.GetConfiguration(), engine.GetLogger(), engine, testutil.DefaultConfigResolver(engine), withProvider(mockProvider))

		folder1 := types.FilePath("/folder1")
		folder2 := types.FilePath("/folder2")

		// Setup different flags for each folder
		config1 := &types.FolderConfig{
			FolderPath:     folder1,
			ConfigResolver: testutil.DefaultConfigResolver(engine),
		}
		config1.SetFeatureFlag(SnykCodeConsistentIgnores, true)
		config2 := &types.FolderConfig{
			FolderPath:     folder2,
			ConfigResolver: testutil.DefaultConfigResolver(engine),
		}
		config2.SetFeatureFlag(SnykCodeConsistentIgnores, false)

		// Each folder should have its own flags
		val1 := service.GetFromFolderConfig(folder1, SnykCodeConsistentIgnores)
		assert.True(t, val1)

		val2 := service.GetFromFolderConfig(folder2, SnykCodeConsistentIgnores)
		assert.False(t, val2)
	})

	t.Run("handles folder config with no feature flags set", func(t *testing.T) {
		engine, mockProvider := setupMockProvider(t)
		service := New(engine.GetConfiguration(), engine.GetLogger(), engine, testutil.DefaultConfigResolver(engine), withProvider(mockProvider))

		folderPath := types.FilePath("/test")

		// Should not panic, should return false when no flags are set
		value := service.GetFromFolderConfig(folderPath, "anyFlag")
		assert.False(t, value)
	})

	t.Run("handles empty folder path", func(t *testing.T) {
		engine, mockProvider := setupMockProvider(t)
		service := New(engine.GetConfiguration(), engine.GetLogger(), engine, testutil.DefaultConfigResolver(engine), withProvider(mockProvider))

		// Should not panic with empty path
		value := service.GetFromFolderConfig("", "anyFlag")
		assert.False(t, value)
	})
}

func TestPopulateFolderConfig(t *testing.T) {
	t.Run("sets feature flags", func(t *testing.T) {
		engine, mockProvider := setupMockProvider(t)
		service := New(engine.GetConfiguration(), engine.GetLogger(), engine, testutil.DefaultConfigResolver(engine), withProvider(mockProvider))

		folderPath := types.FilePath("/test/folder")
		folderConfig := &types.FolderConfig{
			FolderPath:     folderPath,
			ConfigResolver: testutil.DefaultConfigResolver(engine),
		}

		service.PopulateFolderConfig(folderConfig)

		// Mock default: SnykCodeConsistentIgnores=true, SnykCodeInlineIgnore=false
		assert.True(t, folderConfig.GetFeatureFlag(SnykCodeConsistentIgnores))
		assert.False(t, folderConfig.GetFeatureFlag(SnykCodeInlineIgnore))
	})

	t.Run("handles multiple folders", func(t *testing.T) {
		engine, mockProvider := setupMockProvider(t)
		service := New(engine.GetConfiguration(), engine.GetLogger(), engine, testutil.DefaultConfigResolver(engine), withProvider(mockProvider))

		folder1 := &types.FolderConfig{FolderPath: "/folder1", ConfigResolver: testutil.DefaultConfigResolver(engine)}
		folder2 := &types.FolderConfig{FolderPath: "/folder2", ConfigResolver: testutil.DefaultConfigResolver(engine)}

		// Populate both folders
		service.PopulateFolderConfig(folder1)
		service.PopulateFolderConfig(folder2)

		// Both should have flags populated (mock default: SnykCodeConsistentIgnores=true)
		assert.True(t, folder1.GetFeatureFlag(SnykCodeConsistentIgnores))
		assert.True(t, folder2.GetFeatureFlag(SnykCodeConsistentIgnores))
	})

	t.Run("populates SAST settings", func(t *testing.T) {
		engine, mockProvider := setupMockProvider(t)
		service := New(engine.GetConfiguration(), engine.GetLogger(), engine, testutil.DefaultConfigResolver(engine), withProvider(mockProvider))

		folderPath := types.FilePath("/test/folder")
		folderConfig := &types.FolderConfig{
			FolderPath:     folderPath,
			ConfigResolver: testutil.DefaultConfigResolver(engine),
		}

		service.PopulateFolderConfig(folderConfig)

		assert.True(t, folderConfig.GetFeatureFlag(SnykCodeConsistentIgnores))
		sastSettings := types.GetSastSettings(folderConfig.Conf(), folderConfig.FolderPath)
		assert.NotNil(t, sastSettings)
	})

	t.Run("continues on SAST settings error", func(t *testing.T) {
		engine, mockProviderWithError := setupMockProvider(t)
		// Override with error
		mockProviderWithError.sastErr = fmt.Errorf("mock error")
		service := New(engine.GetConfiguration(), engine.GetLogger(), engine, testutil.DefaultConfigResolver(engine), withProvider(mockProviderWithError))

		folderPath := types.FilePath("/test/folder")
		folderConfig := &types.FolderConfig{
			FolderPath:     folderPath,
			ConfigResolver: testutil.DefaultConfigResolver(engine),
		}

		// Even if SAST settings fetch fails, feature flags should still be populated
		service.PopulateFolderConfig(folderConfig)

		assert.True(t, folderConfig.GetFeatureFlag(SnykCodeConsistentIgnores))
	})

	t.Run("concurrent population is thread-safe", func(t *testing.T) {
		engine, mockProvider := setupMockProvider(t)
		service := New(engine.GetConfiguration(), engine.GetLogger(), engine, testutil.DefaultConfigResolver(engine), withProvider(mockProvider))

		var wg sync.WaitGroup
		numFolders := 10
		configs := make([]*types.FolderConfig, numFolders)

		for i := range numFolders {
			configs[i] = &types.FolderConfig{
				FolderPath:     types.FilePath("/folder" + string(rune(i))),
				ConfigResolver: testutil.DefaultConfigResolver(engine),
			}
			wg.Add(1)
			go func(cfg *types.FolderConfig) {
				defer wg.Done()
				service.PopulateFolderConfig(cfg)
			}(configs[i])
		}
		wg.Wait()

		// All configs should be populated with flags
		for _, cfg := range configs {
			assert.True(t, cfg.GetFeatureFlag(SnykCodeConsistentIgnores))
		}
	})
}

func TestFetchSastSettings(t *testing.T) {
	t.Run("caches SAST settings", func(t *testing.T) {
		engine, mockProvider := setupMockProvider(t)
		service := New(engine.GetConfiguration(), engine.GetLogger(), engine, testutil.DefaultConfigResolver(engine), withProvider(mockProvider))

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
		_, b := service.orgToSastSettings.Get(org)
		assert.True(t, b)
	})

	t.Run("different orgs have separate caches", func(t *testing.T) {
		engine, mockProvider := setupMockProvider(t)

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

		service := New(engine.GetConfiguration(), engine.GetLogger(), engine, testutil.DefaultConfigResolver(engine), withProvider(mockProvider))

		settings1, err1 := service.fetchSastSettings(org1)
		require.NoError(t, err1)
		assert.NotNil(t, settings1)

		settings2, err2 := service.fetchSastSettings(org2)
		require.NoError(t, err2)
		assert.NotNil(t, settings2)

		// Cache should have both orgs
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
		engine, mockProvider := setupMockProvider(t)
		service := New(engine.GetConfiguration(), engine.GetLogger(), engine, testutil.DefaultConfigResolver(engine), withProvider(mockProvider))
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
		_, b := service.orgToSastSettings.Get(org)
		assert.True(t, b)
		assert.Len(t, service.orgToSastSettings.GetAll(), 1)
	})
}

func Test_PopulateFolderConfig_UsesFolderOrganization(t *testing.T) {
	engine := testutil.IntegTest(t)

	// Set up two folders with different orgs
	folderPath1, folderPath2, _, folderOrg1, folderOrg2 := testutil.SetupFoldersWithOrgs(t, engine)

	// Create a mock provider that returns different orgs based on folder path
	mockProvider := &mockExternalCallsProvider{
		ignoreApprovalByOrg: make(map[string]bool),
		featureFlagsByOrg:   make(map[string]map[string]bool),
		sastSettingsByOrg:   make(map[string]*sast_contract.SastResponse),
		folderOrgByPath: map[string]string{
			string(folderPath1): folderOrg1,
			string(folderPath2): folderOrg2,
		},
	}

	// Configure different feature flags for each org
	mockProvider.featureFlagsByOrg[folderOrg1] = map[string]bool{
		SnykCodeConsistentIgnores: true,
		SnykCodeInlineIgnore:      false,
	}
	mockProvider.featureFlagsByOrg[folderOrg2] = map[string]bool{
		SnykCodeConsistentIgnores: false,
		SnykCodeInlineIgnore:      true,
	}

	service := &serviceImpl{
		conf:                 engine.GetConfiguration(),
		logger:               engine.GetLogger(),
		provider:             mockProvider,
		orgToFlag:            imcache.New[string, map[string]bool](),
		orgToSastSettings:    imcache.New[string, *sast_contract.SastResponse](),
		orgToSastSettingsErr: imcache.New[string, struct{}](),
		mutex:                &sync.Mutex{},
		overrides:            make(map[string]bool),
	}

	// Populate folder config for folder 1 - needs ConfigResolver for SetFeatureFlag
	folderConfig1 := &types.FolderConfig{
		FolderPath:     folderPath1,
		ConfigResolver: testutil.DefaultConfigResolver(engine),
	}
	service.PopulateFolderConfig(folderConfig1)

	// Verify folder1 got flags from folderOrg1
	assert.True(t, folderConfig1.GetFeatureFlag(SnykCodeConsistentIgnores), "Folder1 should have SnykCodeConsistentIgnores=true from folderOrg1")
	assert.False(t, folderConfig1.GetFeatureFlag(SnykCodeInlineIgnore), "Folder1 should have SnykCodeInlineIgnore=false from folderOrg1")

	// Verify fetch was called with folderOrg1 and cached the correct values
	org1Flags, found := service.orgToFlag.Get(folderOrg1)
	assert.True(t, found, "Service should have cached flags for folderOrg1")
	assert.Contains(t, org1Flags, SnykCodeConsistentIgnores, "Service should have cached SnykCodeConsistentIgnores for folderOrg1")
	assert.True(t, org1Flags[SnykCodeConsistentIgnores], "Service should have cached SnykCodeConsistentIgnores=true for folderOrg1")
	assert.Contains(t, org1Flags, SnykCodeInlineIgnore, "Service should have cached SnykCodeInlineIgnore for folderOrg1")
	assert.False(t, org1Flags[SnykCodeInlineIgnore], "Service should have cached SnykCodeInlineIgnore=false for folderOrg1")

	// Populate folder config for folder 2
	folderConfig2 := &types.FolderConfig{
		FolderPath:     folderPath2,
		ConfigResolver: testutil.DefaultConfigResolver(engine),
	}
	service.PopulateFolderConfig(folderConfig2)

	// Verify folder2 got flags from folderOrg2
	assert.False(t, folderConfig2.GetFeatureFlag(SnykCodeConsistentIgnores), "Folder2 should have SnykCodeConsistentIgnores=false from folderOrg2")
	assert.True(t, folderConfig2.GetFeatureFlag(SnykCodeInlineIgnore), "Folder2 should have SnykCodeInlineIgnore=true from folderOrg2")

	// Verify fetch was called with folderOrg2 and cached the correct values
	org2Flags, found := service.orgToFlag.Get(folderOrg2)
	assert.True(t, found, "Service should have cached flags for folderOrg2")
	assert.Contains(t, org2Flags, SnykCodeConsistentIgnores, "Service should have cached SnykCodeConsistentIgnores for folderOrg2")
	assert.False(t, org2Flags[SnykCodeConsistentIgnores], "Service should have cached SnykCodeConsistentIgnores=false for folderOrg2")
	assert.Contains(t, org2Flags, SnykCodeInlineIgnore, "Service should have cached SnykCodeInlineIgnore for folderOrg2")
	assert.True(t, org2Flags[SnykCodeInlineIgnore], "Service should have cached SnykCodeInlineIgnore=true for folderOrg2")

	// Verify both orgs are cached separately
	assert.Len(t, service.orgToFlag.GetAll(), 2, "Service should have cached flags for both orgs")
	assert.NotEqual(t, folderConfig1.GetFeatureFlag(SnykCodeConsistentIgnores), folderConfig2.GetFeatureFlag(SnykCodeConsistentIgnores), "Folders should have different flag values based on their orgs")
}

func TestServiceImpl_Override_PinsFlag(t *testing.T) {
	t.Helper()
	engine := testutil.UnitTest(t)

	// API returns true for the flag, but Override pins it to false.
	provider := &mockExternalCallsProvider{
		featureFlagsByOrg: map[string]map[string]bool{
			"org1": {UseExperimentalRiskScoreInCLI: true},
		},
		folderOrg: "org1",
	}

	svc := New(engine.GetConfiguration(), engine.GetLogger(), engine, testutil.DefaultConfigResolver(engine), withProvider(provider))
	svc.Override(UseExperimentalRiskScoreInCLI, false)

	folderPath := types.FilePath(t.TempDir())
	folderConfig := config.GetFolderConfigFromEngine(engine, testutil.DefaultConfigResolver(engine), folderPath, engine.GetLogger())
	svc.PopulateFolderConfig(folderConfig)

	assert.False(t, folderConfig.GetFeatureFlag(UseExperimentalRiskScoreInCLI),
		"Override(false) must win over the API-returned true value")
}

func TestFetchSastSettings_NegativeCache(t *testing.T) {
	t.Run("caches SAST error so same-org failure only calls provider once", func(t *testing.T) {
		engine, mockProvider := setupMockProvider(t)
		mockProvider.sastErr = fmt.Errorf("401 unauthorized")

		service := New(engine.GetConfiguration(), engine.GetLogger(), engine, testutil.DefaultConfigResolver(engine), withProvider(mockProvider))
		org := "fedramp-org"

		const N = 100
		for range N {
			_, err := service.fetchSastSettings(org)
			require.Error(t, err)
		}

		mockProvider.mu.Lock()
		calls := mockProvider.sastSettingsCalls
		mockProvider.mu.Unlock()

		assert.Equal(t, 1, calls, "provider should only be called once; subsequent calls should use the negative cache")
	})

	t.Run("GoldenPath_WorksWithNegativeCachePresent", func(t *testing.T) {
		engine, mockProvider := setupMockProvider(t)
		mockProvider.sastSettingsByOrg = map[string]*sast_contract.SastResponse{
			"good-org": {SastEnabled: true},
		}

		service := New(engine.GetConfiguration(), engine.GetLogger(), engine, testutil.DefaultConfigResolver(engine), withProvider(mockProvider))

		resp, err := service.fetchSastSettings("good-org")
		require.NoError(t, err)
		assert.True(t, resp.SastEnabled)
	})

	t.Run("FlushCache clears the negative cache", func(t *testing.T) {
		engine, mockProvider := setupMockProvider(t)
		mockProvider.sastErr = fmt.Errorf("401 unauthorized")

		service := New(engine.GetConfiguration(), engine.GetLogger(), engine, testutil.DefaultConfigResolver(engine), withProvider(mockProvider))
		org := "flush-org"

		_, _ = service.fetchSastSettings(org)

		service.FlushCache()

		// After flush, provider should be called again
		mockProvider.mu.Lock()
		before := mockProvider.sastSettingsCalls
		mockProvider.mu.Unlock()

		_, _ = service.fetchSastSettings(org)

		mockProvider.mu.Lock()
		after := mockProvider.sastSettingsCalls
		mockProvider.mu.Unlock()

		assert.Equal(t, before+1, after, "provider should be called again after FlushCache")
	})

	t.Run("concurrent FlushCache does not re-poison error cache", func(t *testing.T) {
		// TOCTOU guard: if FlushCache() runs while an HTTP error response is in-flight,
		// the error must not be written back into the freshly-cleared cache.
		engine, mockProvider := setupMockProvider(t)
		mockProvider.sastErr = fmt.Errorf("401 unauthorized")
		mockProvider.sastDelay = 50 * time.Millisecond
		sastReady := make(chan struct{}, 1)
		mockProvider.sastReadyCh = sastReady

		service := New(engine.GetConfiguration(), engine.GetLogger(), engine, testutil.DefaultConfigResolver(engine), withProvider(mockProvider))
		org := "toctou-org"

		// Start a fetch that will sleep 50ms inside getSastSettings.
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = service.fetchSastSettings(org)
		}()

		// Wait for getSastSettings to signal it is mid-sleep, then flush.
		testsupport.RequireEventuallyReceive(t, sastReady, 5*time.Second, time.Millisecond, "getSastSettings did not signal in time")
		service.FlushCache()

		testsupport.RequireEventuallyClosed(t, done, 5*time.Second, time.Millisecond, "in-flight getSastSettings goroutine did not finish in time")

		// The gen guard must have prevented the stale error from being written back.
		_, found := service.orgToSastSettingsErr.Get(org)
		assert.False(t, found, "error must not be cached after concurrent FlushCache (TOCTOU guard)")
	})
}

// BenchmarkFetchSastSettings_NegativeCache proves the O(N)→O(1) speedup.
// Before the fix: N=100 folders each make a fresh HTTP call → 100× slower than N=1.
// After the fix:  all 100 calls hit the negative cache → ~same wall time as N=1.
func BenchmarkFetchSastSettings_NegativeCache(b *testing.B) {
	const N = 100

	slowProvider := &mockExternalCallsProvider{
		sastErr: fmt.Errorf("401 unauthorized"),
	}

	// Use a plain in-memory configuration — no engine needed for this benchmark.
	conf := configuration.NewWithOpts()
	logger := zerolog.Nop()
	service := &serviceImpl{
		conf:                 conf,
		logger:               &logger,
		provider:             slowProvider,
		orgToFlag:            imcache.New[string, map[string]bool](),
		orgToSastSettings:    imcache.New[string, *sast_contract.SastResponse](),
		orgToSastSettingsErr: imcache.New[string, struct{}](),
		mutex:                &sync.Mutex{},
		overrides:            make(map[string]bool),
	}
	org := "bench-org"

	b.ResetTimer()
	for range b.N {
		service.FlushCache() // reset per iteration to measure steady-state with cache warm
		for range N {
			_, _ = service.fetchSastSettings(org)
		}
	}

	slowProvider.mu.Lock()
	totalCalls := slowProvider.sastSettingsCalls
	slowProvider.mu.Unlock()

	// With negative caching: provider called once per b.N iteration (once per FlushCache),
	// not N times. Allow up to 2× b.N to tolerate any edge-case double-call.
	if totalCalls > 2*b.N {
		b.Errorf("provider called %d times total for %d iterations (want ≤%d); negative cache is not working", totalCalls, b.N, 2*b.N)
	}
}
