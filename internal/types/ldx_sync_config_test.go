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

package types

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfigSource_String(t *testing.T) {
	tests := []struct {
		source   ConfigSource
		expected string
	}{
		{ConfigSourceDefault, "default"},
		{ConfigSourceGlobal, "global"},
		{ConfigSourceLDXSync, "ldx-sync"},
		{ConfigSourceLDXSyncLocked, "ldx-sync-locked"},
		{ConfigSourceUserOverride, "user-override"},
		{ConfigSourceFolder, "folder"},
		{ConfigSource(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.source.String())
		})
	}
}

func TestSettingScope_String(t *testing.T) {
	tests := []struct {
		scope    SettingScope
		expected string
	}{
		{SettingScopeMachine, "machine"},
		{SettingScopeOrg, "org"},
		{SettingScopeFolder, "folder"},
		{SettingScope(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.scope.String())
		})
	}
}

func TestLDXSyncOrgConfig_GetField(t *testing.T) {
	t.Run("returns nil for nil config", func(t *testing.T) {
		var config *LDXSyncOrgConfig
		assert.Nil(t, config.GetField("test"))
	})

	t.Run("returns nil for nil fields", func(t *testing.T) {
		config := &LDXSyncOrgConfig{OrgId: "org1"}
		assert.Nil(t, config.GetField("test"))
	})

	t.Run("returns nil for missing field", func(t *testing.T) {
		config := NewLDXSyncOrgConfig("org1")
		assert.Nil(t, config.GetField("missing"))
	})

	t.Run("returns field when exists", func(t *testing.T) {
		config := NewLDXSyncOrgConfig("org1")
		config.SetField("test", "value", false, false, "org")

		field := config.GetField("test")
		assert.NotNil(t, field)
		assert.Equal(t, "value", field.Value)
		assert.False(t, field.IsLocked)
		assert.False(t, field.IsEnforced)
	})
}

func TestLDXSyncOrgConfig_SetField(t *testing.T) {
	t.Run("creates fields map if nil", func(t *testing.T) {
		config := &LDXSyncOrgConfig{OrgId: "org1"}
		config.SetField("test", "value", true, true, "group")

		assert.NotNil(t, config.Fields)
		field := config.Fields["test"]
		assert.Equal(t, "value", field.Value)
		assert.True(t, field.IsLocked)
		assert.True(t, field.IsEnforced)
		assert.Equal(t, "group", field.OriginScope)
	})
}

func TestLDXSyncConfigCache_GetOrgConfig(t *testing.T) {
	t.Run("returns nil for nil cache", func(t *testing.T) {
		var cache *LDXSyncConfigCache
		assert.Nil(t, cache.GetOrgConfig("org1"))
	})

	t.Run("returns nil for nil configs map", func(t *testing.T) {
		cache := &LDXSyncConfigCache{}
		assert.Nil(t, cache.GetOrgConfig("org1"))
	})

	t.Run("returns nil for missing org", func(t *testing.T) {
		cache := NewLDXSyncConfigCache()
		assert.Nil(t, cache.GetOrgConfig("missing"))
	})

	t.Run("returns org config when exists", func(t *testing.T) {
		cache := NewLDXSyncConfigCache()
		orgConfig := NewLDXSyncOrgConfig("org1")
		cache.SetOrgConfig(orgConfig)

		result := cache.GetOrgConfig("org1")
		assert.NotNil(t, result)
		assert.Equal(t, "org1", result.OrgId)
	})
}

func TestLDXSyncConfigCache_RemoveOrgConfig(t *testing.T) {
	t.Run("does nothing for nil configs", func(t *testing.T) {
		cache := &LDXSyncConfigCache{}
		cache.RemoveOrgConfig("org1") // should not panic
	})

	t.Run("removes org config", func(t *testing.T) {
		cache := NewLDXSyncConfigCache()
		cache.SetOrgConfig(NewLDXSyncOrgConfig("org1"))
		cache.SetOrgConfig(NewLDXSyncOrgConfig("org2"))

		cache.RemoveOrgConfig("org1")

		assert.Nil(t, cache.GetOrgConfig("org1"))
		assert.NotNil(t, cache.GetOrgConfig("org2"))
	})
}

func TestLDXSyncConfigCache_ConcurrentAccess(t *testing.T) {
	cache := NewLDXSyncConfigCache()
	done := make(chan bool, 10)

	// Concurrent writers for org configs
	for i := 0; i < 5; i++ {
		go func(id int) {
			orgId := "org-" + string(rune('A'+id))
			orgConfig := NewLDXSyncOrgConfig(orgId)
			orgConfig.SetField("test", true, false, false, "")
			cache.SetOrgConfig(orgConfig)
			_ = cache.GetOrgConfig(orgId)
			_ = cache.IsEmpty()
			done <- true
		}(i)
	}

	// Concurrent writers for folder mappings
	for i := 0; i < 5; i++ {
		go func(id int) {
			folder := FilePath("/folder-" + string(rune('A'+id)))
			cache.SetFolderOrg(folder, "org-"+string(rune('A'+id)))
			_ = cache.GetOrgIdForFolder(folder)
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify no panics occurred and data is consistent
	assert.False(t, cache.IsEmpty())
}

func TestConfigResolver_ConcurrentAccess(t *testing.T) {
	cache := NewLDXSyncConfigCache()
	orgConfig := NewLDXSyncOrgConfig("org1")
	orgConfig.SetField(SettingSnykCodeEnabled, true, false, false, "")
	cache.SetOrgConfig(orgConfig)
	cache.SetFolderOrg("/folder", "org1")

	resolver := NewConfigResolver(cache, nil, nil, nil)
	done := make(chan bool, 10)

	// Concurrent readers
	for i := 0; i < 5; i++ {
		go func() {
			_ = resolver.GetBool(SettingSnykCodeEnabled, &FolderConfig{FolderPath: "/folder"})
			done <- true
		}()
	}

	// Concurrent writers
	for i := 0; i < 5; i++ {
		go func(id int) {
			newMachine := map[string]*LDXSyncField{
				SettingApiEndpoint: {Value: "https://api.snyk.io", IsLocked: false},
			}
			resolver.SetLDXSyncMachineConfig(newMachine)
			_ = resolver.GetLDXSyncMachineConfig()
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestGetSettingScope(t *testing.T) {
	t.Run("machine-scope settings", func(t *testing.T) {
		machineSettings := []string{
			SettingApiEndpoint,
			SettingCodeEndpoint,
			SettingAuthenticationMethod,
			SettingProxyHttp,
			SettingProxyHttps,
			SettingProxyNoProxy,
			SettingProxyInsecure,
			SettingAutoConfigureMcpServer,
			SettingPublishSecurityAtInceptionRules,
			SettingTrustEnabled,
			SettingBinaryBaseUrl,
			SettingCliPath,
			SettingAutomaticDownload,
			SettingCliReleaseChannel,
		}

		for _, setting := range machineSettings {
			assert.Equal(t, SettingScopeMachine, GetSettingScope(setting), "expected %s to be machine-scoped", setting)
			assert.True(t, IsMachineWideSetting(setting), "expected IsMachineWideSetting(%s) to be true", setting)
			assert.False(t, IsOrgScopedSetting(setting))
			assert.False(t, IsFolderScopedSetting(setting))
		}
	})

	t.Run("org-scope settings", func(t *testing.T) {
		orgSettings := []string{
			SettingEnabledSeverities,
			SettingRiskScoreThreshold,
			SettingCweIds,
			SettingCveIds,
			SettingRuleIds,
			SettingSnykCodeEnabled,
			SettingSnykOssEnabled,
			SettingSnykIacEnabled,
			SettingScanAutomatic,
			SettingScanNetNew,
			SettingIssueViewOpenIssues,
			SettingIssueViewIgnoredIssues,
		}

		for _, setting := range orgSettings {
			assert.Equal(t, SettingScopeOrg, GetSettingScope(setting), "expected %s to be org-scoped", setting)
			assert.True(t, IsOrgScopedSetting(setting), "expected IsOrgScopedSetting(%s) to be true", setting)
			assert.False(t, IsMachineWideSetting(setting))
			assert.False(t, IsFolderScopedSetting(setting))
		}
	})

	t.Run("folder-scope settings", func(t *testing.T) {
		folderSettings := []string{
			SettingReferenceFolder,
			SettingReferenceBranch,
			SettingAdditionalParameters,
			SettingAdditionalEnvironment,
		}

		for _, setting := range folderSettings {
			assert.Equal(t, SettingScopeFolder, GetSettingScope(setting), "expected %s to be folder-scoped", setting)
			assert.True(t, IsFolderScopedSetting(setting), "expected IsFolderScopedSetting(%s) to be true", setting)
			assert.False(t, IsMachineWideSetting(setting))
			assert.False(t, IsOrgScopedSetting(setting))
		}
	})

	t.Run("unknown settings default to org scope", func(t *testing.T) {
		assert.Equal(t, SettingScopeOrg, GetSettingScope("unknown_setting"))
	})
}

func Test_LDXSyncCache_ConcurrentAccess_NoRace(t *testing.T) {
	cache := NewLDXSyncConfigCache()
	var wg sync.WaitGroup

	// 100 goroutines concurrently accessing cache
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			folderPath := FilePath(fmt.Sprintf("/folder%d", id))
			orgId := fmt.Sprintf("org-%d", id)

			cache.SetFolderOrg(folderPath, orgId)
			_ = cache.GetOrgIdForFolder(folderPath)
		}(i)
	}
	wg.Wait()

	// Verify all mappings exist
	for i := 0; i < 100; i++ {
		folderPath := FilePath(fmt.Sprintf("/folder%d", i))
		orgId := cache.GetOrgIdForFolder(folderPath)
		assert.Equal(t, fmt.Sprintf("org-%d", i), orgId, "Org ID should match for folder %d", i)
	}
}
