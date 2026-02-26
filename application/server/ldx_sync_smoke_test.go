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

package server

import (
	"os"
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

// LDX-Sync test org configurations
// These org IDs and their settings are configured on the test server (SNYK_TOKEN_CONSISTENT_IGNORES).
//
// ldxSyncTestOrg1 (b1a01686-331c-4b59-854c-139216d56bb0):
//   - Auto-determined for: NodejsGoof repo (commit 0336589)
//   - risk_score_threshold:      400             (org-scope)
//   - enabled_severities:        critical,high,medium → SeverityFilter{Critical:true, High:true, Medium:true, Low:false}
//   - auto_configure_mcp_server: "true"          (machine-scope, locked)
//   - cli_release_channel:       "stable"        (machine-scope, unlocked)
//
// ldxSyncTestOrg2 (a25ea1f5-b5fc-4482-bd30-9e768241eb52):
//   - Auto-determined for: PythonGoof repo (commit c32657c)
//   - risk_score_threshold:      600             (org-scope)
//   - enabled_severities:        critical,high   → SeverityFilter{Critical:true, High:true, Medium:false, Low:false}
//   - auto_configure_mcp_server: "true"          (machine-scope, unlocked)
//   - cli_release_channel:       "preview"       (machine-scope, locked)
const (
	ldxSyncTestOrg1 = "b1a01686-331c-4b59-854c-139216d56bb0"
	ldxSyncTestOrg2 = "a25ea1f5-b5fc-4482-bd30-9e768241eb52"
)

// setupLdxSyncTest creates test environment for LDX-Sync cache tests
func setupLdxSyncTest(t *testing.T) (*config.Config, server.Local, *testsupport.JsonRPCRecorder) {
	t.Helper()
	c := testutil.SmokeTest(t, "SNYK_TOKEN_CONSISTENT_IGNORES")

	// Clear any existing config file from previous test runs
	if s, err := storedconfig.ConfigFile(c.IdeName()); err == nil {
		_ = os.Remove(s)
	}

	loc, jsonRpcRecorder := setupServer(t, c)

	// Disable scanning products - only testing cache behavior
	c.SetSnykCodeEnabled(false)
	c.SetSnykIacEnabled(false)
	c.SetSnykOssEnabled(false)

	// Enable LDX-Sync settings propagation for tests that verify NullableField values
	c.SetLDXSyncSettingsEnabled(true)

	cleanupChannels()
	di.Init()

	return c, loc, jsonRpcRecorder
}

// requireLspConfigurationNotification is a helper to check $/snyk.configuration notifications
// validator is a function that validates the configuration parameter
// clearNotifications controls whether to clear notifications after validation (default: true)
func requireLspConfigurationNotification(t *testing.T, jsonRpcRecorder *testsupport.JsonRPCRecorder, validator func(types.LspConfigurationParam), clearNotifications ...bool) {
	t.Helper()

	var notifications []jrpc2.Request
	require.Eventuallyf(t, func() bool {
		notifications = jsonRpcRecorder.FindNotificationsByMethod("$/snyk.configuration")
		return len(notifications) != 0
	}, 10*time.Second, 5*time.Millisecond, "No $/snyk.configuration notifications")

	last := notifications[len(notifications)-1]
	var param types.LspConfigurationParam
	require.NoError(t, last.UnmarshalParams(&param))

	if validator != nil {
		validator(param)
	}

	// Clear notifications by default unless explicitly disabled
	shouldClear := true
	if len(clearNotifications) > 0 {
		shouldClear = clearNotifications[0]
	}
	if shouldClear {
		jsonRpcRecorder.ClearNotifications()
	}
}

// Test_SmokeLdxSync_Initialize verifies LDX-Sync cache population and notifications
// are sent correctly when initializing with a workspace folder
func Test_SmokeLdxSync_Initialize(t *testing.T) {
	c, loc, jsonRpcRecorder := setupLdxSyncTest(t)

	folder := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", loc, c)

	requireLspConfigurationNotification(t, jsonRpcRecorder, func(cfg types.LspConfigurationParam) {
		assert.NotEmpty(t, cfg.ActivateSnykOpenSource)
		assert.NotEmpty(t, cfg.ActivateSnykCode)
		assert.NotEmpty(t, cfg.ActivateSnykIac)
		assert.NotEmpty(t, cfg.Organization)

		// Check machine-scope settings from LDX-Sync
		assert.NotEmpty(t, cfg.AutoConfigureSnykMcpServer, "auto_configure_mcp_server should be set")
		assert.Equal(t, "true", cfg.AutoConfigureSnykMcpServer, "auto_configure_mcp_server should be true (locked)")
		assert.NotEmpty(t, cfg.CliReleaseChannel, "cli_release_channel should be set")
		assert.Equal(t, "stable", cfg.CliReleaseChannel, "cli_release_channel should be stable")
	}, false)

	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder: func(fc types.LspFolderConfig) {
			require.NotNil(t, fc.AutoDeterminedOrg, "Folder should have autoDeterminedOrg set")
			assert.NotEmpty(t, *fc.AutoDeterminedOrg, "Folder should have autoDeterminedOrg from LDX-Sync cache")

			// Check org-scope settings from LDX-Sync
			require.True(t, fc.RiskScoreThreshold.HasValue(), "RiskScoreThreshold should have value from org config")
			assert.Equal(t, 400, fc.RiskScoreThreshold.Get(), "RiskScoreThreshold should be 400 from org config")
			require.True(t, fc.EnabledSeverities.HasValue(), "EnabledSeverities should have value from org config")
			assert.Equal(t, types.SeverityFilter{Critical: true, High: true, Medium: true, Low: false}, fc.EnabledSeverities.Get())
		},
	}, false)

	jsonRpcRecorder.ClearNotifications()
}

// Test_SmokeLdxSync_AddFolder verifies LDX-Sync cache is refreshed and notifications
// are sent when adding a workspace folder dynamically via didChangeWorkspaceFolders
func Test_SmokeLdxSync_AddFolder(t *testing.T) {
	c, loc, jsonRpcRecorder := setupLdxSyncTest(t)

	folder1 := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", loc, c)

	requireLspConfigurationNotification(t, jsonRpcRecorder, func(cfg types.LspConfigurationParam) {
		assert.NotEmpty(t, cfg.ActivateSnykOpenSource)
		assert.NotEmpty(t, cfg.ActivateSnykCode)
		assert.NotEmpty(t, cfg.ActivateSnykIac)
		assert.NotEmpty(t, cfg.Organization)

		// Check machine-scope settings from first org
		assert.NotEmpty(t, cfg.AutoConfigureSnykMcpServer)
		assert.Equal(t, "true", cfg.AutoConfigureSnykMcpServer)
		assert.NotEmpty(t, cfg.CliReleaseChannel)
		assert.Equal(t, "stable", cfg.CliReleaseChannel)
	}, false)

	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder1: func(fc types.LspFolderConfig) {
			require.NotNil(t, fc.AutoDeterminedOrg, "Folder 1 should have autoDeterminedOrg set")
			assert.NotEmpty(t, *fc.AutoDeterminedOrg, "Folder 1 should have autoDeterminedOrg from LDX-Sync cache")

			// Check org-scope settings from LDX-Sync
			require.True(t, fc.RiskScoreThreshold.HasValue(), "RiskScoreThreshold should have value from org config")
			assert.Equal(t, 400, fc.RiskScoreThreshold.Get(), "RiskScoreThreshold should be 400 from org config")
			require.True(t, fc.EnabledSeverities.HasValue(), "EnabledSeverities should have value from org config")
			assert.Equal(t, types.SeverityFilter{Critical: true, High: true, Medium: true, Low: false}, fc.EnabledSeverities.Get())
		},
	}, false)

	jsonRpcRecorder.ClearNotifications()

	folder2, err := storedconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), testsupport.PythonGoof, "c32657c", c.Logger(), false)
	require.NoError(t, err, "Failed to setup second test repo")
	require.NotEmpty(t, folder2, "Folder path should not be empty")
	require.DirExists(t, string(folder2), "Folder should exist")

	workspaceFolder2 := types.WorkspaceFolder{
		Name: "Python Goof",
		Uri:  uri.PathToUri(folder2),
	}
	addWorkSpaceFolder(t, loc, workspaceFolder2)

	// Machine settings: second folder's locked setting overrides, unlocked doesn't
	requireLspConfigurationNotification(t, jsonRpcRecorder, func(cfg types.LspConfigurationParam) {
		assert.NotEmpty(t, cfg.ActivateSnykOpenSource)
		assert.NotEmpty(t, cfg.ActivateSnykCode)
		assert.NotEmpty(t, cfg.ActivateSnykIac)
		assert.NotEmpty(t, cfg.Organization)

		// auto_configure_mcp_server stays true from first folder (second folder's value is unlocked, so doesn't override)
		assert.NotEmpty(t, cfg.AutoConfigureSnykMcpServer)
		assert.Equal(t, "true", cfg.AutoConfigureSnykMcpServer, "auto_configure_mcp_server stays true from first folder (second folder's is unlocked)")
		// cli_release_channel changes to preview from second folder (second folder's value is locked, so overrides)
		assert.NotEmpty(t, cfg.CliReleaseChannel)
		assert.Equal(t, "preview", cfg.CliReleaseChannel, "cli_release_channel changes to preview (second folder's is locked)")
	}, false)

	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder1: func(fc types.LspFolderConfig) {
			require.NotNil(t, fc.AutoDeterminedOrg, "Folder 1 should have autoDeterminedOrg set")
			assert.NotEmpty(t, *fc.AutoDeterminedOrg, "Folder 1 should still have autoDeterminedOrg")

			// Check org-scope settings from first org
			require.True(t, fc.RiskScoreThreshold.HasValue(), "Folder 1 RiskScoreThreshold should have value")
			assert.Equal(t, 400, fc.RiskScoreThreshold.Get(), "Folder 1 should have risk_score_threshold=400")
			require.True(t, fc.EnabledSeverities.HasValue(), "Folder 1 EnabledSeverities should have value")
			assert.Equal(t, types.SeverityFilter{Critical: true, High: true, Medium: true, Low: false}, fc.EnabledSeverities.Get())
		},
		folder2: func(fc types.LspFolderConfig) {
			require.NotNil(t, fc.AutoDeterminedOrg, "Folder 2 should have autoDeterminedOrg set")
			assert.NotEmpty(t, *fc.AutoDeterminedOrg, "Folder 2 should have autoDeterminedOrg from LDX-Sync cache")

			// Check org-scope settings from second org (different values)
			require.True(t, fc.RiskScoreThreshold.HasValue(), "Folder 2 RiskScoreThreshold should have value")
			assert.Equal(t, 600, fc.RiskScoreThreshold.Get(), "Folder 2 should have risk_score_threshold=600 from second org")
			require.True(t, fc.EnabledSeverities.HasValue(), "Folder 2 EnabledSeverities should have value")
			assert.Equal(t, types.SeverityFilter{Critical: true, High: true, Medium: false, Low: false}, fc.EnabledSeverities.Get(), "Folder 2 should have only critical and high from second org")
		},
	}, false)

	jsonRpcRecorder.ClearNotifications()
}

// Test_SmokeLdxSync_ChangePreferredOrg verifies LDX-Sync cache is refreshed and
// notifications are sent when changing the PreferredOrg via didChangeConfiguration
func Test_SmokeLdxSync_ChangePreferredOrg(t *testing.T) {
	c, loc, jsonRpcRecorder := setupLdxSyncTest(t)

	folder := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", loc, c)

	requireLspConfigurationNotification(t, jsonRpcRecorder, func(cfg types.LspConfigurationParam) {
		assert.NotEmpty(t, cfg.ActivateSnykOpenSource)
		assert.NotEmpty(t, cfg.ActivateSnykCode)
		assert.NotEmpty(t, cfg.ActivateSnykIac)
		assert.NotEmpty(t, cfg.Organization)

		// Check initial machine-scope settings
		assert.NotEmpty(t, cfg.AutoConfigureSnykMcpServer)
		assert.Equal(t, "true", cfg.AutoConfigureSnykMcpServer)
		assert.NotEmpty(t, cfg.CliReleaseChannel)
		assert.Equal(t, "stable", cfg.CliReleaseChannel)
	}, false)

	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder: func(fc types.LspFolderConfig) {
			require.NotNil(t, fc.AutoDeterminedOrg, "Folder should have autoDeterminedOrg set")
			assert.NotEmpty(t, *fc.AutoDeterminedOrg, "Folder should have autoDeterminedOrg from LDX-Sync cache")

			// Check initial org-scope settings from first org
			require.True(t, fc.RiskScoreThreshold.HasValue(), "RiskScoreThreshold should have value from org config")
			assert.Equal(t, 400, fc.RiskScoreThreshold.Get(), "RiskScoreThreshold should be 400 from first org")
			require.True(t, fc.EnabledSeverities.HasValue(), "EnabledSeverities should have value from org config")
			assert.Equal(t, types.SeverityFilter{Critical: true, High: true, Medium: true, Low: false}, fc.EnabledSeverities.Get())
		},
	}, false)

	jsonRpcRecorder.ClearNotifications()

	sendModifiedFolderConfiguration(t, c, loc, func(folderConfigs map[types.FilePath]*types.FolderConfig) []types.LspFolderConfig {
		folderConfig := folderConfigs[folder]
		orgSetByUser := true
		var preferredOrg string
		if folderConfig.AutoDeterminedOrg == ldxSyncTestOrg1 {
			preferredOrg = ldxSyncTestOrg2
		} else {
			preferredOrg = ldxSyncTestOrg1
		}
		return []types.LspFolderConfig{{FolderPath: folder, OrgSetByUser: &orgSetByUser, PreferredOrg: &preferredOrg}}
	})

	// Changed PreferredOrg: new org's locked setting overrides, unlocked doesn't
	requireLspConfigurationNotification(t, jsonRpcRecorder, func(cfg types.LspConfigurationParam) {
		assert.NotEmpty(t, cfg.ActivateSnykOpenSource)
		assert.NotEmpty(t, cfg.ActivateSnykCode)
		assert.NotEmpty(t, cfg.ActivateSnykIac)
		assert.NotEmpty(t, cfg.Organization)

		// auto_configure_mcp_server stays true from initial org (new org's value is unlocked, so doesn't override)
		assert.NotEmpty(t, cfg.AutoConfigureSnykMcpServer)
		assert.Equal(t, "true", cfg.AutoConfigureSnykMcpServer, "auto_configure_mcp_server stays true (new org's is unlocked)")
		// cli_release_channel changes to preview from new org (new org's value is locked, so overrides)
		assert.NotEmpty(t, cfg.CliReleaseChannel)
		assert.Equal(t, "preview", cfg.CliReleaseChannel, "cli_release_channel changes to preview (new org's is locked)")
	}, false)

	// Changed PreferredOrg: org-scope settings from new org apply to the folder
	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder: func(fc types.LspFolderConfig) {
			require.NotNil(t, fc.AutoDeterminedOrg, "Folder should have autoDeterminedOrg set")
			assert.NotEmpty(t, *fc.AutoDeterminedOrg, "Folder should have autoDeterminedOrg after config change")

			// Org-scope settings reflect the new org (UUID-keyed cache lookup works correctly)
			require.True(t, fc.RiskScoreThreshold.HasValue(), "RiskScoreThreshold should have value from new org")
			assert.Equal(t, 600, fc.RiskScoreThreshold.Get(), "RiskScoreThreshold should be 600 from second org")
			require.True(t, fc.EnabledSeverities.HasValue(), "EnabledSeverities should have value from new org")
			assert.Equal(t, types.SeverityFilter{Critical: true, High: true, Medium: false, Low: false}, fc.EnabledSeverities.Get(), "Should have only critical and high from second org")
		},
	}, false)

	jsonRpcRecorder.ClearNotifications()
}

// requireStoredFolderConfig loads and returns the stored FolderConfig for the given folder path.
// It fails the test if the folder config cannot be found.
func requireStoredFolderConfig(t *testing.T, c *config.Config, folderPath types.FilePath) *types.FolderConfig {
	t.Helper()
	sc, err := storedconfig.GetStoredConfig(c.Engine().GetConfiguration(), c.Logger(), true)
	require.NoError(t, err)
	normalizedPath := types.PathKey(folderPath)
	fc, ok := sc.FolderConfigs[normalizedPath]
	require.True(t, ok, "Folder config not found for path: %s", folderPath)
	return fc
}

// Test_SmokeLdxSync_ConfigEchoBack_NoSpuriousOverrides verifies that when the feature flag is OFF,
// echoing back $/snyk.folderConfigs notifications does not create spurious user overrides.
// This is a regression test for the echo bug where NullableFields were unconditionally populated,
// causing IDEs to echo them back and create stale overrides.
func Test_SmokeLdxSync_ConfigEchoBack_NoSpuriousOverrides(t *testing.T) {
	c, loc, jsonRpcRecorder := setupLdxSyncTest(t)
	c.SetLDXSyncSettingsEnabled(false)

	folder := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", loc, c)

	// Wait for initial folder config notification and capture the configs for echo-back
	var capturedFolderConfigs []types.LspFolderConfig
	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder: func(fc types.LspFolderConfig) {
			capturedFolderConfigs = append(capturedFolderConfigs, fc)
			// Feature flag OFF: no NullableFields should be present in notification
			assert.True(t, fc.RiskScoreThreshold.IsOmitted(), "RiskScoreThreshold should not be present when feature flag is OFF")
			assert.True(t, fc.EnabledSeverities.IsOmitted(), "EnabledSeverities should not be present when feature flag is OFF")
			assert.True(t, fc.SnykCodeEnabled.IsOmitted(), "SnykCodeEnabled should not be present when feature flag is OFF")
		},
	}, false)

	// Verify no user overrides in initial stored config
	storedFolderConfig := requireStoredFolderConfig(t, c, folder)
	assert.Empty(t, storedFolderConfig.UserOverrides, "Initial stored config should have no user overrides")

	jsonRpcRecorder.ClearNotifications()

	// Simulate IDE echo: send the received folder configs back verbatim
	settings := buildSmokeTestSettings(c)
	settings.FolderConfigs = capturedFolderConfigs
	sendConfigurationDidChange(t, loc, settings)

	// Verify no spurious overrides were created by the echo
	storedFolderConfig = requireStoredFolderConfig(t, c, folder)
	assert.Empty(t, storedFolderConfig.UserOverrides, "Echo-back should not create user overrides")
	assert.NotEmpty(t, storedFolderConfig.AutoDeterminedOrg, "AutoDeterminedOrg should remain set after echo-back")
}

// Test_SmokeLdxSync_GlobalSettingChange_PropagatesCorrectly verifies that global setting changes
// propagate correctly to the effective configuration without stale overrides blocking them.
// With the feature flag OFF, no user overrides are created so global changes always win.
func Test_SmokeLdxSync_GlobalSettingChange_PropagatesCorrectly(t *testing.T) {
	c, loc, jsonRpcRecorder := setupLdxSyncTest(t)
	c.SetLDXSyncSettingsEnabled(false)

	folder := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", loc, c)

	// Ensure SnykCode is disabled when the scan-state cleanup runs (LIFO: this runs before
	// waitForAllScansToComplete, keeping pre-existing NotStarted SnykCode states out of the
	// enabled-products filter).
	t.Cleanup(func() { c.SetSnykCodeEnabled(false) })

	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder: func(fc types.LspFolderConfig) {
			assert.NotNil(t, fc.AutoDeterminedOrg)
		},
	})

	storedFolderConfig := requireStoredFolderConfig(t, c, folder)
	assert.Empty(t, storedFolderConfig.UserOverrides, "No overrides should exist before any changes")

	// Send global setting change: disable SnykCode.
	// ScanningMode=manual prevents auto-scan from firing if products are re-enabled.
	settings := buildSmokeTestSettings(c)
	settings.ActivateSnykCode = "false"
	settings.ActivateSnykCodeSecurity = "false"
	settings.ScanningMode = "manual"
	sendConfigurationDidChange(t, loc, settings)

	// Verify the ConfigResolver reflects the change via global config source
	resolver := di.ConfigResolver()
	require.NotNil(t, resolver, "ConfigResolver should be available")
	storedFolderConfig = requireStoredFolderConfig(t, c, folder)
	assert.False(t, resolver.GetBool(types.SettingSnykCodeEnabled, storedFolderConfig), "ConfigResolver should return false for SnykCode after global disable")

	// Verify no user overrides were created as a side effect
	assert.Empty(t, storedFolderConfig.UserOverrides, "No overrides should exist after global setting change")

	// Re-enable SnykCode and verify no stale override blocks it.
	// ScanningMode=manual keeps auto-scan disabled so re-enabling does not invoke a scan.
	settings = buildSmokeTestSettings(c)
	settings.ActivateSnykCode = "true"
	settings.ActivateSnykCodeSecurity = "true"
	settings.ScanningMode = "manual"
	sendConfigurationDidChange(t, loc, settings)

	storedFolderConfig = requireStoredFolderConfig(t, c, folder)
	assert.True(t, resolver.GetBool(types.SettingSnykCodeEnabled, storedFolderConfig), "ConfigResolver should return true after re-enabling (no stale override blocking it)")
	assert.Empty(t, storedFolderConfig.UserOverrides, "Still no overrides after re-enabling")
}

// Test_SmokeLdxSync_NullableFieldsOnlyPresentForOverrides verifies that NullableFields are only sent
// to the IDE when the value comes from a user override or LDX-Sync source, not from global config.
func Test_SmokeLdxSync_NullableFieldsOnlyPresentForOverrides(t *testing.T) {
	c, loc, jsonRpcRecorder := setupLdxSyncTest(t)
	// Feature flag ON (enabled by setupLdxSyncTest)

	folder := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", loc, c)

	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder: func(fc types.LspFolderConfig) {
			// Fields set by LDX-Sync for ldxSyncTestOrg1: risk_score_threshold=400, enabled_severities=critical,high,medium
			require.True(t, fc.RiskScoreThreshold.HasValue(), "LDX-Sync riskScoreThreshold should be present in JSON")
			assert.Equal(t, 400, fc.RiskScoreThreshold.Get())
			require.True(t, fc.EnabledSeverities.HasValue(), "LDX-Sync enabledSeverities should be present in JSON")

			// Fields NOT in LDX-Sync org config for ldxSyncTestOrg1 → should NOT be sent to IDE
			assert.False(t, fc.SnykCodeEnabled.HasValue(), "Global-config-only field should not be sent to IDE")
			assert.False(t, fc.SnykOssEnabled.HasValue(), "Global-config-only field should not be sent to IDE")
			assert.False(t, fc.SnykIacEnabled.HasValue(), "Global-config-only field should not be sent to IDE")
			assert.False(t, fc.ScanAutomatic.HasValue(), "Global-config-only field should not be sent to IDE")
			assert.False(t, fc.IssueViewOpenIssues.HasValue(), "Global-config-only field should not be sent to IDE")
			assert.False(t, fc.IssueViewIgnoredIssues.HasValue(), "Global-config-only field should not be sent to IDE")
		},
	})
}

// Test_SmokeLdxSync_FeatureFlagOff_LDXSyncSettingsNotPropagated verifies that when the feature flag
// is OFF, no LDX-Sync settings are propagated to the IDE via NullableFields or machine settings.
func Test_SmokeLdxSync_FeatureFlagOff_LDXSyncSettingsNotPropagated(t *testing.T) {
	c, loc, jsonRpcRecorder := setupLdxSyncTest(t)
	c.SetLDXSyncSettingsEnabled(false)

	folder := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", loc, c)

	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder: func(fc types.LspFolderConfig) {
			// Basic fields are always sent regardless of feature flag
			assert.NotEmpty(t, fc.FolderPath, "folderPath should always be sent")
			assert.NotNil(t, fc.AutoDeterminedOrg, "autoDeterminedOrg should always be sent")

			// NullableFields should NOT be present when feature flag is OFF
			assert.False(t, fc.RiskScoreThreshold.HasValue(), "riskScoreThreshold should not be sent when feature flag is OFF")
			assert.False(t, fc.EnabledSeverities.HasValue(), "enabledSeverities should not be sent when feature flag is OFF")
			assert.False(t, fc.SnykCodeEnabled.HasValue(), "snykCodeEnabled should not be sent when feature flag is OFF")
			assert.False(t, fc.SnykOssEnabled.HasValue(), "snykOssEnabled should not be sent when feature flag is OFF")
			assert.False(t, fc.SnykIacEnabled.HasValue(), "snykIacEnabled should not be sent when feature flag is OFF")
			assert.False(t, fc.ScanAutomatic.HasValue(), "scanAutomatic should not be sent when feature flag is OFF")
		},
	})

	// Verify LDX-Sync machine settings were NOT applied to config
	// When feature flag is OFF, updateGlobalConfig is skipped so cliReleaseChannel stays unset
	assert.Empty(t, c.CliReleaseChannel(), "cliReleaseChannel should not be set from LDX-Sync when feature flag is OFF")
}
