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
			assert.Equal(t, 400, fc.RiskScoreThreshold.Value, "RiskScoreThreshold should be 400 from org config")
			require.True(t, fc.EnabledSeverities.HasValue(), "EnabledSeverities should have value from org config")
			assert.Equal(t, types.SeverityFilter{Critical: true, High: true, Medium: true, Low: false}, fc.EnabledSeverities.Value)
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
			assert.Equal(t, 400, fc.RiskScoreThreshold.Value, "RiskScoreThreshold should be 400 from org config")
			require.True(t, fc.EnabledSeverities.HasValue(), "EnabledSeverities should have value from org config")
			assert.Equal(t, types.SeverityFilter{Critical: true, High: true, Medium: true, Low: false}, fc.EnabledSeverities.Value)
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
			assert.Equal(t, 400, fc.RiskScoreThreshold.Value, "Folder 1 should have risk_score_threshold=400")
			require.True(t, fc.EnabledSeverities.HasValue(), "Folder 1 EnabledSeverities should have value")
			assert.Equal(t, types.SeverityFilter{Critical: true, High: true, Medium: true, Low: false}, fc.EnabledSeverities.Value)
		},
		folder2: func(fc types.LspFolderConfig) {
			require.NotNil(t, fc.AutoDeterminedOrg, "Folder 2 should have autoDeterminedOrg set")
			assert.NotEmpty(t, *fc.AutoDeterminedOrg, "Folder 2 should have autoDeterminedOrg from LDX-Sync cache")

			// Check org-scope settings from second org (different values)
			require.True(t, fc.RiskScoreThreshold.HasValue(), "Folder 2 RiskScoreThreshold should have value")
			assert.Equal(t, 600, fc.RiskScoreThreshold.Value, "Folder 2 should have risk_score_threshold=600 from second org")
			require.True(t, fc.EnabledSeverities.HasValue(), "Folder 2 EnabledSeverities should have value")
			assert.Equal(t, types.SeverityFilter{Critical: true, High: true, Medium: false, Low: false}, fc.EnabledSeverities.Value, "Folder 2 should have only critical and high from second org")
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
			assert.Equal(t, 400, fc.RiskScoreThreshold.Value, "RiskScoreThreshold should be 400 from first org")
			require.True(t, fc.EnabledSeverities.HasValue(), "EnabledSeverities should have value from org config")
			assert.Equal(t, types.SeverityFilter{Critical: true, High: true, Medium: true, Low: false}, fc.EnabledSeverities.Value)
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
			assert.Equal(t, 600, fc.RiskScoreThreshold.Value, "RiskScoreThreshold should be 600 from second org")
			require.True(t, fc.EnabledSeverities.HasValue(), "EnabledSeverities should have value from new org")
			assert.Equal(t, types.SeverityFilter{Critical: true, High: true, Medium: false, Low: false}, fc.EnabledSeverities.Value, "Should have only critical and high from second org")
		},
	}, false)

	jsonRpcRecorder.ClearNotifications()
}
