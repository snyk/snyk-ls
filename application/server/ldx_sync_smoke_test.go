// ABOUTME: Smoke tests for LdxSyncService cache population and refresh behavior
// ABOUTME: Tests verify cache correctly populated on initialize, folder changes, login, and config updates
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
	require.Equal(t, 1, len(notifications), "Expected exactly one $/snyk.configuration notification")

	var param types.LspConfigurationParam
	require.NoError(t, notifications[0].UnmarshalParams(&param))

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

	// TODO populate ldxsync that way, so this folder will override global config values -> update checks below
	requireLspConfigurationNotification(t, jsonRpcRecorder, func(cfg types.LspConfigurationParam) {
		assert.NotEmpty(t, cfg.ActivateSnykOpenSource)
		assert.NotEmpty(t, cfg.ActivateSnykCode)
		assert.NotEmpty(t, cfg.ActivateSnykIac)
		assert.NotEmpty(t, cfg.Organization)
	}, false)

	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder: func(fc types.LspFolderConfig) {
			require.NotNil(t, fc.AutoDeterminedOrg, "Folder should have autoDeterminedOrg set")
			assert.NotEmpty(t, *fc.AutoDeterminedOrg, "Folder should have autoDeterminedOrg from LDX-Sync cache")
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
	}, false)

	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder1: func(fc types.LspFolderConfig) {
			require.NotNil(t, fc.AutoDeterminedOrg, "Folder 1 should have autoDeterminedOrg set")
			assert.NotEmpty(t, *fc.AutoDeterminedOrg, "Folder 1 should have autoDeterminedOrg from LDX-Sync cache")
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

	// TODO populate ldxsync that way, so this folder will override global config values (different from first folder) -> update checks below
	requireLspConfigurationNotification(t, jsonRpcRecorder, func(cfg types.LspConfigurationParam) {
		assert.NotEmpty(t, cfg.ActivateSnykOpenSource)
		assert.NotEmpty(t, cfg.ActivateSnykCode)
		assert.NotEmpty(t, cfg.ActivateSnykIac)
		assert.NotEmpty(t, cfg.Organization)
	}, false)

	// TODO populate ldxsync that way, so this folder will override folder config values (different from first folder) -> update checks below
	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder1: func(fc types.LspFolderConfig) {
			require.NotNil(t, fc.AutoDeterminedOrg, "Folder 1 should have autoDeterminedOrg set")
			assert.NotEmpty(t, *fc.AutoDeterminedOrg, "Folder 1 should still have autoDeterminedOrg")
		},
		folder2: func(fc types.LspFolderConfig) {
			require.NotNil(t, fc.AutoDeterminedOrg, "Folder 2 should have autoDeterminedOrg set")
			assert.NotEmpty(t, *fc.AutoDeterminedOrg, "Folder 2 should have autoDeterminedOrg from LDX-Sync cache")
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
	}, false)

	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder: func(fc types.LspFolderConfig) {
			require.NotNil(t, fc.AutoDeterminedOrg, "Folder 2 should have autoDeterminedOrg set")
			assert.NotEmpty(t, *fc.AutoDeterminedOrg, "Folder 2 should have autoDeterminedOrg from LDX-Sync cache")
		},
	}, false)

	jsonRpcRecorder.ClearNotifications()

	// Change PreferredOrg via didChangeConfiguration to trigger LDX-Sync refresh
	sendModifiedStoredFolderConfiguration(t, c, loc, func(folderConfigs map[types.FilePath]*types.FolderConfig) {
		folderConfig := folderConfigs[folder]
		folderConfig.OrgSetByUser = true
		if folderConfig.AutoDeterminedOrg == "b1a01686-331c-4b59-854c-139216d56bb0" {
			folderConfig.PreferredOrg = "code-consistent-ignores-early-access-verification"
		} else {
			folderConfig.PreferredOrg = "ide-risk-score-testing"
		}
	})

	// Changing PreferredOrg triggers LDX-Sync refresh which may update global configuration
	// TODO Skipped until LDX-Sync config is populated on the test server for the changed org. Remove the if false wrapper when it is populated.
	if false {
		requireLspConfigurationNotification(t, jsonRpcRecorder, func(cfg types.LspConfigurationParam) {
			assert.NotEmpty(t, cfg.ActivateSnykOpenSource)
			assert.NotEmpty(t, cfg.ActivateSnykCode)
			assert.NotEmpty(t, cfg.ActivateSnykIac)
			assert.NotEmpty(t, cfg.Organization)
		}, false)
	}

	// TODO Changing PreferredOrg triggers LDX-Sync refresh which may update folder configuration (setup ldx sync for this org that way)
	// Changing PreferredOrg triggers LDX-Sync refresh which may update folder configuration
	// TODO Skipped until LDX-Sync config is populated on the test server for the changed org. Remove the if false wrapper when it is populated.
	if false {
		requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
			folder: func(fc types.LspFolderConfig) {
				require.NotNil(t, fc.AutoDeterminedOrg, "Folder should have autoDeterminedOrg set")
				assert.NotEmpty(t, *fc.AutoDeterminedOrg, "Folder should have autoDeterminedOrg after config change")
			},
		}, false)
	}

	jsonRpcRecorder.ClearNotifications()
}
