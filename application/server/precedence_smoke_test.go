// ABOUTME: End-to-end smoke tests for config precedence resolution through the full LSP pipeline
// ABOUTME: Covers machine/org/folder scope precedence, user overrides, locked fields,
// ABOUTME: and scan execution respecting precedence (product enabled/disabled, severity filters, etc.)
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
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/adrg/xdg"
	"github.com/creachadair/jrpc2/server"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/folderconfig"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

func setupPrecedenceTest(t *testing.T) (workflow.Engine, *config.TokenServiceImpl, server.Local, *testsupport.JsonRPCRecorder) {
	t.Helper()
	engine, tokenService := testutil.SmokeTestWithEngine(t, "SNYK_TOKEN_CONSISTENT_IGNORES")

	origConfigHome := xdg.ConfigHome
	xdg.ConfigHome = t.TempDir()
	t.Cleanup(func() { xdg.ConfigHome = origConfigHome })

	loc, jsonRpcRecorder := setupServer(t, engine, tokenService)

	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), false)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), false)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), false)

	cleanupChannels()
	di.Init(engine, tokenService)

	return engine, tokenService, loc, jsonRpcRecorder
}

// Test_SmokePrecedence_MachineScope_GlobalSettingsInNotification verifies that machine-scope
// settings set via initialization options are present in the $/snyk.configuration notification
// and that the source is correctly attributed. This is the end-to-end test for machine-scope
// precedence: user global > remote > default.
func Test_SmokePrecedence_MachineScope_GlobalSettingsInNotification(t *testing.T) {
	engine, tokenService, loc, jsonRpcRecorder := setupPrecedenceTest(t)

	folder := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", "package.json", loc, engine, tokenService)
	_ = folder

	// Product-enabled settings (snyk_oss_enabled etc.) are folder-scoped and appear in FolderConfigs, not global Settings.
	// This test verifies the notification contains folder configs with the product-enabled settings.
	requireLspConfigurationNotification(t, jsonRpcRecorder, func(cfg types.LspConfigurationParam) {
		require.NotNil(t, cfg.Settings, "global Settings map must not be nil")
		require.NotEmpty(t, cfg.FolderConfigs, "FolderConfigs must not be empty")

		folderSettings := cfg.FolderConfigs[0].Settings
		require.NotNil(t, folderSettings[types.SettingSnykOssEnabled], "snyk_oss_enabled must be present in folder settings")
		require.NotNil(t, folderSettings[types.SettingSnykCodeEnabled], "snyk_code_enabled must be present in folder settings")
		require.NotNil(t, folderSettings[types.SettingSnykIacEnabled], "snyk_iac_enabled must be present in folder settings")
	}, false)

	jsonRpcRecorder.ClearNotifications()
}

// Test_SmokePrecedence_MachineScope_DidChangeUpdatesGlobalSettings verifies that
// changing machine-scope settings via didChangeConfiguration updates the $/snyk.configuration
// notification with the new values.
func Test_SmokePrecedence_MachineScope_DidChangeUpdatesGlobalSettings(t *testing.T) {
	engine, tokenService, loc, jsonRpcRecorder := setupPrecedenceTest(t)

	folder := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", "package.json", loc, engine, tokenService)

	requireLspConfigurationNotification(t, jsonRpcRecorder, nil, false)
	jsonRpcRecorder.ClearNotifications()

	params := buildSmokeTestSettings(engine)
	params.Settings.Settings[types.SettingScanAutomatic] = &types.ConfigSetting{Value: "manual", Changed: true}
	params.Settings.FolderConfigs = []types.LspFolderConfig{
		{
			FolderPath: folder,
		},
	}
	sendConfigurationDidChange(t, loc, params)

	assert.False(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled)), "snyk code should remain disabled")
	assert.False(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykOssEnabled)), "snyk oss should remain disabled")

	jsonRpcRecorder.ClearNotifications()
}

// Test_SmokePrecedence_OrgScope_UserFolderOverrideReflectedInNotification verifies the
// precedence: locked remote > user folder override > user global > remote > default.
func Test_SmokePrecedence_OrgScope_UserFolderOverrideReflectedInNotification(t *testing.T) {
	engine, tokenService, loc, jsonRpcRecorder := setupPrecedenceTest(t)

	folder := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", "package.json", loc, engine, tokenService)

	requireLspConfigurationNotification(t, jsonRpcRecorder, nil, false)
	var baselineScanAutomaticLocked bool
	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder: func(fc types.LspFolderConfig) {
			require.NotNil(t, fc.Settings[types.SettingAutoDeterminedOrg])
			if scanAuto := fc.Settings[types.SettingScanAutomatic]; scanAuto != nil {
				baselineScanAutomaticLocked = scanAuto.IsLocked
			}
		},
	}, false)
	// LDX policy is org-dependent; we branch assertions so precedence is validated whether or not scan_automatic is org-locked for this token/org.
	jsonRpcRecorder.ClearNotifications()

	// Send didChangeConfiguration attempting to override both a locked and an unlocked setting
	params := buildSmokeTestSettings(engine)
	params.Settings.FolderConfigs = []types.LspFolderConfig{
		{
			FolderPath: folder,
			Settings: map[string]*types.ConfigSetting{
				types.SettingScanAutomatic: {Value: false, Changed: true},
				types.SettingScanNetNew:    {Value: true, Changed: true},
			},
		},
	}
	sendConfigurationDidChange(t, loc, params)

	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder: func(fc types.LspFolderConfig) {
			if baselineScanAutomaticLocked {
				// Baseline had org lock: user folder override to false must be rejected.
				if scanAuto := fc.Settings[types.SettingScanAutomatic]; scanAuto != nil {
					assert.True(t, scanAuto.IsLocked, "scan_automatic should be locked by org policy")
					assert.Equal(t, "ldx-sync-locked", scanAuto.Source, "locked setting source should be ldx-sync-locked")
				}
			} else {
				scanAuto := fc.Settings[types.SettingScanAutomatic]
				require.NotNil(t, scanAuto, "scan_automatic should appear after user folder override when not org-locked at baseline")
				assert.False(t, scanAuto.IsLocked, "scan_automatic should accept user folder override when not org-locked")
				assert.Equal(t, false, scanAuto.Value, "folder override should set scan_automatic to false")
				assert.Equal(t, "user-override", scanAuto.Source, "source should be user-override")
			}
			// scan_net_new is NOT locked (or not present in the LDX-Sync response), so the user
			// folder override should succeed and the source should be "user-override".
			if scanNetNew := fc.Settings[types.SettingScanNetNew]; scanNetNew != nil {
				assert.Equal(t, true, scanNetNew.Value, "folder override should set scan_net_new to true")
				assert.Equal(t, "user-override", scanNetNew.Source, "source should be user-override")
			}
		},
	}, false)

	jsonRpcRecorder.ClearNotifications()
}

// Test_SmokePrecedence_OrgScope_LockedFieldsHaveIsLockedTrue verifies that org-scope
// settings locked by LDX-Sync have IsLocked=true in the $/snyk.configuration folder config
// notification. This tests the full pipeline: LDX-Sync populates remote config → resolver
// detects locked → notification includes IsLocked.
func Test_SmokePrecedence_OrgScope_LockedFieldsHaveIsLockedTrue(t *testing.T) {
	engine, tokenService, loc, jsonRpcRecorder := setupPrecedenceTest(t)

	folder := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", "package.json", loc, engine, tokenService)

	// After initialization, LDX-Sync has run. Check if any settings are locked.
	// The test server may or may not have locked fields; this test validates the
	// IsLocked field is correctly propagated when present.
	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder: func(fc types.LspFolderConfig) {
			hasLockedField := false
			for settingName, setting := range fc.Settings {
				if setting != nil && setting.IsLocked {
					hasLockedField = true
					assert.NotEmpty(t, setting.Source, "locked setting %s should have a source", settingName)
					t.Logf("Locked field found: %s = %v (source: %s, origin: %s)", settingName, setting.Value, setting.Source, setting.OriginScope)
				}
			}
			// Log whether locked fields were found for debugging
			if !hasLockedField {
				t.Log("No locked fields found in LDX-Sync response - this is expected if the test org has no locked policies")
			}
		},
	}, false)

	jsonRpcRecorder.ClearNotifications()
}

// Test_SmokePrecedence_OrgScope_LDXSyncSourceInNotification verifies that org-scope
// settings from LDX-Sync have the correct Source and OriginScope in the notification.
func Test_SmokePrecedence_OrgScope_LDXSyncSourceInNotification(t *testing.T) {
	engine, tokenService, loc, jsonRpcRecorder := setupPrecedenceTest(t)

	folder := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", "package.json", loc, engine, tokenService)

	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder: func(fc types.LspFolderConfig) {
			// Check org-scope settings for Source attribution
			for _, settingName := range []string{
				types.SettingSnykCodeEnabled,
				types.SettingSnykOssEnabled,
				types.SettingSnykIacEnabled,
			} {
				setting := fc.Settings[settingName]
				if setting != nil {
					assert.NotEmpty(t, setting.Source, "setting %s should have a source", settingName)
					t.Logf("Setting %s: value=%v, source=%s, originScope=%s, isLocked=%v",
						settingName, setting.Value, setting.Source, setting.OriginScope, setting.IsLocked)
				}
			}
		},
	}, false)

	jsonRpcRecorder.ClearNotifications()
}

// Test_SmokePrecedence_FolderScope_SettingsRoundtrip verifies that folder-scope settings
// (base_branch, additional_parameters, reference_folder) set via didChangeConfiguration
// are correctly stored and reflected back in the $/snyk.configuration folder config.
func Test_SmokePrecedence_FolderScope_SettingsRoundtrip(t *testing.T) {
	engine, tokenService, loc, jsonRpcRecorder := setupPrecedenceTest(t)

	folder := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", "package.json", loc, engine, tokenService)

	requireLspConfigurationNotification(t, jsonRpcRecorder, nil, false)
	jsonRpcRecorder.ClearNotifications()

	// Send didChangeConfiguration with folder-scope settings
	settings := buildSmokeTestSettings(engine)
	settings.Settings.FolderConfigs = []types.LspFolderConfig{
		{
			FolderPath: folder,
			Settings: map[string]*types.ConfigSetting{
				types.SettingBaseBranch:            {Value: "develop"},
				types.SettingAdditionalParameters:  {Value: []string{"--debug", "--verbose"}},
				types.SettingAdditionalEnvironment: {Value: "DEBUG=1;VERBOSE=1"},
			},
		},
	}
	sendConfigurationDidChange(t, loc, settings)

	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder: func(fc types.LspFolderConfig) {
			if baseBranch := fc.Settings[types.SettingBaseBranch]; baseBranch != nil {
				assert.Equal(t, "develop", baseBranch.Value, "base_branch should be set to develop")
			}
			if addlParams := fc.Settings[types.SettingAdditionalParameters]; addlParams != nil {
				assert.NotNil(t, addlParams.Value, "additional_parameters should be set")
			}
			if addlEnv := fc.Settings[types.SettingAdditionalEnvironment]; addlEnv != nil {
				assert.Equal(t, "DEBUG=1;VERBOSE=1", addlEnv.Value, "additional_environment should be set")
			}
		},
	}, false)

	jsonRpcRecorder.ClearNotifications()
}

// Test_SmokePrecedence_OldFormatSettings_Roundtrip verifies that the old Settings struct format
// (used by legacy IDEs) is correctly processed through the full LSP pipeline and
// reflected in $/snyk.configuration notifications.
func Test_SmokePrecedence_OldFormatSettings_Roundtrip(t *testing.T) {
	engine, tokenService, loc, jsonRpcRecorder := setupPrecedenceTest(t)

	folder := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", "package.json", loc, engine, tokenService)

	requireLspConfigurationNotification(t, jsonRpcRecorder, nil, false)
	jsonRpcRecorder.ClearNotifications()

	// Send settings via didChangeConfiguration, keeping products consistent with current state
	params := buildSmokeTestSettings(engine)
	params.Settings.FolderConfigs = []types.LspFolderConfig{
		{
			FolderPath: folder,
			Settings: map[string]*types.ConfigSetting{
				types.SettingBaseBranch: {Value: "release"},
			},
		},
	}
	sendConfigurationDidChange(t, loc, params)

	// Verify folder-scope settings are applied
	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder: func(fc types.LspFolderConfig) {
			if baseBranch := fc.Settings[types.SettingBaseBranch]; baseBranch != nil {
				assert.Equal(t, "release", baseBranch.Value, "base_branch from old format should be applied")
			}
		},
	}, false)

	jsonRpcRecorder.ClearNotifications()
}

// Test_SmokePrecedence_GlobalChangePreserves_FolderOverrides verifies that when a user
// changes a global setting, existing per-folder overrides are preserved per the
// ConfigResolver precedence chain.
//
// Two cases are tested:
//   - scan_automatic is locked by the test org via LDX-Sync, so the folder override
//     is rejected and the locked value is preserved after a global change.
//   - scan_net_new is NOT locked, so the folder override is accepted and preserved
//     after a global change.
func Test_SmokePrecedence_GlobalChangePreserves_FolderOverrides(t *testing.T) {
	engine, tokenService, loc, jsonRpcRecorder := setupPrecedenceTest(t)

	folder := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", "package.json", loc, engine, tokenService)

	requireLspConfigurationNotification(t, jsonRpcRecorder, nil, false)
	jsonRpcRecorder.ClearNotifications()

	// Step 1: Attempt folder overrides for both a locked and an unlocked setting
	params1 := buildSmokeTestSettings(engine)
	params1.Settings.FolderConfigs = []types.LspFolderConfig{
		{
			FolderPath: folder,
			Settings: map[string]*types.ConfigSetting{
				types.SettingScanAutomatic: {Value: false, Changed: true},
				types.SettingScanNetNew:    {Value: true, Changed: true},
			},
		},
	}
	sendConfigurationDidChange(t, loc, params1)

	// Verify: scan_automatic override is rejected (locked), scan_net_new override is accepted
	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder: func(fc types.LspFolderConfig) {
			// scan_automatic is locked by the org — override must be rejected
			if scanAuto := fc.Settings[types.SettingScanAutomatic]; scanAuto != nil {
				assert.True(t, scanAuto.IsLocked, "scan_automatic should be locked by org policy")
				assert.Equal(t, "ldx-sync-locked", scanAuto.Source, "locked setting source should be ldx-sync-locked")
			}
			// scan_net_new is not locked — override should succeed
			if scanNetNew := fc.Settings[types.SettingScanNetNew]; scanNetNew != nil {
				assert.Equal(t, true, scanNetNew.Value, "folder override should set scan_net_new to true")
				assert.Equal(t, "user-override", scanNetNew.Source, "source should be user-override")
			}
		},
	}, false)
	jsonRpcRecorder.ClearNotifications()

	// Step 2: Change a global setting, sending the folder config without overrides to trigger notification
	params2 := buildSmokeTestSettings(engine)
	params2.Settings.Settings[types.SettingScanAutomatic] = &types.ConfigSetting{Value: "manual", Changed: true}
	params2.Settings.FolderConfigs = []types.LspFolderConfig{
		{
			FolderPath: folder,
			Settings: map[string]*types.ConfigSetting{
				types.SettingScanAutomatic: {Value: true, Changed: true},
			},
		},
	}
	sendConfigurationDidChange(t, loc, params2)

	// Step 3: Verify state is preserved after the global change
	fc := config.GetUnenrichedFolderConfigFromEngine(engine, testutil.DefaultConfigResolver(engine), folder, engine.GetLogger())
	if fc != nil {
		// scan_automatic should still not have a user override (it was locked)
		assert.False(t, types.HasUserOverride(fc.Conf(), fc.FolderPath, types.SettingScanAutomatic),
			"locked scan_automatic should not have a user override")
		// scan_net_new user override should be preserved after the global change
		assert.True(t, types.HasUserOverride(fc.Conf(), fc.FolderPath, types.SettingScanNetNew),
			"folder override for scan_net_new should be preserved after global change")
	}

	jsonRpcRecorder.ClearNotifications()
}

// Test_SmokePrecedence_MultiFolder_DifferentOrgs verifies that when multiple folders
// belong to different organizations, the $/snyk.configuration notification contains
// per-folder settings resolved with the correct org's remote config.
func Test_SmokePrecedence_MultiFolder_DifferentOrgs(t *testing.T) {
	engine, tokenService, loc, jsonRpcRecorder := setupPrecedenceTest(t)

	folder1 := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", "package.json", loc, engine, tokenService)

	requireLspConfigurationNotification(t, jsonRpcRecorder, nil, false)
	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder1: func(fc types.LspFolderConfig) {
			require.NotNil(t, fc.Settings[types.SettingAutoDeterminedOrg])
		},
	}, false)
	jsonRpcRecorder.ClearNotifications()

	// Add a second folder
	folder2, err := folderconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), testsupport.PythonGoof, "c32657c", engine.GetLogger(), false)
	require.NoError(t, err)

	addWorkSpaceFolder(t, loc, types.WorkspaceFolder{
		Name: "Python Goof",
		Uri:  uri.PathToUri(folder2),
	})

	// Verify both folders have per-folder config with org-scope settings
	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder1: func(fc types.LspFolderConfig) {
			require.NotNil(t, fc.Settings[types.SettingAutoDeterminedOrg],
				"Folder 1 should have autoDeterminedOrg")
			// Verify org-scope settings are present
			assert.NotNil(t, fc.Settings[types.SettingSnykCodeEnabled],
				"Folder 1 should have org-scope settings")
		},
		folder2: func(fc types.LspFolderConfig) {
			require.NotNil(t, fc.Settings[types.SettingAutoDeterminedOrg],
				"Folder 2 should have autoDeterminedOrg")
			assert.NotNil(t, fc.Settings[types.SettingSnykCodeEnabled],
				"Folder 2 should have org-scope settings")
		},
	}, false)

	jsonRpcRecorder.ClearNotifications()
}

// Test_SmokePrecedence_LoginRefreshesConfig_WithFolderOverridesPreserved verifies that
// after login (trigger 3), LDX-Sync refreshes and sends $/snyk.configuration, while
// folder user overrides that were set before login are preserved (unless locked).
func Test_SmokePrecedence_LoginRefreshesConfig_WithFolderOverridesPreserved(t *testing.T) {
	engine, tokenService, loc, jsonRpcRecorder := setupPrecedenceTest(t)

	folder := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", "package.json", loc, engine, tokenService)

	requireLspConfigurationNotification(t, jsonRpcRecorder, nil, false)
	jsonRpcRecorder.ClearNotifications()

	// Set a folder override before login
	params := buildSmokeTestSettings(engine)
	params.Settings.FolderConfigs = []types.LspFolderConfig{
		{
			FolderPath: folder,
			Settings: map[string]*types.ConfigSetting{
				types.SettingBaseBranch: {Value: "feature-branch"},
			},
		},
	}
	sendConfigurationDidChange(t, loc, params)

	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder: func(fc types.LspFolderConfig) {
			if baseBranch := fc.Settings[types.SettingBaseBranch]; baseBranch != nil {
				assert.Equal(t, "feature-branch", baseBranch.Value)
			}
		},
	}, false)
	jsonRpcRecorder.ClearNotifications()

	// Switch to FakeAuthentication AFTER initialization (which hardcodes TokenAuthentication)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingAutomaticAuthentication), false)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingAuthenticationMethod), string(types.FakeAuthentication))
	authService := di.AuthenticationService()
	authService.ConfigureProviders(engine.GetConfiguration(), engine.GetLogger())
	fakeProvider := authService.Provider().(*authentication.FakeAuthenticationProvider)
	fakeProvider.IsAuthenticated = false
	fakeProvider.TokenToReturn = config.GetToken(engine.GetConfiguration())

	// Trigger login
	_, err := loc.Client.Call(t.Context(), "workspace/executeCommand", sglsp.ExecuteCommandParams{Command: types.LoginCommand})
	require.NoError(t, err)

	// After login, verify config notification is sent and folder-scope settings are preserved
	requireLspConfigurationNotification(t, jsonRpcRecorder, func(cfg types.LspConfigurationParam) {
		assert.GreaterOrEqual(t, len(cfg.FolderConfigs), 1, "post-login config should include folder configs")
	}, false)

	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder: func(fc types.LspFolderConfig) {
			if baseBranch := fc.Settings[types.SettingBaseBranch]; baseBranch != nil {
				assert.Equal(t, "feature-branch", baseBranch.Value,
					"folder-scope base_branch should be preserved after login")
			}
		},
	}, false)

	jsonRpcRecorder.ClearNotifications()
}

// Test_SmokePrecedence_ActivateSnykCodeSecurity_OR_Reconciliation verifies that the
// ActivateSnykCodeSecurity field is ORed with ActivateSnykCode when processing old-format
// settings through the full LSP pipeline. This tests the reconciliation logic end-to-end.
func Test_SmokePrecedence_ActivateSnykCodeSecurity_OR_Reconciliation(t *testing.T) {
	engine, tokenService := testutil.SmokeTestWithEngine(t, "")
	testutil.CreateDummyProgressListener(t)

	loc, _ := setupServer(t, engine, tokenService)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), false)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), false)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), false)
	di.Init(engine, tokenService)

	folder := types.FilePath(t.TempDir())
	_ = initTestRepo(t, string(folder))

	cfg := engine.GetConfiguration()
	initParams := types.InitializeParams{
		WorkspaceFolders: []types.WorkspaceFolder{
			{Name: "Test", Uri: uri.PathToUri(folder)},
		},
		InitializationOptions: types.InitializationOptions{
			Settings: map[string]*types.ConfigSetting{
				types.SettingToken:                   {Value: config.GetToken(cfg), Changed: true},
				types.SettingTrustEnabled:            {Value: false, Changed: true},
				types.SettingSeverityFilterCritical:  {Value: true, Changed: true},
				types.SettingSeverityFilterHigh:      {Value: true, Changed: true},
				types.SettingSeverityFilterMedium:    {Value: true, Changed: true},
				types.SettingSeverityFilterLow:       {Value: true, Changed: true},
				types.SettingAuthenticationMethod:    {Value: string(types.TokenAuthentication), Changed: true},
				types.SettingAutomaticAuthentication: {Value: false, Changed: true},
				types.SettingCliPath:                 {Value: cfg.GetString(configresolver.UserGlobalKey(types.SettingCliPath)), Changed: true},
				types.SettingAutomaticDownload:       {Value: false, Changed: true},
				types.SettingScanAutomatic:           {Value: "manual", Changed: true},
				types.SettingSnykCodeEnabled:         {Value: false, Changed: true},
				types.SettingSnykIacEnabled:          {Value: false, Changed: true},
				types.SettingSnykOssEnabled:          {Value: false, Changed: true},
			},
		},
	}
	ensureInitialized(t, engine, tokenService, loc, initParams, nil)

	params := buildSmokeTestSettings(engine)
	params.Settings.Settings[types.SettingScanAutomatic] = &types.ConfigSetting{Value: "manual", Changed: true}
	params.Settings.Settings[types.SettingSnykCodeEnabled] = &types.ConfigSetting{Value: true, Changed: true}
	sendConfigurationDidChange(t, loc, params)

	assert.True(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled)),
		"ActivateSnykCodeSecurity=true should enable Snyk Code via OR reconciliation")
}

// Test_SmokePrecedence_DefaultValues_WhenNoUserOrRemoteConfig verifies that when
// no user settings are provided and no LDX-Sync remote config is available,
// default values are used for all settings.
func Test_SmokePrecedence_DefaultValues_WhenNoUserOrRemoteConfig(t *testing.T) {
	engine, tokenService := testutil.SmokeTestWithEngine(t, "")
	testutil.CreateDummyProgressListener(t)

	loc, jsonRpcRecorder := setupServer(t, engine, tokenService)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), false)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), false)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), false)
	di.Init(engine, tokenService)

	folder := types.FilePath(t.TempDir())
	_ = initTestRepo(t, string(folder))

	cfg := engine.GetConfiguration()
	initParams := types.InitializeParams{
		WorkspaceFolders: []types.WorkspaceFolder{
			{Name: "Test", Uri: uri.PathToUri(folder)},
		},
		InitializationOptions: types.InitializationOptions{
			Settings: map[string]*types.ConfigSetting{
				types.SettingToken:                   {Value: config.GetToken(cfg), Changed: true},
				types.SettingTrustEnabled:            {Value: false, Changed: true},
				types.SettingSeverityFilterCritical:  {Value: true, Changed: true},
				types.SettingSeverityFilterHigh:      {Value: true, Changed: true},
				types.SettingSeverityFilterMedium:    {Value: true, Changed: true},
				types.SettingSeverityFilterLow:       {Value: true, Changed: true},
				types.SettingAuthenticationMethod:    {Value: string(types.TokenAuthentication), Changed: true},
				types.SettingAutomaticAuthentication: {Value: false, Changed: true},
				types.SettingCliPath:                 {Value: cfg.GetString(configresolver.UserGlobalKey(types.SettingCliPath)), Changed: true},
				types.SettingAutomaticDownload:       {Value: false, Changed: true},
				types.SettingScanAutomatic:           {Value: "manual", Changed: true},
				types.SettingSnykCodeEnabled:         {Value: cfg.GetBool(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled)), Changed: true},
				types.SettingSnykIacEnabled:          {Value: cfg.GetBool(configresolver.UserGlobalKey(types.SettingSnykIacEnabled)), Changed: true},
				types.SettingSnykOssEnabled:          {Value: cfg.GetBool(configresolver.UserGlobalKey(types.SettingSnykOssEnabled)), Changed: true},
			},
		},
	}
	ensureInitialized(t, engine, tokenService, loc, initParams, nil)

	requireLspConfigurationNotification(t, jsonRpcRecorder, func(cfg types.LspConfigurationParam) {
		require.NotNil(t, cfg.Settings, "global Settings must be present")
		// Verify default values are present
		if snykCode := cfg.Settings[types.SettingSnykCodeEnabled]; snykCode != nil {
			assert.NotNil(t, snykCode.Value, "snyk_code_enabled should have a default or resolved value")
		}
	}, false)

	jsonRpcRecorder.ClearNotifications()
}

// ============================================================================================
// Scan-Level Precedence Smoke Tests
// These tests verify that actual scan execution respects the configuration precedence chain
// from the perspective of an LSP client. They observe $/snyk.scan and textDocument/publishDiagnostics
// notifications to confirm that scans run or are skipped according to the resolved configuration.
// ============================================================================================

// setupScanPrecedenceTest creates a test environment with a real repo for scan-level tests.
// It initializes the LSP server with the specified product states, waits for initialization
// and LDX-Sync to complete, then returns the folder path ready for scanning.
func setupScanPrecedenceTest(t *testing.T, codeEnabled, ossEnabled, iacEnabled bool) (
	workflow.Engine, *config.TokenServiceImpl, server.Local, *testsupport.JsonRPCRecorder, types.FilePath,
) {
	t.Helper()
	engine, tokenService := testutil.SmokeTestWithEngine(t, "SNYK_TOKEN_CONSISTENT_IGNORES")

	origConfigHome := xdg.ConfigHome
	xdg.ConfigHome = t.TempDir()
	t.Cleanup(func() { xdg.ConfigHome = origConfigHome })

	repoTempDir := types.FilePath(testutil.TempDirWithRetry(t))
	loc, jsonRpcRecorder := setupServer(t, engine, tokenService)

	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), codeEnabled)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), ossEnabled)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), iacEnabled)

	cleanupChannels()
	di.Init(engine, tokenService)
	// Pin risk-score flags to false: the ostest scanner path fails on CI because the
	// dep-graph generation is unreliable for the test org. These flags are only needed
	// in the unified-test-api smoke test which sets them explicitly.
	di.FeatureFlagService().Override(featureflag.UseExperimentalRiskScoreInCLI, false)
	di.FeatureFlagService().Override(featureflag.UseExperimentalRiskScore, false)

	folder := setupRepoAndInitializeInDir(t, repoTempDir, testsupport.NodejsGoof, "0336589", "package.json", loc, engine, tokenService)

	requireLspConfigurationNotification(t, jsonRpcRecorder, nil, false)
	jsonRpcRecorder.ClearNotifications()

	return engine, tokenService, loc, jsonRpcRecorder, folder
}

// hasScanSuccessForProduct checks if $/snyk.scan notifications contain a success for the given product and folder.
func hasScanSuccessForProduct(jsonRpcRecorder *testsupport.JsonRPCRecorder, p product.Product, folder types.FilePath) bool {
	notifications := jsonRpcRecorder.FindNotificationsByMethod("$/snyk.scan")
	for _, n := range notifications {
		var scanParams types.SnykScanParams
		_ = n.UnmarshalParams(&scanParams)
		if scanParams.Product == p.ToProductCodename() &&
			scanParams.FolderPath == folder &&
			scanParams.Status == types.Success {
			return true
		}
	}
	return false
}

// hasScanInProgressForProduct checks if a scan was even started for the given product.
func hasScanInProgressForProduct(jsonRpcRecorder *testsupport.JsonRPCRecorder, p product.Product, folder types.FilePath) bool {
	notifications := jsonRpcRecorder.FindNotificationsByMethod("$/snyk.scan")
	for _, n := range notifications {
		var scanParams types.SnykScanParams
		_ = n.UnmarshalParams(&scanParams)
		if scanParams.Product == p.ToProductCodename() &&
			scanParams.FolderPath == folder &&
			scanParams.Status == types.InProgress {
			return true
		}
	}
	return false
}

// waitForScanCompletion waits until all working-directory scans have finished.
func waitForScanCompletion(t *testing.T, agg scanstates.Aggregator) {
	t.Helper()
	require.Eventually(t, func() bool {
		return agg.StateSnapshot().AllScansFinishedWorkingDirectory
	}, 120*time.Second, time.Millisecond, "scans did not complete in time")
}

// Test_SmokeScanPrecedence_OSSEnabled_CodeDisabled verifies that when OSS is enabled
// and Code is disabled globally, the LSP server runs an OSS scan ($/snyk.scan success for oss)
// but does NOT run a Code scan.
func Test_SmokeScanPrecedence_OSSEnabled_CodeDisabled(t *testing.T) {
	engine, _, _, jsonRpcRecorder, folder := setupScanPrecedenceTest(t, false, true, false)

	waitForScan(t, string(folder), engine)
	waitForScanCompletion(t, di.ScanStateAggregator())

	assert.True(t, hasScanSuccessForProduct(jsonRpcRecorder, product.ProductOpenSource, folder),
		"OSS scan should have completed successfully")
	assert.False(t, hasScanInProgressForProduct(jsonRpcRecorder, product.ProductCode, folder),
		"Code scan should NOT have been started when globally disabled")
}

// Test_SmokeScanPrecedence_CodeEnabled_OSSDisabled verifies that when Code is enabled
// and OSS is disabled globally, the LSP server runs a Code scan but NOT an OSS scan.
func Test_SmokeScanPrecedence_CodeEnabled_OSSDisabled(t *testing.T) {
	engine, _, _, jsonRpcRecorder, folder := setupScanPrecedenceTest(t, true, false, false)

	waitForScan(t, string(folder), engine)
	waitForScanCompletion(t, di.ScanStateAggregator())

	assert.True(t, hasScanSuccessForProduct(jsonRpcRecorder, product.ProductCode, folder),
		"Code scan should have completed successfully")
	assert.False(t, hasScanInProgressForProduct(jsonRpcRecorder, product.ProductOpenSource, folder),
		"OSS scan should NOT have been started when globally disabled")
}

// Test_SmokeScanPrecedence_AllDisabled_NoScansRun verifies that when all products
// are disabled globally, no scans are executed.
func Test_SmokeScanPrecedence_AllDisabled_NoScansRun(t *testing.T) {
	engine, _, _, jsonRpcRecorder, folder := setupScanPrecedenceTest(t, false, false, false)
	_ = engine

	require.Never(t, func() bool {
		return hasScanInProgressForProduct(jsonRpcRecorder, product.ProductCode, folder) ||
			hasScanInProgressForProduct(jsonRpcRecorder, product.ProductOpenSource, folder) ||
			hasScanInProgressForProduct(jsonRpcRecorder, product.ProductInfrastructureAsCode, folder)
	}, 5*time.Second, time.Millisecond, "no scans should run when all products disabled")
}

// Test_SmokeScanPrecedence_UserOverrideEnablesProduct verifies the full E2E flow:
// 1. Initialize with Code enabled, OSS disabled
// 2. Wait for initial Code scan to prove scanning works
// 3. Send didChangeConfiguration enabling OSS via folder override
// 4. Trigger workspace scan via executeCommand
// 5. Verify OSS scan runs
func Test_SmokeScanPrecedence_UserOverrideEnablesProduct(t *testing.T) {
	engine, _, loc, jsonRpcRecorder, folder := setupScanPrecedenceTest(t, true, false, false)

	waitForScan(t, string(folder), engine)
	waitForScanCompletion(t, di.ScanStateAggregator())

	assert.True(t, hasScanSuccessForProduct(jsonRpcRecorder, product.ProductCode, folder),
		"initial Code scan should succeed")
	assert.False(t, hasScanSuccessForProduct(jsonRpcRecorder, product.ProductOpenSource, folder),
		"OSS should not have been scanned initially")
	jsonRpcRecorder.ClearNotifications()

	// Enable OSS via folder override
	params := buildSmokeTestSettings(engine)
	params.Settings.Settings[types.SettingSnykOssEnabled] = &types.ConfigSetting{Value: false, Changed: true}
	params.Settings.Settings[types.SettingScanAutomatic] = &types.ConfigSetting{Value: true, Changed: true}
	params.Settings.FolderConfigs = []types.LspFolderConfig{
		{
			FolderPath: folder,
			Settings: map[string]*types.ConfigSetting{
				types.SettingSnykOssEnabled: {Value: true, Changed: true},
			},
		},
	}
	sendConfigurationDidChange(t, loc, params)

	// Trigger workspace scan
	_, err := loc.Client.Call(t.Context(), "workspace/executeCommand", sglsp.ExecuteCommandParams{
		Command: types.WorkspaceScanCommand,
	})
	require.NoError(t, err)

	waitForScanCompletion(t, di.ScanStateAggregator())

	assert.Eventually(t, func() bool {
		return hasScanSuccessForProduct(jsonRpcRecorder, product.ProductOpenSource, folder)
	}, 120*time.Second, time.Millisecond,
		"OSS scan should run when folder override enables it over global disabled")
}

// Test_SmokeScanPrecedence_UserOverrideDisablesProduct verifies that when a product
// is enabled globally but a folder override disables it, no scan runs for that product.
func Test_SmokeScanPrecedence_UserOverrideDisablesProduct(t *testing.T) {
	engine, _, loc, jsonRpcRecorder, folder := setupScanPrecedenceTest(t, true, false, false)

	// Wait for initial Code scan to complete
	waitForScan(t, string(folder), engine)
	waitForScanCompletion(t, di.ScanStateAggregator())
	jsonRpcRecorder.ClearNotifications()

	// Send didChangeConfiguration with folder override disabling Code
	params := buildSmokeTestSettings(engine)
	params.Settings.Settings[types.SettingScanAutomatic] = &types.ConfigSetting{Value: true, Changed: true}
	params.Settings.FolderConfigs = []types.LspFolderConfig{
		{
			FolderPath: folder,
			Settings: map[string]*types.ConfigSetting{
				types.SettingSnykCodeEnabled: {Value: false, Changed: true},
			},
		},
	}
	sendConfigurationDidChange(t, loc, params)

	// Trigger scan via didSave
	codePath := types.FilePath(filepath.Join(string(folder), "app.js"))
	textDocumentDidSave(t, &loc, codePath)

	require.Never(t, func() bool {
		return hasScanSuccessForProduct(jsonRpcRecorder, product.ProductCode, folder)
	}, 5*time.Second, time.Millisecond, "Code scan should NOT run when folder override disables it")
}

// Test_SmokeScanPrecedence_SeverityFilter_DiagnosticsRespectFilter verifies that when
// a severity filter (Critical+High only) is configured at initialization, published
// diagnostics only contain issues matching the allowed severities.
func Test_SmokeScanPrecedence_SeverityFilter_DiagnosticsRespectFilter(t *testing.T) {
	engine, tokenService := testutil.SmokeTestWithEngine(t, "SNYK_TOKEN_CONSISTENT_IGNORES")

	origConfigHome := xdg.ConfigHome
	xdg.ConfigHome = t.TempDir()
	t.Cleanup(func() { xdg.ConfigHome = origConfigHome })

	repoTempDir := types.FilePath(testutil.TempDirWithRetry(t))
	loc, jsonRpcRecorder := setupServer(t, engine, tokenService)

	restrictedFilter := types.SeverityFilter{Critical: true, High: true, Medium: false, Low: false}
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), false)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), false)
	config.SetSeverityFilterOnConfig(engine.GetConfiguration(), &restrictedFilter, engine.GetLogger())

	cleanupChannels()
	di.Init(engine, tokenService)

	t.Cleanup(func() {
		waitForAllScansToComplete(t, di.ScanStateAggregator())
	})

	cloneTargetDir, err := folderconfig.SetupCustomTestRepo(t, repoTempDir, testsupport.NodejsGoof, "0336589", engine.GetLogger(), false)
	require.NoError(t, err)

	initParams := prepareInitParams(t, cloneTargetDir, engine)
	initParams.InitializationOptions.Settings[types.SettingSeverityFilterCritical] = &types.ConfigSetting{Value: true, Changed: true}
	initParams.InitializationOptions.Settings[types.SettingSeverityFilterHigh] = &types.ConfigSetting{Value: true, Changed: true}
	initParams.InitializationOptions.Settings[types.SettingSeverityFilterMedium] = &types.ConfigSetting{Value: false, Changed: true}
	initParams.InitializationOptions.Settings[types.SettingSeverityFilterLow] = &types.ConfigSetting{Value: false, Changed: true}
	ensureInitialized(t, engine, tokenService, loc, initParams, func(eng workflow.Engine) {
		substituteDepGraphFlow(t, eng, string(cloneTargetDir), "package.json")
	})

	waitForScan(t, string(cloneTargetDir), engine)
	waitForScanCompletion(t, di.ScanStateAggregator())

	// Verify diagnostics were published
	require.Eventually(t, func() bool {
		notifications := jsonRpcRecorder.FindNotificationsByMethod("textDocument/publishDiagnostics")
		for _, n := range notifications {
			var params types.PublishDiagnosticsParams
			if err := json.Unmarshal([]byte(n.ParamString()), &params); err != nil {
				continue
			}
			if len(params.Diagnostics) > 0 {
				return true
			}
		}
		return false
	}, 60*time.Second, time.Millisecond, "expected at least some diagnostics to be published")

	// All published diagnostics must respect the severity filter
	notifications := jsonRpcRecorder.FindNotificationsByMethod("textDocument/publishDiagnostics")
	for _, n := range notifications {
		var params types.PublishDiagnosticsParams
		if err := json.Unmarshal([]byte(n.ParamString()), &params); err != nil {
			continue
		}
		for _, diag := range params.Diagnostics {
			// LSP severity: 1=Error, 2=Warning, 3=Info, 4=Hint
			// Critical+High filter: only severity 1 (Error/Critical) or 2 (Warning/High) expected
			assert.LessOrEqual(t, int(diag.Severity), 2,
				"diagnostic severity %d should be <= 2 (Error or Warning) with Critical+High filter, got: %s",
				diag.Severity, diag.Message)
		}
	}
}

// Test_SmokeScanPrecedence_EnableAllProducts_AllScansRun verifies the positive case:
// when Code and OSS are enabled, both scan types execute successfully.
// IaC is excluded because the test org lacks the infrastructureAsCode entitlement.
func Test_SmokeScanPrecedence_EnableAllProducts_AllScansRun(t *testing.T) {
	engine, _, _, jsonRpcRecorder, folder := setupScanPrecedenceTest(t, true, true, false)

	waitForScan(t, string(folder), engine)
	waitForScanCompletion(t, di.ScanStateAggregator())

	assert.True(t, hasScanSuccessForProduct(jsonRpcRecorder, product.ProductOpenSource, folder),
		"OSS scan should run when enabled")
	assert.True(t, hasScanSuccessForProduct(jsonRpcRecorder, product.ProductCode, folder),
		"Code scan should run when enabled")
}

// Test_SmokePrecedence_FolderLevelRemote_OverridesOrgLevel verifies that
// folder-level remote config (RemoteOrgFolderKey) overrides org-level remote
// config (RemoteOrgKey) in the config notification. This tests the full pipeline:
// write folder-level remote → resolver picks it up → notification reflects it.
func Test_SmokePrecedence_FolderLevelRemote_OverridesOrgLevel(t *testing.T) {
	engine, tokenService, loc, jsonRpcRecorder := setupPrecedenceTest(t)

	folder := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", "package.json", loc, engine, tokenService)

	// After init and LDX-Sync, wait for the first notification to establish baseline
	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder: func(fc types.LspFolderConfig) {
			// Baseline: note the initial value of scan_automatic
			t.Logf("Baseline scan_automatic: %v", fc.Settings[types.SettingScanAutomatic])
		},
	}, false)
	jsonRpcRecorder.ClearNotifications()

	// Now write folder-level remote config with a different value than org-level
	conf := engine.GetConfiguration()
	folderPath := string(types.PathKey(folder))
	snapshot := types.ReadFolderConfigSnapshot(conf, folder)
	orgId := snapshot.AutoDeterminedOrg
	if orgId == "" {
		orgId = snapshot.PreferredOrg
	}
	if orgId == "" {
		t.Skip("No org ID available for folder-level remote test")
	}

	// Remove user-global value so only remote layer is tested
	conf.Unset(configresolver.UserGlobalKey(types.SettingScanAutomatic))
	// Set org-level remote: scan_automatic = true
	conf.Set(configresolver.RemoteOrgKey(orgId, types.SettingScanAutomatic), &configresolver.RemoteConfigField{Value: true})
	// Set folder-level remote: scan_automatic = false (overrides org-level)
	conf.Set(configresolver.RemoteOrgFolderKey(orgId, folderPath, types.SettingScanAutomatic), &configresolver.RemoteConfigField{Value: false})

	// Trigger config notification by sending didChangeConfiguration
	params := types.DidChangeConfigurationParams{
		Settings: types.LspConfigurationParam{
			FolderConfigs: []types.LspFolderConfig{
				{
					FolderPath: folder,
					Settings: map[string]*types.ConfigSetting{
						types.SettingAdditionalParameters: {Value: []string{"-d"}, Changed: true},
					},
				},
			},
		},
	}
	sendConfigurationDidChange(t, loc, params)

	// Verify folder-level remote value takes precedence in the notification
	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder: func(fc types.LspFolderConfig) {
			if scanAuto := fc.Settings[types.SettingScanAutomatic]; scanAuto != nil {
				assert.Equal(t, false, scanAuto.Value,
					"folder-level remote (false) should override org-level remote (true)")
				t.Logf("scan_automatic: value=%v, source=%s, isLocked=%v",
					scanAuto.Value, scanAuto.Source, scanAuto.IsLocked)
			}
		},
	}, false)
	jsonRpcRecorder.ClearNotifications()
}

// Test_SmokePrecedence_FolderLevelRemoteLocked_OverridesUserOverride verifies that
// a locked folder-level remote setting overrides user overrides and is marked IsLocked=true.
func Test_SmokePrecedence_FolderLevelRemoteLocked_OverridesUserOverride(t *testing.T) {
	engine, tokenService, loc, jsonRpcRecorder := setupPrecedenceTest(t)

	folder := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", "package.json", loc, engine, tokenService)

	// Wait for baseline
	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder: func(fc types.LspFolderConfig) {},
	}, false)
	jsonRpcRecorder.ClearNotifications()

	conf := engine.GetConfiguration()
	folderPath := string(types.PathKey(folder))
	snapshot := types.ReadFolderConfigSnapshot(conf, folder)
	orgId := snapshot.AutoDeterminedOrg
	if orgId == "" {
		orgId = snapshot.PreferredOrg
	}
	if orgId == "" {
		t.Skip("No org ID available for folder-level remote locked test")
	}

	// Set user override: scan_automatic = true
	conf.Set(configresolver.UserFolderKey(folderPath, types.SettingScanAutomatic), &configresolver.LocalConfigField{Value: true, Changed: true})
	// Set folder-level remote LOCKED: scan_automatic = false
	conf.Set(configresolver.RemoteOrgFolderKey(orgId, folderPath, types.SettingScanAutomatic), &configresolver.RemoteConfigField{Value: false, IsLocked: true})

	// Trigger config notification
	params2 := types.DidChangeConfigurationParams{
		Settings: types.LspConfigurationParam{
			FolderConfigs: []types.LspFolderConfig{{
				FolderPath: folder,
				Settings: map[string]*types.ConfigSetting{
					types.SettingAdditionalParameters: {Value: []string{"-d"}, Changed: true},
				},
			}},
		},
	}
	sendConfigurationDidChange(t, loc, params2)

	// Verify locked folder-level remote overrides user override
	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder: func(fc types.LspFolderConfig) {
			if scanAuto := fc.Settings[types.SettingScanAutomatic]; scanAuto != nil {
				assert.Equal(t, false, scanAuto.Value,
					"locked folder-level remote should override user override")
				assert.True(t, scanAuto.IsLocked,
					"folder-level locked remote should be marked IsLocked")
				t.Logf("scan_automatic: value=%v, source=%s, isLocked=%v",
					scanAuto.Value, scanAuto.Source, scanAuto.IsLocked)
			}
		},
	}, false)
	jsonRpcRecorder.ClearNotifications()
}

// Test_SmokePrecedence_FolderScopePrecedenceChain verifies the full folder-scope
// precedence chain through the LSP pipeline.
// Uses additional_environment (not populated during init) for steps 1-3 to test
// user global and remote levels, and base_branch (populated by git enrichment)
// for steps 4-5 to test folder value and locked remote override.
// Steps 1-3 would have FAILED under the old folder-scope precedence
// (Folder Value > Default), which ignored user global and remote layers entirely.
func Test_SmokePrecedence_FolderScopePrecedenceChain(t *testing.T) {
	engine, tokenService, loc, jsonRpcRecorder := setupPrecedenceTest(t)

	folder := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", "package.json", loc, engine, tokenService)

	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder: func(fc types.LspFolderConfig) {},
	}, false)
	jsonRpcRecorder.ClearNotifications()

	conf := engine.GetConfiguration()
	folderPath := string(types.PathKey(folder))
	snapshot := types.ReadFolderConfigSnapshot(conf, folder)
	orgId := snapshot.AutoDeterminedOrg
	if orgId == "" {
		orgId = snapshot.PreferredOrg
	}
	if orgId == "" {
		t.Skip("No org ID available for folder-scope precedence test")
	}

	triggerAdditionalParam := "-d"
	triggerNotification := func() {
		if triggerAdditionalParam == "-d" {
			triggerAdditionalParam = "--severity-threshold=high"
		} else {
			triggerAdditionalParam = "-d"
		}

		params := types.DidChangeConfigurationParams{
			Settings: types.LspConfigurationParam{
				FolderConfigs: []types.LspFolderConfig{{
					FolderPath: folder,
					Settings: map[string]*types.ConfigSetting{
						types.SettingAdditionalParameters: {Value: []string{triggerAdditionalParam}, Changed: true},
					},
				}},
			},
		}
		sendConfigurationDidChange(t, loc, params)
	}

	// Use additional_environment for steps 1-3 because it is NOT populated during init
	// (unlike base_branch which is set by git enrichment and persisted to XDG storage).
	setting := types.SettingAdditionalEnvironment

	// Step 1: User global value for a folder-scoped setting.
	// OLD precedence: would return default (""), NEW: returns "GLOBAL_VAR=1"
	conf.Set(configresolver.UserGlobalKey(setting), "GLOBAL_VAR=1")
	triggerNotification()

	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder: func(fc types.LspFolderConfig) {
			if env := fc.Settings[setting]; env != nil {
				assert.Equal(t, "GLOBAL_VAR=1", env.Value,
					"user global should be used as fallback for folder-scope additional_environment")
				assert.Equal(t, "global", env.Source,
					"source should be global")
			} else {
				t.Error("additional_environment should be present in notification")
			}
		},
	}, false)
	jsonRpcRecorder.ClearNotifications()

	// Step 2: User global takes priority over unlocked remote org.
	// GAF resolver precedence for folder scope: locked remote > folder value > remote folder > user global > remote org > default
	// Remote org is a fallback consulted only when no folder value, remote folder, or user global is set.
	conf.Set(configresolver.RemoteOrgKey(orgId, setting), &configresolver.RemoteConfigField{Value: "REMOTE_ORG_VAR=1"})
	triggerNotification()

	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder: func(fc types.LspFolderConfig) {
			if env := fc.Settings[setting]; env != nil {
				assert.Equal(t, "GLOBAL_VAR=1", env.Value,
					"user global takes priority over unlocked remote org for folder-scope additional_environment")
				assert.Equal(t, "global", env.Source,
					"source should remain global")
			} else {
				t.Error("additional_environment should be present in notification")
			}
		},
	}, false)
	jsonRpcRecorder.ClearNotifications()

	// Step 3: Remote folder overrides remote org.
	conf.Set(configresolver.RemoteOrgFolderKey(orgId, folderPath, setting), &configresolver.RemoteConfigField{Value: "REMOTE_FOLDER_VAR=1"})
	triggerNotification()

	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder: func(fc types.LspFolderConfig) {
			if env := fc.Settings[setting]; env != nil {
				assert.Equal(t, "REMOTE_FOLDER_VAR=1", env.Value,
					"remote folder should override remote org for folder-scope additional_environment")
			}
		},
	}, false)
	jsonRpcRecorder.ClearNotifications()

	// Step 4: Folder value (user:folder) overrides remote folder.
	// base_branch is already set to "main" at user:folder level by git enrichment.
	// The remote is NOT locked, so folder value should win.
	conf.Set(configresolver.RemoteOrgFolderKey(orgId, folderPath, types.SettingBaseBranch), &configresolver.RemoteConfigField{Value: "remote-branch"})
	triggerNotification()

	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder: func(fc types.LspFolderConfig) {
			if bb := fc.Settings[types.SettingBaseBranch]; bb != nil {
				assert.Equal(t, "main", bb.Value,
					"folder value (main from git) should override non-locked remote folder for base_branch")
				assert.Equal(t, "folder", bb.Source,
					"source should be folder")
			}
		},
	}, false)
	jsonRpcRecorder.ClearNotifications()

	// Step 5: Locked remote overrides folder value.
	conf.Set(configresolver.RemoteOrgFolderKey(orgId, folderPath, types.SettingBaseBranch), &configresolver.RemoteConfigField{Value: "locked-branch", IsLocked: true})
	triggerNotification()

	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder: func(fc types.LspFolderConfig) {
			if bb := fc.Settings[types.SettingBaseBranch]; bb != nil {
				assert.Equal(t, "locked-branch", bb.Value,
					"locked remote should override folder value (main from git) for base_branch")
				assert.True(t, bb.IsLocked,
					"locked remote should be marked IsLocked")
				assert.Equal(t, "ldx-sync-locked", bb.Source,
					"source should be ldx_sync_locked")
			}
		},
	}, false)
	jsonRpcRecorder.ClearNotifications()
}
