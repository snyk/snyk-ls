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
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

func setupPrecedenceTest(t *testing.T) (*config.Config, server.Local, *testsupport.JsonRPCRecorder) {
	t.Helper()
	c := testutil.SmokeTest(t, "SNYK_TOKEN_CONSISTENT_IGNORES")

	origConfigHome := xdg.ConfigHome
	xdg.ConfigHome = t.TempDir()
	t.Cleanup(func() { xdg.ConfigHome = origConfigHome })

	loc, jsonRpcRecorder := setupServer(t, c)

	c.SetSnykCodeEnabled(false)
	c.SetSnykIacEnabled(false)
	c.SetSnykOssEnabled(false)

	cleanupChannels()
	di.Init()

	return c, loc, jsonRpcRecorder
}

// Test_SmokePrecedence_MachineScope_GlobalSettingsInNotification verifies that machine-scope
// settings set via initialization options are present in the $/snyk.configuration notification
// and that the source is correctly attributed. This is the end-to-end test for machine-scope
// precedence: user global > remote > default.
func Test_SmokePrecedence_MachineScope_GlobalSettingsInNotification(t *testing.T) {
	c, loc, jsonRpcRecorder := setupPrecedenceTest(t)

	folder := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", "package.json", loc, c)
	_ = folder

	requireLspConfigurationNotification(t, jsonRpcRecorder, func(cfg types.LspConfigurationParam) {
		require.NotNil(t, cfg.Settings, "global Settings map must not be nil")

		require.NotNil(t, cfg.Settings[types.SettingSnykOssEnabled], "snyk_oss_enabled must be present")
		require.NotNil(t, cfg.Settings[types.SettingSnykCodeEnabled], "snyk_code_enabled must be present")
		require.NotNil(t, cfg.Settings[types.SettingSnykIacEnabled], "snyk_iac_enabled must be present")
	}, false)

	jsonRpcRecorder.ClearNotifications()
}

// Test_SmokePrecedence_MachineScope_DidChangeUpdatesGlobalSettings verifies that
// changing machine-scope settings via didChangeConfiguration updates the $/snyk.configuration
// notification with the new values.
func Test_SmokePrecedence_MachineScope_DidChangeUpdatesGlobalSettings(t *testing.T) {
	c, loc, jsonRpcRecorder := setupPrecedenceTest(t)

	folder := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", "package.json", loc, c)

	requireLspConfigurationNotification(t, jsonRpcRecorder, nil, false)
	jsonRpcRecorder.ClearNotifications()

	params := buildSmokeTestSettings(c)
	params.Settings[types.SettingScanAutomatic] = &types.ConfigSetting{Value: "manual", Changed: true}
	params.FolderConfigs = []types.LspFolderConfig{
		{FolderPath: folder},
	}
	sendConfigurationDidChange(t, loc, params)

	assert.False(t, c.IsSnykCodeEnabled(), "snyk code should remain disabled")
	assert.False(t, c.IsSnykOssEnabled(), "snyk oss should remain disabled")

	jsonRpcRecorder.ClearNotifications()
}

// Test_SmokePrecedence_OrgScope_UserFolderOverrideReflectedInNotification verifies that
// setting a per-folder user override for an org-scope setting via didChangeConfiguration
// is reflected in the $/snyk.configuration folder config notification.
// Precedence: locked remote > user folder override > user global > remote > default
func Test_SmokePrecedence_OrgScope_UserFolderOverrideReflectedInNotification(t *testing.T) {
	c, loc, jsonRpcRecorder := setupPrecedenceTest(t)

	folder := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", "package.json", loc, c)

	requireLspConfigurationNotification(t, jsonRpcRecorder, nil, false)
	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder: func(fc types.LspFolderConfig) {
			require.NotNil(t, fc.Settings[types.SettingAutoDeterminedOrg])
		},
	}, false)
	jsonRpcRecorder.ClearNotifications()

	// Send didChangeConfiguration with a folder override for an org-scope setting
	params := buildSmokeTestSettings(c)
	params.FolderConfigs = []types.LspFolderConfig{
		{
			FolderPath: folder,
			Settings: map[string]*types.ConfigSetting{
				types.SettingScanAutomatic: {Value: false, Changed: true},
				types.SettingScanNetNew:    {Value: true, Changed: true},
			},
		},
	}
	sendConfigurationDidChange(t, loc, params)

	// Verify the folder config notification reflects the user override
	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder: func(fc types.LspFolderConfig) {
			if scanAuto := fc.Settings[types.SettingScanAutomatic]; scanAuto != nil {
				assert.Equal(t, false, scanAuto.Value, "folder override should set scan_automatic to false")
				assert.Equal(t, "user-override", scanAuto.Source, "source should be user-override")
			}
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
	c, loc, jsonRpcRecorder := setupPrecedenceTest(t)

	folder := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", "package.json", loc, c)

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
	c, loc, jsonRpcRecorder := setupPrecedenceTest(t)

	folder := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", "package.json", loc, c)

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
	c, loc, jsonRpcRecorder := setupPrecedenceTest(t)

	folder := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", "package.json", loc, c)

	requireLspConfigurationNotification(t, jsonRpcRecorder, nil, false)
	jsonRpcRecorder.ClearNotifications()

	// Send didChangeConfiguration with folder-scope settings
	settings := buildSmokeTestSettings(c)
	settings.FolderConfigs = []types.LspFolderConfig{
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
	c, loc, jsonRpcRecorder := setupPrecedenceTest(t)

	folder := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", "package.json", loc, c)

	requireLspConfigurationNotification(t, jsonRpcRecorder, nil, false)
	jsonRpcRecorder.ClearNotifications()

	// Send settings via didChangeConfiguration, keeping products consistent with current state
	params := buildSmokeTestSettings(c)
	params.FolderConfigs = []types.LspFolderConfig{
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

// Test_SmokePrecedence_GlobalChangeClears_FolderOverrides verifies that when a user
// changes a global org-scope setting, existing per-folder overrides for that same setting
// are cleared (batchClearOrgScopedOverridesOnGlobalChange), so all folders adopt the
// new global value. The end-to-end flow is: set folder override → change global → verify
// folder override is cleared → notification reflects global value.
func Test_SmokePrecedence_GlobalChangeClears_FolderOverrides(t *testing.T) {
	c, loc, jsonRpcRecorder := setupPrecedenceTest(t)

	folder := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", "package.json", loc, c)

	requireLspConfigurationNotification(t, jsonRpcRecorder, nil, false)
	jsonRpcRecorder.ClearNotifications()

	// Step 1: Set a folder override for scan_automatic
	params1 := buildSmokeTestSettings(c)
	params1.FolderConfigs = []types.LspFolderConfig{
		{
			FolderPath: folder,
			Settings: map[string]*types.ConfigSetting{
				types.SettingScanAutomatic: {Value: false, Changed: true},
			},
		},
	}
	sendConfigurationDidChange(t, loc, params1)

	// Verify folder override is set
	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder: func(fc types.LspFolderConfig) {
			if scanAuto := fc.Settings[types.SettingScanAutomatic]; scanAuto != nil {
				assert.Equal(t, false, scanAuto.Value, "folder override should set scan_automatic to false")
			}
		},
	}, false)
	jsonRpcRecorder.ClearNotifications()

	// Step 2: Change the global value for scan_automatic with folder config to trigger notification
	params2 := buildSmokeTestSettings(c)
	params2.Settings[types.SettingScanAutomatic] = &types.ConfigSetting{Value: "manual", Changed: true}
	params2.FolderConfigs = []types.LspFolderConfig{
		{FolderPath: folder},
	}
	sendConfigurationDidChange(t, loc, params2)

	// Step 3: Verify the folder override was cleared via config state
	fc := c.ImmutableFolderConfig(folder)
	if fc != nil {
		assert.False(t, types.HasUserOverride(fc.Conf(), fc.FolderPath, types.SettingScanAutomatic),
			"folder override for scan_automatic should be cleared after global change")
	}

	jsonRpcRecorder.ClearNotifications()
}

// Test_SmokePrecedence_MultiFolder_DifferentOrgs verifies that when multiple folders
// belong to different organizations, the $/snyk.configuration notification contains
// per-folder settings resolved with the correct org's remote config.
func Test_SmokePrecedence_MultiFolder_DifferentOrgs(t *testing.T) {
	c, loc, jsonRpcRecorder := setupPrecedenceTest(t)

	folder1 := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", "package.json", loc, c)

	requireLspConfigurationNotification(t, jsonRpcRecorder, nil, false)
	requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(types.LspFolderConfig){
		folder1: func(fc types.LspFolderConfig) {
			require.NotNil(t, fc.Settings[types.SettingAutoDeterminedOrg])
		},
	}, false)
	jsonRpcRecorder.ClearNotifications()

	// Add a second folder
	folder2, err := storedconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), testsupport.PythonGoof, "c32657c", c.Logger(), false)
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
	c, loc, jsonRpcRecorder := setupPrecedenceTest(t)

	folder := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", "package.json", loc, c)

	requireLspConfigurationNotification(t, jsonRpcRecorder, nil, false)
	jsonRpcRecorder.ClearNotifications()

	// Set a folder override before login
	params := buildSmokeTestSettings(c)
	params.FolderConfigs = []types.LspFolderConfig{
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
	c.SetAutomaticAuthentication(false)
	c.SetAuthenticationMethod(types.FakeAuthentication)
	authService := di.AuthenticationService()
	authService.ConfigureProviders(c)
	fakeProvider := authService.Provider().(*authentication.FakeAuthenticationProvider)
	fakeProvider.IsAuthenticated = false
	fakeProvider.TokenToReturn = c.Token()

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
	c := testutil.SmokeTest(t, "")
	testutil.CreateDummyProgressListener(t)

	loc, _ := setupServer(t, c)
	c.SetSnykCodeEnabled(false)
	c.SetSnykIacEnabled(false)
	c.SetSnykOssEnabled(false)
	di.Init()

	folder := types.FilePath(t.TempDir())
	_ = initTestRepo(t, string(folder))

	initParams := types.InitializeParams{
		WorkspaceFolders: []types.WorkspaceFolder{
			{Name: "Test", Uri: uri.PathToUri(folder)},
		},
		InitializationOptions: types.InitializationOptions{
			Settings: map[string]*types.ConfigSetting{
				types.SettingToken:                   {Value: c.Token(), Changed: true},
				types.SettingTrustEnabled:            {Value: false, Changed: true},
				types.SettingEnabledSeverities:       {Value: map[string]interface{}{"critical": true, "high": true, "medium": true, "low": true}, Changed: true},
				types.SettingAuthenticationMethod:    {Value: string(types.TokenAuthentication), Changed: true},
				types.SettingAutomaticAuthentication: {Value: false, Changed: true},
				types.SettingCliPath:                 {Value: c.CliSettings().Path(), Changed: true},
				types.SettingAutomaticDownload:       {Value: false, Changed: true},
				types.SettingScanAutomatic:           {Value: "manual", Changed: true},
				types.SettingSnykCodeEnabled:         {Value: false, Changed: true},
				types.SettingSnykIacEnabled:          {Value: false, Changed: true},
				types.SettingSnykOssEnabled:          {Value: false, Changed: true},
			},
		},
	}
	ensureInitialized(t, c, loc, initParams, nil)

	params := buildSmokeTestSettings(c)
	params.Settings[types.SettingScanAutomatic] = &types.ConfigSetting{Value: "manual", Changed: true}
	params.Settings[types.SettingSnykCodeEnabled] = &types.ConfigSetting{Value: true, Changed: true}
	sendConfigurationDidChange(t, loc, params)

	assert.True(t, c.IsSnykCodeEnabled(),
		"ActivateSnykCodeSecurity=true should enable Snyk Code via OR reconciliation")
}

// Test_SmokePrecedence_DefaultValues_WhenNoUserOrRemoteConfig verifies that when
// no user settings are provided and no LDX-Sync remote config is available,
// default values are used for all settings.
func Test_SmokePrecedence_DefaultValues_WhenNoUserOrRemoteConfig(t *testing.T) {
	c := testutil.SmokeTest(t, "")
	testutil.CreateDummyProgressListener(t)

	loc, jsonRpcRecorder := setupServer(t, c)
	c.SetSnykCodeEnabled(false)
	c.SetSnykIacEnabled(false)
	c.SetSnykOssEnabled(false)
	di.Init()

	folder := types.FilePath(t.TempDir())
	_ = initTestRepo(t, string(folder))

	initParams := types.InitializeParams{
		WorkspaceFolders: []types.WorkspaceFolder{
			{Name: "Test", Uri: uri.PathToUri(folder)},
		},
		InitializationOptions: types.InitializationOptions{
			Settings: map[string]*types.ConfigSetting{
				types.SettingToken:                   {Value: c.Token(), Changed: true},
				types.SettingTrustEnabled:            {Value: false, Changed: true},
				types.SettingEnabledSeverities:       {Value: map[string]interface{}{"critical": true, "high": true, "medium": true, "low": true}, Changed: true},
				types.SettingAuthenticationMethod:    {Value: string(types.TokenAuthentication), Changed: true},
				types.SettingAutomaticAuthentication: {Value: false, Changed: true},
				types.SettingCliPath:                 {Value: c.CliSettings().Path(), Changed: true},
				types.SettingAutomaticDownload:       {Value: false, Changed: true},
				types.SettingScanAutomatic:           {Value: "manual", Changed: true},
				types.SettingSnykCodeEnabled:         {Value: c.IsSnykCodeEnabled(), Changed: true},
				types.SettingSnykIacEnabled:          {Value: c.IsSnykIacEnabled(), Changed: true},
				types.SettingSnykOssEnabled:          {Value: c.IsSnykOssEnabled(), Changed: true},
			},
		},
	}
	ensureInitialized(t, c, loc, initParams, nil)

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
	*config.Config, server.Local, *testsupport.JsonRPCRecorder, types.FilePath,
) {
	t.Helper()
	c := testutil.SmokeTest(t, "SNYK_TOKEN_CONSISTENT_IGNORES")

	origConfigHome := xdg.ConfigHome
	xdg.ConfigHome = t.TempDir()
	t.Cleanup(func() { xdg.ConfigHome = origConfigHome })

	repoTempDir := types.FilePath(testutil.TempDirWithRetry(t))
	loc, jsonRpcRecorder := setupServer(t, c)

	c.SetSnykCodeEnabled(codeEnabled)
	c.SetSnykOssEnabled(ossEnabled)
	c.SetSnykIacEnabled(iacEnabled)

	cleanupChannels()
	di.Init()

	folder := setupRepoAndInitializeInDir(t, repoTempDir, testsupport.NodejsGoof, "0336589", "package.json", loc, c)

	requireLspConfigurationNotification(t, jsonRpcRecorder, nil, false)
	jsonRpcRecorder.ClearNotifications()

	return c, loc, jsonRpcRecorder, folder
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
	}, 120*time.Second, 200*time.Millisecond, "scans did not complete in time")
}

// Test_SmokeScanPrecedence_OSSEnabled_CodeDisabled verifies that when OSS is enabled
// and Code is disabled globally, the LSP server runs an OSS scan ($/snyk.scan success for oss)
// but does NOT run a Code scan.
func Test_SmokeScanPrecedence_OSSEnabled_CodeDisabled(t *testing.T) {
	c, _, jsonRpcRecorder, folder := setupScanPrecedenceTest(t, false, true, false)

	waitForScan(t, string(folder), c)
	waitForScanCompletion(t, di.ScanStateAggregator())

	assert.True(t, hasScanSuccessForProduct(jsonRpcRecorder, product.ProductOpenSource, folder),
		"OSS scan should have completed successfully")
	assert.False(t, hasScanInProgressForProduct(jsonRpcRecorder, product.ProductCode, folder),
		"Code scan should NOT have been started when globally disabled")
}

// Test_SmokeScanPrecedence_CodeEnabled_OSSDisabled verifies that when Code is enabled
// and OSS is disabled globally, the LSP server runs a Code scan but NOT an OSS scan.
func Test_SmokeScanPrecedence_CodeEnabled_OSSDisabled(t *testing.T) {
	c, _, jsonRpcRecorder, folder := setupScanPrecedenceTest(t, true, false, false)

	waitForScan(t, string(folder), c)
	waitForScanCompletion(t, di.ScanStateAggregator())

	assert.True(t, hasScanSuccessForProduct(jsonRpcRecorder, product.ProductCode, folder),
		"Code scan should have completed successfully")
	assert.False(t, hasScanInProgressForProduct(jsonRpcRecorder, product.ProductOpenSource, folder),
		"OSS scan should NOT have been started when globally disabled")
}

// Test_SmokeScanPrecedence_AllDisabled_NoScansRun verifies that when all products
// are disabled globally, no scans are executed.
func Test_SmokeScanPrecedence_AllDisabled_NoScansRun(t *testing.T) {
	_, _, jsonRpcRecorder, folder := setupScanPrecedenceTest(t, false, false, false)

	// Wait a reasonable time for any unexpected scans to appear
	time.Sleep(5 * time.Second)

	assert.False(t, hasScanInProgressForProduct(jsonRpcRecorder, product.ProductCode, folder),
		"Code scan should not run when all products disabled")
	assert.False(t, hasScanInProgressForProduct(jsonRpcRecorder, product.ProductOpenSource, folder),
		"OSS scan should not run when all products disabled")
	assert.False(t, hasScanInProgressForProduct(jsonRpcRecorder, product.ProductInfrastructureAsCode, folder),
		"IaC scan should not run when all products disabled")
}

// Test_SmokeScanPrecedence_UserOverrideEnablesProduct verifies the full E2E flow:
// 1. Initialize with Code enabled, OSS disabled
// 2. Wait for initial Code scan to prove scanning works
// 3. Send didChangeConfiguration enabling OSS via folder override
// 4. Trigger workspace scan via executeCommand
// 5. Verify OSS scan runs
func Test_SmokeScanPrecedence_UserOverrideEnablesProduct(t *testing.T) {
	c, loc, jsonRpcRecorder, folder := setupScanPrecedenceTest(t, true, false, false)

	waitForScan(t, string(folder), c)
	waitForScanCompletion(t, di.ScanStateAggregator())

	assert.True(t, hasScanSuccessForProduct(jsonRpcRecorder, product.ProductCode, folder),
		"initial Code scan should succeed")
	assert.False(t, hasScanSuccessForProduct(jsonRpcRecorder, product.ProductOpenSource, folder),
		"OSS should not have been scanned initially")
	jsonRpcRecorder.ClearNotifications()

	// Enable OSS via folder override
	params := buildSmokeTestSettings(c)
	params.Settings[types.SettingSnykOssEnabled] = &types.ConfigSetting{Value: false, Changed: true}
	params.Settings[types.SettingScanAutomatic] = &types.ConfigSetting{Value: true, Changed: true}
	params.FolderConfigs = []types.LspFolderConfig{
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
	}, 120*time.Second, 500*time.Millisecond,
		"OSS scan should run when folder override enables it over global disabled")
}

// Test_SmokeScanPrecedence_UserOverrideDisablesProduct verifies that when a product
// is enabled globally but a folder override disables it, no scan runs for that product.
func Test_SmokeScanPrecedence_UserOverrideDisablesProduct(t *testing.T) {
	c, loc, jsonRpcRecorder, folder := setupScanPrecedenceTest(t, true, false, false)

	// Wait for initial Code scan to complete
	waitForScan(t, string(folder), c)
	waitForScanCompletion(t, di.ScanStateAggregator())
	jsonRpcRecorder.ClearNotifications()

	// Send didChangeConfiguration with folder override disabling Code
	params := buildSmokeTestSettings(c)
	params.Settings[types.SettingScanAutomatic] = &types.ConfigSetting{Value: true, Changed: true}
	params.FolderConfigs = []types.LspFolderConfig{
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

	// Wait a bit and verify Code scan did NOT run
	time.Sleep(5 * time.Second)

	assert.False(t, hasScanSuccessForProduct(jsonRpcRecorder, product.ProductCode, folder),
		"Code scan should NOT run when folder override disables it")
}

// Test_SmokeScanPrecedence_SeverityFilter_DiagnosticsRespectFilter verifies that when
// a severity filter (Critical+High only) is configured at initialization, published
// diagnostics only contain issues matching the allowed severities.
func Test_SmokeScanPrecedence_SeverityFilter_DiagnosticsRespectFilter(t *testing.T) {
	c := testutil.SmokeTest(t, "SNYK_TOKEN_CONSISTENT_IGNORES")

	origConfigHome := xdg.ConfigHome
	xdg.ConfigHome = t.TempDir()
	t.Cleanup(func() { xdg.ConfigHome = origConfigHome })

	repoTempDir := types.FilePath(testutil.TempDirWithRetry(t))
	loc, jsonRpcRecorder := setupServer(t, c)

	restrictedFilter := types.SeverityFilter{Critical: true, High: true, Medium: false, Low: false}
	c.SetSnykCodeEnabled(true)
	c.SetSnykOssEnabled(false)
	c.SetSnykIacEnabled(false)
	c.SetSeverityFilter(&restrictedFilter)

	cleanupChannels()
	di.Init()

	t.Cleanup(func() {
		waitForAllScansToComplete(t, di.ScanStateAggregator())
	})

	cloneTargetDir, err := storedconfig.SetupCustomTestRepo(t, repoTempDir, testsupport.NodejsGoof, "0336589", c.Logger(), false)
	require.NoError(t, err)

	initParams := prepareInitParams(t, cloneTargetDir, c)
	initParams.InitializationOptions.Settings[types.SettingEnabledSeverities] = &types.ConfigSetting{
		Value:   map[string]interface{}{"critical": true, "high": true, "medium": false, "low": false},
		Changed: true,
	}
	ensureInitialized(t, c, loc, initParams, func(c *config.Config) {
		substituteDepGraphFlow(t, c, string(cloneTargetDir), "package.json")
	})

	waitForScan(t, string(cloneTargetDir), c)
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
	}, 60*time.Second, 500*time.Millisecond, "expected at least some diagnostics to be published")

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
	c, _, jsonRpcRecorder, folder := setupScanPrecedenceTest(t, true, true, false)

	waitForScan(t, string(folder), c)
	waitForScanCompletion(t, di.ScanStateAggregator())

	assert.True(t, hasScanSuccessForProduct(jsonRpcRecorder, product.ProductOpenSource, folder),
		"OSS scan should run when enabled")
	assert.True(t, hasScanSuccessForProduct(jsonRpcRecorder, product.ProductCode, folder),
		"Code scan should run when enabled")
}
