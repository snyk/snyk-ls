/*
 * © 2022-2026 Snyk Limited All rights reserved.
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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

const htmlRefreshTimeout = 5 * time.Second
const htmlRefreshTick = time.Millisecond

func Test_RefreshHtmlSettings_OnAuthentication(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder, _ := setupServer(t, engine, tokenService)

	_, err := loc.Client.Call(t.Context(), "initialize", nil)
	require.NoError(t, err)
	engine.GetConfiguration().Set(types.SettingIsLspInitialized, true)

	// Trigger auth via the real auth service so that updateCredentials fires the notification.
	// UpdateCredentials(token, sendNotification=true, updateApiUrl=false) is the same path
	// taken when a real authentication completes.
	di.AuthenticationService().UpdateCredentials("integ-test-token", true, false)

	assert.Eventually(
		t,
		func() bool {
			return len(jsonRPCRecorder.FindNotificationsByMethod(types.SnykRefreshHtmlSettings)) > 0
		},
		htmlRefreshTimeout,
		htmlRefreshTick,
		"expected $/snyk.refreshHtmlSettings notification after authentication",
	)
}

func Test_RefreshHtmlSettings_OnFolderAdded(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder, _ := setupServer(t, engine, tokenService)

	_, err := loc.Client.Call(t.Context(), "initialize", nil)
	require.NoError(t, err)
	engine.GetConfiguration().Set(types.SettingIsLspInitialized, true)

	params := types.DidChangeWorkspaceFoldersParams{
		Event: types.WorkspaceFoldersChangeEvent{
			Added: []types.WorkspaceFolder{
				{Name: "added-folder", Uri: uri.PathToUri(types.FilePath(t.TempDir()))},
			},
		},
	}
	_, err = loc.Client.Call(t.Context(), "workspace/didChangeWorkspaceFolders", params)
	require.NoError(t, err)

	assert.Eventually(
		t,
		func() bool {
			return len(jsonRPCRecorder.FindNotificationsByMethod(types.SnykRefreshHtmlSettings)) > 0
		},
		htmlRefreshTimeout,
		htmlRefreshTick,
		"expected $/snyk.refreshHtmlSettings notification after folder added",
	)
}

func Test_RefreshHtmlSettings_OnFolderRemoved(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder, _ := setupServer(t, engine, tokenService)

	// Initialize with a folder so we can remove it
	folderPath := types.FilePath(t.TempDir())
	_, err := loc.Client.Call(t.Context(), "initialize", types.InitializeParams{
		WorkspaceFolders: []types.WorkspaceFolder{
			{Name: "existing-folder", Uri: uri.PathToUri(folderPath)},
		},
	})
	require.NoError(t, err)
	engine.GetConfiguration().Set(types.SettingIsLspInitialized, true)

	params := types.DidChangeWorkspaceFoldersParams{
		Event: types.WorkspaceFoldersChangeEvent{
			Removed: []types.WorkspaceFolder{
				{Name: "existing-folder", Uri: uri.PathToUri(folderPath)},
			},
		},
	}
	_, err = loc.Client.Call(t.Context(), "workspace/didChangeWorkspaceFolders", params)
	require.NoError(t, err)

	assert.Eventually(
		t,
		func() bool {
			return len(jsonRPCRecorder.FindNotificationsByMethod(types.SnykRefreshHtmlSettings)) > 0
		},
		htmlRefreshTimeout,
		htmlRefreshTick,
		"expected $/snyk.refreshHtmlSettings notification after folder removed",
	)
}

func Test_RefreshHtmlSettings_OnOrgChange_SentAfterFolderProcessing(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder, _ := setupServer(t, engine, tokenService)

	_, err := loc.Client.Call(t.Context(), "initialize", nil)
	require.NoError(t, err)
	engine.GetConfiguration().Set(types.SettingIsLspInitialized, true)

	params := types.DidChangeConfigurationParams{
		Settings: types.LspConfigurationParam{
			Settings: map[string]*types.ConfigSetting{
				types.SettingOrganization: {Value: "new-test-org", Changed: true},
			},
		},
	}
	_, err = loc.Client.Call(t.Context(), "workspace/didChangeConfiguration", params)
	require.NoError(t, err)

	// Notification must be sent exactly once — not before folder processing, not twice.
	assert.Eventually(
		t,
		func() bool {
			return len(jsonRPCRecorder.FindNotificationsByMethod(types.SnykRefreshHtmlSettings)) == 1
		},
		htmlRefreshTimeout,
		htmlRefreshTick,
		"expected exactly one $/snyk.refreshHtmlSettings notification after org change",
	)
}

func Test_RefreshHtmlSettings_OnTokenChange(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder, _ := setupServer(t, engine, tokenService)

	_, err := loc.Client.Call(t.Context(), "initialize", nil)
	require.NoError(t, err)
	engine.GetConfiguration().Set(types.SettingIsLspInitialized, true)

	params := types.DidChangeConfigurationParams{
		Settings: types.LspConfigurationParam{
			Settings: map[string]*types.ConfigSetting{
				types.SettingToken: {Value: "new-test-token", Changed: true},
			},
		},
	}
	_, err = loc.Client.Call(t.Context(), "workspace/didChangeConfiguration", params)
	require.NoError(t, err)

	assert.Eventually(
		t,
		func() bool {
			return len(jsonRPCRecorder.FindNotificationsByMethod(types.SnykRefreshHtmlSettings)) > 0
		},
		htmlRefreshTimeout,
		htmlRefreshTick,
		"expected $/snyk.refreshHtmlSettings notification after token change",
	)
}

func Test_RefreshHtmlSettings_NotSentDuringInitialize(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder, _ := setupServer(t, engine, tokenService)
	t.Cleanup(func() {
		engine.GetConfiguration().Set(types.SettingIsLspInitialized, true)
		types.SignalLspInitialized(engine.GetConfiguration())
	})

	// Do NOT set SettingIsLspInitialized — it starts false
	params := types.DidChangeConfigurationParams{
		Settings: types.LspConfigurationParam{
			Settings: map[string]*types.ConfigSetting{
				types.SettingOrganization: {Value: "some-org", Changed: true},
			},
		},
	}
	_, err := loc.Client.Call(t.Context(), "workspace/didChangeConfiguration", params)
	require.NoError(t, err)

	// Also try folder change while not initialized
	folderParams := types.DidChangeWorkspaceFoldersParams{
		Event: types.WorkspaceFoldersChangeEvent{
			Added: []types.WorkspaceFolder{
				{Name: "folder", Uri: uri.PathToUri(types.FilePath(t.TempDir()))},
			},
		},
	}
	_, err = loc.Client.Call(t.Context(), "workspace/didChangeWorkspaceFolders", folderParams)
	require.NoError(t, err)

	assert.Never(
		t,
		func() bool {
			return len(jsonRPCRecorder.FindNotificationsByMethod(types.SnykRefreshHtmlSettings)) > 0
		},
		300*time.Millisecond,
		htmlRefreshTick,
		"$/snyk.refreshHtmlSettings must not be sent before LSP is initialized",
	)
}

func Test_RefreshHtmlSettings_ExactlyOneNotificationOnCombinedTokenAndOrgChange(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder, _ := setupServer(t, engine, tokenService)

	_, err := loc.Client.Call(t.Context(), "initialize", nil)
	require.NoError(t, err)
	engine.GetConfiguration().Set(types.SettingIsLspInitialized, true)

	params := types.DidChangeConfigurationParams{
		Settings: types.LspConfigurationParam{
			Settings: map[string]*types.ConfigSetting{
				types.SettingToken:        {Value: "combined-change-token", Changed: true},
				types.SettingOrganization: {Value: "combined-org", Changed: true},
			},
		},
	}
	_, err = loc.Client.Call(t.Context(), "workspace/didChangeConfiguration", params)
	require.NoError(t, err)

	// Wait for at least one notification to arrive.
	assert.Eventually(
		t,
		func() bool {
			return len(jsonRPCRecorder.FindNotificationsByMethod(types.SnykRefreshHtmlSettings)) >= 1
		},
		htmlRefreshTimeout,
		htmlRefreshTick,
		"expected at least one $/snyk.refreshHtmlSettings notification when token and org both change",
	)

	assert.Never(
		t,
		func() bool {
			return len(jsonRPCRecorder.FindNotificationsByMethod(types.SnykRefreshHtmlSettings)) > 1
		},
		200*time.Millisecond,
		htmlRefreshTick,
		"expected exactly one $/snyk.refreshHtmlSettings notification when token and org both change",
	)
}

func Test_RefreshHtmlSettings_NotSentOnUnchangedFlagToken(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder, _ := setupServer(t, engine, tokenService)

	_, err := loc.Client.Call(t.Context(), "initialize", nil)
	require.NoError(t, err)
	engine.GetConfiguration().Set(types.SettingIsLspInitialized, true)

	// Send a token value with Changed=false.
	// The credential must be written (reconnect recovery), but the notification must not fire.
	params := types.DidChangeConfigurationParams{
		Settings: types.LspConfigurationParam{
			Settings: map[string]*types.ConfigSetting{
				types.SettingToken: {Value: "different-value", Changed: false},
			},
		},
	}
	_, err = loc.Client.Call(t.Context(), "workspace/didChangeConfiguration", params)
	require.NoError(t, err)

	assert.Never(
		t,
		func() bool {
			return len(jsonRPCRecorder.FindNotificationsByMethod(types.SnykRefreshHtmlSettings)) > 0
		},
		300*time.Millisecond,
		htmlRefreshTick,
		"$/snyk.refreshHtmlSettings must not fire when Changed=false even if token value differs",
	)
}

func Test_applyToken_WritesCredentialOnReconnect(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder, _ := setupServer(t, engine, tokenService)

	_, err := loc.Client.Call(t.Context(), "initialize", nil)
	require.NoError(t, err)
	engine.GetConfiguration().Set(types.SettingIsLspInitialized, true)

	// Simulate a reconnect: IDE sends a full settings snapshot with Changed=false.
	// The credential must be written even though Changed=false, because the LS may have
	// restarted and lost the credential. The notification must not fire (Changed=false means
	// the IDE is not signaling a user-initiated change, just recovering state).
	params := types.DidChangeConfigurationParams{
		Settings: types.LspConfigurationParam{
			Settings: map[string]*types.ConfigSetting{
				types.SettingToken: {Value: "reconnect-token", Changed: false},
			},
		},
	}
	_, err = loc.Client.Call(t.Context(), "workspace/didChangeConfiguration", params)
	require.NoError(t, err)

	// Credential must be written even though Changed=false
	assert.Eventually(
		t,
		func() bool {
			return config.GetToken(engine.GetConfiguration()) == "reconnect-token"
		},
		htmlRefreshTimeout,
		htmlRefreshTick,
		"credential must be written even when Changed=false (reconnect recovery)",
	)

	// But no refresh notification must fire — Changed=false suppresses the notification
	assert.Never(
		t,
		func() bool {
			return len(jsonRPCRecorder.FindNotificationsByMethod(types.SnykRefreshHtmlSettings)) > 0
		},
		300*time.Millisecond,
		htmlRefreshTick,
		"$/snyk.refreshHtmlSettings must not fire when Changed=false",
	)
}

func Test_RefreshHtmlSettings_NotSentOnUnchangedToken(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder, _ := setupServer(t, engine, tokenService)

	_, err := loc.Client.Call(t.Context(), "initialize", nil)
	require.NoError(t, err)
	engine.GetConfiguration().Set(types.SettingIsLspInitialized, true)

	// Set the current token so we can send the same value
	currentToken := "existing-token"
	di.AuthenticationService().UpdateCredentials(currentToken, false, false)
	jsonRPCRecorder.ClearNotifications()

	// Confirm our token is now set
	require.Equal(t, currentToken, config.GetToken(engine.GetConfiguration()))

	// Send the SAME token value — should produce no refresh notification
	params := types.DidChangeConfigurationParams{
		Settings: types.LspConfigurationParam{
			Settings: map[string]*types.ConfigSetting{
				types.SettingToken: {Value: currentToken, Changed: true},
			},
		},
	}
	_, err = loc.Client.Call(t.Context(), "workspace/didChangeConfiguration", params)
	require.NoError(t, err)

	assert.Never(
		t,
		func() bool {
			return len(jsonRPCRecorder.FindNotificationsByMethod(types.SnykRefreshHtmlSettings)) > 0
		},
		300*time.Millisecond,
		htmlRefreshTick,
		"$/snyk.refreshHtmlSettings must not fire when token is unchanged",
	)
}

func Test_RefreshHtmlSettings_DeferredAfterInit_OnAuthentication(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder, _ := setupServer(t, engine, tokenService)

	_, err := loc.Client.Call(t.Context(), "initialize", nil)
	require.NoError(t, err)
	// Do NOT set SettingIsLspInitialized — LSP is not yet initialized

	// Clean up: signal init so the deferred goroutine in the notifier can unblock
	t.Cleanup(func() {
		engine.GetConfiguration().Set(types.SettingIsLspInitialized, true)
		types.SignalLspInitialized(engine.GetConfiguration())
	})

	// Fire UpdateCredentials while LSP is not yet initialized.
	// The auth_service_impl path has no call-site guard, so it sends
	// RefreshHtmlSettingsParams directly to the notifier, which defers
	// delivery until WaitForLspInitialized returns.
	di.AuthenticationService().UpdateCredentials("integ-test-token", true, false)

	// Notification must NOT arrive while uninitialized.
	assert.Never(
		t,
		func() bool {
			return len(jsonRPCRecorder.FindNotificationsByMethod(types.SnykRefreshHtmlSettings)) > 0
		},
		100*time.Millisecond,
		htmlRefreshTick,
		"$/snyk.refreshHtmlSettings must not arrive before LSP is initialized",
	)

	// Now signal LSP init — the deferred notification must be delivered.
	engine.GetConfiguration().Set(types.SettingIsLspInitialized, true)
	types.SignalLspInitialized(engine.GetConfiguration())

	assert.Eventually(
		t,
		func() bool {
			return len(jsonRPCRecorder.FindNotificationsByMethod(types.SnykRefreshHtmlSettings)) > 0
		},
		htmlRefreshTimeout,
		htmlRefreshTick,
		"$/snyk.refreshHtmlSettings must arrive after LSP is initialized (deferred delivery)",
	)
}
