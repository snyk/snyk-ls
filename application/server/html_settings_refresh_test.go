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

func Test_RefreshHtmlSettings_OnOrgChange(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder, _ := setupServer(t, engine, tokenService)

	_, err := loc.Client.Call(t.Context(), "initialize", nil)
	require.NoError(t, err)
	engine.GetConfiguration().Set(types.SettingIsLspInitialized, true)

	// Send didChangeConfiguration with a changed org
	params := types.DidChangeConfigurationParams{
		Settings: types.LspConfigurationParam{
			Settings: map[string]*types.ConfigSetting{
				types.SettingOrganization: {Value: "new-test-org", Changed: true},
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
		"expected $/snyk.refreshHtmlSettings notification after org change",
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

func Test_RefreshHtmlSettings_NotSentDuringInitialize(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder, _ := setupServer(t, engine, tokenService)
	t.Cleanup(func() { types.SignalLspInitialized(engine.GetConfiguration()) })

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
