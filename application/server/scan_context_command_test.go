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

// IDE-2036 Checkpoint 2.1: integration tests verifying that the scan commands
// (WorkspaceScanCommand, WorkspaceFolderScanCommand, ClearCacheCommand) use the
// server-lifetime scanCtx rather than context.Background() for goroutines that
// outlive the command's execution.
//
// All three tests are RED on the current tree (which still uses context.Background()
// in the respective command structs) and must go GREEN after the production fix.

import (
	"testing"
	"time"

	"github.com/snyk/go-application-framework/pkg/configuration"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

// ---------------------------------------------------------------------------
// trustedCapturingFolder: a minimal types.Folder that captures the context
// passed to ScanFolder. Used by INTEG-104 to verify ClearCacheCommand threads
// the server-lifetime scanCtx rather than context.Background().
// ---------------------------------------------------------------------------

type trustedCapturingFolder struct {
	*contextCapturingFolder
	path types.FilePath
}

func newTrustedCapturingFolder(path types.FilePath) *trustedCapturingFolder {
	return &trustedCapturingFolder{
		contextCapturingFolder: newContextCapturingFolder(),
		path:                   path,
	}
}

// Path satisfies types.Folder so folder.Path() logging does not panic.
func (f *trustedCapturingFolder) Path() types.FilePath { return f.path }

// Uri satisfies types.Folder; clearCache skips the folderUri filter when
// parsedFolderUri is nil, but the interface requires the method.
func (f *trustedCapturingFolder) Uri() sglsp.DocumentURI { return uri.PathToUri(f.path) }

// Clear satisfies types.Folder; ClearCacheCommand calls folder.Clear() before
// triggering folder.ScanFolder.
func (f *trustedCapturingFolder) Clear() {}

// ---------------------------------------------------------------------------
// trustedWorkspace: wraps a real Workspace but overrides GetFolderTrust to
// return a single fake trusted folder. Allows INTEG-104 to intercept
// ScanFolder without running a real scan.
// ---------------------------------------------------------------------------

type trustedWorkspace struct {
	types.Workspace
	trustedFolder types.Folder
}

func (w *trustedWorkspace) GetFolderTrust() (trusted []types.Folder, untrusted []types.Folder) {
	return []types.Folder{w.trustedFolder}, nil
}

// scanContextCommandInitParams avoids background CLI downloads during initialize.
// These tests only assert scanCtx cancellation on shutdown; a real download leaves
// snyk-win.exe locked on Windows and breaks t.TempDir cleanup.
func scanContextCommandInitParams(conf configuration.Configuration) types.InitializeParams {
	return types.InitializeParams{
		InitializationOptions: types.InitializationOptions{
			Settings: map[string]*types.ConfigSetting{
				types.SettingCliPath:           {Value: types.GetGlobalString(conf, types.SettingCliPath), Changed: true},
				types.SettingAutomaticDownload: {Value: false, Changed: true},
				types.SettingScanAutomatic:     {Value: "manual", Changed: true},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// INTEG-102 — WorkspaceScanCommand uses server-lifetime scanCtx
//
// TestWorkspaceScanCommandCtxCanceledOnShutdown verifies that the ctx passed
// to ScanWorkspace by workspaceScanCommand.Execute is the server-lifetime
// scanCtx (canceled on shutdown), NOT context.Background() which never cancels.
// ---------------------------------------------------------------------------
func TestWorkspaceScanCommandCtxCanceledOnShutdown(t *testing.T) {
	t.Parallel()

	engine, tokenService := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()

	// WithRealDI() wires the real command.NewService so ExecuteCommandData
	// calls the real CreateFromCommandData → workspaceScanCommand.
	loc, _, _ := setupServer(t, engine, tokenService, WithRealDI())

	// Initialize the LSP session so the server is ready to handle commands.
	_, err := loc.Client.Call(t.Context(), "initialize", scanContextCommandInitParams(conf))
	require.NoError(t, err)
	_, err = loc.Client.Call(t.Context(), "initialized", nil)
	require.NoError(t, err)
	types.WaitForLspInitialized(conf)

	// Replace the workspace with a context-capturing wrapper AFTER initialization
	// so the init handshake uses the real workspace.
	realWs := config.GetWorkspace(conf)
	require.NotNil(t, realWs)
	capturingWs := newContextCapturingWorkspace(realWs)
	config.SetWorkspace(conf, capturingWs)

	// Send workspace/executeCommand WorkspaceScanCommand.
	params := sglsp.ExecuteCommandParams{Command: types.WorkspaceScanCommand}
	_, err = loc.Client.Call(t.Context(), "workspace/executeCommand", params)
	require.NoError(t, err)

	// Wait for ScanWorkspace to be called by the command.
	select {
	case <-capturingWs.called:
		// good
	case <-time.After(5 * time.Second):
		t.Fatal("ScanWorkspace was not called within 5s after WorkspaceScanCommand [IDE-2036-INTEG-102]")
	}

	scanCtx := capturingWs.capturedCtx()
	require.NotNil(t, scanCtx)
	assert.NoError(t, scanCtx.Err(), "scan context must be live before shutdown [IDE-2036-INTEG-102]")

	// Shutdown must cancel the context.
	_, err = loc.Client.Call(t.Context(), "shutdown", nil)
	require.NoError(t, err)

	assert.Eventually(t, func() bool {
		return scanCtx.Err() != nil
	}, 3*time.Second, time.Millisecond,
		"scan context must be canceled after shutdown — WorkspaceScanCommand still uses context.Background() [IDE-2036-INTEG-102]")
}

// ---------------------------------------------------------------------------
// INTEG-104 — ClearCacheCommand ScanFolder uses server-lifetime scanCtx
//
// TestClearCacheCommandScanFolderCtxCanceledOnShutdown verifies that the ctx
// passed to folder.ScanFolder by ClearCacheCommand.purgeInMemoryCache is the
// server-lifetime scanCtx (not context.Background()) so that the goroutine is
// canceled on shutdown.
// ---------------------------------------------------------------------------
func TestClearCacheCommandScanFolderCtxCanceledOnShutdown(t *testing.T) {
	t.Parallel()

	engine, tokenService := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()

	loc, _, _ := setupServer(t, engine, tokenService, WithRealDI())

	_, err := loc.Client.Call(t.Context(), "initialize", scanContextCommandInitParams(conf))
	require.NoError(t, err)
	_, err = loc.Client.Call(t.Context(), "initialized", nil)
	require.NoError(t, err)
	types.WaitForLspInitialized(conf)

	// Build a trusted capturing folder and wrap the workspace so ClearCacheCommand
	// sees it as trusted (with auto-scan enabled).
	fakePath := types.FilePath(t.TempDir() + "/fake-folder")
	capturingFolder := newTrustedCapturingFolder(fakePath)
	realWs := config.GetWorkspace(conf)
	require.NotNil(t, realWs)
	wrappedWs := &trustedWorkspace{Workspace: realWs, trustedFolder: capturingFolder}
	config.SetWorkspace(conf, wrappedWs)

	// Send ClearCacheCommand: args are (folderUri, cacheType).
	// Empty folderUri means "all folders"; "inMemory" clears in-memory and triggers ScanFolder.
	params := sglsp.ExecuteCommandParams{
		Command:   types.ClearCacheCommand,
		Arguments: []any{"", "inMemory"},
	}
	_, err = loc.Client.Call(t.Context(), "workspace/executeCommand", params)
	require.NoError(t, err)

	// Wait for ScanFolder to be called by ClearCacheCommand.purgeInMemoryCache.
	select {
	case <-capturingFolder.called:
		// good
	case <-time.After(5 * time.Second):
		t.Fatal("ScanFolder was not called within 5s after ClearCacheCommand [IDE-2036-INTEG-104]")
	}

	scanCtx := capturingFolder.capturedCtx()
	require.NotNil(t, scanCtx)
	assert.NoError(t, scanCtx.Err(), "scan context must be live before shutdown [IDE-2036-INTEG-104]")

	_, err = loc.Client.Call(t.Context(), "shutdown", nil)
	require.NoError(t, err)

	assert.Eventually(t, func() bool {
		return scanCtx.Err() != nil
	}, 3*time.Second, time.Millisecond,
		"scan context must be canceled after shutdown — ClearCacheCommand still uses context.Background() [IDE-2036-INTEG-104]")
}
