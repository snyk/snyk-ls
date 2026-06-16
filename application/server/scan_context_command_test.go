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
	"context"
	"sync"
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/command"
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

// ---------------------------------------------------------------------------
// folderCommandCapturingWorkspace: wraps a real Workspace and is used by
// INTEG-103 to intercept both GetFolderContaining (so WorkspaceFolderScanCommand
// can find the folder) and GetFolderTrust/TrustFoldersAndScan (so the trust
// flow captures the context from HandleUntrustedFolders).
// ---------------------------------------------------------------------------

type folderCommandCapturingWorkspace struct {
	types.Workspace

	interceptPath types.FilePath
	scanFolder    *trustedCapturingFolder // returned by GetFolderContaining

	mu       sync.Mutex
	trustCtx context.Context
	called   chan struct{}

	fakeTrusted types.Folder // folder returned as "untrusted" by GetFolderTrust
}

func newFolderCommandCapturingWorkspace(delegate types.Workspace, interceptPath types.FilePath) *folderCommandCapturingWorkspace {
	fakePath := interceptPath
	scanFolder := newTrustedCapturingFolder(fakePath)
	return &folderCommandCapturingWorkspace{
		Workspace:     delegate,
		interceptPath: interceptPath,
		scanFolder:    scanFolder,
		called:        make(chan struct{}, 1),
		fakeTrusted:   newNamedCapturingFolder(fakePath),
	}
}

// GetFolderContaining: return our capturing folder for the intercepted path.
func (w *folderCommandCapturingWorkspace) GetFolderContaining(path types.FilePath) types.Folder {
	if path == w.interceptPath {
		return w.scanFolder
	}
	return w.Workspace.GetFolderContaining(path)
}

// GetFolderTrust: always return the fake folder as untrusted so the trust
// dialog fires when HandleUntrustedFolders is called.
func (w *folderCommandCapturingWorkspace) GetFolderTrust() ([]types.Folder, []types.Folder) {
	return nil, []types.Folder{w.fakeTrusted}
}

// TrustFoldersAndScan: capture the context passed by HandleUntrustedFolders.
func (w *folderCommandCapturingWorkspace) TrustFoldersAndScan(ctx context.Context, _ []types.Folder) {
	w.mu.Lock()
	w.trustCtx = ctx
	w.mu.Unlock()
	select {
	case w.called <- struct{}{}:
	default:
	}
}

func (w *folderCommandCapturingWorkspace) capturedTrustCtx() context.Context {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.trustCtx
}

// ---------------------------------------------------------------------------
// INTEG-102 — WorkspaceScanCommand uses server-lifetime scanCtx
//
// TestWorkspaceScanCommandCtxCanceledOnShutdown verifies that the ctx passed
// to ScanWorkspace by workspaceScanCommand.Execute is the server-lifetime
// scanCtx (canceled on shutdown), NOT context.Background() which never cancels.
//
// RED on current tree: workspace_scan.go:47 uses context.Background().
// GREEN after fix: workspaceScanCommand uses cmd.scanCtx.
// ---------------------------------------------------------------------------
func TestWorkspaceScanCommandCtxCanceledOnShutdown(t *testing.T) {
	// Not parallel: injects a workspace into the configuration (engine-global state).
	engine, tokenService := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()

	// WithRealDI() wires the real command.NewService so ExecuteCommandData
	// calls the real CreateFromCommandData → workspaceScanCommand.
	loc, _, _ := setupServer(t, engine, tokenService, WithRealDI())

	// Initialize the LSP session so the server is ready to handle commands.
	_, err := loc.Client.Call(t.Context(), "initialize", nil)
	require.NoError(t, err)
	_, err = loc.Client.Call(t.Context(), "initialized", nil)
	require.NoError(t, err)

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
// INTEG-103 — WorkspaceFolderScanCommand HandleUntrustedFolders uses scanCtx
//
// TestWorkspaceFolderScanCommandUntrustedCtxCanceledOnShutdown verifies that
// HandleUntrustedFolders called by workspaceFolderScanCommand.Execute receives
// the server-lifetime scanCtx (not context.Background()) so that trust-scan
// goroutines are canceled on shutdown.
//
// RED on current tree: workspace_folder_scan.go:68 calls
// HandleUntrustedFolders(context.Background(), ...).
// GREEN after fix: uses cmd.scanCtx.
// ---------------------------------------------------------------------------
func TestWorkspaceFolderScanCommandUntrustedCtxCanceledOnShutdown(t *testing.T) {
	// Not parallel: modifies engine-global workspace.
	engine, tokenService := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()

	// Trust-checking must be enabled so HandleUntrustedFolders triggers the dialog.
	conf.Set("snyk.trustedFolders", true)

	// Callback responds "DoTrust" so TrustFoldersAndScan is called.
	loc, _, _ := setupServer(t, engine, tokenService,
		WithRealDI(),
		WithCallback(func(_ context.Context, _ *jrpc2.Request) (any, error) {
			return types.MessageActionItem{Title: command.DoTrust}, nil
		}),
	)

	_, err := loc.Client.Call(t.Context(), "initialize", nil)
	require.NoError(t, err)
	_, err = loc.Client.Call(t.Context(), "initialized", nil)
	require.NoError(t, err)

	// Build the capturing workspace. The fake path is both the "folder to scan"
	// (returned by GetFolderContaining) and the "untrusted folder" (returned by
	// GetFolderTrust). WorkspaceFolderScanCommand will:
	//   1. GetFolderContaining(fakePath) → our capturing folder
	//   2. f.Clear(), f.ScanFolder(requestCtx)
	//   3. HandleUntrustedFolders(???, ...) ← must use scanCtx, currently uses context.Background()
	//   4. Trust dialog fires → TrustFoldersAndScan(ctx, ...) captures ctx
	fakePath := types.FilePath(t.TempDir() + "/fake-wf-folder")
	realWs := config.GetWorkspace(conf)
	require.NotNil(t, realWs)
	capturingWs := newFolderCommandCapturingWorkspace(realWs, fakePath)
	config.SetWorkspace(conf, capturingWs)

	// Send WorkspaceFolderScanCommand with the fake path.
	params := sglsp.ExecuteCommandParams{
		Command:   types.WorkspaceFolderScanCommand,
		Arguments: []any{string(fakePath)},
	}
	_, err = loc.Client.Call(t.Context(), "workspace/executeCommand", params)
	require.NoError(t, err)

	// Wait for TrustFoldersAndScan to be called (triggered by the "DoTrust" callback).
	select {
	case <-capturingWs.called:
		// good
	case <-time.After(10 * time.Second):
		t.Fatal("TrustFoldersAndScan was not called within 10s after WorkspaceFolderScanCommand [IDE-2036-INTEG-103]")
	}

	trustCtx := capturingWs.capturedTrustCtx()
	require.NotNil(t, trustCtx)
	assert.NoError(t, trustCtx.Err(), "trust ctx must be live before shutdown [IDE-2036-INTEG-103]")

	_, err = loc.Client.Call(t.Context(), "shutdown", nil)
	require.NoError(t, err)

	assert.Eventually(t, func() bool {
		return trustCtx.Err() != nil
	}, 3*time.Second, time.Millisecond,
		"scan context must be canceled after shutdown — WorkspaceFolderScanCommand.HandleUntrustedFolders still uses context.Background() [IDE-2036-INTEG-103]")
}

// ---------------------------------------------------------------------------
// INTEG-104 — ClearCacheCommand ScanFolder uses server-lifetime scanCtx
//
// TestClearCacheCommandScanFolderCtxCanceledOnShutdown verifies that the ctx
// passed to folder.ScanFolder by ClearCacheCommand.purgeInMemoryCache is the
// server-lifetime scanCtx (not context.Background()) so that the goroutine is
// canceled on shutdown.
//
// RED on current tree: clear_cache.go:95 uses context.Background().
// GREEN after fix: uses cmd.scanCtx.
// ---------------------------------------------------------------------------
func TestClearCacheCommandScanFolderCtxCanceledOnShutdown(t *testing.T) {
	// Not parallel: modifies engine-global workspace.
	engine, tokenService := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()

	loc, _, _ := setupServer(t, engine, tokenService, WithRealDI())

	_, err := loc.Client.Call(t.Context(), "initialize", nil)
	require.NoError(t, err)
	_, err = loc.Client.Call(t.Context(), "initialized", nil)
	require.NoError(t, err)

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
