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

// TestScanContextCanceledOnShutdown (IDE-2036-INTEG-004) verifies that the
// context passed to ScanWorkspace by initializedHandler is canceled when the
// shutdown handler runs.
//
// Run with:
//
//	go test ./application/server/... -run TestScanContextCanceledOnShutdown -v -count=1

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

// contextCapturingWorkspace wraps a real types.Workspace and records the
// context that ScanWorkspace was called with, unblocking a channel so the
// test can synchronize without polling.
type contextCapturingWorkspace struct {
	types.Workspace // embed the real workspace for all other method calls

	mu      sync.Mutex
	scanCtx context.Context
	called  chan struct{}
}

func newContextCapturingWorkspace(delegate types.Workspace) *contextCapturingWorkspace {
	return &contextCapturingWorkspace{
		Workspace: delegate,
		called:    make(chan struct{}, 1),
	}
}

func (w *contextCapturingWorkspace) ScanWorkspace(ctx context.Context) {
	w.mu.Lock()
	w.scanCtx = ctx
	w.mu.Unlock()
	select {
	case w.called <- struct{}{}:
	default:
	}
	// Do not forward to the real workspace — we do not want real scans in this test.
}

func (w *contextCapturingWorkspace) capturedCtx() context.Context {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.scanCtx
}

func TestScanContextCanceledOnShutdown(t *testing.T) {
	// Not parallel: injects a workspace into the configuration, which modifies
	// engine-global state. Run sequentially so it does not interfere with other tests.

	engine, tokenService := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()

	// Enable automatic scanning (the default, but pin it explicitly so the test
	// is not sensitive to the default changing).
	conf.Set(
		configresolver.RemoteOrgKey("", types.SettingScanAutomatic),
		&configresolver.RemoteConfigField{Value: true, IsLocked: true},
	)

	// Setup the server using the standard test helper. This creates and registers
	// a real workspace via di.TestInit / config.SetWorkspace.
	loc, _, _ := setupServer(t, engine, tokenService)

	// Wrap the real workspace so we can capture the scan context.
	realWs := config.GetWorkspace(conf)
	require.NotNil(t, realWs, "workspace must be set after setupServer")
	capturingWs := newContextCapturingWorkspace(realWs)
	config.SetWorkspace(conf, capturingWs)

	// Run the LSP initialization handshake to trigger initializedHandler.
	_, err := loc.Client.Call(t.Context(), "initialize", nil)
	require.NoError(t, err)

	_, err = loc.Client.Call(t.Context(), "initialized", nil)
	require.NoError(t, err)

	// Wait for ScanWorkspace to be called (initialized handler triggers it
	// asynchronously; give it a generous timeout).
	select {
	case <-capturingWs.called:
		// good — ScanWorkspace was called
	case <-time.After(10 * time.Second):
		t.Fatal("ScanWorkspace was not called within 10s after initialized")
	}

	scanCtx := capturingWs.capturedCtx()
	require.NotNil(t, scanCtx, "ScanWorkspace must have been called with a non-nil context")

	// Before shutdown: the scan context must NOT be canceled yet.
	assert.NoError(t, scanCtx.Err(), "scan context must be live before shutdown")

	// Trigger shutdown — this should cancel the scan context.
	_, err = loc.Client.Call(t.Context(), "shutdown", nil)
	require.NoError(t, err)

	// After shutdown: the scan context must be canceled so that in-flight scan
	// goroutines can exit (preventing Windows temp-dir cleanup races [IDE-2036]).
	assert.Eventually(t, func() bool {
		return scanCtx.Err() != nil
	}, 3*time.Second, time.Millisecond,
		"scan context must be canceled after shutdown (currently uses context.Background() which never cancels)")
}

// contextCapturingFolder wraps a types.Folder and captures the context passed
// to ScanFile or ScanFolder, allowing tests to verify the handler threads the
// correct cancellable scanCtx rather than context.Background().
type contextCapturingFolder struct {
	types.Folder // embed for all other method calls

	mu      sync.Mutex
	scanCtx context.Context
	called  chan struct{}
}

func newContextCapturingFolder() *contextCapturingFolder {
	return &contextCapturingFolder{
		called: make(chan struct{}, 1),
	}
}

func (f *contextCapturingFolder) ScanFile(ctx context.Context, _ types.FilePath) {
	f.mu.Lock()
	f.scanCtx = ctx
	f.mu.Unlock()
	select {
	case f.called <- struct{}{}:
	default:
	}
}

func (f *contextCapturingFolder) ScanFolder(ctx context.Context) {
	f.mu.Lock()
	f.scanCtx = ctx
	f.mu.Unlock()
	select {
	case f.called <- struct{}{}:
	default:
	}
}

func (f *contextCapturingFolder) IsTrusted() bool {
	return true
}

func (f *contextCapturingFolder) IsAutoScanEnabled() bool {
	return true
}

func (f *contextCapturingFolder) capturedCtx() context.Context {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.scanCtx
}

// folderCapturingWorkspace wraps a types.Workspace and, when GetFolderContaining
// is called, returns a contextCapturingFolder for files that match the intercept path.
// All other workspace methods are delegated to the real workspace.
type folderCapturingWorkspace struct {
	types.Workspace

	interceptPath types.FilePath
	folder        *contextCapturingFolder
}

func (w *folderCapturingWorkspace) GetFolderContaining(path types.FilePath) types.Folder {
	if path == w.interceptPath {
		return w.folder
	}
	return w.Workspace.GetFolderContaining(path)
}

// changeCapturingWorkspace wraps a types.Workspace and overrides
// ChangeWorkspaceFolders to return a contextCapturingFolder so tests can
// observe the context passed to ScanFolder by the handler.
type changeCapturingWorkspace struct {
	types.Workspace

	folder *contextCapturingFolder
}

func (w *changeCapturingWorkspace) ChangeWorkspaceFolders(_ types.DidChangeWorkspaceFoldersParams) []types.Folder {
	// Return the capturing folder as the "changed" folder so the handler will
	// call ScanFolder on it using its scanCtx.
	return []types.Folder{w.folder}
}

// TestTextDocumentDidSaveHandlerUsesScanCtx (IDE-2036-INTEG-005) verifies that
// the context passed to folder.ScanFile (and folder.ScanFolder for .snyk files)
// by textDocumentDidSaveHandler is the cancellable server-lifetime scanCtx —
// not context.Background() which ignores shutdown.
//
// Run with:
//
//	go test ./application/server/... -run TestTextDocumentDidSaveHandlerUsesScanCtx -v -count=1
func TestTextDocumentDidSaveHandlerUsesScanCtx(t *testing.T) {
	// Not parallel: replaces the global workspace in the config.
	engine, tokenService := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()

	loc, _, _ := setupServer(t, engine, tokenService)

	// Wrap the real workspace: when the handler looks up the folder for our
	// synthetic file path, it will receive the context-capturing folder.
	realWs := config.GetWorkspace(conf)
	require.NotNil(t, realWs, "workspace must be set after setupServer")

	capturingFolder := newContextCapturingFolder()
	fakePath := types.FilePath(filepath.Join(t.TempDir(), "fakefile.js"))
	fakeURI := uri.PathToUri(fakePath)
	wrappedWs := &folderCapturingWorkspace{
		Workspace:     realWs,
		interceptPath: uri.PathFromUri(fakeURI),
		folder:        capturingFolder,
	}
	config.SetWorkspace(conf, wrappedWs)

	// Send textDocument/didSave for the fake file path. The handler will call
	// GetFolderContaining(fakePath), which returns the capturing folder, then
	// call folder.ScanFile(scanCtx, fakePath) in a goroutine.
	didSaveParams := sglsp.DidSaveTextDocumentParams{
		TextDocument: sglsp.TextDocumentIdentifier{URI: fakeURI},
	}
	_, err := loc.Client.Call(t.Context(), textDocumentDidSaveOperation, didSaveParams)
	require.NoError(t, err)

	// Wait for ScanFile (or ScanFolder for .snyk) to be called asynchronously.
	select {
	case <-capturingFolder.called:
		// good — scan was called with some context
	case <-time.After(5 * time.Second):
		t.Fatal("ScanFile was not called within 5s after textDocument/didSave")
	}

	scanCtx := capturingFolder.capturedCtx()
	require.NotNil(t, scanCtx, "ScanFile must have been called with a non-nil context")

	// Before shutdown: context must be live.
	assert.NoError(t, scanCtx.Err(), "scan context must be live before shutdown")

	// Shutdown must cancel the context.
	_, err = loc.Client.Call(t.Context(), "shutdown", nil)
	require.NoError(t, err)

	assert.Eventually(t, func() bool {
		return scanCtx.Err() != nil
	}, 3*time.Second, time.Millisecond,
		"scan context must be canceled after shutdown — textDocumentDidSaveHandler still uses context.Background() [IDE-2036]")
}

// namedCapturingFolder extends contextCapturingFolder with a fixed path so that
// GetTrustMessage (which calls folder.Path()) does not panic.
type namedCapturingFolder struct {
	*contextCapturingFolder
	path types.FilePath
}

func newNamedCapturingFolder(path types.FilePath) *namedCapturingFolder {
	return &namedCapturingFolder{
		contextCapturingFolder: newContextCapturingFolder(),
		path:                   path,
	}
}

func (f *namedCapturingFolder) Path() types.FilePath { return f.path }

// trustCapturingWorkspace wraps a real types.Workspace and, when
// TrustFoldersAndScan is called, captures the context and unblocks a channel.
// GetFolderTrust always returns the real workspace's trusted folders as untrusted
// so that HandleUntrustedFolders triggers the trust dialog and ultimately calls
// TrustFoldersAndScan with the context HandleFolders was given.
type trustCapturingWorkspace struct {
	types.Workspace

	mu      sync.Mutex
	scanCtx context.Context
	called  chan struct{}

	// fakeTrusted is the folder we pretend is untrusted so the trust dialog fires.
	fakeTrusted types.Folder
}

func newTrustCapturingWorkspace(delegate types.Workspace, fakeFolder types.Folder) *trustCapturingWorkspace {
	return &trustCapturingWorkspace{
		Workspace:   delegate,
		called:      make(chan struct{}, 1),
		fakeTrusted: fakeFolder,
	}
}

// GetFolderTrust returns the fake folder as untrusted so HandleUntrustedFolders
// triggers the trust dialog (and ultimately calls TrustFoldersAndScan).
func (w *trustCapturingWorkspace) GetFolderTrust() ([]types.Folder, []types.Folder) {
	return nil, []types.Folder{w.fakeTrusted}
}

func (w *trustCapturingWorkspace) TrustFoldersAndScan(ctx context.Context, _ []types.Folder) {
	w.mu.Lock()
	w.scanCtx = ctx
	w.mu.Unlock()
	select {
	case w.called <- struct{}{}:
	default:
	}
	// Do not call the real workspace — we don't want real scans.
}

func (w *trustCapturingWorkspace) capturedCtx() context.Context {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.scanCtx
}

// TestHandleFoldersScanCtxCanceledOnShutdown (IDE-2036-INTEG-101) verifies that
// the context passed to HandleFolders by initializedHandler is the server-lifetime
// scanCtx (canceled on shutdown), NOT context.Background() which never cancels.
//
// Run with:
//
//	go test ./application/server/... -run TestHandleFoldersScanCtxCanceledOnShutdown -v -count=1
func TestHandleFoldersScanCtxCanceledOnShutdown(t *testing.T) {
	// Not parallel: injects a workspace into the configuration, modifying
	// engine-global state. Run sequentially so it does not interfere with others.

	engine, tokenService := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()

	// Trust-checking must be enabled so HandleUntrustedFolders runs.
	conf.Set(configresolver.UserGlobalKey(types.SettingTrustEnabled), true)

	// The test callback responds "DoTrust" to the window/showMessageRequest so
	// that TrustFoldersAndScan is called (which is where we capture the ctx).
	loc, _, _ := setupServer(t, engine, tokenService, WithCallback(func(_ context.Context, _ *jrpc2.Request) (any, error) {
		return types.MessageActionItem{Title: command.DoTrust}, nil
	}))

	// Build a minimal capturing folder with a valid path so that GetTrustMessage
	// (called by showTrustDialog) does not panic when iterating untrusted folders.
	capturingFolder := newNamedCapturingFolder(types.FilePath(t.TempDir() + "/fake-untrusted"))
	realWs := config.GetWorkspace(conf)
	require.NotNil(t, realWs)

	// Wrap the workspace so GetFolderTrust returns our folder as untrusted, and
	// TrustFoldersAndScan captures the context passed by HandleFolders.
	trustWs := newTrustCapturingWorkspace(realWs, capturingFolder)
	config.SetWorkspace(conf, trustWs)

	// Trigger the LSP lifecycle: initialize → initialized.
	_, err := loc.Client.Call(t.Context(), "initialize", nil)
	require.NoError(t, err)

	_, err = loc.Client.Call(t.Context(), "initialized", nil)
	require.NoError(t, err)

	// Wait for TrustFoldersAndScan to be called.
	select {
	case <-trustWs.called:
		// good
	case <-time.After(10 * time.Second):
		t.Fatal("TrustFoldersAndScan was not called within 10s after initialized")
	}

	scanCtx := trustWs.capturedCtx()
	require.NotNil(t, scanCtx)

	// Before shutdown: the scan context must be live.
	assert.NoError(t, scanCtx.Err(), "scan context must be live before shutdown")

	// Shutdown must cancel the context so in-flight untrusted-folder scan goroutines exit.
	_, err = loc.Client.Call(t.Context(), "shutdown", nil)
	require.NoError(t, err)

	assert.Eventually(t, func() bool {
		return scanCtx.Err() != nil
	}, 3*time.Second, time.Millisecond,
		"scan context must be canceled after shutdown — HandleFolders still uses context.Background() [IDE-2036-INTEG-101]")
}

// TestWorkspaceDidChangeFoldersHandlerUsesScanCtx (IDE-2036-INTEG-006) verifies
// that the context passed to folder.ScanFolder by
// workspaceDidChangeWorkspaceFoldersHandler is the cancellable server-lifetime
// scanCtx — not context.Background() which ignores shutdown.
//
// Run with:
//
//	go test ./application/server/... -run TestWorkspaceDidChangeFoldersHandlerUsesScanCtx -v -count=1
func TestWorkspaceDidChangeFoldersHandlerUsesScanCtx(t *testing.T) {
	// Not parallel: replaces the global workspace in the config.
	engine, tokenService := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()

	loc, _, _ := setupServer(t, engine, tokenService)

	// Wrap the real workspace: when ChangeWorkspaceFolders is called by the
	// handler, return our context-capturing folder as a "changed" folder.
	realWs := config.GetWorkspace(conf)
	require.NotNil(t, realWs, "workspace must be set after setupServer")

	capturingFolder := newContextCapturingFolder()
	wrappedWs := &changeCapturingWorkspace{
		Workspace: realWs,
		folder:    capturingFolder,
	}
	config.SetWorkspace(conf, wrappedWs)

	// Send workspace/didChangeWorkspaceFolders to trigger the handler.
	// The handler calls ChangeWorkspaceFolders (returning our capturing folder)
	// then go folder.ScanFolder(scanCtx) for each folder with auto-scan enabled.
	changeParams := types.DidChangeWorkspaceFoldersParams{
		Event: types.WorkspaceFoldersChangeEvent{
			Added: []types.WorkspaceFolder{
				{Name: "test-folder", Uri: uri.PathToUri(types.FilePath(t.TempDir()))},
			},
		},
	}
	_, err := loc.Client.Call(t.Context(), "workspace/didChangeWorkspaceFolders", changeParams)
	require.NoError(t, err)

	// Wait for ScanFolder to be called asynchronously.
	select {
	case <-capturingFolder.called:
		// good — ScanFolder was called with some context
	case <-time.After(5 * time.Second):
		t.Fatal("ScanFolder was not called within 5s after workspace/didChangeWorkspaceFolders")
	}

	scanCtx := capturingFolder.capturedCtx()
	require.NotNil(t, scanCtx, "ScanFolder must have been called with a non-nil context")

	// Before shutdown: context must be live.
	assert.NoError(t, scanCtx.Err(), "scan context must be live before shutdown")

	// Shutdown must cancel the context.
	_, err = loc.Client.Call(t.Context(), "shutdown", nil)
	require.NoError(t, err)

	assert.Eventually(t, func() bool {
		return scanCtx.Err() != nil
	}, 3*time.Second, time.Millisecond,
		"scan context must be canceled after shutdown — workspaceDidChangeWorkspaceFoldersHandler still uses context.Background() [IDE-2036]")
}
