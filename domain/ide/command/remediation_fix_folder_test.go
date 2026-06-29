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

package command_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/snyk/remediation"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

// ---------------------------------------------------------------------------
// Shared test infrastructure
// ---------------------------------------------------------------------------

// fakeNotifier records all values sent via Send.
type fakeNotifier struct {
	mu   sync.Mutex
	sent []any
}

func (f *fakeNotifier) Send(msg any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, msg)
}

func (f *fakeNotifier) SendShowMessage(_ sglsp.MessageType, _ string) {}
func (f *fakeNotifier) SendError(_ error)                             {}
func (f *fakeNotifier) SendErrorDiagnostic(_ types.FilePath, _ error) {}
func (f *fakeNotifier) Receive() (any, bool)                          { return nil, true }
func (f *fakeNotifier) CreateListener(_ func(params any))             {}
func (f *fakeNotifier) DisposeListener()                              {}

func (f *fakeNotifier) Sent() []any {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]any, len(f.sent))
	copy(cp, f.sent)
	return cp
}

func (f *fakeNotifier) ApplyEditsSent() []types.ApplyWorkspaceEditParams {
	var out []types.ApplyWorkspaceEditParams
	for _, s := range f.Sent() {
		if p, ok := s.(types.ApplyWorkspaceEditParams); ok {
			out = append(out, p)
		}
	}
	return out
}

// fakeFolderRemediator is a fake FolderRemediator for handler unit tests.
type fakeFolderRemediator struct {
	edit *types.WorkspaceEdit
	err  error
}

func (f *fakeFolderRemediator) FixFolder(_ context.Context, _ types.FilePath) (*types.WorkspaceEdit, error) {
	return f.edit, f.err
}

// initGitRepo creates a minimal git repo in a temp dir for tests that need a
// real directory on disk.
func initGitRepoForCmd(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "git %v: %s", args, string(out))
	}
	run("init")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "Test")
	// Overlay filesystems (e.g. Docker on Linux) have write-ordering delays that
	// can cause git to report "not a valid object" when the object database is
	// read immediately after a write. core.checkStat=minimal tells git not to
	// recheck filesystem timestamps for objects it has already cached in memory,
	// which suppresses the false-negative reads on overlayfs.
	run("config", "core.checkStat", "minimal")
	// Commit an initial file so HEAD is valid.
	f := filepath.Join(dir, "main.go")
	require.NoError(t, os.WriteFile(f, []byte("package main\n"), 0644))
	run("add", ".")
	run("commit", "-m", "init")
	return dir
}

// makeFixFolderCommandData constructs a CommandData for the fixFolder command.
func makeFixFolderCommandData(args ...any) types.CommandData {
	return types.CommandData{
		CommandId: types.RemediationAgentFixFolderCommand,
		Arguments: args,
	}
}

// ---------------------------------------------------------------------------
// Acceptance tests (ACC-001..005): round-trip through real serviceImpl
// ---------------------------------------------------------------------------

// buildFixFolderService constructs a real serviceImpl wired with the given
// provider and notifier, routing through the real ExecuteCommandData →
// CreateFromCommandData dispatch. The engine has workspace/applyEdit enabled so
// the capability guard inside Execute passes.
func buildFixFolderService(t *testing.T, provider remediation.FolderRemediator, notifier *fakeNotifier) types.CommandService {
	t.Helper()
	engine, _ := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	caps := types.ClientCapabilities{}
	caps.Workspace.ApplyEdit = true
	conf.Set(types.SettingClientCapabilities, caps)
	logger := engine.GetLogger()
	return command.NewService(engine, logger, nil, nil, notifier, nil, nil, nil, nil, nil, nil, nil, provider)
}

// ACC-001: gate ON; fake runner edits a file; applyEdit sent with keys under folder.
func TestFixFolder_Acceptance_SendsApplyEditUnderPassedFolder(t *testing.T) {
	repo := initGitRepoForCmd(t)
	folderURI := string(uri.PathToUri(types.FilePath(repo)))

	mainAbs := filepath.Join(repo, "main.go")
	edit := &types.WorkspaceEdit{
		Changes: map[string][]types.TextEdit{
			mainAbs: {{Range: types.Range{}, NewText: "package main\nvar x = 2\n"}},
		},
	}
	provider := &fakeFolderRemediator{edit: edit}
	notifier := &fakeNotifier{}
	svc := buildFixFolderService(t, provider, notifier)

	_, err := svc.ExecuteCommandData(context.Background(), makeFixFolderCommandData(folderURI), nil)
	require.NoError(t, err)

	applyEdits := notifier.ApplyEditsSent()
	require.Len(t, applyEdits, 1, "exactly one applyEdit must be sent")
	for key := range applyEdits[0].Edit.Changes {
		// Key must be under the passed folder (as a file:// URI or path).
		// The notifier receives sglsp.WorkspaceEdit whose keys are document URIs.
		assert.True(t,
			len(key) >= len(repo) && key[:len(repo)] == repo ||
				len(key) >= len(folderURI) && key[:len(folderURI)] == folderURI,
			"applyEdit key %q must be under passed folder %q", key, repo)
	}
}

// ACC-002: fake runner records the dir it was invoked with; no nested worktree.
func TestFixFolder_Acceptance_RunsInPassedFolderNoNestedWorktree(t *testing.T) {
	repo := initGitRepoForCmd(t)
	folderURI := string(uri.PathToUri(types.FilePath(repo)))

	var invokedRoot string
	var runnerCallCount int32
	provider := &trackingFolderRemediator{
		fn: func(_ context.Context, root types.FilePath) (*types.WorkspaceEdit, error) {
			atomic.AddInt32(&runnerCallCount, 1)
			invokedRoot = string(root)
			return nil, nil
		},
	}
	notifier := &fakeNotifier{}
	svc := buildFixFolderService(t, provider, notifier)

	_, err := svc.ExecuteCommandData(context.Background(), makeFixFolderCommandData(folderURI), nil)
	require.NoError(t, err)

	assert.Equal(t, repo, invokedRoot, "provider must be invoked with the passed folder")
	assert.Equal(t, int32(1), atomic.LoadInt32(&runnerCallCount))

	// No nested snyk-remy-* or worktree dir inside the folder.
	entries, _ := os.ReadDir(repo)
	for _, e := range entries {
		assert.NotContains(t, e.Name(), "snyk-remy-")
		assert.NotContains(t, e.Name(), "wt")
	}
}

// trackingFolderRemediator is a FolderRemediator that delegates to a closure.
type trackingFolderRemediator struct {
	fn func(ctx context.Context, root types.FilePath) (*types.WorkspaceEdit, error)
}

func (tr *trackingFolderRemediator) FixFolder(ctx context.Context, root types.FilePath) (*types.WorkspaceEdit, error) {
	return tr.fn(ctx, root)
}

// ACC-003: gate OFF (provider nil) → error, no applyEdit, runner never invoked.
func TestFixFolder_Acceptance_FeatureOff_ReturnsError(t *testing.T) {
	repo := initGitRepoForCmd(t)
	folderURI := string(uri.PathToUri(types.FilePath(repo)))

	notifier := &fakeNotifier{}
	svc := buildFixFolderService(t, nil /* nil provider = feature off */, notifier)

	_, err := svc.ExecuteCommandData(context.Background(), makeFixFolderCommandData(folderURI), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not enabled")
	assert.Empty(t, notifier.ApplyEditsSent(), "no applyEdit must be sent when feature is off")
}

// ACC-004: folder OUTSIDE open workspace folders is accepted.
func TestFixFolder_Acceptance_ExternalFolderAccepted(t *testing.T) {
	// The folder is outside any "workspace" — the command must not do a membership check.
	repo := initGitRepoForCmd(t)
	folderURI := string(uri.PathToUri(types.FilePath(repo)))

	mainAbs := filepath.Join(repo, "main.go")
	edit := &types.WorkspaceEdit{
		Changes: map[string][]types.TextEdit{
			mainAbs: {{Range: types.Range{}, NewText: "package main\nvar x = 99\n"}},
		},
	}
	provider := &fakeFolderRemediator{edit: edit}
	notifier := &fakeNotifier{}
	svc := buildFixFolderService(t, provider, notifier)

	_, err := svc.ExecuteCommandData(context.Background(), makeFixFolderCommandData(folderURI), nil)
	require.NoError(t, err, "external folder must be accepted")
	applyEdits := notifier.ApplyEditsSent()
	require.Len(t, applyEdits, 1)
}

// ACC-005: gate ON; fake runner makes NO changes → no applyEdit sent.
func TestFixFolder_Acceptance_NoChanges_NoApplyEdit(t *testing.T) {
	repo := initGitRepoForCmd(t)
	folderURI := string(uri.PathToUri(types.FilePath(repo)))

	provider := &fakeFolderRemediator{edit: nil} // nil = no changes
	notifier := &fakeNotifier{}
	svc := buildFixFolderService(t, provider, notifier)

	_, err := svc.ExecuteCommandData(context.Background(), makeFixFolderCommandData(folderURI), nil)
	require.NoError(t, err)
	assert.Empty(t, notifier.ApplyEditsSent(), "no applyEdit must be sent when there are no changes")
}

// ---------------------------------------------------------------------------
// Unit tests for remediationFixFolderCommand.Execute (UNIT-006..010)
// ---------------------------------------------------------------------------

// newFixFolderCmd constructs a remediationFixFolderCommand for unit testing via
// the exported constructor.
func newFixFolderCmd(args []any, provider remediation.FolderRemediator, notifier *fakeNotifier) types.Command {
	return command.NewRemediationFixFolderCommand(types.CommandData{
		CommandId: types.RemediationAgentFixFolderCommand,
		Arguments: args,
	}, provider, notifier)
}

// UNIT-006: wrong arg count → error.
func TestFixFolder_Execute_WrongArgCount(t *testing.T) {
	notifier := &fakeNotifier{}
	cmd := newFixFolderCmd([]any{}, &fakeFolderRemediator{}, notifier)
	_, err := cmd.Execute(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "one folder URI argument")
	assert.Empty(t, notifier.ApplyEditsSent())
}

// UNIT-007: invalid arg (empty / non-string) → error.
func TestFixFolder_Execute_InvalidArg(t *testing.T) {
	notifier := &fakeNotifier{}

	// non-string arg
	cmd := newFixFolderCmd([]any{42}, &fakeFolderRemediator{}, notifier)
	_, err := cmd.Execute(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "non-empty string")

	// empty string arg
	cmd2 := newFixFolderCmd([]any{""}, &fakeFolderRemediator{}, notifier)
	_, err2 := cmd2.Execute(context.Background())
	require.Error(t, err2)
	assert.Contains(t, err2.Error(), "non-empty string")

	assert.Empty(t, notifier.ApplyEditsSent())
}

// UNIT-008: URI for nonexistent path → "not a directory" error before dispatch.
func TestFixFolder_Execute_NonexistentFolder(t *testing.T) {
	notifier := &fakeNotifier{}
	nonexistent := "file:///tmp/this-path-should-not-exist-ever-12345xyz"
	cmd := newFixFolderCmd([]any{nonexistent}, &fakeFolderRemediator{}, notifier)
	_, err := cmd.Execute(context.Background())
	require.Error(t, err)
	assert.Empty(t, notifier.ApplyEditsSent())
}

// UNIT-009: provider nil → "not enabled" error; no applyEdit.
func TestFixFolder_Execute_NilProviderReturnsError(t *testing.T) {
	repo := initGitRepoForCmd(t)
	folderURI := string(uri.PathToUri(types.FilePath(repo)))
	notifier := &fakeNotifier{}
	cmd := newFixFolderCmd([]any{folderURI}, nil /* nil provider */, notifier)
	_, err := cmd.Execute(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not enabled")
	assert.Empty(t, notifier.ApplyEditsSent())
}

// UNIT-010: provider returns nil edit → (nil, nil); no applyEdit.
func TestFixFolder_Execute_NilEdit_NoApplyEdit(t *testing.T) {
	repo := initGitRepoForCmd(t)
	folderURI := string(uri.PathToUri(types.FilePath(repo)))
	notifier := &fakeNotifier{}
	provider := &fakeFolderRemediator{edit: nil}
	cmd := newFixFolderCmd([]any{folderURI}, provider, notifier)
	result, err := cmd.Execute(context.Background())
	require.NoError(t, err)
	assert.Nil(t, result)
	assert.Empty(t, notifier.ApplyEditsSent(), "no applyEdit must be sent for nil edit")
}

// ---------------------------------------------------------------------------
// Handler error propagation
// ---------------------------------------------------------------------------

func TestFixFolder_Execute_ProviderError_Propagated(t *testing.T) {
	repo := initGitRepoForCmd(t)
	folderURI := string(uri.PathToUri(types.FilePath(repo)))
	notifier := &fakeNotifier{}
	sentinel := errors.New("fix failed")
	provider := &fakeFolderRemediator{err: sentinel}
	cmd := newFixFolderCmd([]any{folderURI}, provider, notifier)
	_, err := cmd.Execute(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, sentinel)
	assert.Empty(t, notifier.ApplyEditsSent())
}

// ---------------------------------------------------------------------------
// Fix 1: ApplyEdit capability guard (UNIT-011, UNIT-012)
// ---------------------------------------------------------------------------

// newFixFolderCmdWithEngine constructs a remediationFixFolderCommand with an
// engine so that the capability guard can be exercised.
func newFixFolderCmdWithEngine(t *testing.T, args []any, provider remediation.FolderRemediator, notifier *fakeNotifier, applyEdit bool) types.Command {
	t.Helper()
	engine, _ := testutil.UnitTestWithEngine(t)
	if applyEdit {
		conf := engine.GetConfiguration()
		caps := types.ClientCapabilities{}
		caps.Workspace.ApplyEdit = true
		conf.Set(types.SettingClientCapabilities, caps)
	}
	return command.NewRemediationFixFolderCommandWithEngine(types.CommandData{
		CommandId: types.RemediationAgentFixFolderCommand,
		Arguments: args,
	}, provider, notifier, engine)
}

// UNIT-011: when ApplyEdit capability is false AND provider returns a non-empty
// edit, Execute must return a non-nil error and notifier.Send must NEVER be called.
func TestFixFolder_Execute_ApplyEditCapabilityFalse_ReturnsErrorNoSend(t *testing.T) {
	repo := initGitRepoForCmd(t)
	folderURI := string(uri.PathToUri(types.FilePath(repo)))
	notifier := &fakeNotifier{}

	mainAbs := filepath.Join(repo, "main.go")
	edit := &types.WorkspaceEdit{
		Changes: map[string][]types.TextEdit{
			mainAbs: {{Range: types.Range{}, NewText: "package main\nvar x = 2\n"}},
		},
	}
	provider := &fakeFolderRemediator{edit: edit}

	// Build command with ApplyEdit=false (capability not set)
	cmd := newFixFolderCmdWithEngine(t, []any{folderURI}, provider, notifier, false /* applyEdit=false */)
	_, err := cmd.Execute(context.Background())

	require.Error(t, err, "must return error when ApplyEdit capability is false")
	assert.Contains(t, err.Error(), "applyEdit", "error must mention the missing capability")
	assert.Empty(t, notifier.ApplyEditsSent(), "notifier.Send must NOT be called when capability is absent")
}

// UNIT-012b: when provider is nil AND client lacks applyEdit, Execute must
// return the "not enabled" error — NOT the capability error. The feature-gate
// check (provider nil) must precede the applyEdit capability check.
func TestFixFolder_Execute_NilProvider_BeforeCapabilityCheck(t *testing.T) {
	repo := initGitRepoForCmd(t)
	folderURI := string(uri.PathToUri(types.FilePath(repo)))
	notifier := &fakeNotifier{}

	// Build command with nil provider AND applyEdit=false.
	cmd := newFixFolderCmdWithEngine(t, []any{folderURI}, nil /* nil provider */, notifier, false /* applyEdit=false */)
	_, err := cmd.Execute(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not enabled",
		"when provider is nil, Execute must return 'not enabled' regardless of applyEdit capability; got: %v", err)
	assert.NotContains(t, err.Error(), "applyEdit",
		"capability error must NOT be surfaced when the feature is off (provider nil)")
}

// UNIT-012: when ApplyEdit capability is true AND provider returns a non-empty
// edit, Execute must succeed and notifier.Send must be called.
func TestFixFolder_Execute_ApplyEditCapabilityTrue_SendsEdit(t *testing.T) {
	repo := initGitRepoForCmd(t)
	folderURI := string(uri.PathToUri(types.FilePath(repo)))
	notifier := &fakeNotifier{}

	mainAbs := filepath.Join(repo, "main.go")
	edit := &types.WorkspaceEdit{
		Changes: map[string][]types.TextEdit{
			mainAbs: {{Range: types.Range{}, NewText: "package main\nvar x = 2\n"}},
		},
	}
	provider := &fakeFolderRemediator{edit: edit}

	// Build command with ApplyEdit=true
	cmd := newFixFolderCmdWithEngine(t, []any{folderURI}, provider, notifier, true /* applyEdit=true */)
	_, err := cmd.Execute(context.Background())

	require.NoError(t, err)
	require.Len(t, notifier.ApplyEditsSent(), 1, "notifier.Send must be called exactly once when capability is present")
}
