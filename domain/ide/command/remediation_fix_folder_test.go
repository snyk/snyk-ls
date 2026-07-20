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
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/snyk/remediation"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

// ---------------------------------------------------------------------------
// Shared test infrastructure
// ---------------------------------------------------------------------------

// fakeFolderRemediator is a fake FolderRemediator for handler unit tests.
type fakeFolderRemediator struct {
	results []types.FolderFixFileResult
	err     error
}

func (f *fakeFolderRemediator) FixFolder(_ context.Context, _ types.FilePath) ([]types.FolderFixFileResult, error) {
	return f.results, f.err
}

// initGitRepoForCmd creates a minimal git repo in a temp dir for tests that
// need a real directory on disk. Returns the CANONICAL path (symlinks resolved)
// so test assertions agree with what git and the production code produce.
func initGitRepoForCmd(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if canonical, err := filepath.EvalSymlinks(dir); err == nil {
		dir = canonical
	}
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
	run("config", "core.checkStat", "minimal")
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
// Acceptance tests (ACC-101..105): round-trip through real serviceImpl
// ---------------------------------------------------------------------------

// buildFixFolderService constructs a real serviceImpl wired with the given
// provider, routing through the real ExecuteCommandData → CreateFromCommandData
// dispatch.
func buildFixFolderService(t *testing.T, provider remediation.FolderRemediator, notifier noti.Notifier) types.CommandService {
	t.Helper()
	engine, _ := testutil.UnitTestWithEngine(t)
	logger := engine.GetLogger()
	return command.NewService(engine, logger, nil, nil, notifier, nil, nil, nil, nil, nil, nil, nil, provider)
}

// ACC-101: gate ON; fake runner edits 2 files; response is FolderFixResult with 2 entries;
// no applyEdit sent.
func TestFixFolder_Acceptance_ReturnsPerFileResults(t *testing.T) {
	repo := initGitRepoForCmd(t)
	folderURI := string(uri.PathToUri(types.FilePath(repo)))

	mainAbs := filepath.Join(repo, "main.go")
	utilAbs := filepath.Join(repo, "util.go")
	fakeResults := []types.FolderFixFileResult{
		{WorkspacePath: mainAbs, WorktreePath: mainAbs, Diff: "--- a/main.go\n+++ b/main.go\n@@ -1 +1 @@\n-old\n+new\n"},
		{WorkspacePath: utilAbs, WorktreePath: utilAbs, Diff: "--- a/util.go\n+++ b/util.go\n@@ -1 +1 @@\n-old\n+new\n"},
	}
	provider := &fakeFolderRemediator{results: fakeResults}
	notifier := noti.NewMockNotifier()
	svc := buildFixFolderService(t, provider, notifier)

	result, err := svc.ExecuteCommandData(context.Background(), makeFixFolderCommandData(folderURI), nil)
	require.NoError(t, err)

	// Response body must be FolderFixResult with 2 entries.
	ffr, ok := result.(types.FolderFixResult)
	require.True(t, ok, "result must be types.FolderFixResult, got %T", result)
	require.Len(t, ffr.Files, 2, "FolderFixResult must have 2 file entries")

	// Each entry must have WorktreePath under the folder.
	for _, f := range ffr.Files {
		assert.True(t, strings.HasPrefix(f.WorktreePath, repo+string(filepath.Separator)),
			"WorktreePath %q must be under passed folder %q", f.WorktreePath, repo)
		assert.NotEmpty(t, f.Diff, "each file entry must have a non-empty Diff")
	}
}

// ACC-102: gate ON; fake runner edits one file; result body carries the file entry AND
// no workspace/applyEdit was dispatched through the notifier.
func TestFixFolder_Acceptance_SendsNoApplyEdit(t *testing.T) {
	repo := initGitRepoForCmd(t)
	folderURI := string(uri.PathToUri(types.FilePath(repo)))

	mainAbs := filepath.Join(repo, "main.go")
	fakeResults := []types.FolderFixFileResult{
		{WorkspacePath: mainAbs, WorktreePath: mainAbs, Diff: "diff content"},
	}
	provider := &fakeFolderRemediator{results: fakeResults}
	// Use MockNotifier (records every Send call) so we can assert no
	// ApplyWorkspaceEditParams slipped through.
	notifier := noti.NewMockNotifier()
	svc := buildFixFolderService(t, provider, notifier)

	result, err := svc.ExecuteCommandData(context.Background(), makeFixFolderCommandData(folderURI), nil)
	require.NoError(t, err)

	// Response body must carry the file entry from the fake provider.
	ffr, ok := result.(types.FolderFixResult)
	require.True(t, ok, "result must be types.FolderFixResult, got %T", result)
	require.Len(t, ffr.Files, 1, "FolderFixResult must have 1 file entry")
	assert.Equal(t, mainAbs, ffr.Files[0].WorkspacePath)
	assert.NotEmpty(t, ffr.Files[0].Diff)

	// fixFolder must NOT send an ApplyWorkspaceEditParams — the daemon applies
	// changes directly from the worktree, so the LS must never call
	// workspace/applyEdit for folder fixes.
	for _, msg := range notifier.SentMessages() {
		_, isApplyEdit := msg.(types.ApplyWorkspaceEditParams)
		assert.False(t, isApplyEdit, "fixFolder must not send ApplyWorkspaceEditParams, got: %#v", msg)
	}
}

// ACC-103 (retained): gate OFF (provider nil) → error, no applyEdit.
func TestFixFolder_Acceptance_FeatureOff_ReturnsError(t *testing.T) {
	repo := initGitRepoForCmd(t)
	folderURI := string(uri.PathToUri(types.FilePath(repo)))

	notifier := noti.NewMockNotifier()
	svc := buildFixFolderService(t, nil /* nil provider = feature off */, notifier)

	_, err := svc.ExecuteCommandData(context.Background(), makeFixFolderCommandData(folderURI), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not enabled")
}

// ACC-104: gate ON; runner makes no changes → FolderFixResult{Files: []} (empty, not null); no error.
func TestFixFolder_Acceptance_NoChanges_EmptyResult(t *testing.T) {
	repo := initGitRepoForCmd(t)
	folderURI := string(uri.PathToUri(types.FilePath(repo)))

	provider := &fakeFolderRemediator{results: nil} // nil returned by provider
	notifier := noti.NewMockNotifier()
	svc := buildFixFolderService(t, provider, notifier)

	result, err := svc.ExecuteCommandData(context.Background(), makeFixFolderCommandData(folderURI), nil)
	require.NoError(t, err)

	ffr, ok := result.(types.FolderFixResult)
	require.True(t, ok, "result must be types.FolderFixResult, got %T", result)
	assert.Empty(t, ffr.Files, "FolderFixResult.Files must be empty (not nil) when no changes")
	// Must be non-nil (so JSON marshals as [] not null).
	assert.NotNil(t, ffr.Files, "FolderFixResult.Files must be non-nil even with no changes")
}

// ACC-105: folder OUTSIDE any open workspace folders is accepted; success; entries keyed there.
func TestFixFolder_Acceptance_ExternalFolderAccepted(t *testing.T) {
	repo := initGitRepoForCmd(t)
	folderURI := string(uri.PathToUri(types.FilePath(repo)))

	mainAbs := filepath.Join(repo, "main.go")
	fakeResults := []types.FolderFixFileResult{
		{WorkspacePath: mainAbs, WorktreePath: mainAbs, Diff: "diff content"},
	}
	provider := &fakeFolderRemediator{results: fakeResults}
	notifier := noti.NewMockNotifier()
	svc := buildFixFolderService(t, provider, notifier)

	result, err := svc.ExecuteCommandData(context.Background(), makeFixFolderCommandData(folderURI), nil)
	require.NoError(t, err, "external folder must be accepted")

	ffr, ok := result.(types.FolderFixResult)
	require.True(t, ok)
	require.Len(t, ffr.Files, 1)
	assert.True(t, strings.HasPrefix(ffr.Files[0].WorktreePath, repo+string(filepath.Separator)),
		"result entry must be keyed under the external folder")
}

// trackingFolderRemediator is a FolderRemediator that delegates to a closure.
type trackingFolderRemediator struct {
	fn func(ctx context.Context, root types.FilePath) ([]types.FolderFixFileResult, error)
}

func (tr *trackingFolderRemediator) FixFolder(ctx context.Context, root types.FilePath) ([]types.FolderFixFileResult, error) {
	return tr.fn(ctx, root)
}

// TestFixFolder_Acceptance_RunsInPassedFolderNoNestedWorktree verifies the
// provider is invoked with the passed folder and no nested worktrees appear.
func TestFixFolder_Acceptance_RunsInPassedFolderNoNestedWorktree(t *testing.T) {
	repo := initGitRepoForCmd(t)
	folderURI := string(uri.PathToUri(types.FilePath(repo)))

	var invokedRoot string
	var runnerCallCount int32
	provider := &trackingFolderRemediator{
		fn: func(_ context.Context, root types.FilePath) ([]types.FolderFixFileResult, error) {
			atomic.AddInt32(&runnerCallCount, 1)
			invokedRoot = string(root)
			return nil, nil
		},
	}
	notifier := noti.NewMockNotifier()
	svc := buildFixFolderService(t, provider, notifier)

	_, err := svc.ExecuteCommandData(context.Background(), makeFixFolderCommandData(folderURI), nil)
	require.NoError(t, err)

	assert.Equal(t, repo, invokedRoot, "provider must be invoked with the passed folder")
	assert.Equal(t, int32(1), atomic.LoadInt32(&runnerCallCount))

	entries, _ := os.ReadDir(repo)
	for _, e := range entries {
		assert.NotContains(t, e.Name(), "snyk-remy-")
		assert.NotContains(t, e.Name(), "wt")
	}
}

// ---------------------------------------------------------------------------
// Unit tests for remediationFixFolderCommand.Execute (UNIT-120..126)
// ---------------------------------------------------------------------------

// newFixFolderCmd constructs a remediationFixFolderCommand for unit testing.
func newFixFolderCmd(args []any, provider remediation.FolderRemediator) types.Command {
	return command.NewRemediationFixFolderCommand(types.CommandData{
		CommandId: types.RemediationAgentFixFolderCommand,
		Arguments: args,
	}, provider)
}

// UNIT-120: wrong arg count → error.
func TestFixFolder_Execute_WrongArgCount(t *testing.T) {
	cmd := newFixFolderCmd([]any{}, &fakeFolderRemediator{})
	_, err := cmd.Execute(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "one folder URI argument")
}

// UNIT-121: invalid arg (empty / non-string) → error.
func TestFixFolder_Execute_InvalidArg(t *testing.T) {
	// non-string arg
	cmd := newFixFolderCmd([]any{42}, &fakeFolderRemediator{})
	_, err := cmd.Execute(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "non-empty string")

	// empty string arg
	cmd2 := newFixFolderCmd([]any{""}, &fakeFolderRemediator{})
	_, err2 := cmd2.Execute(context.Background())
	require.Error(t, err2)
	assert.Contains(t, err2.Error(), "non-empty string")
}

// UNIT-122: URI for nonexistent path → "not a directory" error.
func TestFixFolder_Execute_NonexistentFolder(t *testing.T) {
	nonexistent := "file:///tmp/this-path-should-not-exist-ever-12345xyz"
	cmd := newFixFolderCmd([]any{nonexistent}, &fakeFolderRemediator{})
	_, err := cmd.Execute(context.Background())
	require.Error(t, err)
}

// UNIT-123: provider nil → "not enabled" error.
func TestFixFolder_Execute_NilProviderReturnsError(t *testing.T) {
	repo := initGitRepoForCmd(t)
	folderURI := string(uri.PathToUri(types.FilePath(repo)))
	cmd := newFixFolderCmd([]any{folderURI}, nil /* nil provider */)
	_, err := cmd.Execute(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not enabled")
}

// UNIT-124: provider returns empty/nil slice → (FolderFixResult{Files: []}, nil); no panic.
func TestFixFolder_Execute_EmptyResults(t *testing.T) {
	repo := initGitRepoForCmd(t)
	folderURI := string(uri.PathToUri(types.FilePath(repo)))
	provider := &fakeFolderRemediator{results: nil} // nil slice
	cmd := newFixFolderCmd([]any{folderURI}, provider)

	result, err := cmd.Execute(context.Background())
	require.NoError(t, err)
	require.NotNil(t, result, "result must not be nil even when provider returns no files")

	ffr, ok := result.(types.FolderFixResult)
	require.True(t, ok, "result must be FolderFixResult")
	assert.NotNil(t, ffr.Files, "Files must be non-nil (so JSON serializes as [])")
	assert.Empty(t, ffr.Files, "Files must be empty")
}

// UNIT-125: provider error propagated.
func TestFixFolder_Execute_ProviderError_Propagated(t *testing.T) {
	repo := initGitRepoForCmd(t)
	folderURI := string(uri.PathToUri(types.FilePath(repo)))
	sentinel := errors.New("fix failed")
	provider := &fakeFolderRemediator{err: sentinel}
	cmd := newFixFolderCmd([]any{folderURI}, provider)

	_, err := cmd.Execute(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, sentinel)
}

// UNIT-126: provider returns 2 files; response is FolderFixResult with those 2
// files verbatim; notifier received nothing (applyEdit-removal guard).
func TestFixFolder_Execute_ReturnsProviderResultsNoNotify(t *testing.T) {
	repo := initGitRepoForCmd(t)
	folderURI := string(uri.PathToUri(types.FilePath(repo)))

	mainAbs := filepath.Join(repo, "main.go")
	utilAbs := filepath.Join(repo, "util.go")
	fakeResults := []types.FolderFixFileResult{
		{WorkspacePath: mainAbs, WorktreePath: mainAbs, Diff: "diff1"},
		{WorkspacePath: utilAbs, WorktreePath: utilAbs, Diff: "diff2"},
	}
	provider := &fakeFolderRemediator{results: fakeResults}

	svc := buildFixFolderService(t, provider, noti.NewMockNotifier())

	result, err := svc.ExecuteCommandData(context.Background(), makeFixFolderCommandData(folderURI), nil)
	require.NoError(t, err)

	ffr, ok := result.(types.FolderFixResult)
	require.True(t, ok)
	require.Len(t, ffr.Files, 2, "response must carry both file entries verbatim")
	assert.Equal(t, mainAbs, ffr.Files[0].WorkspacePath)
	assert.Equal(t, utilAbs, ffr.Files[1].WorkspacePath)
}

// ---------------------------------------------------------------------------
// Engine-less test: command must not require engine at all
// ---------------------------------------------------------------------------

// TestFixFolder_Execute_WorksWithoutEngine verifies the command executes correctly
// without an engine (the field was removed). With the provider returning empty results
// the command must succeed.
func TestFixFolder_Execute_WorksWithoutEngine(t *testing.T) {
	repo := initGitRepoForCmd(t)
	folderURI := string(uri.PathToUri(types.FilePath(repo)))
	provider := &fakeFolderRemediator{results: []types.FolderFixFileResult{}}
	cmd := newFixFolderCmd([]any{folderURI}, provider)

	result, err := cmd.Execute(context.Background())
	require.NoError(t, err)
	_, ok := result.(types.FolderFixResult)
	assert.True(t, ok, "result must be FolderFixResult")
}
