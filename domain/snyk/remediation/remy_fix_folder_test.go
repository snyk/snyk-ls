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

package remediation_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/snyk/remediation"
	"github.com/snyk/snyk-ls/internal/types"
)

// createDetachedWorktree creates a detached git worktree from mainRepo at a
// temporary path and returns the canonical path. It registers a t.Cleanup to
// remove the worktree so test isolation is guaranteed.
func createDetachedWorktree(t *testing.T, mainRepo string) string {
	t.Helper()
	wtDir := t.TempDir()
	cmd := exec.Command("git", "-C", mainRepo, "worktree", "add", "--detach", wtDir, "HEAD")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git worktree add --detach: %s", string(out))
	t.Cleanup(func() {
		_ = exec.Command("git", "-C", mainRepo, "worktree", "remove", "--force", wtDir).Run()
	})
	canonical, evalErr := filepath.EvalSymlinks(wtDir)
	if evalErr == nil {
		return canonical
	}
	return wtDir
}

// ---------------------------------------------------------------------------
// UNIT-101: FixFolder returns one result per changed file
// ---------------------------------------------------------------------------

// TestFixFolder_ReturnsResultForChangedFile verifies that when the fake runner
// modifies a tracked file, FixFolder returns one FolderFixFileResult whose
// WorkspacePath == WorktreePath == <folder>/main.go and whose Diff contains
// the changed content. The runner must be called with (folder, "").
func TestFixFolder_ReturnsResultForChangedFile(t *testing.T) {
	repo := initGitRepo(t)
	commitFile(t, repo, "main.go", "package main\nvar x = 1\n")

	mainAbs := filepath.Join(repo, "main.go")

	var runnerDir, runnerFindingID string
	runner := func(_ context.Context, _ workflow.Engine, root, findingID string) error {
		runnerDir = root
		runnerFindingID = findingID
		return os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\nvar x = 2\n"), 0644)
	}

	p := remediation.NewRemyProvider(nil, runner)
	fr, ok := p.(remediation.FolderRemediator)
	require.True(t, ok, "remyProvider must implement FolderRemediator")

	results, err := fr.FixFolder(context.Background(), types.FilePath(repo))
	require.NoError(t, err)
	require.Len(t, results, 1, "expected one result for one changed file")

	r := results[0]
	assert.Equal(t, mainAbs, r.WorktreePath, "WorktreePath must be <folder>/main.go")
	assert.Equal(t, mainAbs, r.WorkspacePath, "WorkspacePath must be <folder>/main.go")
	assert.Contains(t, r.Diff, "var x = 2", "Diff must contain the changed line")

	// Runner must be called with exactly the passed folder and empty findingID.
	assert.Equal(t, repo, runnerDir, "runner must be called with the passed folder")
	assert.Empty(t, runnerFindingID, "runner must be called with empty findingID for folder path")
}

// ---------------------------------------------------------------------------
// UNIT-102: FixFolder returns empty slice when runner makes no changes
// ---------------------------------------------------------------------------

func TestFixFolder_NoChangesReturnsEmpty(t *testing.T) {
	repo := initGitRepo(t)
	commitFile(t, repo, "main.go", "package main\nvar x = 1\n")

	p := remediation.NewRemyProvider(nil, noopRunner)
	fr, ok := p.(remediation.FolderRemediator)
	require.True(t, ok)

	results, err := fr.FixFolder(context.Background(), types.FilePath(repo))
	require.NoError(t, err)
	assert.Empty(t, results, "no-change run must return empty slice")
}

// ---------------------------------------------------------------------------
// UNIT-103: FixFolder propagates runner errors
// ---------------------------------------------------------------------------

func TestFixFolder_PropagatesRunnerError(t *testing.T) {
	repo := initGitRepo(t)
	commitFile(t, repo, "main.go", "package main\n")

	sentinel := errors.New("remy runner failed")
	p := remediation.NewRemyProvider(nil, errRunner(sentinel))
	fr, ok := p.(remediation.FolderRemediator)
	require.True(t, ok)

	results, err := fr.FixFolder(context.Background(), types.FilePath(repo))
	require.Error(t, err)
	assert.ErrorIs(t, err, sentinel)
	assert.Nil(t, results)
}

// ---------------------------------------------------------------------------
// UNIT-104: FixFolder rejects non-absolute / empty paths
// ---------------------------------------------------------------------------

func TestFixFolder_RejectsNonAbsolutePath(t *testing.T) {
	var runnerCalled bool
	trackingRunner := func(_ context.Context, _ workflow.Engine, _, _ string) error {
		runnerCalled = true
		return nil
	}

	p := remediation.NewRemyProvider(nil, trackingRunner)
	fr, ok := p.(remediation.FolderRemediator)
	require.True(t, ok)

	// Relative path
	results, err := fr.FixFolder(context.Background(), types.FilePath("relative/path"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "absolute")
	assert.Nil(t, results)
	assert.False(t, runnerCalled, "runner must NOT be called on invalid path")

	// Empty path
	results2, err2 := fr.FixFolder(context.Background(), types.FilePath(""))
	require.Error(t, err2)
	assert.Contains(t, err2.Error(), "absolute")
	assert.Nil(t, results2)
	assert.False(t, runnerCalled, "runner must NOT be called on empty path")
}

// ---------------------------------------------------------------------------
// UNIT-105: FixFolder rejects subdirectory of a git root
// ---------------------------------------------------------------------------

func TestFixFolder_SubdirOfGitRoot_ReturnsError(t *testing.T) {
	repo := initGitRepo(t)
	commitFile(t, repo, "sub/main.go", "package main\nvar x = 1\n")
	subdir := filepath.Join(repo, "sub")

	var runnerCalled bool
	runner := func(_ context.Context, _ workflow.Engine, _, _ string) error {
		runnerCalled = true
		return nil
	}

	p := remediation.NewRemyProvider(nil, runner)
	fr, ok := p.(remediation.FolderRemediator)
	require.True(t, ok)

	results, err := fr.FixFolder(context.Background(), types.FilePath(subdir))
	require.Error(t, err, "FixFolder must return an error when passed a subdirectory of a git root")
	assert.Nil(t, results)
	assert.False(t, runnerCalled, "runner must NOT be called when the precondition guard fires")
}

// ---------------------------------------------------------------------------
// UNIT-106: FixFolder rejects a non-git directory
// ---------------------------------------------------------------------------

func TestFixFolder_NonGitDirectory_ReturnsError(t *testing.T) {
	nonGit := t.TempDir()

	var runnerCalled bool
	runner := func(_ context.Context, _ workflow.Engine, _, _ string) error {
		runnerCalled = true
		return nil
	}

	p := remediation.NewRemyProvider(nil, runner)
	fr, ok := p.(remediation.FolderRemediator)
	require.True(t, ok)

	results, err := fr.FixFolder(context.Background(), types.FilePath(nonGit))
	require.Error(t, err)
	assert.Nil(t, results)
	assert.False(t, runnerCalled)
}

// ---------------------------------------------------------------------------
// UNIT-107: FixFolder rejects dirty tracked files
// ---------------------------------------------------------------------------

func TestFixFolder_TrackedFileModified_StillErrors(t *testing.T) {
	repo := initGitRepo(t)
	commitFile(t, repo, "main.go", "package main\nvar x = 1\n")

	err := os.WriteFile(filepath.Join(repo, "main.go"), []byte("package main\nvar x = 99\n"), 0644)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(repo, "artifact.bin"), []byte("binary"), 0644)
	require.NoError(t, err)

	var runnerCalled bool
	runner := func(_ context.Context, _ workflow.Engine, _, _ string) error {
		runnerCalled = true
		return nil
	}

	p := remediation.NewRemyProvider(nil, runner)
	fr, ok := p.(remediation.FolderRemediator)
	require.True(t, ok)

	results, err := fr.FixFolder(context.Background(), types.FilePath(repo))
	require.Error(t, err)
	assert.Nil(t, results)
	assert.False(t, runnerCalled)
}

// ---------------------------------------------------------------------------
// UNIT-108: FixFolder succeeds when the only dirty state is untracked files
// ---------------------------------------------------------------------------

func TestFixFolder_UntrackedFileOnly_DoesNotError(t *testing.T) {
	repo := initGitRepo(t)
	commitFile(t, repo, "main.go", "package main\nvar x = 1\n")

	err := os.WriteFile(filepath.Join(repo, "artifact.bin"), []byte("binary"), 0644)
	require.NoError(t, err)

	runner := func(_ context.Context, _ workflow.Engine, root, _ string) error {
		return os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\nvar x = 2\n"), 0644)
	}

	p := remediation.NewRemyProvider(nil, runner)
	fr, ok := p.(remediation.FolderRemediator)
	require.True(t, ok)

	results, err := fr.FixFolder(context.Background(), types.FilePath(repo))
	require.NoError(t, err, "FixFolder must not error when the only dirty state is untracked files")
	assert.NotEmpty(t, results, "FixFolder must return results when the runner modifies a tracked file")
}

// ---------------------------------------------------------------------------
// UNIT-109: WorktreePath / WorkspacePath keyed under the PASSED (non-canonical) path
// ---------------------------------------------------------------------------

// TestFixFolder_SymlinkPath_KeyedUnderPassedPath locks the daemon contract:
// when the caller passes a symlinked folder path, every WorktreePath and
// WorkspacePath must be prefixed by the EXACT passed (non-canonical) path, not
// the resolved path. The daemon remaps by the prefix it passed; canonicalizing
// inside FixFolder would break the daemon's prefix match.
func TestFixFolder_SymlinkPath_KeyedUnderPassedPath(t *testing.T) {
	realDir := t.TempDir()
	var err error
	realDir, err = filepath.EvalSymlinks(realDir)
	require.NoError(t, err)
	initGitRepoInDir(t, realDir)
	commitFileInDir(t, realDir, "main.go", "package main\nvar x = 1\n")

	linkDir := filepath.Join(t.TempDir(), "link")
	if symlinkErr := os.Symlink(realDir, linkDir); symlinkErr != nil {
		t.Skipf("cannot create symlink (os restriction): %v", symlinkErr)
	}

	runner := func(_ context.Context, _ workflow.Engine, root, _ string) error {
		return os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\nvar x = 2\n"), 0644)
	}

	p := remediation.NewRemyProvider(nil, runner)
	fr, ok := p.(remediation.FolderRemediator)
	require.True(t, ok)

	results, err := fr.FixFolder(context.Background(), types.FilePath(linkDir))
	require.NoError(t, err)
	require.NotEmpty(t, results, "FixFolder must return results when a file was modified")

	sep := string(filepath.Separator)
	for _, r := range results {
		assert.True(t, strings.HasPrefix(r.WorktreePath, linkDir+sep),
			"WorktreePath %q must be prefixed by the passed symlinked path %q (daemon contract)", r.WorktreePath, linkDir)
		assert.True(t, strings.HasPrefix(r.WorkspacePath, linkDir+sep),
			"WorkspacePath %q must be prefixed by the passed symlinked path %q (daemon contract)", r.WorkspacePath, linkDir)
	}
}

// ---------------------------------------------------------------------------
// UNIT-110: FixFolder returns one result per changed file (multi-file)
// ---------------------------------------------------------------------------

func TestFixFolder_MultiFile_OneResultPerFile(t *testing.T) {
	repo := initGitRepo(t)
	commitFile(t, repo, "a.go", "package main\nvar a = 1\n")
	commitFile(t, repo, "b.go", "package main\nvar b = 1\n")
	commitFile(t, repo, "c.go", "package main\nvar c = 1\n")

	runner := func(_ context.Context, _ workflow.Engine, root, _ string) error {
		_ = os.WriteFile(filepath.Join(root, "a.go"), []byte("package main\nvar a = 2\n"), 0644)
		_ = os.WriteFile(filepath.Join(root, "b.go"), []byte("package main\nvar b = 2\n"), 0644)
		_ = os.WriteFile(filepath.Join(root, "c.go"), []byte("package main\nvar c = 2\n"), 0644)
		return nil
	}

	p := remediation.NewRemyProvider(nil, runner)
	fr, ok := p.(remediation.FolderRemediator)
	require.True(t, ok)

	results, err := fr.FixFolder(context.Background(), types.FilePath(repo))
	require.NoError(t, err)
	require.Len(t, results, 3, "must return one result per changed file")

	paths := make(map[string]bool)
	for _, r := range results {
		paths[r.WorktreePath] = true
		assert.NotEmpty(t, r.Diff, "each result must have a non-empty Diff")
	}
	assert.Contains(t, paths, filepath.Join(repo, "a.go"))
	assert.Contains(t, paths, filepath.Join(repo, "b.go"))
	assert.Contains(t, paths, filepath.Join(repo, "c.go"))
}

// ---------------------------------------------------------------------------
// UNIT-111: FixFolder invokes runner with exactly the passed folder
// ---------------------------------------------------------------------------

func TestFixFolder_RunsDirectlyInPassedFolder(t *testing.T) {
	repo := initGitRepo(t)
	commitFile(t, repo, "main.go", "package main\n")

	var invokedWith string
	trackingRunner := func(_ context.Context, _ workflow.Engine, root, _ string) error {
		invokedWith = root
		return nil
	}

	p := remediation.NewRemyProvider(nil, trackingRunner)
	fr, ok := p.(remediation.FolderRemediator)
	require.True(t, ok)

	_, err := fr.FixFolder(context.Background(), types.FilePath(repo))
	require.NoError(t, err)

	assert.Equal(t, repo, invokedWith, "runner must be invoked with the passed folder, not a child dir")

	// No snyk-remy-* temp directories must have been created inside the folder.
	entries, readErr := os.ReadDir(repo)
	require.NoError(t, readErr)
	for _, e := range entries {
		assert.NotContains(t, e.Name(), "snyk-remy-",
			"no nested snyk-remy-* temp dir must be created inside the passed folder")
	}
}

// ---------------------------------------------------------------------------
// Retained: clean worktree succeeds
// ---------------------------------------------------------------------------

func TestFixFolder_CleanWorktree_Succeeds(t *testing.T) {
	repo := initGitRepo(t)
	commitFile(t, repo, "main.go", "package main\nvar x = 1\n")

	runner := func(_ context.Context, _ workflow.Engine, root, _ string) error {
		return os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\nvar x = 2\n"), 0644)
	}

	p := remediation.NewRemyProvider(nil, runner)
	fr, ok := p.(remediation.FolderRemediator)
	require.True(t, ok)

	results, err := fr.FixFolder(context.Background(), types.FilePath(repo))
	require.NoError(t, err, "FixFolder must succeed on a clean worktree")
	assert.NotEmpty(t, results, "FixFolder must return results when the runner modifies files")
}

// ---------------------------------------------------------------------------
// Retained: uncommitted changes returns error
// ---------------------------------------------------------------------------

func TestFixFolder_UncommittedChanges_ReturnsError(t *testing.T) {
	repo := initGitRepo(t)
	commitFile(t, repo, "main.go", "package main\nvar x = 1\n")

	err := os.WriteFile(filepath.Join(repo, "main.go"), []byte("package main\nvar x = 99\n"), 0644)
	require.NoError(t, err)

	var runnerCalled bool
	runner := func(_ context.Context, _ workflow.Engine, _, _ string) error {
		runnerCalled = true
		return nil
	}

	p := remediation.NewRemyProvider(nil, runner)
	fr, ok := p.(remediation.FolderRemediator)
	require.True(t, ok)

	results, err := fr.FixFolder(context.Background(), types.FilePath(repo))
	require.Error(t, err)
	assert.Nil(t, results)
	assert.False(t, runnerCalled)
}

// ---------------------------------------------------------------------------
// UNIT-112: Runner that consumes the caller context budget — results still returned
// ---------------------------------------------------------------------------

// TestFixFolder_RunnerConsumesContextBudget_ResultsStillReturned verifies that
// when the runner completes (writing file changes) but exhausts the caller's
// context deadline in the process, the git enumeration phase still succeeds and
// the completed fix is returned — not discarded as a context error.
//
// The implementation decouples the git enumeration from the runner's timeout
// by giving enumeration its own fresh context after the runner returns.
// Without this decoupling, an expired caller context causes gitChangedFiles
// the git enumeration to fail immediately and the completed fix to be lost.
func TestFixFolder_RunnerConsumesContextBudget_ResultsStillReturned(t *testing.T) {
	repo := initGitRepo(t)
	commitFile(t, repo, "main.go", "package main\nvar x = 1\n")

	const runnerDelay = 120 * time.Millisecond
	const callerBudget = 80 * time.Millisecond

	runner := func(_ context.Context, _ workflow.Engine, root, _ string) error {
		// Write the fix first, then sleep past the caller budget.
		// This simulates a real runner that completes its work but whose context
		// has expired by the time it returns — the fix IS done, so the results
		// must not be thrown away.
		if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\nvar x = 2\n"), 0644); err != nil {
			return err
		}
		time.Sleep(runnerDelay)
		return nil
	}

	p := remediation.NewRemyProvider(nil, runner)
	fr, ok := p.(remediation.FolderRemediator)
	require.True(t, ok)

	ctx, cancel := context.WithTimeout(context.Background(), callerBudget)
	defer cancel()

	results, err := fr.FixFolder(ctx, types.FilePath(repo))
	require.NoError(t, err,
		"FixFolder must return results even when the runner exhausts the caller context: "+
			"git enumeration must use its own fresh context, not the expired caller context")
	require.NotEmpty(t, results, "completed fix must produce at least one file result")

	found := false
	for _, r := range results {
		if r.WorkspacePath == filepath.Join(repo, "main.go") && r.Diff != "" {
			found = true
		}
	}
	assert.True(t, found, "result must contain main.go with a non-empty Diff")
}

// ---------------------------------------------------------------------------
// UNIT-113: All changed files appear in results — no silent drops
// ---------------------------------------------------------------------------

// TestFixFolder_AllChangedFilesPresent_NoSilentDrop verifies that every file
// the runner modifies appears in the results. No file may be silently dropped
// due to a per-file diff error. The single-pass git diff approach eliminates the
// previous N×gitFileDiff pattern where a per-file error would silently omit the file.
func TestFixFolder_AllChangedFilesPresent_NoSilentDrop(t *testing.T) {
	repo := initGitRepo(t)
	commitFile(t, repo, "a.go", "package main\nvar a = 1\n")
	commitFile(t, repo, "b.go", "package main\nvar b = 1\n")
	commitFile(t, repo, "c.go", "package main\nvar c = 1\n")

	runner := func(_ context.Context, _ workflow.Engine, root, _ string) error {
		_ = os.WriteFile(filepath.Join(root, "a.go"), []byte("package main\nvar a = 2\n"), 0644)
		_ = os.WriteFile(filepath.Join(root, "b.go"), []byte("package main\nvar b = 2\n"), 0644)
		_ = os.WriteFile(filepath.Join(root, "c.go"), []byte("package main\nvar c = 2\n"), 0644)
		return nil
	}

	p := remediation.NewRemyProvider(nil, runner)
	fr := p.(remediation.FolderRemediator)

	results, err := fr.FixFolder(context.Background(), types.FilePath(repo))
	require.NoError(t, err)
	require.Len(t, results, 3, "all three changed files must appear in results; none silently dropped")

	paths := make(map[string]bool)
	for _, r := range results {
		paths[r.WorkspacePath] = true
		assert.NotEmpty(t, r.Diff, "each result must have a non-empty Diff")
	}
	assert.Contains(t, paths, filepath.Join(repo, "a.go"), "a.go must not be silently dropped")
	assert.Contains(t, paths, filepath.Join(repo, "b.go"), "b.go must not be silently dropped")
	assert.Contains(t, paths, filepath.Join(repo, "c.go"), "c.go must not be silently dropped")
}

// ---------------------------------------------------------------------------
// UNIT-114: Runner that deletes a tracked file — entry has empty WorktreePath
// ---------------------------------------------------------------------------

// TestFixFolder_DeletedFile_HasEmptyWorktreePath verifies that when the runner
// deletes a tracked file, the result entry has:
//   - non-empty Diff (the deletion diff from HEAD showing the removed lines)
//   - non-empty WorkspacePath (the workspace path the daemon must delete)
//   - empty WorktreePath (signals deletion to the daemon — no file to copy)
//
// Without this fix, deleted files would carry a non-empty WorktreePath pointing
// to a file that no longer exists in the worktree, causing the daemon's
// copy-based landing to fail.
func TestFixFolder_DeletedFile_HasEmptyWorktreePath(t *testing.T) {
	repo := initGitRepo(t)
	commitFile(t, repo, "todelete.go", "package main\nvar x = 1\n")

	runner := func(_ context.Context, _ workflow.Engine, root, _ string) error {
		return os.Remove(filepath.Join(root, "todelete.go"))
	}

	p := remediation.NewRemyProvider(nil, runner)
	fr := p.(remediation.FolderRemediator)

	results, err := fr.FixFolder(context.Background(), types.FilePath(repo))
	require.NoError(t, err)
	require.Len(t, results, 1, "deleted file must produce exactly one result entry")

	r := results[0]
	assert.NotEmpty(t, r.Diff,
		"deletion diff must be non-empty (contains the removed lines)")
	assert.NotEmpty(t, r.WorkspacePath,
		"WorkspacePath must be non-empty for a deletion (daemon needs it to delete the workspace file)")
	assert.Empty(t, r.WorktreePath,
		"WorktreePath must be empty for a deletion — the file no longer exists in the worktree; "+
			"daemon deletes the workspace file rather than copying from the worktree")
	assert.Equal(t, filepath.Join(repo, "todelete.go"), r.WorkspacePath,
		"WorkspacePath must be the absolute path of the deleted file")
}

// ---------------------------------------------------------------------------
// UNIT-115: color.diff=always does not corrupt diffs (--no-color required)
// ---------------------------------------------------------------------------

// TestFixFolder_ColorDiffConfig_ReturnsValidDiff verifies that git color.diff=always
// in the local config does not corrupt the returned diffs. Without --no-color, ANSI
// escape sequences are injected into "diff --git" header lines, breaking any parser
// that looks for the literal prefix. With --no-color the output is plain text.
func TestFixFolder_ColorDiffConfig_ReturnsValidDiff(t *testing.T) {
	mainRepo := initGitRepo(t)
	commitFile(t, mainRepo, "main.go", "package main\nvar x = 1\n")
	wt := createDetachedWorktree(t, mainRepo)

	// Configure color.diff=always in the worktree's git config so git will inject
	// ANSI escape sequences into diff output unless explicitly suppressed.
	configCmd := exec.Command("git", "-C", wt, "config", "color.diff", "always")
	configOut, configErr := configCmd.CombinedOutput()
	require.NoError(t, configErr, "git config color.diff always: %s", string(configOut))

	runner := func(_ context.Context, _ workflow.Engine, root, _ string) error {
		return os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\nvar x = 2\n"), 0o644)
	}

	p := remediation.NewRemyProvider(nil, runner)
	fr := p.(remediation.FolderRemediator)

	results, err := fr.FixFolder(context.Background(), types.FilePath(wt))
	require.NoError(t, err)
	require.NotEmpty(t, results, "color.diff=always must not suppress results; --no-color must be used")

	for _, r := range results {
		// ANSI escape sequences start with ESC (\x1b); a properly --no-color diff has none.
		assert.NotContains(t, r.Diff, "\x1b",
			"diff must not contain ANSI escape sequences when --no-color is used")
		assert.Contains(t, r.Diff, "@@", "diff must contain a valid unified-diff hunk header")
	}
}

// ---------------------------------------------------------------------------
// UNIT-116: diff.external config does not suppress diffs (--no-ext-diff required)
// ---------------------------------------------------------------------------

// TestFixFolder_ExternalDiffConfig_ReturnsValidDiff verifies that a diff.external
// config (e.g. a custom pager like delta or difftastic) does not prevent FixFolder
// from returning valid unified diffs. Without --no-ext-diff, git invokes the external
// tool, which may emit non-unified output or exit non-zero, silently dropping results.
func TestFixFolder_ExternalDiffConfig_ReturnsValidDiff(t *testing.T) {
	mainRepo := initGitRepo(t)
	commitFile(t, mainRepo, "main.go", "package main\nvar x = 1\n")
	wt := createDetachedWorktree(t, mainRepo)

	// Configure a bogus external differ that always exits non-zero.
	configCmd := exec.Command("git", "-C", wt, "config", "diff.external", "/bin/false")
	configOut, configErr := configCmd.CombinedOutput()
	require.NoError(t, configErr, "git config diff.external /bin/false: %s", string(configOut))

	runner := func(_ context.Context, _ workflow.Engine, root, _ string) error {
		return os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\nvar x = 2\n"), 0o644)
	}

	p := remediation.NewRemyProvider(nil, runner)
	fr := p.(remediation.FolderRemediator)

	results, err := fr.FixFolder(context.Background(), types.FilePath(wt))
	require.NoError(t, err, "--no-ext-diff must bypass the external differ; FixFolder must not error")
	require.NotEmpty(t, results, "diff.external config must not suppress results")

	for _, r := range results {
		assert.Contains(t, r.Diff, "@@", "diff must be a valid unified diff with hunk headers")
	}
}

// ---------------------------------------------------------------------------
// UNIT-117: Rename surfaces as deletion of the old path (--no-renames)
// ---------------------------------------------------------------------------

// TestFixFolder_Rename_OldPathIsDeletedEntry verifies that when the runner renames
// a tracked file, the old path appears in results with WorktreePath=="" — signaling
// a deletion to the daemon so it removes the old workspace file. With --no-renames,
// git reports a rename as D<old> (and the new path as untracked, outside the contract).
func TestFixFolder_Rename_OldPathIsDeletedEntry(t *testing.T) {
	mainRepo := initGitRepo(t)
	commitFile(t, mainRepo, "old.go", "package main\nvar x = 1\n")
	wt := createDetachedWorktree(t, mainRepo)

	runner := func(_ context.Context, _ workflow.Engine, root, _ string) error {
		return os.Rename(filepath.Join(root, "old.go"), filepath.Join(root, "new.go"))
	}

	p := remediation.NewRemyProvider(nil, runner)
	fr := p.(remediation.FolderRemediator)

	results, err := fr.FixFolder(context.Background(), types.FilePath(wt))
	require.NoError(t, err)

	// old.go must appear as a deletion (WorktreePath=="").
	var oldEntry *types.FolderFixFileResult
	for i := range results {
		if strings.HasSuffix(results[i].WorkspacePath, "old.go") {
			oldEntry = &results[i]
		}
	}
	require.NotNil(t, oldEntry, "old.go must appear in results as a deletion entry after rename")
	assert.Empty(t, oldEntry.WorktreePath,
		"renamed-away (deleted) path must have WorktreePath==\"\" so the daemon deletes the workspace file")
	assert.NotEmpty(t, oldEntry.Diff, "deletion entry for old.go must have a non-empty diff")
}

// ---------------------------------------------------------------------------
// UNIT-118: Non-ASCII filename handled correctly (NUL-separated, no octal escaping)
// ---------------------------------------------------------------------------

// TestFixFolder_NonASCIIFilename_CorrectEditEntry verifies that a file with a
// non-ASCII name (café.go) is returned as a correct edit entry, not misclassified
// as a deletion. Git quotes non-ASCII filenames by default (core.quotePath=true),
// turning café.go into "caf\303\251.go". With -z, paths are NUL-separated and
// never quoted, so the raw UTF-8 name is preserved.
func TestFixFolder_NonASCIIFilename_CorrectEditEntry(t *testing.T) {
	mainRepo := initGitRepo(t)
	commitFile(t, mainRepo, "café.go", "package main\nvar x = 1\n")
	wt := createDetachedWorktree(t, mainRepo)

	runner := func(_ context.Context, _ workflow.Engine, root, _ string) error {
		return os.WriteFile(filepath.Join(root, "café.go"), []byte("package main\nvar x = 2\n"), 0o644)
	}

	p := remediation.NewRemyProvider(nil, runner)
	fr := p.(remediation.FolderRemediator)

	results, err := fr.FixFolder(context.Background(), types.FilePath(wt))
	require.NoError(t, err)

	var cafeEntry *types.FolderFixFileResult
	for i := range results {
		if strings.HasSuffix(results[i].WorkspacePath, "café.go") {
			cafeEntry = &results[i]
		}
	}
	require.NotNil(t, cafeEntry, "café.go must appear in results; non-ASCII filename must not be lost")
	assert.NotEmpty(t, cafeEntry.WorktreePath,
		"café.go was modified (not deleted); WorktreePath must be non-empty")
	assert.NotEmpty(t, cafeEntry.Diff, "café.go result must have a non-empty diff")
}

// ---------------------------------------------------------------------------
// UNIT-119: textconv gitattribute does not suppress diffs (--no-textconv required)
// ---------------------------------------------------------------------------

// TestFixFolder_TextconvIgnored_FileAppearsInResults verifies that --no-textconv is
// passed when computing per-file diffs. A textconv filter configured to output nothing
// (/bin/true) makes textconv-filtered diff empty: both old and new blobs appear as
// empty, so git diff (without --no-textconv) would produce no output for the file.
//
// Without --no-textconv the file would yield an empty diff → previously silently
// dropped (now an error). With --no-textconv (the current implementation), git diffs
// the raw blob bytes instead, the change is detected, and the file correctly appears
// in results with a non-empty Diff.
//
// Regression: if --no-textconv is removed, FixFolder returns an error (empty diff for
// a listed file is now an error), and this test fails on require.NoError.
func TestFixFolder_TextconvIgnored_FileAppearsInResults(t *testing.T) {
	repo := initGitRepo(t)
	commitFile(t, repo, "main.go", "package main\nvar x = 1\n")

	// Configure a textconv that always outputs nothing: git runs "/bin/true <blob-path>"
	// which exits 0 with no output. Both old and new blobs appear as empty through the
	// filter, so without --no-textconv git diff produces an empty result for the file.
	attrsPath := filepath.Join(repo, ".gitattributes")
	err := os.WriteFile(attrsPath, []byte("*.go diff=testconv\n"), 0o644)
	require.NoError(t, err, "write .gitattributes")

	configCmd := exec.Command("git", "-C", repo, "config", "diff.testconv.textconv", "/bin/true")
	configOut, configErr := configCmd.CombinedOutput()
	require.NoError(t, configErr, "git config diff.testconv.textconv: %s", string(configOut))

	// Runner modifies the tracked file.
	runner := func(_ context.Context, _ workflow.Engine, root, _ string) error {
		return os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\nvar x = 2\n"), 0o644)
	}

	p := remediation.NewRemyProvider(nil, runner)
	fr, ok := p.(remediation.FolderRemediator)
	require.True(t, ok)

	results, err := fr.FixFolder(context.Background(), types.FilePath(repo))
	require.NoError(t, err,
		"FixFolder must not error when a textconv is configured; --no-textconv must bypass the filter")
	require.Len(t, results, 1, "modified file must appear in results despite textconv configuration")
	assert.Contains(t, results[0].Diff, "var x = 2",
		"Diff must reflect the raw blob change, not the empty textconv output")
}

// ---------------------------------------------------------------------------
// UNIT-120: Pre-flight git guards succeed even with an already-cancelled caller context
// ---------------------------------------------------------------------------

// TestFixFolder_CancelledCallerContext_GuardsStillSucceed verifies that the
// pre-flight git integrity checks (rev-parse --show-prefix and git status) are
// not bound to the caller's context. When the caller passes an already-cancelled
// context, the guards must still run successfully so the fix can proceed.
//
// On Linux the cancelled context causes the git subprocess to receive SIGKILL;
// on Windows the equivalent TerminateProcess call fails with "Access is denied".
// Both surface as an error from the guard, making the test deterministically RED
// on any OS before the fix.
func TestFixFolder_CancelledCallerContext_GuardsStillSucceed(t *testing.T) {
	repo := initGitRepo(t)
	commitFile(t, repo, "main.go", "package main\nvar x = 1\n")

	runner := func(_ context.Context, _ workflow.Engine, root, _ string) error {
		return os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\nvar x = 2\n"), 0644)
	}

	p := remediation.NewRemyProvider(nil, runner)
	fr, ok := p.(remediation.FolderRemediator)
	require.True(t, ok)

	// Use an already-cancelled context to simulate a tight/expired caller deadline.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results, err := fr.FixFolder(ctx, types.FilePath(repo))
	require.NoError(t, err,
		"FixFolder's git integrity guards must not be tied to the caller context: "+
			"an already-cancelled caller context must not prevent the pre-flight guards from running")
	require.NotEmpty(t, results,
		"FixFolder must return results even when the caller context is already cancelled before the call")
}
