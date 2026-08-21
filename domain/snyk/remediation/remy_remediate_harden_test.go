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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/snyk/remediation"
	"github.com/snyk/snyk-ls/internal/types"
)

// ---------------------------------------------------------------------------
// HARDEN-1: buildWorkspaceEdits must use a fresh context for git enumeration
//
// After the runner returns in collectFixEdits, buildWorkspaceEdits must derive
// its own context rooted at context.Background() for all git subprocess calls.
// If it reuses the caller's timeout-bounded context (which the runner just
// consumed), a COMPLETED fix is discarded as context.DeadlineExceeded.
// ---------------------------------------------------------------------------

// TestRemediate_EnumCtx_SurvivesCallerDeadline verifies that edits are returned
// even when the runner exhausts the caller's entire time budget before returning.
// Without the fix, buildWorkspaceEdits's git calls fail because the inherited ctx
// is already expired, and the completed fix is discarded.
func TestRemediate_EnumCtx_SurvivesCallerDeadline(t *testing.T) {
	t.Parallel()

	repoRoot := initGitRepo(t)
	commitFile(t, repoRoot, "main.go", "package main\nvar x = 1\n")
	absPath := filepath.Join(repoRoot, "main.go")

	callerCtx, cancelCaller := context.WithCancel(context.Background())
	defer cancelCaller()

	// The runner writes the fix, then cancels the caller ctx — which also expires
	// the provider's derived ctx — and returns nil ("fix succeeded"). The caller
	// must still retrieve the edits even though the ctx is now dead.
	// Canceling explicitly (rather than waiting out a short provider timeout)
	// keeps the expiry independent of machine speed: slow pre-runner git ops on a
	// loaded Windows agent can no longer consume the budget before the runner runs.
	runner := func(ctx context.Context, _ workflow.Engine, root string, _ string) error {
		if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\nvar x = 2\n"), 0o644); err != nil {
			return err
		}
		cancelCaller()
		<-ctx.Done()
		return nil
	}

	p := remediation.NewRemyProviderWithTimeout(runner, 30*time.Second)

	edit, err := p.Remediate(callerCtx, remediation.RemediationRequest{
		FindingId:   "f1",
		ContentRoot: types.FilePath(repoRoot),
		FilePath:    types.FilePath(absPath),
	})
	require.NoError(t, err, "buildWorkspaceEdits must not propagate a ctx expiry error — edits from a completed runner must be returned")
	require.NotNil(t, edit, "edits must be returned even when the caller ctx is expired at git-enumeration time")
	assert.Contains(t, edit.Changes, absPath)
}

// ---------------------------------------------------------------------------
// HARDEN-2: gitChangedFiles must include --no-renames
//
// Without --no-renames, git collapses a rename to only the destination path.
// The snapshot is keyed by the original path, so the destination misses the
// snapshot and is skipped; the source (deleted file) is also never surfaced —
// the old workspace file persists and the fix is silently dropped.
// With --no-renames, the rename surfaces as delete(old)+add(new); the old-path
// lookup produces a deletion edit, new.go is skipped (not in snapshot).
// ---------------------------------------------------------------------------

// TestRemediate_Rename_ProducesDeletionEdit verifies that when the runner renames
// a tracked file (old.go → new.go), a deletion edit for old.go is returned.
// Without --no-renames, the rename collapses to new.go only; old.go is never
// enumerated, so no deletion edit is produced for the requested file.
func TestRemediate_Rename_ProducesDeletionEdit(t *testing.T) {
	t.Parallel()

	repoRoot := initGitRepo(t)
	commitFile(t, repoRoot, "old.go", "package main\nvar x = 1\n")

	// Enable git rename detection so that "git diff --name-only HEAD" (without
	// --no-renames) collapses a rename to only the destination path.
	out, err := exec.Command("git", "-C", repoRoot, "config", "diff.renames", "true").CombinedOutput()
	require.NoError(t, err, "git config diff.renames: %s", string(out))

	absOldPath := filepath.Join(repoRoot, "old.go")

	// The runner stages a rename (git mv) in the worktree so git diff HEAD sees
	// both the deletion and the addition with rename detection enabled.
	runner := func(_ context.Context, _ workflow.Engine, root string, _ string) error {
		cmd := exec.Command("git", "-c", "core.checkStat=minimal", "-C", root, "mv", "old.go", "new.go")
		if mvOut, mvErr := cmd.CombinedOutput(); mvErr != nil {
			return fmt.Errorf("git mv: %w (%s)", mvErr, string(mvOut))
		}
		return nil
	}

	p := remediation.NewRemyProvider(nil, runner)

	edit, err := p.Remediate(context.Background(), remediation.RemediationRequest{
		FindingId:   "f1",
		ContentRoot: types.FilePath(repoRoot),
		FilePath:    types.FilePath(absOldPath),
	})
	require.NoError(t, err)
	// The deletion of old.go must be surfaced as a non-nil edit; without
	// --no-renames the rename collapses to new.go only and old.go is lost.
	require.NotNil(t, edit, "rename of old.go must surface a deletion edit for old.go")
	assert.Contains(t, edit.Changes, absOldPath, "edit must be keyed by old.go (the requested file)")
}

// ---------------------------------------------------------------------------
// HARDEN-3: workspaceEditFromContent must not reject empty committed files
//
// Committed-empty files (0 bytes at HEAD) have originalContent == []byte{}.
// The old guard `if len(originalContent) == 0 { return error }` causes their
// edits to be silently dropped by the `continue` in buildWorkspaceEdits.
// parseDiffHunks for "@@ -0,0 +1,N @@" sets currentLine = 0-1 = -1 which
// makes makeLineEdit return an error (startLine < 0). The fix:
//   1. Remove the empty-content guard from workspaceEditFromContent.
//   2. Clamp currentLine to 0 in parseDiffHunks when the hunk header has n=0
//      (i.e. "@@ -0,0 +... @@"), so insertions start at line 0.
// ---------------------------------------------------------------------------

// TestRemediate_EmptyFile_ProducesInsertionEdit verifies that when the runner
// writes content to a committed-empty tracked file, Remediate returns a
// correct insertion WorkspaceEdit. Before the fix, the edit is silently
// dropped. Run under -race to catch any data race in the edit path.
func TestRemediate_EmptyFile_ProducesInsertionEdit(t *testing.T) {
	t.Parallel()

	repoRoot := initGitRepo(t)
	// Commit an empty file (0 bytes at HEAD).
	commitFile(t, repoRoot, "empty.go", "")
	absPath := filepath.Join(repoRoot, "empty.go")

	runner := func(_ context.Context, _ workflow.Engine, root string, _ string) error {
		return os.WriteFile(filepath.Join(root, "empty.go"), []byte("package main\nvar x = 1\n"), 0o644)
	}

	p := remediation.NewRemyProvider(nil, runner)

	edit, err := p.Remediate(context.Background(), remediation.RemediationRequest{
		FindingId:   "f1",
		ContentRoot: types.FilePath(repoRoot),
		FilePath:    types.FilePath(absPath),
	})
	require.NoError(t, err, "empty committed file must not cause an error")
	require.NotNil(t, edit, "content written to a committed-empty file must produce an insertion edit")
	require.Contains(t, edit.Changes, absPath)

	edits := edit.Changes[absPath]
	require.NotEmpty(t, edits, "must have at least one TextEdit")

	// The insertion edit starts at line 0 (0-indexed) because the original file
	// is empty; the range end must also be 0 (pure insertion, no deletion).
	te := edits[0]
	assert.Equal(t, 0, te.Range.Start.Line, "insertion must start at line 0")
	assert.Equal(t, 0, te.Range.End.Line, "pure insertion: end line must equal start line")
	assert.Contains(t, te.NewText, "package main", "NewText must contain the inserted content")
}

// ---------------------------------------------------------------------------
// HARDEN-4: gitFileDiff must pass --no-color, --no-ext-diff, --no-textconv
//
// collectFileDiffs (the FixFolder path) explicitly documents all three flags.
// gitFileDiff (the Remediate path) omitted them. With color.diff=always in
// the repo gitconfig, git diff emits ANSI escape sequences even through a
// pipe — parseDiffHunks then fails to match the "@@ ... @@" hunk header and
// returns an empty hunk list, causing workspaceEditFromContent to return an
// error and buildWorkspaceEdits to silently drop the file. The result is a
// nil WorkspaceEdit for an otherwise successful remy run.
// ---------------------------------------------------------------------------

// TestRemediate_ColorDiffAlways_ProducesEdit verifies that when the git repo
// has color.diff=always configured, Remediate still returns a correct
// WorkspaceEdit. Without --no-color in gitFileDiff the ANSI codes corrupt
// parseDiffHunks and the edit is nil.
func TestRemediate_ColorDiffAlways_ProducesEdit(t *testing.T) {
	t.Parallel()

	repoRoot := initGitRepo(t)
	// Force ANSI color output even through a pipe, simulating a developer's
	// global gitconfig with color.diff=always.  git diff then emits escape
	// sequences unless explicitly suppressed with --no-color.
	setLocalGitConfig(t, repoRoot, "color.diff", "always")
	commitFile(t, repoRoot, "main.go", "package main\nvar x = 1\n")
	absPath := filepath.Join(repoRoot, "main.go")

	runner := func(_ context.Context, _ workflow.Engine, root string, _ string) error {
		return os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\nvar x = 2\n"), 0o644)
	}

	p := remediation.NewRemyProvider(nil, runner)

	edit, err := p.Remediate(context.Background(), remediation.RemediationRequest{
		FindingId:   "f1",
		ContentRoot: types.FilePath(repoRoot),
		FilePath:    types.FilePath(absPath),
	})
	require.NoError(t, err)
	require.NotNil(t, edit, "color.diff=always must not corrupt the diff — edit must be non-nil")
	assert.Contains(t, edit.Changes, absPath, "edit must include the modified file")
}

// setLocalGitConfig sets a key-value pair in the local git config of repoRoot.
func setLocalGitConfig(t *testing.T, repoRoot, key, value string) {
	t.Helper()
	cmd := exec.Command("git", "-C", repoRoot, "config", "--local", key, value)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git config --local %s %s: %s", key, value, string(out))
}

// ---------------------------------------------------------------------------
// HARDEN-5: gitChangedFiles must detect content changes when git's stat cache
// considers the file clean (mtime+size identical to the cached index entry).
//
// Root cause (IDE-2289): git compares worktree stat (mtime/size) against the
// index. With core.checkStat=minimal it checks ONLY mtime+size. On Windows,
// coarse last-write-time granularity places the runner's write in the same
// clock tick as the worktree checkout → mtime+size match → git skips content
// hashing → git diff reports no changes → gitChangedFiles returns empty →
// Remediate returns (nil, nil) and the completed fix is silently dropped.
//
// Git has a "racy-git" safety net: when a file's mtime equals the index
// file's own mtime, git always re-reads the file (the write could have raced
// with the index write). On Windows, slow CI means the index is written in a
// later clock tick than the checked-out files, so index_mtime > file_mtime
// and the racy check does NOT fire. We reproduce this deterministically on
// Linux by advancing the worktree index file mtime to a future time.
//
// Fix: invalidateStatCache sets the index file's own mtime to 1 second past
// the Unix epoch via os.Chtimes (not epoch itself — git's is_racy_timestamp()
// treats a zero index mtime as "unset" and skips the racy check entirely).
// Every tracked file's cached mtime is then >= the index mtime, so git's
// racy-git rule re-reads and re-hashes every entry on the next diff — one
// syscall, not one per tracked file. Unchanged files produce the same blob
// hash as HEAD and vanish from diff output; the modified file is correctly
// surfaced.
// ---------------------------------------------------------------------------

// TestRemediate_StatCleanSameSize_StillDetected forces the exact Windows
// stat-clean condition deterministically on Linux:
//  1. Commit a file with content v1.
//  2. In the worktree, overwrite with SAME-BYTE-SIZE v2 and reset mtime via
//     os.Chtimes → mtime+size match the index entry exactly (stat-clean).
//  3. Advance the worktree index file mtime to a future time, defeating git's
//     racy-git protection (which only fires when index_mtime <= file_mtime).
//
// Without the fix, git diff -z --name-only HEAD returns empty → nil edit.
func TestRemediate_StatCleanSameSize_StillDetected(t *testing.T) {
	t.Parallel()

	repoRoot := initGitRepo(t)
	// core.checkStat=minimal (second-precision mtime) is the key prerequisite:
	// the fix works by setting the index mtime to 1 second past epoch, which
	// must differ from the checkout timestamp's integer second. Explicitly set
	// it here so the test's premise is self-documenting and robust to
	// initGitRepo changes.
	setLocalGitConfig(t, repoRoot, "core.checkStat", "minimal")
	// Both versions must be exactly the same byte length — SIZE_CHANGED stays 0.
	const v1 = "package main\nvar x = 1\n"
	const v2 = "package main\nvar x = 2\n"
	if len(v1) != len(v2) {
		t.Fatalf("test invariant broken: v1 (%d bytes) != v2 (%d bytes)", len(v1), len(v2))
	}
	commitFile(t, repoRoot, "main.go", v1)
	absPath := filepath.Join(repoRoot, "main.go")

	runner := statCleanRunner("main.go", v2)

	p := remediation.NewRemyProvider(nil, runner)

	edit, err := p.Remediate(context.Background(), remediation.RemediationRequest{
		FindingId:   "f1",
		ContentRoot: types.FilePath(repoRoot),
		FilePath:    types.FilePath(absPath),
	})
	require.NoError(t, err)
	require.NotNil(t, edit,
		"content-changed file must produce an edit even when git stat cache sees mtime+size unchanged (IDE-2289 regression guard)")
	assert.Contains(t, edit.Changes, absPath)
}

// TestInvalidateStatCache_GitFailure_PropagatesError verifies that when the
// underlying git rev-parse --git-path call fails (here: root is not a git
// repository), invalidateStatCache returns a non-nil error so callers surface
// the failure rather than running git diff on a stale index and silently
// dropping a completed fix.
func TestInvalidateStatCache_GitFailure_PropagatesError(t *testing.T) {
	t.Parallel()
	// A plain temp dir has no .git — git rev-parse --git-path fails with a fatal error.
	err := remediation.InvalidateStatCacheForTest(context.Background(), t.TempDir())
	require.Error(t, err, "invalidateStatCache must propagate git failure instead of silently no-oping")
}
