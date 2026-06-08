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

	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/snyk/remediation"
	"github.com/snyk/snyk-ls/internal/types"
)

// initGitRepo sets up a minimal git repository under dir so the provider can
// use git-based change detection. Returns the repo root.
func initGitRepo(t *testing.T) string {
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
	return dir
}

// commitFile writes content to path (relative to repo root), stages, and commits it.
func commitFile(t *testing.T, repoRoot, relPath, content string) {
	t.Helper()
	absPath := filepath.Join(repoRoot, relPath)
	require.NoError(t, os.MkdirAll(filepath.Dir(absPath), 0o755))
	require.NoError(t, os.WriteFile(absPath, []byte(content), 0o644))

	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repoRoot
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "git %v: %s", args, string(out))
	}

	run("add", relPath)
	run("commit", "-m", "initial")
}

// fakeRunner is a test remyRunner that accepts (and ignores) a nil engine.
// fn is the actual test logic to run.
func fakeRunner(fn func(ctx context.Context, root string, findingID string) error) func(ctx context.Context, eng workflow.Engine, root string, findingID string) error {
	return func(ctx context.Context, _ workflow.Engine, root string, findingID string) error {
		return fn(ctx, root, findingID)
	}
}

// TestRemyProvider_EmptyFindingId_ReturnsNil asserts that an empty FindingId
// produces (nil, nil) and the runner is never called.
func TestRemyProvider_EmptyFindingId_ReturnsNil(t *testing.T) {
	called := false
	runner := fakeRunner(func(_ context.Context, _ string, _ string) error {
		called = true
		return nil
	})

	p := remediation.NewRemyProvider(nil, runner)

	edit, err := p.Remediate(context.Background(), remediation.RemediationRequest{
		FindingId:   "",
		ContentRoot: "/some/path",
		FilePath:    "/some/path/file.go",
	})

	require.NoError(t, err)
	assert.Nil(t, edit)
	assert.False(t, called, "runner must not be called when FindingId is empty")
}

// TestRemyProvider_EmptyContentRoot_ReturnsNil asserts that an empty ContentRoot
// produces (nil, nil) and the runner is never called.
func TestRemyProvider_EmptyContentRoot_ReturnsNil(t *testing.T) {
	called := false
	runner := fakeRunner(func(_ context.Context, _ string, _ string) error {
		called = true
		return nil
	})

	p := remediation.NewRemyProvider(nil, runner)

	edit, err := p.Remediate(context.Background(), remediation.RemediationRequest{
		FindingId:   "some-finding-id",
		ContentRoot: "",
		FilePath:    "/some/path/file.go",
	})

	require.NoError(t, err)
	assert.Nil(t, edit)
	assert.False(t, called, "runner must not be called when ContentRoot is empty")
}

// TestRemyProvider_EmptyFilePath_ReturnsNil asserts that an empty FilePath
// produces (nil, nil) and the runner is never called.
func TestRemyProvider_EmptyFilePath_ReturnsNil(t *testing.T) {
	called := false
	runner := fakeRunner(func(_ context.Context, _ string, _ string) error {
		called = true
		return nil
	})

	p := remediation.NewRemyProvider(nil, runner)

	edit, err := p.Remediate(context.Background(), remediation.RemediationRequest{
		FindingId:   "some-finding-id",
		ContentRoot: "/some/path",
		FilePath:    "",
	})

	require.NoError(t, err)
	assert.Nil(t, edit)
	assert.False(t, called, "runner must not be called when FilePath is empty")
}

// TestRemyProvider_CallsRunnerWithCorrectArgs verifies that the runner receives
// an isolated worktree path (not the real workspace) and the correct FindingId.
func TestRemyProvider_CallsRunnerWithCorrectArgs(t *testing.T) {
	repoRoot := initGitRepo(t)
	commitFile(t, repoRoot, "main.go", "package main\n\nfunc main() {}\n")

	var gotRoot, gotFindingID string
	runner := fakeRunner(func(_ context.Context, root string, findingID string) error {
		gotRoot = root
		gotFindingID = findingID
		return nil
	})

	p := remediation.NewRemyProvider(nil, runner)

	_, err := p.Remediate(context.Background(), remediation.RemediationRequest{
		FindingId:   "finding-abc",
		ContentRoot: types.FilePath(repoRoot),
		FilePath:    types.FilePath(filepath.Join(repoRoot, "main.go")),
	})
	require.NoError(t, err)

	// Runner receives the temporary worktree path, not the real workspace root.
	assert.NotEqual(t, repoRoot, gotRoot, "runner must receive isolated worktree, not real workspace")
	assert.True(t, filepath.IsAbs(gotRoot), "worktree path must be absolute")
	assert.Equal(t, "finding-abc", gotFindingID)
}

// TestRemyProvider_RunnerError_Propagated verifies that errors from the runner
// are returned to the caller.
func TestRemyProvider_RunnerError_Propagated(t *testing.T) {
	repoRoot := initGitRepo(t)
	commitFile(t, repoRoot, "main.go", "package main\n\nfunc main() {}\n")

	runnerErr := errors.New("remy subprocess failed")
	runner := fakeRunner(func(_ context.Context, _ string, _ string) error {
		return runnerErr
	})

	p := remediation.NewRemyProvider(nil, runner)

	edit, err := p.Remediate(context.Background(), remediation.RemediationRequest{
		FindingId:   "finding-abc",
		ContentRoot: types.FilePath(repoRoot),
		FilePath:    types.FilePath(filepath.Join(repoRoot, "main.go")),
	})

	assert.ErrorIs(t, err, runnerErr)
	assert.Nil(t, edit)
}

// TestRemyProvider_NoChanges_ReturnsNil verifies that when the runner makes no
// changes to the ContentRoot, Remediate returns (nil, nil).
func TestRemyProvider_NoChanges_ReturnsNil(t *testing.T) {
	repoRoot := initGitRepo(t)
	commitFile(t, repoRoot, "main.go", "package main\n\nfunc main() {}\n")

	runner := fakeRunner(func(_ context.Context, _ string, _ string) error {
		return nil
	})

	p := remediation.NewRemyProvider(nil, runner)

	edit, err := p.Remediate(context.Background(), remediation.RemediationRequest{
		FindingId:   "finding-abc",
		ContentRoot: types.FilePath(repoRoot),
		FilePath:    types.FilePath(filepath.Join(repoRoot, "main.go")),
	})

	require.NoError(t, err)
	assert.Nil(t, edit, "no changes should produce nil edit")
}

// TestRemyProvider_ReturnsWorkspaceEdit verifies that when the fake runner
// writes a known change to a file in the worktree, Remediate returns a
// WorkspaceEdit keyed by the real workspace path (not the temp worktree path).
func TestRemyProvider_ReturnsWorkspaceEdit(t *testing.T) {
	repoRoot := initGitRepo(t)
	original := "package main\n\nimport \"fmt\"\n\nfunc main() {\n\tfmt.Println(\"hello\")\n}\n"
	commitFile(t, repoRoot, "main.go", original)

	modified := "package main\n\nimport \"fmt\"\n\nfunc main() {\n\tfmt.Println(\"world\")\n}\n"
	// The Changes key must use the real workspace path, not the worktree path.
	absPath := filepath.Join(repoRoot, "main.go")

	runner := fakeRunner(func(_ context.Context, root string, _ string) error {
		// Write to the worktree root the runner received, not repoRoot.
		return os.WriteFile(filepath.Join(root, "main.go"), []byte(modified), 0o644)
	})

	p := remediation.NewRemyProvider(nil, runner)

	edit, err := p.Remediate(context.Background(), remediation.RemediationRequest{
		FindingId:   "finding-abc",
		ContentRoot: types.FilePath(repoRoot),
		FilePath:    types.FilePath(absPath),
	})

	require.NoError(t, err)
	require.NotNil(t, edit, "changed file should produce a non-nil WorkspaceEdit")
	require.Contains(t, edit.Changes, absPath, "Changes should be keyed by absolute path")

	textEdits := edit.Changes[absPath]
	require.NotEmpty(t, textEdits, "should have at least one TextEdit")

	// The edit should affect line 5 (0-indexed). The unified diff for a
	// single-line replacement produces a deletion TextEdit (NewText="") followed
	// by an insertion TextEdit (NewText contains "world"). Verify that at least
	// one TextEdit touches line 5 and that collectively the edits reference "world".
	var affectsLine5 bool
	var hasWorld bool
	for _, te := range textEdits {
		if te.Range.Start.Line == 5 {
			affectsLine5 = true
		}
		if strings.Contains(te.NewText, "world") {
			hasWorld = true
		}
	}
	assert.True(t, affectsLine5, "expected at least one TextEdit on line 5")
	assert.True(t, hasWorld, "expected a TextEdit whose NewText contains 'world'")
}

// TestRemyProvider_MultiFileChange_PartitionsAndCaches verifies that when remy
// changes multiple files:
//   - the first Remediate call returns only the changes for req.FilePath
//   - changes for the other files are cached
//   - the second Remediate call (for another file) is served from cache without
//     re-invoking the runner
func TestRemyProvider_MultiFileChange_PartitionsAndCaches(t *testing.T) {
	repoRoot := initGitRepo(t)
	commitFile(t, repoRoot, "a.go", "package main\n\nvar X = 1\n")
	commitFile(t, repoRoot, "b.go", "package main\n\nvar Y = 2\n")

	absA := filepath.Join(repoRoot, "a.go")
	absB := filepath.Join(repoRoot, "b.go")

	runnerCalls := 0
	runner := fakeRunner(func(_ context.Context, root string, _ string) error {
		runnerCalls++
		if err := os.WriteFile(filepath.Join(root, "a.go"), []byte("package main\n\nvar X = 10\n"), 0o644); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(root, "b.go"), []byte("package main\n\nvar Y = 20\n"), 0o644)
	})

	p := remediation.NewRemyProvider(nil, runner)

	// First call: code action invoked at a.go — should return only a.go changes.
	editA, err := p.Remediate(context.Background(), remediation.RemediationRequest{
		FindingId:   "finding-a",
		ContentRoot: types.FilePath(repoRoot),
		FilePath:    types.FilePath(absA),
	})
	require.NoError(t, err)
	require.NotNil(t, editA, "first call must return changes for a.go")
	assert.Contains(t, editA.Changes, absA, "first edit must be keyed by a.go workspace path")
	assert.NotContains(t, editA.Changes, absB, "first edit must not include b.go")
	assert.Equal(t, 1, runnerCalls, "runner must be called exactly once")

	// Second call: code action invoked at b.go — must be served from cache.
	editB, err := p.Remediate(context.Background(), remediation.RemediationRequest{
		FindingId:   "finding-b",
		ContentRoot: types.FilePath(repoRoot),
		FilePath:    types.FilePath(absB),
	})
	require.NoError(t, err)
	require.NotNil(t, editB, "second call must return cached changes for b.go")
	assert.Contains(t, editB.Changes, absB, "second edit must be keyed by b.go workspace path")
	assert.NotContains(t, editB.Changes, absA, "second edit must not include a.go")
	assert.Equal(t, 1, runnerCalls, "runner must NOT be called again on cache hit")
}

// TestMakeLineEdit_NegativeStartLine verifies that makeLineEdit returns an error
// when startLine is negative. We test this by constructing a diff that would
// trigger a negative cursor position. Since makeLineEdit is unexported, we test
// it indirectly via workspaceEditFromContent with a crafted diff hunk.
func TestMakeLineEdit_NegativeStartLine(t *testing.T) {
	// A diff hunk that references line 0 (which translates to currentLine = -1
	// when 1-indexed is converted to 0-indexed) followed by a deletion triggers
	// the negative-index guard in makeLineEdit.
	// @@ -0,1 +0,0 @@ means startLine=0 in diff (1-indexed), which becomes -1 (0-indexed).
	// We set up real git fixtures to drive the full path.
	repoRoot := initGitRepo(t)
	// Use a file with content to commit.
	commitFile(t, repoRoot, "x.go", "line1\nline2\n")

	// Craft a diff that has hunk starting at line 0 (malformed: should start at 1).
	// parseDiffHunks converts "0" to currentLine = -1, and the "-" deletion
	// calls applyDeletion(s, lastLine) which then calls makeLineEdit(-1, 0, "", lastLine).
	// That must return an error; parseDiffHunks returns it; workspaceEditFromContent
	// propagates it.
	diff := "@@ -0,1 +0,0 @@\n-line1\n"
	original := []byte("line1\nline2\n")
	absPath := filepath.Join(repoRoot, "x.go")

	edit, err := remediation.ExportedWorkspaceEditFromContent(absPath, original, diff)
	assert.Error(t, err, "negative startLine must produce an error")
	assert.Nil(t, edit)
}

// TestMakeLineEdit_StartLineExceedsFileLength verifies that a hunk referencing
// a line beyond the file's length produces an error via workspaceEditFromContent.
func TestMakeLineEdit_StartLineExceedsFileLength(t *testing.T) {
	repoRoot := initGitRepo(t)
	commitFile(t, repoRoot, "y.go", "only one line\n")

	// File has 2 lines after split (["only one line", ""]). lastLine = 2.
	// A hunk at line 100 means currentLine = 99 which exceeds lastLine.
	diff := "@@ -100,1 +100,0 @@\n-phantom line\n"
	original := []byte("only one line\n")
	absPath := filepath.Join(repoRoot, "y.go")

	edit, err := remediation.ExportedWorkspaceEditFromContent(absPath, original, diff)
	assert.Error(t, err, "startLine exceeding file length must produce an error")
	assert.Nil(t, edit)
}

// TestWorkspaceEditFromContent_EmptyOriginalContent verifies that an empty
// original content produces an error.
func TestWorkspaceEditFromContent_EmptyOriginalContent(t *testing.T) {
	repoRoot := initGitRepo(t)
	commitFile(t, repoRoot, "z.go", "something\n")
	absPath := filepath.Join(repoRoot, "z.go")

	edit, err := remediation.ExportedWorkspaceEditFromContent(absPath, []byte{}, "@@ -1,1 +1,0 @@\n-something\n")
	assert.Error(t, err, "empty original content must produce an error")
	assert.Nil(t, edit)
}

// TestWorkspaceEditFromContent_EmptyDiff verifies that an empty diff string
// produces an error.
func TestWorkspaceEditFromContent_EmptyDiff(t *testing.T) {
	repoRoot := initGitRepo(t)
	commitFile(t, repoRoot, "w.go", "hello\n")
	absPath := filepath.Join(repoRoot, "w.go")

	// An empty string diff: strings.Split("", "\n") produces [""] which has
	// length 1, and after removing the trailing empty element we get length 0,
	// triggering the "diff is empty" guard.
	edit, err := remediation.ExportedWorkspaceEditFromContent(absPath, []byte("hello\n"), "")
	assert.Error(t, err, "empty diff must produce an error")
	assert.Nil(t, edit)
}

// TestApplyInsertion_MergeConsecutive verifies that two consecutive insertion
// lines at the same source position are merged into a single TextEdit.
func TestApplyInsertion_MergeConsecutive(t *testing.T) {
	repoRoot := initGitRepo(t)
	// Commit a file so we can compute a real diff.
	original := "package main\n\nfunc foo() {}\n"
	commitFile(t, repoRoot, "merge.go", original)

	absPath := filepath.Join(repoRoot, "merge.go")

	// The diff inserts two consecutive lines before line 3 (0-indexed line 2).
	// In unified diff format, "+line" lines at the same hunk position before any
	// context or deletion line should be merged.
	diff := "@@ -3,0 +3,2 @@\n+// inserted line 1\n+// inserted line 2\n"

	edit, err := remediation.ExportedWorkspaceEditFromContent(absPath, []byte(original), diff)
	require.NoError(t, err)
	require.NotNil(t, edit)

	textEdits := edit.Changes[absPath]
	require.NotEmpty(t, textEdits)

	// Both insertions must be merged into one TextEdit.
	merged := false
	for _, te := range textEdits {
		if strings.Contains(te.NewText, "// inserted line 1") && strings.Contains(te.NewText, "// inserted line 2") {
			merged = true
		}
	}
	assert.True(t, merged, "consecutive insertions at same source line must be merged into one TextEdit")
}

// TestRemyProvider_InvalidateFile_EvictsFromCache verifies that calling
// InvalidateFile removes the specified path from the cache so that the next
// Remediate call for that file triggers a new remy run rather than serving
// stale cached diffs.
func TestRemyProvider_InvalidateFile_EvictsFromCache(t *testing.T) {
	repoRoot := initGitRepo(t)
	commitFile(t, repoRoot, "a.go", "package main\n\nvar X = 1\n")
	commitFile(t, repoRoot, "b.go", "package main\n\nvar Y = 2\n")

	absA := filepath.Join(repoRoot, "a.go")
	absB := filepath.Join(repoRoot, "b.go")

	runnerCalls := 0
	runner := fakeRunner(func(_ context.Context, root string, _ string) error {
		runnerCalls++
		if err := os.WriteFile(filepath.Join(root, "a.go"), []byte("package main\n\nvar X = 10\n"), 0o644); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(root, "b.go"), []byte("package main\n\nvar Y = 20\n"), 0o644)
	})

	p := remediation.NewRemyProvider(nil, runner)

	// First call populates cache with b.go changes.
	_, err := p.Remediate(context.Background(), remediation.RemediationRequest{
		FindingId:   "finding-a",
		ContentRoot: types.FilePath(repoRoot),
		FilePath:    types.FilePath(absA),
	})
	require.NoError(t, err)
	assert.Equal(t, 1, runnerCalls)

	// Invalidate b.go as if didChange fired for it.
	inv, ok := p.(remediation.FileChangeNotifier)
	require.True(t, ok, "remyProvider must implement FileChangeNotifier")
	inv.InvalidateFile(types.FilePath(absB))

	// Second call for b.go must re-run remy, not serve from (now-evicted) cache.
	editB, err := p.Remediate(context.Background(), remediation.RemediationRequest{
		FindingId:   "finding-b",
		ContentRoot: types.FilePath(repoRoot),
		FilePath:    types.FilePath(absB),
	})
	require.NoError(t, err)
	assert.Equal(t, 2, runnerCalls, "runner must be called again after cache eviction")
	require.NotNil(t, editB)
	assert.Contains(t, editB.Changes, absB)
}

// TestRemediate_GitRoot_SubdirWorkspace verifies that when ContentRoot is a
// subdirectory of a git repo, Remediate resolves the git root and produces
// Changes keyed by the correct absolute workspace paths (gitRoot/relPath),
// not by subdirRoot/relPath.
func TestRemediate_GitRoot_SubdirWorkspace(t *testing.T) {
	// Set up a repo at the parent level.
	repoRoot := initGitRepo(t)
	commitFile(t, repoRoot, "pkg/main.go", "package main\n\nvar X = 1\n")

	// Simulate a workspace folder that is a subdirectory of the repo.
	subdir := filepath.Join(repoRoot, "pkg")
	absMain := filepath.Join(repoRoot, "pkg", "main.go")

	runner := fakeRunner(func(_ context.Context, root string, _ string) error {
		return os.WriteFile(filepath.Join(root, "pkg", "main.go"), []byte("package main\n\nvar X = 10\n"), 0o644)
	})

	p := remediation.NewRemyProvider(nil, runner)

	edit, err := p.Remediate(context.Background(), remediation.RemediationRequest{
		FindingId:   "finding-subdir",
		ContentRoot: types.FilePath(subdir),
		FilePath:    types.FilePath(absMain),
	})
	require.NoError(t, err)
	require.NotNil(t, edit, "subdir workspace must produce a non-nil edit")
	assert.Contains(t, edit.Changes, absMain,
		"Changes must be keyed by the real workspace path (gitRoot/relPath), not subdir/relPath")
}

// TestNewRemyProvider_NilRunner_SetsDefault verifies that NewRemyProvider with a
// nil runner substitutes the default gafRunner. The default runner is never
// invoked here because Remediate short-circuits on empty FindingId.
func TestNewRemyProvider_NilRunner_SetsDefault(t *testing.T) {
	p := remediation.NewRemyProvider(nil, nil)
	require.NotNil(t, p)
	edit, err := p.Remediate(context.Background(), remediation.RemediationRequest{})
	require.NoError(t, err)
	assert.Nil(t, edit)
}

// TestRemyProvider_ContentRootNotGitRepo_ReturnsError verifies that when
// ContentRoot is not inside a git repository, Remediate returns an error from
// the git root resolution step.
func TestRemyProvider_ContentRootNotGitRepo_ReturnsError(t *testing.T) {
	runner := fakeRunner(func(_ context.Context, _ string, _ string) error { return nil })
	p := remediation.NewRemyProvider(nil, runner)

	notARepo := t.TempDir() // plain directory, no .git
	_, err := p.Remediate(context.Background(), remediation.RemediationRequest{
		FindingId:   "finding-x",
		ContentRoot: types.FilePath(notARepo),
		FilePath:    types.FilePath(filepath.Join(notARepo, "file.go")),
	})
	assert.Error(t, err, "ContentRoot not in a git repo must produce an error")
}

// TestRemyProvider_NonAbsoluteContentRoot_ReturnsError verifies that a relative
// ContentRoot path produces an error.
func TestRemyProvider_NonAbsoluteContentRoot_ReturnsError(t *testing.T) {
	runner := fakeRunner(func(_ context.Context, _ string, _ string) error { return nil })
	p := remediation.NewRemyProvider(nil, runner)

	_, err := p.Remediate(context.Background(), remediation.RemediationRequest{
		FindingId:   "finding-x",
		ContentRoot: "relative/path",
		FilePath:    "/abs/file.go",
	})
	assert.Error(t, err, "non-absolute ContentRoot must produce an error")
}

// TestRemyProvider_FilePathNotInChanges_ReturnsNil verifies that when remy only
// changes files other than req.FilePath, Remediate returns (nil, nil).
func TestRemyProvider_FilePathNotInChanges_ReturnsNil(t *testing.T) {
	repoRoot := initGitRepo(t)
	commitFile(t, repoRoot, "a.go", "package main\n\nvar X = 1\n")
	commitFile(t, repoRoot, "b.go", "package main\n\nvar Y = 2\n")

	absA := filepath.Join(repoRoot, "a.go")

	runner := fakeRunner(func(_ context.Context, root string, _ string) error {
		return os.WriteFile(filepath.Join(root, "b.go"), []byte("package main\n\nvar Y = 20\n"), 0o644)
	})

	p := remediation.NewRemyProvider(nil, runner)

	edit, err := p.Remediate(context.Background(), remediation.RemediationRequest{
		FindingId:   "finding-a",
		ContentRoot: types.FilePath(repoRoot),
		FilePath:    types.FilePath(absA),
	})
	require.NoError(t, err)
	assert.Nil(t, edit, "remy did not touch req.FilePath, so edit must be nil")
}

// TestCacheValid_StatError_InvalidatesCache verifies that when a cached file is
// deleted on disk, cacheValid returns false and the next Remediate re-runs remy.
func TestCacheValid_StatError_InvalidatesCache(t *testing.T) {
	repoRoot := initGitRepo(t)
	commitFile(t, repoRoot, "a.go", "package main\n\nvar X = 1\n")
	commitFile(t, repoRoot, "b.go", "package main\n\nvar Y = 2\n")

	absA := filepath.Join(repoRoot, "a.go")
	absB := filepath.Join(repoRoot, "b.go")

	runnerCalls := 0
	runner := fakeRunner(func(_ context.Context, root string, _ string) error {
		runnerCalls++
		if err := os.WriteFile(filepath.Join(root, "a.go"), []byte("package main\n\nvar X = 10\n"), 0o644); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(root, "b.go"), []byte("package main\n\nvar Y = 20\n"), 0o644)
	})

	p := remediation.NewRemyProvider(nil, runner)

	_, err := p.Remediate(context.Background(), remediation.RemediationRequest{
		FindingId:   "finding-a",
		ContentRoot: types.FilePath(repoRoot),
		FilePath:    types.FilePath(absA),
	})
	require.NoError(t, err)
	assert.Equal(t, 1, runnerCalls)

	// Delete b.go from workspace so os.Stat fails in cacheValid → cache evicted.
	require.NoError(t, os.Remove(absB))

	_, err = p.Remediate(context.Background(), remediation.RemediationRequest{
		FindingId:   "finding-b",
		ContentRoot: types.FilePath(repoRoot),
		FilePath:    types.FilePath(absB),
	})
	// Runner re-invoked because cache was invalidated by Stat failure.
	assert.Equal(t, 2, runnerCalls, "runner must re-run after Stat-based cache invalidation")
	_ = err
}

// TestParseDiffHunks_MalformedHunkHeader_ReturnsError verifies that a @@ line
// that does not match the expected pattern produces an error.
func TestParseDiffHunks_MalformedHunkHeader_ReturnsError(t *testing.T) {
	repoRoot := initGitRepo(t)
	commitFile(t, repoRoot, "m.go", "hello\n")
	absPath := filepath.Join(repoRoot, "m.go")

	diff := "@@ not-valid @@\n-hello\n"
	edit, err := remediation.ExportedWorkspaceEditFromContent(absPath, []byte("hello\n"), diff)
	assert.Error(t, err, "malformed hunk header must produce an error")
	assert.Nil(t, edit)
}

// TestParseDiffHunks_DeleteionOfDashDashLine verifies that a deletion of a line
// starting with "--" (e.g. a SQL comment "-- old query") is recorded correctly.
// The diff line for that deletion is "--- old query", which must NOT be confused
// with a file header and must produce a TextEdit deleting the original line.
func TestParseDiffHunks_DeletionOfDashDashLine(t *testing.T) {
	repoRoot := initGitRepo(t)
	original := "-- old query\n"
	commitFile(t, repoRoot, "q.sql", original)
	absPath := filepath.Join(repoRoot, "q.sql")

	// Diff: delete "-- old query" (→ diff line "--- old query"), insert "-- new query".
	diff := "@@ -1 +1 @@\n--- old query\n+-- new query\n"
	edit, err := remediation.ExportedWorkspaceEditFromContent(absPath, []byte(original), diff)
	require.NoError(t, err, "deletion of a '--' line must not be treated as a file header")
	require.NotNil(t, edit, "deletion of '--' line must produce a non-nil edit")
	edits := edit.Changes[absPath]
	require.NotEmpty(t, edits, "must have at least one TextEdit")
	// The deletion TextEdit must target line 0 and have empty NewText.
	found := false
	for _, te := range edits {
		if te.Range.Start.Line == 0 && te.NewText == "" {
			found = true
		}
	}
	assert.True(t, found, "expected a deletion TextEdit on line 0")
}

// TestParseDiffHunks_NoNewlineAtEndOfFile verifies that the "\ No newline at end
// of file" diff marker is handled without error by adjusting the line cursor.
func TestParseDiffHunks_NoNewlineAtEndOfFile(t *testing.T) {
	repoRoot := initGitRepo(t)
	original := "hello"
	commitFile(t, repoRoot, "n.go", original)
	absPath := filepath.Join(repoRoot, "n.go")

	// Unified diff for changing "hello" (no newline) to "world" (no newline).
	diff := "@@ -1 +1 @@\n-hello\n\\ No newline at end of file\n+world\n\\ No newline at end of file\n"
	edit, err := remediation.ExportedWorkspaceEditFromContent(absPath, []byte(original), diff)
	require.NoError(t, err, "no-newline marker must be parsed without error")
	require.NotNil(t, edit)
	assert.Contains(t, edit.Changes, absPath)
}
