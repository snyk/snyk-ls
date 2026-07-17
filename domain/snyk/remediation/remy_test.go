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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/snyk/remediation"
)

// initGitRepo sets up a minimal git repository under a temp dir and returns
// the repo root.
func initGitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	// Canonicalize so the returned path matches git's view (git rev-parse
	// --show-toplevel resolves symlinks). On macOS t.TempDir() is under /var
	// (a symlink to /private/var); without this the production canonicalization
	// produces cache keys the test's non-canonical paths never match.
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

// TestMakeLineEdit_NegativeStartLine verifies that a hunk starting at line 0
// (which translates to currentLine = -1 in 0-indexed) produces an error.
func TestMakeLineEdit_NegativeStartLine(t *testing.T) {
	diff := "@@ -0,1 +0,0 @@\n-line1\n"
	original := []byte("line1\nline2\n")

	edit, err := remediation.ExportedWorkspaceEditFromContent("/tmp/x.go", original, diff)
	assert.Error(t, err, "negative startLine must produce an error")
	assert.Nil(t, edit)
}

// TestMakeLineEdit_StartLineExceedsFileLength verifies that a hunk referencing
// a line beyond the file's length produces an error.
func TestMakeLineEdit_StartLineExceedsFileLength(t *testing.T) {
	diff := "@@ -100,1 +100,0 @@\n-phantom line\n"
	original := []byte("only one line\n")

	edit, err := remediation.ExportedWorkspaceEditFromContent("/tmp/y.go", original, diff)
	assert.Error(t, err, "startLine exceeding file length must produce an error")
	assert.Nil(t, edit)
}

// TestWorkspaceEditFromContent_EmptyOriginalContent verifies that an empty
// original content produces an error.
func TestWorkspaceEditFromContent_EmptyOriginalContent(t *testing.T) {
	edit, err := remediation.ExportedWorkspaceEditFromContent("/tmp/z.go", []byte{}, "@@ -1,1 +1,0 @@\n-something\n")
	assert.Error(t, err, "empty original content must produce an error")
	assert.Nil(t, edit)
}

// TestWorkspaceEditFromContent_EmptyDiff verifies that an empty diff string
// produces an error.
func TestWorkspaceEditFromContent_EmptyDiff(t *testing.T) {
	edit, err := remediation.ExportedWorkspaceEditFromContent("/tmp/w.go", []byte("hello\n"), "")
	assert.Error(t, err, "empty diff must produce an error")
	assert.Nil(t, edit)
}

// TestApplyInsertion_MergeConsecutive verifies that two consecutive insertion
// lines at the same source position are merged into a single TextEdit.
func TestApplyInsertion_MergeConsecutive(t *testing.T) {
	repoRoot := initGitRepo(t)
	original := "package main\n\nfunc foo() {}\n"
	commitFile(t, repoRoot, "merge.go", original)
	absPath := filepath.Join(repoRoot, "merge.go")

	diff := "@@ -3,0 +3,2 @@\n+// inserted line 1\n+// inserted line 2\n"

	edit, err := remediation.ExportedWorkspaceEditFromContent(absPath, []byte(original), diff)
	require.NoError(t, err)
	require.NotNil(t, edit)

	textEdits := edit.Changes[absPath]
	require.NotEmpty(t, textEdits)

	merged := false
	for _, te := range textEdits {
		if strings.Contains(te.NewText, "// inserted line 1") && strings.Contains(te.NewText, "// inserted line 2") {
			merged = true
		}
	}
	assert.True(t, merged, "consecutive insertions at same source line must be merged into one TextEdit")
}

// TestParseDiffHunks_MalformedHunkHeader_ReturnsError verifies that a @@ line
// that does not match the expected pattern produces an error.
func TestParseDiffHunks_MalformedHunkHeader_ReturnsError(t *testing.T) {
	diff := "@@ not-valid @@\n-hello\n"
	edit, err := remediation.ExportedWorkspaceEditFromContent("/tmp/m.go", []byte("hello\n"), diff)
	assert.Error(t, err, "malformed hunk header must produce an error")
	assert.Nil(t, edit)
}

// TestParseDiffHunks_DeletionOfDashDashLine verifies that a deletion of a line
// starting with "--" (e.g. a SQL comment "-- old query") is recorded correctly.
func TestParseDiffHunks_DeletionOfDashDashLine(t *testing.T) {
	repoRoot := initGitRepo(t)
	original := "-- old query\n"
	commitFile(t, repoRoot, "q.sql", original)
	absPath := filepath.Join(repoRoot, "q.sql")

	diff := "@@ -1 +1 @@\n--- old query\n+-- new query\n"
	edit, err := remediation.ExportedWorkspaceEditFromContent(absPath, []byte(original), diff)
	require.NoError(t, err, "deletion of a '--' line must not be treated as a file header")
	require.NotNil(t, edit)
	edits := edit.Changes[absPath]
	require.NotEmpty(t, edits)
	found := false
	for _, te := range edits {
		if te.Range.Start.Line == 0 && te.NewText == "" {
			found = true
		}
	}
	assert.True(t, found, "expected a deletion TextEdit on line 0")
}

// TestParseDiffHunks_NoNewlineAtEndOfFile verifies that the "\ No newline at end
// of file" diff marker is handled without error.
func TestParseDiffHunks_NoNewlineAtEndOfFile(t *testing.T) {
	repoRoot := initGitRepo(t)
	original := "hello"
	commitFile(t, repoRoot, "n.go", original)
	absPath := filepath.Join(repoRoot, "n.go")

	diff := "@@ -1 +1 @@\n-hello\n\\ No newline at end of file\n+world\n\\ No newline at end of file\n"
	edit, err := remediation.ExportedWorkspaceEditFromContent(absPath, []byte(original), diff)
	require.NoError(t, err, "no-newline marker must be parsed without error")
	require.NotNil(t, edit)
	assert.Contains(t, edit.Changes, absPath)
}
