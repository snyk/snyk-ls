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

// errRunner returns a remyRunner that always returns err.
func errRunner(err error) func(_ context.Context, _ workflow.Engine, _, _ string) error {
	return func(_ context.Context, _ workflow.Engine, _, _ string) error {
		return err
	}
}

// initGitRepoInDir initializes a git repository in an already-existing dir.
func initGitRepoInDir(t *testing.T, dir string) {
	t.Helper()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...) //nolint:gosec // test helper: git args are hardcoded strings, not user input
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "git %v: %s", args, string(out))
	}
	run("init")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "Test")
	run("config", "core.checkStat", "minimal")
}

// commitFileInDir is an alias for commitFile using a pre-existing repo root.
func commitFileInDir(t *testing.T, repoRoot, relPath, content string) {
	t.Helper()
	commitFile(t, repoRoot, relPath, content)
}

// ---------------------------------------------------------------------------
// UNIT-001: FixFolder returns edits keyed under the passed folder
// ---------------------------------------------------------------------------

// TestFixFolder_ReturnsEditsKeyedUnderFolder verifies that when the fake runner
// modifies a tracked file inside the passed folder, FixFolder returns a
// WorkspaceEdit whose only key is <folder>/<file>.
func TestFixFolder_ReturnsEditsKeyedUnderFolder(t *testing.T) {
	repo := initGitRepo(t)
	commitFile(t, repo, "main.go", "package main\nvar x = 1\n")

	mainAbs := filepath.Join(repo, "main.go")

	runner := func(_ context.Context, _ workflow.Engine, root, findingID string) error {
		assert.Empty(t, findingID, "runner must be called with empty findingID for folder path")
		return os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\nvar x = 2\n"), 0644)
	}

	p := remediation.NewRemyProvider(nil, runner)
	edit, err := p.FixFolder(context.Background(), types.FilePath(repo))
	require.NoError(t, err)
	require.NotNil(t, edit, "expected a WorkspaceEdit when a tracked file was modified")
	assert.Contains(t, edit.Changes, mainAbs, "edit key must be <folder>/<file>")
	for key := range edit.Changes {
		assert.True(t, len(key) > len(repo) && key[:len(repo)] == repo,
			"edit key %q must be under passed folder %q", key, repo)
	}
}

// ---------------------------------------------------------------------------
// UNIT-002: FixFolder returns (nil, nil) when runner makes no changes
// ---------------------------------------------------------------------------

func TestFixFolder_NoChangesReturnsNil(t *testing.T) {
	repo := initGitRepo(t)
	commitFile(t, repo, "main.go", "package main\nvar x = 1\n")

	p := remediation.NewRemyProvider(nil, noopRunner)
	edit, err := p.FixFolder(context.Background(), types.FilePath(repo))
	require.NoError(t, err)
	assert.Nil(t, edit, "no-change run must return nil edit")
}

// ---------------------------------------------------------------------------
// UNIT-003: FixFolder propagates runner errors
// ---------------------------------------------------------------------------

func TestFixFolder_PropagatesRunnerError(t *testing.T) {
	repo := initGitRepo(t)
	commitFile(t, repo, "main.go", "package main\n")

	sentinel := errors.New("remy runner failed")
	p := remediation.NewRemyProvider(nil, errRunner(sentinel))
	edit, err := p.FixFolder(context.Background(), types.FilePath(repo))
	require.Error(t, err)
	assert.ErrorIs(t, err, sentinel)
	assert.Nil(t, edit)
}

// ---------------------------------------------------------------------------
// UNIT-004: FixFolder rejects non-absolute / empty paths
// ---------------------------------------------------------------------------

func TestFixFolder_RejectsNonAbsolutePath(t *testing.T) {
	var runnerCalled bool
	trackingRunner := func(_ context.Context, _ workflow.Engine, _, _ string) error {
		runnerCalled = true
		return nil
	}

	p := remediation.NewRemyProvider(nil, trackingRunner)

	edit, err := p.FixFolder(context.Background(), types.FilePath("relative/path"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "absolute")
	assert.Nil(t, edit)
	assert.False(t, runnerCalled, "runner must NOT be called on invalid path")

	edit2, err2 := p.FixFolder(context.Background(), types.FilePath(""))
	require.Error(t, err2)
	assert.Contains(t, err2.Error(), "absolute")
	assert.Nil(t, edit2)
	assert.False(t, runnerCalled, "runner must NOT be called on empty path")
}

// ---------------------------------------------------------------------------
// UNIT-005a: FixFolder rejects a subdirectory of a git repo with an error
// ---------------------------------------------------------------------------

func TestFixFolder_SubdirOfGitRoot_ReturnEdits(t *testing.T) {
	repo := initGitRepo(t)
	commitFile(t, repo, "sub/main.go", "package main\nvar x = 1\n")

	subdir := filepath.Join(repo, "sub")

	var runnerCalled bool
	runner := func(_ context.Context, _ workflow.Engine, _, _ string) error {
		runnerCalled = true
		return nil
	}

	p := remediation.NewRemyProvider(nil, runner)
	edit, err := p.FixFolder(context.Background(), types.FilePath(subdir))
	require.Error(t, err, "FixFolder must return an error when passed a subdirectory of a git root")
	assert.Nil(t, edit, "FixFolder must return nil edit when returning an error")
	assert.False(t, runnerCalled, "runner must NOT be called when the precondition guard fires")
}

// ---------------------------------------------------------------------------
// UNIT-005b: FixFolder rejects a directory that is not a git repository
// ---------------------------------------------------------------------------

func TestFixFolder_NonGitDirectory_ReturnsError(t *testing.T) {
	nonGit := t.TempDir()

	var runnerCalled bool
	runner := func(_ context.Context, _ workflow.Engine, _, _ string) error {
		runnerCalled = true
		return nil
	}

	p := remediation.NewRemyProvider(nil, runner)
	edit, err := p.FixFolder(context.Background(), types.FilePath(nonGit))
	require.Error(t, err, "FixFolder must return an error for a non-git directory")
	assert.Nil(t, edit)
	assert.False(t, runnerCalled, "runner must NOT be called when the precondition guard fires")
}

// TestFixFolder_GitRoot_EditsKeyedUnderPassedRoot asserts the daemon contract:
// when the passed folder IS the git root, edits are keyed under that folder.
func TestFixFolder_GitRoot_EditsKeyedUnderPassedRoot(t *testing.T) {
	repo := initGitRepo(t)
	commitFile(t, repo, "main.go", "package main\nvar x = 1\n")

	mainAbs := filepath.Join(repo, "main.go")

	runner := func(_ context.Context, _ workflow.Engine, root, _ string) error {
		return os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\nvar x = 2\n"), 0644)
	}

	p := remediation.NewRemyProvider(nil, runner)
	edit, err := p.FixFolder(context.Background(), types.FilePath(repo))
	require.NoError(t, err)
	require.NotNil(t, edit)
	assert.Contains(t, edit.Changes, mainAbs)
	for key := range edit.Changes {
		assert.True(t, len(key) > len(repo) && key[:len(repo)] == repo,
			"edit key %q must be under passed folder %q", key, repo)
	}
}

// ---------------------------------------------------------------------------
// UNIT-005: FixFolder runs directly in the passed folder (no nested worktree)
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
	_, err := p.FixFolder(context.Background(), types.FilePath(repo))
	require.NoError(t, err)

	assert.Equal(t, repo, invokedWith, "runner must be invoked with the passed folder, not a child dir")

	entries, readErr := os.ReadDir(repo)
	require.NoError(t, readErr)
	for _, e := range entries {
		assert.NotContains(t, e.Name(), "snyk-remy-",
			"no nested snyk-remy-* temp dir must be created inside the passed folder")
	}

	parent := filepath.Dir(repo)
	siblings, _ := os.ReadDir(parent)
	for _, s := range siblings {
		if s.IsDir() && s.Name() != filepath.Base(repo) {
			assert.NotContains(t, s.Name(), "wt",
				"no nested worktree dir must be created as a sibling of the passed folder")
		}
	}
}

// ---------------------------------------------------------------------------
// DAEMON CONTRACT: FixFolder edit keys must be under the PASSED (non-canonical) path
// ---------------------------------------------------------------------------

func TestFixFolder_SymlinkPath_EditsKeyedUnderPassedPath(t *testing.T) {
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
	edit, err := p.FixFolder(context.Background(), types.FilePath(linkDir))
	require.NoError(t, err)
	require.NotNil(t, edit, "FixFolder must return a non-nil edit when a file was modified")

	for key := range edit.Changes {
		assert.True(t, strings.HasPrefix(key, linkDir+string(filepath.Separator)),
			"edit key %q must be prefixed by the passed symlinked path %q (daemon contract); "+
				"if it is prefixed by the canonical path %q, FixFolder incorrectly canonicalized r",
			key, linkDir, realDir)
	}
}
