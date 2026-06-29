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
	"path/filepath"
	"strings"
	"testing"

	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/snyk/remediation"
	"github.com/snyk/snyk-ls/internal/types"
)

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
		// findingID must be empty for the folder path
		assert.Empty(t, findingID, "runner must be called with empty findingID for folder path")
		return os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\nvar x = 2\n"), 0644)
	}

	p := remediation.NewRemyProvider(nil, runner)
	fr, ok := p.(remediation.FolderRemediator)
	require.True(t, ok, "remyProvider must implement FolderRemediator")

	edit, err := fr.FixFolder(context.Background(), types.FilePath(repo))
	require.NoError(t, err)
	require.NotNil(t, edit, "expected a WorkspaceEdit when a tracked file was modified")
	assert.Contains(t, edit.Changes, mainAbs, "edit key must be <folder>/<file>")
	// Every key in the edit must be under the passed folder.
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
	fr, ok := p.(remediation.FolderRemediator)
	require.True(t, ok)

	edit, err := fr.FixFolder(context.Background(), types.FilePath(repo))
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
	fr, ok := p.(remediation.FolderRemediator)
	require.True(t, ok)

	edit, err := fr.FixFolder(context.Background(), types.FilePath(repo))
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
	fr, ok := p.(remediation.FolderRemediator)
	require.True(t, ok)

	// Relative path
	edit, err := fr.FixFolder(context.Background(), types.FilePath("relative/path"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "absolute")
	assert.Nil(t, edit)
	assert.False(t, runnerCalled, "runner must NOT be called on invalid path")

	// Empty path
	edit2, err2 := fr.FixFolder(context.Background(), types.FilePath(""))
	require.Error(t, err2)
	assert.Contains(t, err2.Error(), "absolute")
	assert.Nil(t, edit2)
	assert.False(t, runnerCalled, "runner must NOT be called on empty path")
}

// ---------------------------------------------------------------------------
// UNIT-005a: FixFolder rejects a subdirectory of a git repo with an error
// ---------------------------------------------------------------------------

// TestFixFolder_SubdirOfGitRoot_ReturnEdits verifies that FixFolder returns a
// non-nil error (and no edits) when the passed path is a subdirectory of the
// git root. The contract requires the caller to pass the git repository root
// itself (e.g. a detached-HEAD worktree created by the daemon); passing a
// subdirectory is rejected so the fix runner cannot silently escape its
// isolation boundary.
func TestFixFolder_SubdirOfGitRoot_ReturnEdits(t *testing.T) {
	// Create a git repo with a tracked file inside a subdirectory.
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
	require.True(t, ok, "remyProvider must implement FolderRemediator")

	// Call FixFolder with the SUBDIRECTORY path — must return an error.
	edit, err := fr.FixFolder(context.Background(), types.FilePath(subdir))
	require.Error(t, err, "FixFolder must return an error when passed a subdirectory of a git root")
	assert.Nil(t, edit, "FixFolder must return nil edit when returning an error")
	assert.False(t, runnerCalled, "runner must NOT be called when the precondition guard fires")
}

// ---------------------------------------------------------------------------
// UNIT-005b: FixFolder rejects a directory that is not a git repository
// ---------------------------------------------------------------------------

// TestFixFolder_NonGitDirectory_ReturnsError verifies that FixFolder returns a
// non-nil error when the passed path is not inside any git repository.
func TestFixFolder_NonGitDirectory_ReturnsError(t *testing.T) {
	// Use a temp dir that has no git init — it is not a git repo.
	nonGit := t.TempDir()

	var runnerCalled bool
	runner := func(_ context.Context, _ workflow.Engine, _, _ string) error {
		runnerCalled = true
		return nil
	}

	p := remediation.NewRemyProvider(nil, runner)
	fr, ok := p.(remediation.FolderRemediator)
	require.True(t, ok)

	edit, err := fr.FixFolder(context.Background(), types.FilePath(nonGit))
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
	fr, ok := p.(remediation.FolderRemediator)
	require.True(t, ok)

	edit, err := fr.FixFolder(context.Background(), types.FilePath(repo))
	require.NoError(t, err)
	require.NotNil(t, edit)
	// Daemon contract: key must be under the passed folder (repo root here).
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
	fr, ok := p.(remediation.FolderRemediator)
	require.True(t, ok)

	_, err := fr.FixFolder(context.Background(), types.FilePath(repo))
	require.NoError(t, err)

	// Runner must be invoked with exactly the passed folder.
	assert.Equal(t, repo, invokedWith, "runner must be invoked with the passed folder, not a child dir")

	// No snyk-remy-* temp directories must have been created inside the folder.
	entries, readErr := os.ReadDir(repo)
	require.NoError(t, readErr)
	for _, e := range entries {
		assert.NotContains(t, e.Name(), "snyk-remy-",
			"no nested snyk-remy-* temp dir must be created inside the passed folder")
	}

	// Also assert no worktree child exists as a sibling with "wt" suffix.
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

// TestFixFolder_SymlinkPath_EditsKeyedUnderPassedPath locks the daemon contract:
// when the caller passes a symlinked folder path as ContentRoot, FixFolder must
// return edit keys under the EXACT passed path (not the canonicalized/resolved
// path). The external daemon remaps edits by the prefix of the path it passed;
// canonicalizing `r` inside FixFolder would make edits key under the resolved
// path, breaking the daemon's prefix match on any path with a symlink component.
//
// On Linux we reproduce the macOS /var→/private/var class by creating an
// explicit symlink. The test is skipped gracefully if symlink creation fails.
func TestFixFolder_SymlinkPath_EditsKeyedUnderPassedPath(t *testing.T) {
	// Set up a real git repo under a canonical dir.
	realDir := t.TempDir()
	var err error
	realDir, err = filepath.EvalSymlinks(realDir)
	require.NoError(t, err)
	initGitRepoInDir(t, realDir)
	commitFileInDir(t, realDir, "main.go", "package main\nvar x = 1\n")

	// Create a symlink to the real dir — the daemon-like caller passes this.
	linkDir := filepath.Join(t.TempDir(), "link")
	if symlinkErr := os.Symlink(realDir, linkDir); symlinkErr != nil {
		t.Skipf("cannot create symlink (os restriction): %v", symlinkErr)
	}

	// The runner writes a change so we get a non-nil edit back.
	runner := func(_ context.Context, _ workflow.Engine, root, _ string) error {
		return os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\nvar x = 2\n"), 0644)
	}

	p := remediation.NewRemyProvider(nil, runner)
	fr, ok := p.(remediation.FolderRemediator)
	require.True(t, ok)

	// Call FixFolder with the SYMLINKED (non-canonical) path.
	edit, err := fr.FixFolder(context.Background(), types.FilePath(linkDir))
	require.NoError(t, err)
	require.NotNil(t, edit, "FixFolder must return a non-nil edit when a file was modified")

	// Daemon contract: every edit key must begin with the PASSED path (linkDir),
	// not the canonical resolved path (realDir). Canonicalizing inside FixFolder
	// would produce keys under realDir, breaking the daemon's prefix remap.
	// Use a path-separator-aware check so a sibling directory whose name merely
	// starts with linkDir cannot produce a false pass.
	for key := range edit.Changes {
		assert.True(t, strings.HasPrefix(key, linkDir+string(filepath.Separator)),
			"edit key %q must be prefixed by the passed symlinked path %q (daemon contract); "+
				"if it is prefixed by the canonical path %q, FixFolder incorrectly canonicalized r",
			key, linkDir, realDir)
	}
}
