/*
 * © 2024 Snyk Limited
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

package vcs

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestClone_ShouldClone(t *testing.T) {
	engine := testutil.UnitTest(t)
	repoPath := types.FilePath(t.TempDir())
	initWorktreeRepo(t, repoPath, false)

	tmpFolderPath := types.FilePath(t.TempDir())
	cloneTargetBranchName := "master"
	repo, err := Clone(engine.GetLogger(), repoPath, tmpFolderPath, cloneTargetBranchName)

	assert.NotNil(t, repo)
	assert.NoError(t, err)
}

func TestClone_ShouldClone_SameOriginRemoteUrl(t *testing.T) {
	engine := testutil.UnitTest(t)
	repoPath := types.FilePath(t.TempDir())
	srcRepo, _ := initWorktreeRepo(t, repoPath, false)

	tmpFolderPath := types.FilePath(t.TempDir())
	cloneTargetBranchName := "master"
	clonedRepo, err := Clone(engine.GetLogger(), repoPath, tmpFolderPath, cloneTargetBranchName)

	assert.NotNil(t, clonedRepo)
	assert.NoError(t, err)

	srcConfig, err := srcRepo.Config()
	assert.NoError(t, err)
	remoteSrcConfig := srcConfig.Remotes["origin"]
	assert.NotNil(t, remoteSrcConfig)

	clonedRepoConfig, err := clonedRepo.Config()
	assert.NoError(t, err)
	remoteDstConfig := clonedRepoConfig.Remotes["origin"]
	assert.NotNil(t, remoteDstConfig)

	assert.Equal(t, remoteSrcConfig.URLs[0], remoteDstConfig.URLs[0])
}

func TestClone_InvalidBranchName(t *testing.T) {
	engine := testutil.UnitTest(t)
	repoPath := types.FilePath(t.TempDir())
	initWorktreeRepo(t, repoPath, false)

	tmpFolderPath := types.FilePath(t.TempDir())
	cloneTargetBranchName := "foobar"
	repo, err := Clone(engine.GetLogger(), repoPath, tmpFolderPath, cloneTargetBranchName)

	assert.Nil(t, repo)
	assert.Error(t, err)
}

func TestClone_DetachedHead_TargetBranchExists(t *testing.T) {
	engine := testutil.UnitTest(t)
	repoPath := types.FilePath(t.TempDir())
	destinationPath := types.FilePath(newWorktreeDir(t))
	repo, currentHead := initWorktreeRepo(t, repoPath, true)
	worktree, err := repo.Worktree()
	assert.NoError(t, err)
	_, err = worktree.Commit("testCommit", &git.CommitOptions{
		Author: &object.Signature{Name: t.Name()},
	})
	assert.NoError(t, err)

	// Now checkout the old head hash
	err = worktree.Checkout(&git.CheckoutOptions{Hash: currentHead.Hash()})
	assert.NoError(t, err)
	cloneTargetBranchName := "master"
	cloneRepo, err := Clone(engine.GetLogger(), repoPath, destinationPath, cloneTargetBranchName)

	assert.NoError(t, err)
	assert.NotNil(t, cloneRepo)
}

func TestClone_DetachedHead_TargetBranchExists_SameOriginRemoteUrl(t *testing.T) {
	engine := testutil.UnitTest(t)
	repoPath := types.FilePath(t.TempDir())
	destinationPath := types.FilePath(newWorktreeDir(t))
	srcRepo, currentHead := initWorktreeRepo(t, repoPath, true)
	worktree, err := srcRepo.Worktree()
	assert.NoError(t, err)
	_, err = worktree.Commit("testCommit", &git.CommitOptions{
		Author: &object.Signature{Name: t.Name()},
	})
	assert.NoError(t, err)

	// Now checkout the old head hash
	err = worktree.Checkout(&git.CheckoutOptions{Hash: currentHead.Hash()})
	assert.NoError(t, err)
	cloneTargetBranchName := "master"
	clonedRepo, err := Clone(engine.GetLogger(), repoPath, destinationPath, cloneTargetBranchName)

	assert.NoError(t, err)
	assert.NotNil(t, clonedRepo)

	srcConfig, err := srcRepo.Config()
	assert.NoError(t, err)
	remoteSrcConfig := srcConfig.Remotes["origin"]
	assert.NotNil(t, remoteSrcConfig)

	clonedRepoConfig, err := clonedRepo.Config()
	assert.NoError(t, err)
	remoteDstConfig := clonedRepoConfig.Remotes["origin"]
	assert.NotNil(t, remoteDstConfig)

	assert.Equal(t, remoteSrcConfig.URLs[0], remoteDstConfig.URLs[0])
}

func TestClone_DetachedHead_TargetBranchDoesNotExists(t *testing.T) {
	engine := testutil.UnitTest(t)
	repoPath := types.FilePath(t.TempDir())
	destinationPath := types.FilePath(newWorktreeDir(t))
	repo, currentHead := initWorktreeRepo(t, repoPath, true)
	worktree, err := repo.Worktree()
	assert.NoError(t, err)
	_, err = worktree.Commit("testCommit", &git.CommitOptions{
		Author: &object.Signature{Name: t.Name()},
	})
	assert.NoError(t, err)

	// Now checkout the old head hash
	err = worktree.Checkout(&git.CheckoutOptions{Hash: currentHead.Hash()})
	assert.NoError(t, err)
	cloneTargetBranchName := "feat/feat"
	cloneRepo, err := Clone(engine.GetLogger(), repoPath, destinationPath, cloneTargetBranchName)

	assert.Error(t, err)
	assert.Nil(t, cloneRepo)
}

func TestClone_DetachedHead_TargetBranchExists_OpenChanges(t *testing.T) {
	engine := testutil.UnitTest(t)
	repoPath := types.FilePath(t.TempDir())
	destinationPath := types.FilePath(newWorktreeDir(t))
	repo, currentHead := initWorktreeRepo(t, repoPath, true)
	worktree, err := repo.Worktree()
	assert.NoError(t, err)
	_, err = worktree.Commit("testCommit", &git.CommitOptions{
		Author: &object.Signature{Name: t.Name()},
	})
	assert.NoError(t, err)

	// Now checkout the old head hash
	err = worktree.Checkout(&git.CheckoutOptions{Hash: currentHead.Hash()})
	assert.NoError(t, err)

	testfile := filepath.Join(string(repoPath), "testFile3.txt")
	err = os.WriteFile(testfile, []byte("testData"), 0600)
	assert.NoError(t, err)

	cloneTargetBranchName := "master"
	cloneRepo, err := Clone(engine.GetLogger(), repoPath, destinationPath, cloneTargetBranchName)

	assert.NoError(t, err)
	assert.NotNil(t, cloneRepo)
	assert.NoFileExists(t, filepath.Join(string(destinationPath), testfile))
}

func TestClone_InvalidGitRepo(t *testing.T) {
	engine := testutil.UnitTest(t)
	repoPath := types.FilePath(t.TempDir())
	tmpFolderPath := types.FilePath(t.TempDir())
	branchName := "feat/foobar"

	repo, err := Clone(engine.GetLogger(), repoPath, tmpFolderPath, branchName)

	assert.Nil(t, repo)
	assert.Error(t, err)
}

func TestClone_ShouldShallowClone(t *testing.T) {
	engine := testutil.UnitTest(t)
	repoPath := types.FilePath(t.TempDir())
	initWorktreeRepoWithHistory(t, repoPath, 10)

	tmpFolderPath := types.FilePath(t.TempDir())
	repo, err := Clone(engine.GetLogger(), repoPath, tmpFolderPath, "master")
	require.NoError(t, err)
	require.NotNil(t, repo)

	// A shallow clone with Depth: 1 yields exactly 1 reachable commit.
	// go-git returns "object not found" when walking past the graft boundary,
	// so we count until that error.
	logIter, err := repo.Log(&git.LogOptions{})
	require.NoError(t, err)

	commitCount := 0
	_ = logIter.ForEach(func(c *object.Commit) error {
		commitCount++
		return nil
	})
	assert.Equal(t, 1, commitCount, "shallow clone should have exactly 1 commit")
}

func TestClone_FromSubfolder_ShouldClone(t *testing.T) {
	engine := testutil.UnitTest(t)
	repoPath := types.FilePath(t.TempDir())
	initWorktreeRepo(t, repoPath, false)

	// Create a subfolder inside the git repo
	subfolder := filepath.Join(string(repoPath), "subproject")
	require.NoError(t, os.MkdirAll(subfolder, 0o755))

	tmpFolderPath := types.FilePath(t.TempDir())
	cloneTargetBranchName := "master"

	// Clone using the subfolder path (not the git root)
	repo, err := Clone(engine.GetLogger(), types.FilePath(subfolder), tmpFolderPath, cloneTargetBranchName)

	assert.NotNil(t, repo)
	assert.NoError(t, err)
}

func TestClone_MaterializesNestedWindowsDeviceFileName(t *testing.T) {
	engine := testutil.UnitTest(t)
	repoPath := types.FilePath(t.TempDir())
	testutil.InitGitRepoWithFiles(t, repoPath, map[string]string{
		"testFile.txt":         "testData",
		"scripts/build/prn.sh": "#!/bin/sh\necho build\n",
	})

	destinationPath := types.FilePath(newWorktreeDir(t))
	repo, err := Clone(engine.GetLogger(), repoPath, destinationPath, "master")

	require.NoError(t, err)
	require.NotNil(t, repo)
	requireFileContent(t, filepath.Join(string(destinationPath), "testFile.txt"), "testData")
	requireFileContent(t, filepath.Join(string(destinationPath), "scripts", "build", "prn.sh"), "#!/bin/sh\necho build\n")
}

func TestClone_MaterializesWindowsReservedDeviceNames(t *testing.T) {
	testCases := []struct {
		name     string
		filePath string
	}{
		{name: "CON", filePath: "con.go"},
		{name: "NUL", filePath: "NUL.md"},
		{name: "AUX as directory", filePath: "aux/x.txt"},
		{name: "COM1", filePath: "com1.txt"},
		{name: "LPT9", filePath: "lpt9.js"},
		{name: "CONIN$", filePath: "conin$.sh"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			engine := testutil.UnitTest(t)
			repoPath := types.FilePath(t.TempDir())
			testutil.InitGitRepoWithFiles(t, repoPath, map[string]string{tc.filePath: "content"})

			destinationPath := types.FilePath(newWorktreeDir(t))
			repo, err := Clone(engine.GetLogger(), repoPath, destinationPath, "master")

			require.NoError(t, err)
			require.NotNil(t, repo)
			requireFileContent(t, filepath.Join(string(destinationPath), filepath.FromSlash(tc.filePath)), "content")
		})
	}
}

// TestClone_MaterializesBackslashInFileName guards a name that is ordinary on
// POSIX filesystems and that real git does commit, against the separator check
// materializeTree applies to entry names.
func TestClone_MaterializesBackslashInFileName(t *testing.T) {
	testsupport.NotOnWindows(t, `a backslash is a path separator on Windows, so no such file can exist there`)
	engine := testutil.UnitTest(t)
	repoPath := types.FilePath(t.TempDir())
	testutil.InitGitRepoWithFiles(t, repoPath, map[string]string{`weird\name.txt`: "content"})

	destinationPath := types.FilePath(newWorktreeDir(t))
	repo, err := Clone(engine.GetLogger(), repoPath, destinationPath, "master")

	require.NoError(t, err)
	require.NotNil(t, repo)
	requireFileContent(t, filepath.Join(string(destinationPath), `weird\name.txt`), "content")
}

func TestClone_DetachedHead_MaterializesWindowsDeviceFileName(t *testing.T) {
	engine := testutil.UnitTest(t)
	repoPath := types.FilePath(t.TempDir())
	srcRepo := testutil.InitGitRepoWithFiles(t, repoPath, map[string]string{
		"testFile.txt":         "testData",
		"scripts/build/prn.sh": "#!/bin/sh\necho build\n",
	})
	testutil.DetachGitRepoHeadBehindMaster(t, srcRepo)

	destinationPath := types.FilePath(newWorktreeDir(t))
	repo, err := Clone(engine.GetLogger(), repoPath, destinationPath, "master")

	require.NoError(t, err)
	require.NotNil(t, repo)
	requireFileContent(t, filepath.Join(string(destinationPath), "testFile.txt"), "testData")
	requireFileContent(t, filepath.Join(string(destinationPath), "scripts", "build", "prn.sh"), "#!/bin/sh\necho build\n")
}

func TestClone_MaterializesExecutablesAndSymlinks(t *testing.T) {
	testsupport.NotOnWindows(t, "symlink creation needs elevated privileges on Windows")
	engine := testutil.UnitTest(t)
	repoPath := types.FilePath(t.TempDir())
	testutil.InitGitRepoWithEntries(t, repoPath, map[string]testutil.GitFixtureFile{
		"plain.txt":  {Content: "plain", Mode: filemode.Regular},
		"run.sh":     {Content: "#!/bin/sh\n", Mode: filemode.Executable},
		"link-to-me": {Content: "plain.txt", Mode: filemode.Symlink},
	})

	destinationPath := types.FilePath(newWorktreeDir(t))
	repo, err := Clone(engine.GetLogger(), repoPath, destinationPath, "master")
	require.NoError(t, err)
	require.NotNil(t, repo)

	executable, err := os.Stat(OSPath(filepath.Join(string(destinationPath), "run.sh")))
	require.NoError(t, err)
	assert.NotZero(t, executable.Mode()&0100, "executable bit should survive materialization")

	linkPath := OSPath(filepath.Join(string(destinationPath), "link-to-me"))
	link, err := os.Lstat(linkPath)
	require.NoError(t, err)
	assert.NotZero(t, link.Mode()&os.ModeSymlink, "symlink should be written as a symlink")
	linkTarget, err := os.Readlink(linkPath)
	require.NoError(t, err)
	assert.Equal(t, "plain.txt", linkTarget)
}

// TestMaterializeWorktree_ReportsUnreadableSubtree pins that a subtree go-git
// cannot load is an error rather than a short worktree reported as complete: a
// partial baseline gets persisted against the real commit hash, and the
// snapshot-exists check then suppresses every later scan.
//
// It drives materializeWorktree rather than Clone because a commit referencing
// a missing object cannot be served by upload-pack at all, so a Clone-level
// test would fail during the fetch and prove nothing about the walk.
func TestMaterializeWorktree_ReportsUnreadableSubtree(t *testing.T) {
	engine := testutil.UnitTest(t)
	repoPath := types.FilePath(t.TempDir())
	repo := testutil.InitGitRepo(t, repoPath)

	// A root tree naming a subtree whose object was never written, alongside a
	// file sorting after it that a truncating walk would silently drop.
	missingSubtree := plumbing.NewHash("1111111111111111111111111111111111111111")
	commitHash := testutil.CommitGitTree(t, repo, testutil.WriteGitTree(t, repo.Storer, []object.TreeEntry{
		{Name: "gone", Mode: filemode.Dir, Hash: missingSubtree},
		{Name: "zz-last.txt", Mode: filemode.Regular, Hash: testutil.WriteGitBlob(t, repo.Storer, "kept")},
	}))

	destinationPath := t.TempDir()
	err := materializeWorktree(engine.GetLogger(), repo, destinationPath, commitHash)

	require.Error(t, err, "an unreadable subtree must fail, not truncate the worktree")
	assert.NoFileExists(t, OSPath(filepath.Join(destinationPath, "zz-last.txt")))
}

func TestClone_DoesNotWriteThroughSymlinkedTreeEntries(t *testing.T) {
	testsupport.NotOnWindows(t, "symlink creation needs elevated privileges on Windows")
	engine := testutil.UnitTest(t)
	repoPath := types.FilePath(t.TempDir())
	outsidePath := t.TempDir()
	repo := testutil.InitGitRepo(t, repoPath)

	// "EVIL" twice: a symlink out of the worktree, then the directory holding
	// "payload". Git orders "EVIL" before "EVIL/", so a materializer that creates
	// symlinks as it walks has the link in place before it writes the file.
	innerTree := testutil.WriteGitTree(t, repo.Storer, []object.TreeEntry{
		{Name: "payload", Mode: filemode.Regular, Hash: testutil.WriteGitBlob(t, repo.Storer, "owned")},
	})
	testutil.CommitGitTree(t, repo, testutil.WriteGitTree(t, repo.Storer, []object.TreeEntry{
		{Name: "EVIL", Mode: filemode.Symlink, Hash: testutil.WriteGitBlob(t, repo.Storer, outsidePath)},
		{Name: "EVIL", Mode: filemode.Dir, Hash: innerTree},
	}))

	destinationPath := types.FilePath(newWorktreeDir(t))
	_, err := Clone(engine.GetLogger(), repoPath, destinationPath, "master")
	require.NoError(t, err)

	entries, err := os.ReadDir(outsidePath)
	require.NoError(t, err)
	assert.Empty(t, entries, "materialization must not write through a symlink named by the tree")
	assert.FileExists(t, filepath.Join(string(destinationPath), "EVIL", "payload"))
}

func TestClone_DoesNotWriteThroughSymlinkNamedByAnotherSymlink(t *testing.T) {
	testsupport.NotOnWindows(t, "symlink creation needs elevated privileges on Windows")
	engine := testutil.UnitTest(t)
	repoPath := types.FilePath(t.TempDir())
	outsidePath := t.TempDir()
	repo := testutil.InitGitRepo(t, repoPath)

	// "a" points out of the worktree and "a/b" carries a slash in its name, which
	// go-git's decoder accepts. Both defer to the symlink pass, "a" sorts first,
	// so creating "a/b" resolves its parent through the link.
	testutil.CommitGitTree(t, repo, testutil.WriteGitTree(t, repo.Storer, []object.TreeEntry{
		{Name: "a", Mode: filemode.Symlink, Hash: testutil.WriteGitBlob(t, repo.Storer, outsidePath)},
		{Name: "a/b", Mode: filemode.Symlink, Hash: testutil.WriteGitBlob(t, repo.Storer, "payload")},
	}))

	destinationPath := types.FilePath(newWorktreeDir(t))
	_, cloneErr := Clone(engine.GetLogger(), repoPath, destinationPath, "master")

	entries, err := os.ReadDir(outsidePath)
	require.NoError(t, err)
	assert.Empty(t, entries, "materialization must not write through a symlink it created itself")

	require.ErrorIs(t, cloneErr, ErrInvalidTreeEntryName,
		"a tree entry name git could not have produced must abort the clone")
}

func TestClone_RejectsDotGitDisguisedTreeEntries(t *testing.T) {
	testCases := []struct {
		name     string
		filePath string
	}{
		{name: "NTFS short name", filePath: "git~1"},
		{name: "trailing space", filePath: ".git "},
		{name: "nested trailing dot", filePath: "nested/.git./config"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			engine := testutil.UnitTest(t)
			repoPath := types.FilePath(t.TempDir())
			testutil.InitGitRepoWithFiles(t, repoPath, map[string]string{tc.filePath: "payload"})

			destinationPath := types.FilePath(newWorktreeDir(t))
			repo, err := Clone(engine.GetLogger(), repoPath, destinationPath, "master")

			require.Error(t, err)
			assert.Nil(t, repo)
			// Must be go-git's ValidTreePath, the guard the materializer rests on
			// for .git safety, and not our own separator check.
			require.ErrorIs(t, err, ErrRejectedTreeEntryPath)
			require.NotErrorIs(t, err, ErrInvalidTreeEntryName)
			assert.NoFileExists(t, OSPath(filepath.Join(string(destinationPath), filepath.FromSlash(tc.filePath))))
		})
	}
}

// requireFileContent reads through OSPath, because a plain Lstat of a reserved
// device name on Windows resolves to the device instead of what we wrote.
func requireFileContent(t *testing.T, path, want string) {
	t.Helper()
	content, err := os.ReadFile(OSPath(path)) //nolint:gosec // test-controlled path
	require.NoError(t, err)
	assert.Equal(t, want, string(content))
}

// TestClone_MaterializesCollidingEntries covers two legal tree entries that land
// on one path. One of them has to lose, but losing the whole baseline is this
// ticket's own bug, so the clone must still succeed and later entries must still
// be written.
//
// Only the duplicate-name case collides on a case-sensitive filesystem, so it is
// the one that actually exercises the tolerance here; the case-differing pair is
// the shape real repositories have, and collides on APFS and NTFS.
func TestClone_MaterializesCollidingEntries(t *testing.T) {
	testCases := []struct {
		name  string
		first string
		last  string
	}{
		{name: "duplicate names", first: "dup.txt", last: "dup.txt"},
		{name: "names differing only in case", first: "A.txt", last: "a.txt"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			engine := testutil.UnitTest(t)
			repoPath := types.FilePath(t.TempDir())
			repo := testutil.InitGitRepo(t, repoPath)
			blob := testutil.WriteGitBlob(t, repo.Storer, "content")
			testutil.CommitGitTree(t, repo, testutil.WriteGitTree(t, repo.Storer, []object.TreeEntry{
				{Name: tc.first, Mode: filemode.Regular, Hash: blob},
				{Name: tc.last, Mode: filemode.Regular, Hash: blob},
				{Name: "zz-sibling.txt", Mode: filemode.Regular, Hash: testutil.WriteGitBlob(t, repo.Storer, "after")},
			}))

			destinationPath := types.FilePath(newWorktreeDir(t))
			cloned, err := Clone(engine.GetLogger(), repoPath, destinationPath, "master")

			require.NoError(t, err, "a colliding entry must not cost the whole baseline")
			require.NotNil(t, cloned)
			assert.FileExists(t, filepath.Join(string(destinationPath), tc.first))
			// The entry sorting after the collision still has to be written; an
			// abort would silently truncate the baseline right here.
			requireFileContent(t, filepath.Join(string(destinationPath), "zz-sibling.txt"), "after")
		})
	}
}

// TestClone_RejectsGitmodulesSymlinks pins go-git's validSymlinkName, upstream
// git's CVE-2018-11235 mitigation, which ValidTreePath does not cover.
func TestClone_RejectsGitmodulesSymlinks(t *testing.T) {
	testCases := []struct {
		name  string
		entry string
	}{
		{name: "at the root", entry: ".gitmodules"},
		{name: "in a subdirectory", entry: "sub/.gitmodules"},
		{name: "case insensitively", entry: ".GitModules"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			engine := testutil.UnitTest(t)
			repoPath := types.FilePath(t.TempDir())
			testutil.InitGitRepoWithEntries(t, repoPath, map[string]testutil.GitFixtureFile{
				tc.entry: {Content: "../outside/evil", Mode: filemode.Symlink},
			})

			destinationPath := types.FilePath(newWorktreeDir(t))
			_, err := Clone(engine.GetLogger(), repoPath, destinationPath, "master")

			require.ErrorIs(t, err, ErrGitModulesSymlink)
			assert.NoFileExists(t, filepath.Join(string(destinationPath), filepath.FromSlash(tc.entry)))
		})
	}
}

func TestMaterializeWorktree_RejectsRelativeRoot(t *testing.T) {
	engine := testutil.UnitTest(t)
	repoPath := types.FilePath(t.TempDir())
	repo := testutil.InitGitRepoWithFiles(t, repoPath, map[string]string{"a.txt": "content"})
	master, err := repo.Reference(plumbing.Master, true)
	require.NoError(t, err)

	err = materializeWorktree(engine.GetLogger(), repo, "relative/destination", master.Hash())

	require.ErrorIs(t, err, ErrRelativeWorktreeRoot)
}

// newWorktreeDir returns an empty directory whose cleanup goes through OSPath.
// t.TempDir's own cleanup uses an unprefixed RemoveAll and calls t.Errorf when
// it fails, which on Windows is every directory holding a reserved device name.
func newWorktreeDir(t *testing.T) string {
	t.Helper()
	//nolint:usetesting // t.TempDir cleans up with an unprefixed RemoveAll, which cannot delete a reserved device name on Windows
	dir, err := os.MkdirTemp("", "snyk-ls-worktree")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(OSPath(dir)) })
	return dir
}

func TestLocalRepoHasChanges_SameBranchNames_NoModification_SkipClone(t *testing.T) {
	engine := testutil.UnitTest(t)
	repoPath := types.FilePath(t.TempDir())
	initWorktreeRepo(t, repoPath, false)
	shouldclone, err := LocalRepoHasChanges(engine.GetConfiguration(), engine.GetLogger(), repoPath)

	assert.NoError(t, err)
	assert.False(t, shouldclone)
}

func TestLocalRepoHasChanges_SameBranchNames_WithModification_Clone(t *testing.T) {
	engine := testutil.UnitTest(t)
	repoPath := types.FilePath(t.TempDir())
	initWorktreeRepo(t, repoPath, true)
	shouldclone, err := LocalRepoHasChanges(engine.GetConfiguration(), engine.GetLogger(), repoPath)

	assert.NoError(t, err)
	assert.True(t, shouldclone)
}

func TestLocalRepoHasChanges_DifferentBranchNames_Clone(t *testing.T) {
	engine := testutil.UnitTest(t)
	repoPath := types.FilePath(t.TempDir())
	repo, _ := initWorktreeRepo(t, repoPath, true)
	wt, err := repo.Worktree()
	assert.NoError(t, err)
	err = wt.Checkout(&git.CheckoutOptions{
		Branch: plumbing.NewBranchReferenceName("feat/new"),
		Create: true,
	})
	assert.NoError(t, err)

	shouldclone, err := LocalRepoHasChanges(engine.GetConfiguration(), engine.GetLogger(), repoPath)

	assert.True(t, shouldclone)
	assert.NoError(t, err)
}

func TestLocalRepoHasChanges_HasUncommittedChanges(t *testing.T) {
	repo, _ := initWorktreeRepo(t, types.FilePath(t.TempDir()), true)

	hasChanges := hasUncommitedChanges(repo)

	assert.True(t, hasChanges)
}

func TestLocalRepoHasChanges_HasCommittedChanges(t *testing.T) {
	repo, _ := initWorktreeRepo(t, types.FilePath(t.TempDir()), false)

	hasChanges := hasUncommitedChanges(repo)

	assert.False(t, hasChanges)
}

func initWorktreeRepoWithHistory(t *testing.T, repoPath types.FilePath, commits int) *git.Repository {
	t.Helper()
	repo, err := git.PlainInit(string(repoPath), false)
	require.NoError(t, err)

	worktree, err := repo.Worktree()
	require.NoError(t, err)

	for i := 0; i < commits; i++ {
		filename := filepath.Join(string(repoPath), fmt.Sprintf("file_%d.txt", i))
		require.NoError(t, os.WriteFile(filename, []byte(fmt.Sprintf("content %d", i)), 0600))
		_, err = worktree.Add(filepath.Base(filename))
		require.NoError(t, err)
		_, err = worktree.Commit(fmt.Sprintf("commit %d", i), &git.CommitOptions{
			Author: &object.Signature{Name: t.Name()},
		})
		require.NoError(t, err)
	}

	repoConfig, err := repo.Config()
	require.NoError(t, err)
	repoConfig.Remotes["origin"] = &config.RemoteConfig{
		Name: "origin",
		URLs: []string{"git@github.com:snyk/snyk-goof.git"},
	}
	require.NoError(t, repo.Storer.SetConfig(repoConfig))
	return repo
}

func initWorktreeRepo(t *testing.T, repoPath types.FilePath, isModified bool) (*git.Repository, *plumbing.Reference) {
	t.Helper()
	repoPathAsString := string(repoPath)
	repo, err := git.PlainInit(repoPathAsString, false)
	assert.NoError(t, err)

	absoluteFileName := filepath.Join(repoPathAsString, "testFile.txt")
	err = os.WriteFile(absoluteFileName, []byte("testData"), 0600)
	assert.NoError(t, err)
	worktree, err := repo.Worktree()
	assert.NoError(t, err)
	_, err = worktree.Add(filepath.Base(absoluteFileName))
	assert.NoError(t, err)

	_, err = worktree.Commit("init", &git.CommitOptions{
		Author: &object.Signature{Name: t.Name()},
	})
	assert.NoError(t, err)
	testfile2 := filepath.Join(repoPathAsString, "testFile2.txt")
	err = os.WriteFile(testfile2, []byte("testData"), 0600)
	assert.NoError(t, err)

	_, err = worktree.Add(filepath.Base(testfile2))
	assert.NoError(t, err)

	if !isModified {
		_, err = worktree.Commit("testCommit", &git.CommitOptions{
			Author: &object.Signature{Name: t.Name()},
		})
		assert.NoError(t, err)
	}

	head, err := repo.Head()
	assert.NoError(t, err)

	repoConfig, err := repo.Config()
	assert.NoError(t, err)

	repoConfig.Remotes["origin"] = &config.RemoteConfig{
		Name: "origin",
		URLs: []string{"git@github.com:snyk/snyk-goof.git"},
	}
	err = repo.Storer.SetConfig(repoConfig)
	assert.NoError(t, err)
	return repo, head
}
