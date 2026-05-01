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
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestClone_ShouldClone(t *testing.T) {
	engine := testutil.UnitTest(t)
	repoPath := types.FilePath(t.TempDir())
	initGitRepo(t, repoPath, false)

	tmpFolderPath := types.FilePath(t.TempDir())
	cloneTargetBranchName := "master"
	repo, err := Clone(engine.GetLogger(), repoPath, tmpFolderPath, cloneTargetBranchName)

	assert.NotNil(t, repo)
	assert.NoError(t, err)
}

func TestClone_ShouldClone_SameOriginRemoteUrl(t *testing.T) {
	engine := testutil.UnitTest(t)
	repoPath := types.FilePath(t.TempDir())
	srcRepo, _ := initGitRepo(t, repoPath, false)

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
	initGitRepo(t, repoPath, false)

	tmpFolderPath := types.FilePath(t.TempDir())
	cloneTargetBranchName := "foobar"
	repo, err := Clone(engine.GetLogger(), repoPath, tmpFolderPath, cloneTargetBranchName)

	assert.Nil(t, repo)
	assert.Error(t, err)
}

func TestClone_DetachedHead_TargetBranchExists(t *testing.T) {
	engine := testutil.UnitTest(t)
	repoPath := types.FilePath(t.TempDir())
	destinationPath := types.FilePath(t.TempDir())
	repo, currentHead := initGitRepo(t, repoPath, true)
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
	destinationPath := types.FilePath(t.TempDir())
	srcRepo, currentHead := initGitRepo(t, repoPath, true)
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
	destinationPath := types.FilePath(t.TempDir())
	repo, currentHead := initGitRepo(t, repoPath, true)
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
	destinationPath := types.FilePath(t.TempDir())
	repo, currentHead := initGitRepo(t, repoPath, true)
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
	initGitRepoWithHistory(t, repoPath, 10)

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
	initGitRepo(t, repoPath, false)

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

func TestLocalRepoHasChanges_SameBranchNames_NoModification_SkipClone(t *testing.T) {
	engine := testutil.UnitTest(t)
	repoPath := types.FilePath(t.TempDir())
	initGitRepo(t, repoPath, false)
	shouldclone, err := LocalRepoHasChanges(engine.GetConfiguration(), engine.GetLogger(), repoPath)

	assert.NoError(t, err)
	assert.False(t, shouldclone)
}

func TestLocalRepoHasChanges_SameBranchNames_WithModification_Clone(t *testing.T) {
	engine := testutil.UnitTest(t)
	repoPath := types.FilePath(t.TempDir())
	initGitRepo(t, repoPath, true)
	shouldclone, err := LocalRepoHasChanges(engine.GetConfiguration(), engine.GetLogger(), repoPath)

	assert.NoError(t, err)
	assert.True(t, shouldclone)
}

func TestLocalRepoHasChanges_DifferentBranchNames_Clone(t *testing.T) {
	engine := testutil.UnitTest(t)
	repoPath := types.FilePath(t.TempDir())
	repo, _ := initGitRepo(t, repoPath, true)
	wt, err := repo.Worktree()
	assert.NoError(t, err)
	err = wt.Checkout(&git.CheckoutOptions{
		Branch: "feat/new",
		Create: true,
	})
	assert.NoError(t, err)

	shouldclone, err := LocalRepoHasChanges(engine.GetConfiguration(), engine.GetLogger(), repoPath)

	assert.True(t, shouldclone)
	assert.NoError(t, err)
}

func TestLocalRepoHasChanges_HasUncommittedChanges(t *testing.T) {
	repo, _ := initGitRepo(t, types.FilePath(t.TempDir()), true)

	hasChanges := hasUncommitedChanges(repo)

	assert.True(t, hasChanges)
}

func TestLocalRepoHasChanges_HasCommittedChanges(t *testing.T) {
	repo, _ := initGitRepo(t, types.FilePath(t.TempDir()), false)

	hasChanges := hasUncommitedChanges(repo)

	assert.False(t, hasChanges)
}

func initGitRepoWithHistory(t *testing.T, repoPath types.FilePath, commits int) *git.Repository {
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

func initGitRepo(t *testing.T, repoPath types.FilePath, isModified bool) (*git.Repository, *plumbing.Reference) {
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
