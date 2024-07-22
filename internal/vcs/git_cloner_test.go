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
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"testing"
)

func TestClone_ShouldClone(t *testing.T) {
	c := testutil.UnitTest(t)
	repoPath := t.TempDir()
	initGitRepo(t, repoPath, false)

	tmpFolderPath := t.TempDir()
	cloneTargetBranchName := "master"
	repo, err := Clone(c.Logger(), repoPath, tmpFolderPath, cloneTargetBranchName)

	assert.NotNil(t, repo)
	assert.NoError(t, err)
}

func TestClone_InvalidBranchName(t *testing.T) {
	c := testutil.UnitTest(t)
	repoPath := t.TempDir()
	initGitRepo(t, repoPath, false)

	tmpFolderPath := t.TempDir()
	cloneTargetBranchName := "foobar"
	repo, err := Clone(c.Logger(), repoPath, tmpFolderPath, cloneTargetBranchName)

	assert.Nil(t, repo)
	assert.Error(t, err)
}

func TestClone_DetachedHead_TargetBranchExists(t *testing.T) {
	c := testutil.UnitTest(t)
	repoPath := t.TempDir()
	destinationPath := t.TempDir()
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
	cloneRepo, err := Clone(c.Logger(), repoPath, destinationPath, cloneTargetBranchName)

	assert.NoError(t, err)
	assert.NotNil(t, cloneRepo)
}

func TestClone_DetachedHead_TargetBranchDoesNotExists(t *testing.T) {
	c := testutil.UnitTest(t)
	repoPath := t.TempDir()
	destinationPath := t.TempDir()
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
	cloneRepo, err := Clone(c.Logger(), repoPath, destinationPath, cloneTargetBranchName)

	assert.Error(t, err)
	assert.Nil(t, cloneRepo)
}

func TestClone_DetachedHead_TargetBranchExists_OpenChanges(t *testing.T) {
	c := testutil.UnitTest(t)
	repoPath := t.TempDir()
	destinationPath := t.TempDir()
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

	testfile := filepath.Join(repoPath, "testFile3.txt")
	err = os.WriteFile(testfile, []byte("testData"), 0600)
	assert.NoError(t, err)

	cloneTargetBranchName := "master"
	cloneRepo, err := Clone(c.Logger(), repoPath, destinationPath, cloneTargetBranchName)

	assert.NoError(t, err)
	assert.NotNil(t, cloneRepo)
	assert.NoFileExists(t, filepath.Join(destinationPath, testfile))
}

func TestClone_InvalidGitRepo(t *testing.T) {
	c := testutil.UnitTest(t)
	repoPath := t.TempDir()
	tmpFolderPath := t.TempDir()
	branchName := "feat/foobar"

	repo, err := Clone(c.Logger(), repoPath, tmpFolderPath, branchName)

	assert.Nil(t, repo)
	assert.Error(t, err)
}

func TestShouldClone_SameBranchNames_NoModification_SkipClone(t *testing.T) {
	c := testutil.UnitTest(t)
	repoPath := t.TempDir()
	initGitRepo(t, repoPath, false)
	cloneTargetBranchName := "master"
	shouldclone, err := ShouldClone(c.Logger(), repoPath, cloneTargetBranchName)

	assert.NoError(t, err)
	assert.False(t, shouldclone)
}

func TestShouldClone_SameBranchNames_WithModification_Clone(t *testing.T) {
	c := testutil.UnitTest(t)
	repoPath := t.TempDir()
	initGitRepo(t, repoPath, true)
	cloneTargetBranchName := "master"
	shouldclone, err := ShouldClone(c.Logger(), repoPath, cloneTargetBranchName)

	assert.NoError(t, err)
	assert.True(t, shouldclone)
}

func TestShouldClone_DifferentBranchNames_Clone(t *testing.T) {
	c := testutil.UnitTest(t)
	repoPath := t.TempDir()
	initGitRepo(t, repoPath, true)
	cloneTargetBranchName := "feat/new"

	shouldclone, err := ShouldClone(c.Logger(), repoPath, cloneTargetBranchName)

	assert.True(t, shouldclone)
	assert.NoError(t, err)
}

func TestShouldClone_HasUncommittedChanges(t *testing.T) {
	repo, _ := initGitRepo(t, t.TempDir(), true)

	hasChanges := hasUncommitedChanges(repo)

	assert.True(t, hasChanges)
}

func TestShouldClone_HasCommittedChanges(t *testing.T) {
	repo, _ := initGitRepo(t, t.TempDir(), false)

	hasChanges := hasUncommitedChanges(repo)

	assert.False(t, hasChanges)
}

func initGitRepo(t *testing.T, repoPath string, isModified bool) (*git.Repository, *plumbing.Reference) {
	t.Helper()
	repo, err := git.PlainInit(repoPath, false)
	assert.NoError(t, err)

	absoluteFileName := filepath.Join(repoPath, "testFile.txt")
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
	testfile2 := filepath.Join(repoPath, "testFile2.txt")
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

	return repo, head
}
