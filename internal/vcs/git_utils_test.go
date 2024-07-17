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
	"errors"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"os"
	"path/filepath"
	"testing"
)

func TestClone_ShouldClone(t *testing.T) {
	logger := zerolog.Nop()
	mgo := NewMockGitOps()
	repoPath := "/path/to/repo"
	tmpRepoPath := "/tmp/path/to/repo"
	baseBranchName := "main"
	repo := &git.Repository{}

	mgo.On("PlainClone", mock.Anything, false, mock.AnythingOfType("*git.CloneOptions")).Return(repo, nil)

	repo, err := Clone(repoPath, tmpRepoPath, baseBranchName, &logger, mgo)

	assert.NotNil(t, repo)
	assert.NoError(t, err)
	mgo.AssertExpectations(t)
}

func TestClone_InvalidGitRepo(t *testing.T) {
	logger := zerolog.Nop()
	mgo := NewMockGitOps()
	repoPath := "/path/to/repo"
	tmpRepoPath := "/path/to/repo"
	branchName := "feat/foobar"

	mgo.On("PlainClone", mock.Anything, false, mock.AnythingOfType("*git.CloneOptions")).Return(nil, errors.New("failed to clone"))

	repo, err := Clone(repoPath, tmpRepoPath, branchName, &logger, mgo)

	assert.Nil(t, repo)
	assert.NotNil(t, err)
	mgo.AssertExpectations(t)
}

func TestShouldClone_SameBranchNames_NoModification_SkipClone(t *testing.T) {
	logger := zerolog.Nop()
	mgo := NewMockGitOps()
	repoPath := "/path/to/repo"
	baseBranchName := "main"
	currentBranchName := plumbing.ReferenceName("refs/heads/main")
	repo := &git.Repository{}

	mgo.On("PlainOpen", repoPath).Return(repo, nil)
	headRef := plumbing.NewHashReference(currentBranchName, plumbing.NewHash("abc123"))
	mgo.On("Head", repo).Return(headRef, nil)

	shouldclone, err := ShouldClone(repoPath, mgo, &logger, baseBranchName)

	assert.False(t, shouldclone)
	assert.NoError(t, err)
	mgo.AssertNotCalled(t, "PlainClone", mock.Anything, mock.AnythingOfType("*git.CloneOptions"))
	mgo.AssertExpectations(t)
}

func TestShouldClone_SameBranchNames_WithModification_Clone(t *testing.T) {
	logger := zerolog.Nop()
	gw := NewGitWrapper()
	folderPath := t.TempDir()
	_ = initGitRepo(t, folderPath, true)

	baseBranchName := "master"

	shouldclone, err := ShouldClone(folderPath, gw, &logger, baseBranchName)

	assert.True(t, shouldclone)
	assert.NoError(t, err)
}

func TestShouldClone_DifferentBranchNames_Clone(t *testing.T) {
	logger := zerolog.Nop()
	mgo := NewMockGitOps()
	repoPath := "/path/to/repo"
	baseBranchName := "main"
	currentBranchName := plumbing.ReferenceName("refs/heads/feat/abc")
	repo := &git.Repository{}

	mgo.On("PlainOpen", repoPath).Return(repo, nil)
	headRef := plumbing.NewHashReference(currentBranchName, plumbing.NewHash("abc123"))
	mgo.On("Head", repo).Return(headRef, nil)

	shouldclone, err := ShouldClone(repoPath, mgo, &logger, baseBranchName)

	assert.True(t, shouldclone)
	assert.NoError(t, err)
	mgo.AssertNotCalled(t, "PlainClone", mock.Anything, mock.AnythingOfType("*git.CloneOptions"))
	mgo.AssertExpectations(t)
}

func TestShouldClone_HasUncommittedChanges(t *testing.T) {
	repo := initGitRepo(t, t.TempDir(), true)

	hasChanges := hasUncommitedChanges(repo)

	assert.True(t, hasChanges)
}

func TestShouldClone_HasCommittedChanges(t *testing.T) {
	repo := initGitRepo(t, t.TempDir(), false)

	hasChanges := hasUncommitedChanges(repo)

	assert.False(t, hasChanges)
}

func initGitRepo(t *testing.T, repoPath string, isModified bool) *git.Repository {
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
	return repo
}
