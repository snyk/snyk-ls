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
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
)

type mockGitOps struct {
	mock.Mock
}

var _ GitOps = (*mockGitOps)(nil)

func (m *mockGitOps) PlainOpen(path string) (*git.Repository, error) {
	args := m.Called(path)
	if repo, ok := args.Get(0).(*git.Repository); ok {
		return repo, args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockGitOps) PlainClone(path string, isBare bool, options *git.CloneOptions) (*git.Repository, error) {
	args := m.Called(path, isBare, options)
	if repo, ok := args.Get(0).(*git.Repository); ok {
		return repo, args.Error(1)
	}
	return nil, args.Error(1)
}
func (m *mockGitOps) Head(repo *git.Repository) (*plumbing.Reference, error) {
	args := m.Called(repo)
	if ref, ok := args.Get(0).(*plumbing.Reference); ok {
		return ref, args.Error(1)
	}
	return nil, args.Error(1)
}

func TestClone_DifferentBranchNames_ShouldClone(t *testing.T) {
	logger := zerolog.Nop()
	mgo := &mockGitOps{}
	repoPath := "/path/to/repo"
	tmpRepoPath := "/tmp/path/to/repo"
	baseBranchName := "main"
	currentBranchName := plumbing.ReferenceName("refs/heads/feat/foobar")
	repo := &git.Repository{}

	mgo.On("PlainOpen", repoPath).Return(repo, nil)
	headRef := plumbing.NewHashReference(currentBranchName, plumbing.NewHash("abc123"))
	mgo.On("Head", repo).Return(headRef, nil)
	mgo.On("PlainClone", mock.Anything, false, mock.AnythingOfType("*git.CloneOptions")).Return(repo, nil)

	repo, err := Clone(repoPath, tmpRepoPath, baseBranchName, &logger, mgo)

	assert.NotNil(t, repo)
	assert.Nil(t, err)
	mgo.AssertExpectations(t)
}

func TestClone_InvalidGitRepo(t *testing.T) {
	logger := zerolog.Nop()
	mgo := &mockGitOps{}
	repoPath := "/path/to/repo"
	tmpRepoPath := "/path/to/repo"
	branchName := "feat/foobar"

	mgo.On("PlainOpen", repoPath).Return(nil, errors.New("failed to open repository"))

	repo, err := Clone(repoPath, tmpRepoPath, branchName, &logger, mgo)

	assert.Nil(t, repo)
	assert.NotNil(t, err)
	mgo.AssertExpectations(t)
}

func TestClone_InvalidGitRepo_FailedHead(t *testing.T) {
	logger := zerolog.Nop()
	mgo := &mockGitOps{}
	repoPath := "/path/to/repo"
	tmpRepoPath := "/path/to/repo"
	branchName := "feat/foobar"
	repo := &git.Repository{}

	mgo.On("PlainOpen", repoPath).Return(repo, nil)
	mgo.On("Head", repo).Return(nil, errors.New("failed to fetch head"))

	repo, err := Clone(repoPath, tmpRepoPath, branchName, &logger, mgo)

	assert.Nil(t, repo)
	assert.NotNil(t, err)
	mgo.AssertExpectations(t)
}

func TestClone_SameBranchNames_SkipClone(t *testing.T) {
	logger := zerolog.Nop()
	mgo := &mockGitOps{}
	repoPath := "/path/to/repo"
	tmpRepoPath := "/tmp/path/to/repo"
	baseBranchName := "main"
	currentBranchName := plumbing.ReferenceName("refs/heads/main")
	repo := &git.Repository{}

	mgo.On("PlainOpen", repoPath).Return(repo, nil)
	headRef := plumbing.NewHashReference(currentBranchName, plumbing.NewHash("abc123"))
	mgo.On("Head", repo).Return(headRef, nil)

	repo, err := Clone(repoPath, tmpRepoPath, baseBranchName, &logger, mgo)

	assert.Nil(t, repo)
	assert.Nil(t, err)
	mgo.AssertNotCalled(t, "PlainClone", mock.Anything, mock.AnythingOfType("*git.CloneOptions"))
	mgo.AssertExpectations(t)
}

func TestClone_DifferentBranchNames_FailedClone(t *testing.T) {
	logger := zerolog.Nop()
	mgo := &mockGitOps{}
	repoPath := "/path/to/repo"
	tmpRepoPath := "/tmp/path/to/repo"
	baseBranchName := "main"
	currentBranchName := plumbing.ReferenceName("refs/heads/feat/foobar")
	repo := &git.Repository{}

	mgo.On("PlainOpen", repoPath).Return(repo, nil)
	headRef := plumbing.NewHashReference(currentBranchName, plumbing.NewHash("abc123"))
	mgo.On("Head", repo).Return(headRef, nil)
	mgo.On("PlainClone", mock.Anything, false, mock.AnythingOfType("*git.CloneOptions")).Return(nil, errors.New("failed to clone repo"))

	repo, err := Clone(repoPath, tmpRepoPath, baseBranchName, &logger, mgo)

	assert.Nil(t, repo)
	assert.NotNil(t, err)
	mgo.AssertExpectations(t)
}
