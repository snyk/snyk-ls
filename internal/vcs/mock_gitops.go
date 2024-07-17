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
	"github.com/stretchr/testify/mock"
)

type MockGitOps struct {
	mock.Mock
}

func NewMockGitOps() *MockGitOps {
	return &MockGitOps{}
}

var _ GitOps = (*MockGitOps)(nil)

func (m *MockGitOps) PlainOpen(path string) (*git.Repository, error) {
	args := m.Called(path)
	if repo, ok := args.Get(0).(*git.Repository); ok {
		return repo, args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockGitOps) PlainClone(path string, isBare bool, options *git.CloneOptions) (*git.Repository, error) {
	args := m.Called(path, isBare, options)
	if repo, ok := args.Get(0).(*git.Repository); ok {
		return repo, args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockGitOps) Head(repo *git.Repository) (*plumbing.Reference, error) {
	args := m.Called(repo)
	if ref, ok := args.Get(0).(*plumbing.Reference); ok {
		return ref, args.Error(1)
	}
	return nil, args.Error(1)
}
