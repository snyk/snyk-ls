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

package snyk

import (
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestLoadCache_Empty(t *testing.T) {
	appFs := afero.NewMemMapFs()
	logger := zerolog.New(nil)

	cp := NewGitCacheProvider(&logger, appFs)

	cp.LoadCache()

	assert.Empty(t, cp.cache)
}

func TestLoadCache_NotEmpty(t *testing.T) {
	issueList := []Issue{
		{
			GlobalIdentity: uuid.New().String(),
		},
	}
	appFs := afero.NewMemMapFs()
	logger := zerolog.New(nil)
	folderPath := "/home/myusr/testrepo"
	hashedFolderPath, _ := hashPath(folderPath)
	commitHash := "eab0f18c4432b2a41e0f8e6c9831fe84be92b3db"
	p := product.ProductCode

	cp := NewGitCacheProvider(&logger, appFs)

	err := cp.AddToCache(folderPath, commitHash, issueList, p)
	cp.LoadCache()

	assert.Nil(t, err)
	assert.Equal(t, commitHash, cp.cache[hashedFolderPath])
}

func TestAddToCache_NewCommit(t *testing.T) {
	issueList := []Issue{
		{
			GlobalIdentity: uuid.New().String(),
		},
	}
	appFs := afero.NewMemMapFs()
	logger := zerolog.New(nil)
	folderPath := "/home/myusr/testrepo"
	hashedFolderPath, _ := hashPath(folderPath)
	commitHash := "eab0f18c4432b2a41e0f8e6c9831fe84be92b3db"
	p := product.ProductCode

	cp := NewGitCacheProvider(&logger, appFs)

	err := cp.AddToCache(folderPath, commitHash, issueList, p)
	list, _ := cp.GetPersistedIssueList(folderPath, p)

	assert.Nil(t, err)
	assert.NotEmpty(t, list)
	assert.Contains(t, hashedFolderPath, cp.cache)
	assert.Equal(t, commitHash, cp.cache[hashedFolderPath])
}

func TestAddToCache_ExistingCommit_ShouldNotPersist(t *testing.T) {
	issueList := []Issue{
		{
			GlobalIdentity: uuid.New().String(),
		},
	}
	newIssueList := []Issue{
		{
			GlobalIdentity: uuid.New().String(),
		},
	}
	appFs := afero.NewMemMapFs()
	logger := zerolog.New(nil)
	folderPath := "/home/myusr/testrepo"
	commitHash := "eab0f18c4432b2a41e0f8e6c9831fe84be92b3db"
	p := product.ProductCode

	cp := NewGitCacheProvider(&logger, appFs)

	err := cp.AddToCache(folderPath, commitHash, issueList, p)
	err = cp.AddToCache(folderPath, commitHash, newIssueList, p)
	list, _ := cp.GetPersistedIssueList(folderPath, p)

	assert.Nil(t, err)
	assert.NotEmpty(t, list)
	assert.Equal(t, issueList[0].GetGlobalIdentity(), list[0].GetGlobalIdentity())
	assert.NotEqual(t, newIssueList[0].GetGlobalIdentity(), list[0].GetGlobalIdentity())
}

func TestGetCommitHashFor_ReturnsCommitHash(t *testing.T) {
	issueList := []Issue{
		{
			GlobalIdentity: uuid.New().String(),
		},
	}

	appFs := afero.NewMemMapFs()
	logger := zerolog.New(nil)
	folderPath := "/home/myusr/testrepo"
	hashedFolderPath, err := hashPath(folderPath)
	commitHash := "eab0f18c4432b2a41e0f8e6c9831fe84be92b3db"
	p := product.ProductCode
	cp := NewGitCacheProvider(&logger, appFs)

	err = cp.AddToCache(folderPath, commitHash, issueList, p)
	commitHash, err = cp.GetCommitHashFor(folderPath)

	assert.Nil(t, err)
	assert.Equal(t, commitHash, cp.cache[hashedFolderPath])
}

func TestGetPersistedIssueList_ReturnsValidIssueListForProduct(t *testing.T) {
	existingCodeIssues := []Issue{
		{
			GlobalIdentity: uuid.New().String(),
		},
	}
	existingOssIssues := []Issue{
		{
			GlobalIdentity: uuid.New().String(),
		},
	}

	appFs := afero.NewMemMapFs()
	logger := zerolog.New(nil)
	folderPath := "/home/myusr/testrepo"
	commitHash := "eab0f18c4432b2a41e0f8e6c9831fe84be92b3db"
	pc := product.ProductCode
	po := product.ProductOpenSource
	cp := NewGitCacheProvider(&logger, appFs)

	err := cp.AddToCache(folderPath, commitHash, existingCodeIssues, pc)
	err = cp.AddToCache(folderPath, commitHash, existingOssIssues, po)
	actualCodeIssues, err := cp.GetPersistedIssueList(folderPath, pc)

	assert.Nil(t, err)
	assert.Equal(t, existingCodeIssues[0].GetGlobalIdentity(), actualCodeIssues[0].GetGlobalIdentity())
}

func TestClear_ExistingCache(t *testing.T) {
	existingCodeIssues := []Issue{
		{
			GlobalIdentity: uuid.New().String(),
		},
	}
	appFs := afero.NewMemMapFs()
	logger := zerolog.New(nil)
	folderPath := "/home/myusr/testrepo"
	commitHash := "eab0f18c4432b2a41e0f8e6c9831fe84be92b3db"
	pc := product.ProductCode
	cp := NewGitCacheProvider(&logger, appFs)

	err := cp.AddToCache(folderPath, commitHash, existingCodeIssues, pc)
	cp.Clear()

	assert.Nil(t, err)
	assert.Empty(t, cp.cache)
}

func TestClear_ExistingCacheNonExistingProduct(t *testing.T) {
	existingCodeIssues := []Issue{
		{
			GlobalIdentity: uuid.New().String(),
		},
	}

	appFs := afero.NewMemMapFs()
	logger := zerolog.New(nil)
	folderPath := "/home/myusr/testrepo"
	commitHash := "eab0f18c4432b2a41e0f8e6c9831fe84be92b3db"
	pc := product.ProductCode
	cp := NewGitCacheProvider(&logger, appFs)

	err := cp.AddToCache(folderPath, commitHash, existingCodeIssues, pc)
	cp.Clear()

	assert.Nil(t, err)
	assert.Empty(t, cp.cache)
}

func TestClearIssues_ExistingCacheExistingProduct(t *testing.T) {
	existingCodeIssues := []Issue{
		{
			GlobalIdentity: uuid.New().String(),
		},
	}

	appFs := afero.NewMemMapFs()
	logger := zerolog.New(nil)
	folderPath := "/home/myusr/testrepo"
	commitHash := "eab0f18c4432b2a41e0f8e6c9831fe84be92b3db"
	pc := product.ProductCode
	cp := NewGitCacheProvider(&logger, appFs)

	err := cp.AddToCache(folderPath, commitHash, existingCodeIssues, pc)
	cp.ClearIssues(folderPath, pc)

	assert.Nil(t, err)
	assert.Empty(t, cp.cache)
}

func TestClearIssues_ExistingCacheNonExistingProduct(t *testing.T) {
	existingCodeIssues := []Issue{
		{
			GlobalIdentity: uuid.New().String(),
		},
	}

	appFs := afero.NewMemMapFs()
	logger := zerolog.New(nil)
	folderPath := "/home/myusr/testrepo"
	commitHash := "eab0f18c4432b2a41e0f8e6c9831fe84be92b3db"
	pc := product.ProductCode
	cp := NewGitCacheProvider(&logger, appFs)

	err := cp.AddToCache(folderPath, commitHash, existingCodeIssues, pc)
	cp.ClearIssues(folderPath, product.ProductUnknown)

	assert.Nil(t, err)
	assert.NotEmpty(t, cp.cache)
}

func TestClearIssues_NonExistingCacheNonExistingProduct(t *testing.T) {
	existingCodeIssues := []Issue{
		{
			GlobalIdentity: uuid.New().String(),
		},
	}

	appFs := afero.NewMemMapFs()
	logger := zerolog.New(nil)
	folderPath := "/home/myusr/testrepo"
	commitHash := "eab0f18c4432b2a41e0f8e6c9831fe84be92b3db"
	pc := product.ProductCode
	cp := NewGitCacheProvider(&logger, appFs)

	err := cp.AddToCache(folderPath, commitHash, existingCodeIssues, pc)
	cp.ClearIssues("/invalid/folder/path", product.ProductUnknown)

	assert.Nil(t, err)
	assert.NotEmpty(t, cp.cache)
}
