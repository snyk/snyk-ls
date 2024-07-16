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

package persistence

import (
	"github.com/adrg/xdg"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"os"
	"path/filepath"
	"testing"
)

func TestInit_Empty(t *testing.T) {
	appFs := afero.NewMemMapFs()
	logger := zerolog.New(nil)
	folderPath := "/home/myusr/testrepo"
	expectedCacheDir := filepath.Join(xdg.CacheHome, CacheFolder)
	cut := NewGitPersistenceProvider(&logger, appFs)
	actualCacheDir, err := cut.init(folderPath)

	assert.NoError(t, err)
	assert.Empty(t, cut.cache)
	assert.Equal(t, expectedCacheDir, actualCacheDir)
}

func TestInit_NotEmpty(t *testing.T) {
	issueList := []snyk.Issue{
		{
			GlobalIdentity: uuid.New().String(),
		},
	}
	appFs := afero.NewMemMapFs()
	logger := zerolog.New(nil)
	folderPath := "/home/myusr/testrepo"
	expectedCacheDir := filepath.Join(xdg.CacheHome, CacheFolder)
	hash, err := hashPath(folderPath)
	assert.NoError(t, err)

	commitHash := "eab0f18c4432b2a41e0f8e6c9831fe84be92b3db"
	p := product.ProductCode

	cut := NewGitPersistenceProvider(&logger, appFs)

	// Here we call Add before init to make sure we have files already created
	err = cut.Add(folderPath, commitHash, issueList, p)
	assert.NoError(t, err)

	actualCacheDir, err := cut.init(folderPath)
	assert.NoError(t, err)

	assert.Equal(t, commitHash, cut.cache[hash][p])
	assert.Equal(t, expectedCacheDir, actualCacheDir)
}

func TestAddTo_NewCommit(t *testing.T) {
	issueList := []snyk.Issue{
		{
			GlobalIdentity: uuid.New().String(),
		},
	}
	appFs := afero.NewMemMapFs()
	logger := zerolog.New(nil)
	folderPath := "/home/myusr/testrepo"
	hash, err := hashPath(folderPath)
	assert.NoError(t, err)

	commitHash := "eab0f18c4432b2a41e0f8e6c9831fe84be92b3db"
	p := product.ProductCode

	cut := NewGitPersistenceProvider(&logger, appFs)

	err = cut.Add(folderPath, commitHash, issueList, p)
	assert.NoError(t, err)

	list, err := cut.GetPersistedIssueList(folderPath, p)
	assert.NoError(t, err)

	assert.NotEmpty(t, list)
	assert.Equal(t, commitHash, cut.cache[hash][p])
}

func TestAddToCache_ExistingCommit_ShouldNotOverrideExistingSnapshots(t *testing.T) {
	issueList := []snyk.Issue{
		{
			GlobalIdentity: uuid.New().String(),
		},
	}
	newIssueList := []snyk.Issue{
		{
			GlobalIdentity: uuid.New().String(),
		},
	}
	appFs := afero.NewMemMapFs()
	logger := zerolog.New(nil)
	folderPath := "/home/myusr/testrepo"
	commitHash := "eab0f18c4432b2a41e0f8e6c9831fe84be92b3db"
	p := product.ProductCode

	cut := NewGitPersistenceProvider(&logger, appFs)

	err := cut.Add(folderPath, commitHash, issueList, p)
	assert.NoError(t, err)
	err = cut.Add(folderPath, commitHash, newIssueList, p)
	assert.NoError(t, err)
	list, err := cut.GetPersistedIssueList(folderPath, p)
	assert.NoError(t, err)

	assert.NotEmpty(t, list)
	assert.Equal(t, issueList[0].GetGlobalIdentity(), list[0].GetGlobalIdentity())
	assert.NotEqual(t, newIssueList[0].GetGlobalIdentity(), list[0].GetGlobalIdentity())
}

func TestGetCommitHashFor_ReturnsCommitHash(t *testing.T) {
	issueList := []snyk.Issue{
		{
			GlobalIdentity: uuid.New().String(),
		},
	}

	appFs := afero.NewMemMapFs()
	logger := zerolog.New(nil)
	folderPath := "/home/myusr/testrepo"
	hash, err := hashPath(folderPath)
	assert.NoError(t, err)
	commitHash := "eab0f18c4432b2a41e0f8e6c9831fe84be92b3db"
	p := product.ProductCode
	cut := NewGitPersistenceProvider(&logger, appFs)

	err = cut.Add(folderPath, commitHash, issueList, p)
	assert.NoError(t, err)
	actualCommitHash, err := cut.getCommitHashForProduct(folderPath, p)

	assert.NoError(t, err)
	assert.Equal(t, cut.cache[hash][p], actualCommitHash)
}

func TestGetPersistedIssueList_ReturnsValidIssueListForProduct(t *testing.T) {
	existingCodeIssues := []snyk.Issue{
		{
			GlobalIdentity: uuid.New().String(),
		},
	}
	existingOssIssues := []snyk.Issue{
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
	cut := NewGitPersistenceProvider(&logger, appFs)

	err := cut.Add(folderPath, commitHash, existingCodeIssues, pc)
	assert.NoError(t, err)
	err = cut.Add(folderPath, commitHash, existingOssIssues, po)
	assert.NoError(t, err)
	actualCodeIssues, err := cut.GetPersistedIssueList(folderPath, pc)
	assert.NoError(t, err)
	assert.Equal(t, existingCodeIssues[0].GetGlobalIdentity(), actualCodeIssues[0].GetGlobalIdentity())
}

func TestClear_ExistingCache(t *testing.T) {
	existingCodeIssues := []snyk.Issue{
		{
			GlobalIdentity: uuid.New().String(),
		},
	}
	appFs := afero.NewMemMapFs()
	logger := zerolog.New(nil)
	folderPath := "/home/myusr/testrepo"
	commitHash := "eab0f18c4432b2a41e0f8e6c9831fe84be92b3db"
	cacheDir := filepath.Join(xdg.CacheHome, CacheFolder)
	hash, err := hashPath(folderPath)
	assert.NoError(t, err)
	pc := product.ProductCode
	cut := NewGitPersistenceProvider(&logger, appFs)

	err = cut.Add(folderPath, commitHash, existingCodeIssues, pc)
	assert.NoError(t, err)

	cut.Clear(folderPath)

	assert.Empty(t, cut.cache)
	assert.False(t, cut.snapshotExistsOnDisk(cacheDir, hash, commitHash, pc))
}

func TestClear_ExistingCacheNonExistingProduct(t *testing.T) {
	existingCodeIssues := []snyk.Issue{
		{
			GlobalIdentity: uuid.New().String(),
		},
	}

	appFs := afero.NewMemMapFs()
	logger := zerolog.New(nil)
	folderPath := "/home/myusr/testrepo"
	cacheDir := filepath.Join(xdg.CacheHome, CacheFolder)
	hash, err := hashPath(folderPath)
	assert.NoError(t, err)

	commitHash := "eab0f18c4432b2a41e0f8e6c9831fe84be92b3db"
	pc := product.ProductCode
	cut := NewGitPersistenceProvider(&logger, appFs)

	err = cut.Add(folderPath, commitHash, existingCodeIssues, pc)
	cut.Clear(folderPath)

	assert.Nil(t, err)
	assert.Empty(t, cut.cache)
	assert.False(t, cut.snapshotExistsOnDisk(cacheDir, hash, commitHash, pc))
}

func TestClearIssues_ExistingCacheExistingProduct(t *testing.T) {
	existingCodeIssues := []snyk.Issue{
		{
			GlobalIdentity: uuid.New().String(),
		},
	}

	appFs := afero.NewMemMapFs()
	logger := zerolog.New(nil)
	folderPath := "/home/myusr/testrepo"
	cacheDir := filepath.Join(xdg.CacheHome, CacheFolder)
	hash, err := hashPath(folderPath)
	assert.NoError(t, err)

	commitHash := "eab0f18c4432b2a41e0f8e6c9831fe84be92b3db"
	pc := product.ProductCode
	cut := NewGitPersistenceProvider(&logger, appFs)

	err = cut.Add(folderPath, commitHash, existingCodeIssues, pc)
	assert.NoError(t, err)

	err = cut.ClearForProduct(folderPath, commitHash, pc)
	assert.NoError(t, err)

	assert.Empty(t, cut.cache[hash][pc])
	assert.False(t, cut.snapshotExistsOnDisk(cacheDir, hash, commitHash, pc))
}

func TestClearIssues_ExistingCacheNonExistingProduct(t *testing.T) {
	existingCodeIssues := []snyk.Issue{
		{
			GlobalIdentity: uuid.New().String(),
		},
	}

	appFs := afero.NewMemMapFs()
	logger := zerolog.New(nil)
	folderPath := "/home/myusr/testrepo"
	cacheDir := filepath.Join(xdg.CacheHome, CacheFolder)
	hash, err := hashPath(folderPath)
	assert.NoError(t, err)

	commitHash := "eab0f18c4432b2a41e0f8e6c9831fe84be92b3db"
	pc := product.ProductCode
	cut := NewGitPersistenceProvider(&logger, appFs)

	err = cut.Add(folderPath, commitHash, existingCodeIssues, pc)
	assert.NoError(t, err)

	err = cut.ClearForProduct(folderPath, commitHash, product.ProductUnknown)
	assert.Error(t, err)

	assert.NotEmpty(t, cut.cache)
	assert.NotEmpty(t, cut.cache[hash][pc])
	assert.True(t, cut.snapshotExistsOnDisk(cacheDir, hash, commitHash, pc))
}

func TestClearIssues_NonExistingCacheNonExistingProduct(t *testing.T) {
	existingCodeIssues := []snyk.Issue{
		{
			GlobalIdentity: uuid.New().String(),
		},
	}

	appFs := afero.NewMemMapFs()
	logger := zerolog.New(nil)
	folderPath := "/home/myusr/testrepo"
	cacheDir := filepath.Join(xdg.CacheHome, CacheFolder)
	hash, err := hashPath(folderPath)
	assert.NoError(t, err)

	commitHash := "eab0f18c4432b2a41e0f8e6c9831fe84be92b3db"
	pc := product.ProductCode
	cut := NewGitPersistenceProvider(&logger, appFs)

	err = cut.Add(folderPath, commitHash, existingCodeIssues, pc)
	assert.NoError(t, err)

	err = cut.ClearForProduct("/invalid/folder/path", commitHash, product.ProductUnknown)
	assert.Error(t, err)

	assert.NotEmpty(t, cut.cache)
	assert.True(t, cut.snapshotExistsOnDisk(cacheDir, hash, commitHash, pc))
}

func TestCreateOrAppendToCache_NewCache(t *testing.T) {
	appFs := afero.NewMemMapFs()
	logger := zerolog.New(nil)
	folderPath := "/home/myusr/testrepo"
	hash, err := hashPath(folderPath)
	assert.NoError(t, err)

	commitHash := "eab0f18c4432b2a41e0f8e6c9831fe84be92b3db"
	pc := product.ProductCode

	cut := NewGitPersistenceProvider(&logger, appFs)
	cut.createOrAppendToCache(hash, commitHash, pc)

	assert.NotEmpty(t, cut.cache)
}

func TestCreateOrAppendToCache_ExistingCacheSameProductSameHash(t *testing.T) {
	appFs := afero.NewMemMapFs()
	logger := zerolog.New(nil)
	folderPath := "/home/myusr/testrepo"
	hash, err := hashPath(folderPath)
	assert.NoError(t, err)

	commitHash := "eab0f18c4432b2a41e0f8e6c9831fe84be92b3db"
	pc := product.ProductCode

	cut := NewGitPersistenceProvider(&logger, appFs)
	cut.createOrAppendToCache(hash, commitHash, pc)
	cut.createOrAppendToCache(hash, commitHash, pc)

	assert.Equal(t, commitHash, cut.cache[hash][pc])
}

func TestCreateOrAppendToCache_ExistingCacheDifferentProductSameHash(t *testing.T) {
	appFs := afero.NewMemMapFs()
	logger := zerolog.New(nil)
	folderPath := "/home/myusr/testrepo"
	hash, err := hashPath(folderPath)
	assert.NoError(t, err)

	commitHash := "eab0f18c4432b2a41e0f8e6c9831fe84be92b3db"
	pc := product.ProductCode
	po := product.ProductOpenSource

	cut := NewGitPersistenceProvider(&logger, appFs)
	cut.createOrAppendToCache(hash, commitHash, pc)
	cut.createOrAppendToCache(hash, commitHash, po)

	assert.Equal(t, commitHash, cut.cache[hash][pc])
	assert.Equal(t, commitHash, cut.cache[hash][po])
}

func TestCreateOrAppendToCache_ExistingCacheDifferentProductDifferentHash(t *testing.T) {
	appFs := afero.NewMemMapFs()
	logger := zerolog.New(nil)
	folderPath := "/home/myusr/testrepo"
	hash, err := hashPath(folderPath)
	assert.NoError(t, err)

	pcCommitHash := "eab0f18c4432b2a41e0f8e6c9831fe84be92b3db"
	poCommitHash := "wwwwf18c4432b2a41e0f8e6c9831fe33be92b3db"
	pc := product.ProductCode
	po := product.ProductOpenSource

	cut := NewGitPersistenceProvider(&logger, appFs)
	cut.createOrAppendToCache(hash, pcCommitHash, pc)
	cut.createOrAppendToCache(hash, poCommitHash, po)

	assert.Equal(t, pcCommitHash, cut.cache[hash][pc])
	assert.Equal(t, poCommitHash, cut.cache[hash][po])
}

func TestCreateOrAppendToCache_ExistingCacheDifferentPathDifferentProductDifferentHash(t *testing.T) {
	appFs := afero.NewMemMapFs()
	logger := zerolog.New(nil)
	folderPath := "/home/myusr/testrepo"
	hash, err := hashPath(folderPath)
	assert.NoError(t, err)

	otherFolderPath := "/home/myusr/newrepo"
	otherHashPath, _ := hashPath(otherFolderPath)
	pcCommitHash := "eab0f18c4432b2a41e0f8e6c9831fe84be92b3db"
	poCommitHash := "wwwwf18c4432b2a41e0f8e6c9831fe33be92b3db"
	pc := product.ProductCode
	po := product.ProductOpenSource

	cut := NewGitPersistenceProvider(&logger, appFs)
	cut.createOrAppendToCache(hash, pcCommitHash, pc)
	cut.createOrAppendToCache(otherHashPath, poCommitHash, po)

	assert.Equal(t, pcCommitHash, cut.cache[hash][pc])
	assert.Equal(t, poCommitHash, cut.cache[otherHashPath][po])
}

func TestEnsureCacheDirExists_DefaultCase(t *testing.T) {
	appFs := afero.NewMemMapFs()
	logger := zerolog.New(nil)
	folderPath := "/home/myusr/testrepo"
	expectedCacheDir := filepath.Join(xdg.CacheHome, CacheFolder)
	cut := NewGitPersistenceProvider(&logger, appFs)

	actualCacheDir, err := cut.ensureCacheDirExists(folderPath)

	assert.NoError(t, err)
	assert.Empty(t, cut.cache)
	assert.Equal(t, expectedCacheDir, actualCacheDir)
}

type MockFs struct {
	mock.Mock
	afero.Fs
}

func (m *MockFs) Stat(name string) (os.FileInfo, error) {
	args := m.Called(name)
	return nil, args.Error(1)
}

func (m *MockFs) Mkdir(name string, perm os.FileMode) error {
	args := m.Called(name, perm)
	return args.Error(0)
}

func TestEnsureCacheDirExists_CacheDirIsReadonly_FallbackToGitDir(t *testing.T) {
	c := testutil.UnitTest(t)
	tmpDir := t.TempDir()
	xdg.CacheHome = tmpDir
	appFs := afero.NewOsFs()

	folderPath := "/home/myusr/testrepo"
	gitSnykCacheDir := filepath.Join(filepath.Join(folderPath, ".git"), CacheFolder)
	cut := NewGitPersistenceProvider(c.Logger(), appFs)

	actualCacheDir, err := cut.ensureCacheDirExists(folderPath)

	assert.NoError(t, err)
	assert.Empty(t, cut.cache)
	assert.Equal(t, gitSnykCacheDir, actualCacheDir)
}
