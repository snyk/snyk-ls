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
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/google/uuid"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/util"
	"github.com/snyk/snyk-ls/internal/vcs"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"testing"
)

func TestInit_Empty(t *testing.T) {
	c := testutil.UnitTest(t)
	folderPath := t.TempDir()
	initGitRepo(t, folderPath, false)
	expectedCacheDir := filepath.Join(filepath.Join(folderPath, ".git", CacheFolder))
	cut := NewGitPersistenceProvider(c.Logger(), vcs.NewGitWrapper())
	actualCacheDir, err := cut.init(folderPath)

	assert.NoError(t, err)
	assert.Empty(t, cut.cache)
	assert.Equal(t, expectedCacheDir, actualCacheDir)
}

func TestInit_NotEmpty(t *testing.T) {
	c := testutil.UnitTest(t)
	folderPath := t.TempDir()
	repo := initGitRepo(t, folderPath, false)

	issueList := []snyk.Issue{
		{
			GlobalIdentity: uuid.New().String(),
		},
	}
	expectedCacheDir := filepath.Join(filepath.Join(folderPath, ".git", CacheFolder))
	hash := hashedFolderPath(util.Murmur(folderPath))

	commitHash, err := vcs.HeadRefHashForRepo(repo)
	assert.NoError(t, err)
	p := product.ProductCode

	cut := NewGitPersistenceProvider(c.Logger(), vcs.NewGitWrapper())

	// Here we call Add before init to make sure we have files already created
	err = cut.Add(folderPath, commitHash, issueList, p)
	assert.NoError(t, err)

	actualCacheDir, err := cut.init(folderPath)
	assert.NoError(t, err)

	assert.Equal(t, commitHash, cut.cache[hash][p])
	assert.Equal(t, expectedCacheDir, actualCacheDir)
}

func TestAdd_NewCommit(t *testing.T) {
	c := testutil.UnitTest(t)
	folderPath := t.TempDir()
	repo := initGitRepo(t, folderPath, false)

	issueList := []snyk.Issue{
		{
			GlobalIdentity: uuid.New().String(),
		},
	}
	hash := hashedFolderPath(util.Murmur(folderPath))

	commitHash, err := vcs.HeadRefHashForRepo(repo)
	assert.NoError(t, err)
	p := product.ProductCode

	cut := NewGitPersistenceProvider(c.Logger(), vcs.NewGitWrapper())

	err = cut.Add(folderPath, commitHash, issueList, p)
	assert.NoError(t, err)

	list, err := cut.GetPersistedIssueList(folderPath, p)
	assert.NoError(t, err)

	assert.NotEmpty(t, list)
	assert.Equal(t, commitHash, cut.cache[hash][p])
}

func TestAdd_ExistingCommit_ShouldNotOverrideExistingSnapshots(t *testing.T) {
	c := testutil.UnitTest(t)
	folderPath := t.TempDir()
	repo := initGitRepo(t, folderPath, false)

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

	commitHash, err := vcs.HeadRefHashForRepo(repo)
	assert.NoError(t, err)

	p := product.ProductCode

	cut := NewGitPersistenceProvider(c.Logger(), vcs.NewGitWrapper())

	err = cut.Add(folderPath, commitHash, issueList, p)
	assert.NoError(t, err)
	err = cut.Add(folderPath, commitHash, newIssueList, p)
	assert.NoError(t, err)
	list, err := cut.GetPersistedIssueList(folderPath, p)
	assert.NoError(t, err)

	assert.NotEmpty(t, list)
	assert.Equal(t, issueList[0].GetGlobalIdentity(), list[0].GetGlobalIdentity())
	assert.NotEqual(t, newIssueList[0].GetGlobalIdentity(), list[0].GetGlobalIdentity())
}

func TestAdd_ExistingCommit_ShouldOverrideExistingSnapshots(t *testing.T) {
	c := testutil.UnitTest(t)
	folderPath := t.TempDir()
	repo := initGitRepo(t, folderPath, true)

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

	commitHash, err := vcs.HeadRefHashForRepo(repo)
	assert.NoError(t, err)

	p := product.ProductCode

	cut := NewGitPersistenceProvider(c.Logger(), vcs.NewGitWrapper())

	err = cut.Add(folderPath, commitHash, issueList, p)
	assert.NoError(t, err)
	wt, err := repo.Worktree()
	assert.NoError(t, err)
	_, err = wt.Commit("testCommit", &git.CommitOptions{
		Author: &object.Signature{Name: t.Name()},
	})
	assert.NoError(t, err)
	newCommitHash, err := vcs.HeadRefHashForRepo(repo)
	assert.NoError(t, err)

	err = cut.Add(folderPath, newCommitHash, newIssueList, p)
	assert.NoError(t, err)
	list, err := cut.GetPersistedIssueList(folderPath, p)
	assert.NoError(t, err)

	assert.NotEmpty(t, list)
	assert.Equal(t, newIssueList[0].GetGlobalIdentity(), list[0].GetGlobalIdentity())
	assert.NotEqual(t, issueList[0].GetGlobalIdentity(), list[0].GetGlobalIdentity())
	cacheDir := filepath.Join(folderPath, ".git", CacheFolder)
	hash := hashedFolderPath(util.Murmur(folderPath))
	assert.NoError(t, err)
	newIssuesExist := cut.Exists(folderPath, newCommitHash, p)
	assert.True(t, newIssuesExist)
	oldIssuesExist := cut.Exists(folderPath, commitHash, p)
	assert.False(t, oldIssuesExist)

	newFileExists := issuesFileExists(cacheDir, hash, newCommitHash, p)
	assert.True(t, newFileExists)
	oldFileExists := issuesFileExists(cacheDir, hash, commitHash, p)
	assert.False(t, oldFileExists)
}

func TestGetCommitHashFor_ReturnsCommitHash(t *testing.T) {
	c := testutil.UnitTest(t)
	folderPath := t.TempDir()
	repo := initGitRepo(t, folderPath, false)

	issueList := []snyk.Issue{
		{
			GlobalIdentity: uuid.New().String(),
		},
	}

	hash := hashedFolderPath(util.Murmur(folderPath))
	commitHash, err := vcs.HeadRefHashForRepo(repo)
	assert.NoError(t, err)
	p := product.ProductCode
	cut := NewGitPersistenceProvider(c.Logger(), vcs.NewGitWrapper())

	err = cut.Add(folderPath, commitHash, issueList, p)
	assert.NoError(t, err)
	actualCommitHash, err := cut.getCommitHashForProduct(folderPath, p)

	assert.NoError(t, err)
	assert.Equal(t, cut.cache[hash][p], actualCommitHash)
}

func TestGetPersistedIssueList_ReturnsValidIssueListForProduct(t *testing.T) {
	c := testutil.UnitTest(t)
	folderPath := t.TempDir()
	repo := initGitRepo(t, folderPath, false)
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

	commitHash, err := vcs.HeadRefHashForRepo(repo)
	assert.NoError(t, err)
	pc := product.ProductCode
	po := product.ProductOpenSource
	cut := NewGitPersistenceProvider(c.Logger(), vcs.NewGitWrapper())

	err = cut.Add(folderPath, commitHash, existingCodeIssues, pc)
	assert.NoError(t, err)
	err = cut.Add(folderPath, commitHash, existingOssIssues, po)
	assert.NoError(t, err)
	actualCodeIssues, err := cut.GetPersistedIssueList(folderPath, pc)
	assert.NoError(t, err)
	assert.Equal(t, existingCodeIssues[0].GetGlobalIdentity(), actualCodeIssues[0].GetGlobalIdentity())
}

func TestClear_ExistingCache(t *testing.T) {
	c := testutil.UnitTest(t)
	folderPath := t.TempDir()
	repo := initGitRepo(t, folderPath, false)

	existingCodeIssues := []snyk.Issue{
		{
			GlobalIdentity: uuid.New().String(),
		},
	}

	commitHash, err := vcs.HeadRefHashForRepo(repo)
	assert.NoError(t, err)
	cacheDir := filepath.Join(xdg.CacheHome, CacheFolder)
	hash := hashedFolderPath(util.Murmur(folderPath))
	assert.NoError(t, err)
	pc := product.ProductCode
	cut := NewGitPersistenceProvider(c.Logger(), vcs.NewGitWrapper())

	err = cut.Add(folderPath, commitHash, existingCodeIssues, pc)
	assert.NoError(t, err)

	cut.Clear(folderPath)

	assert.Empty(t, cut.cache)
	assert.False(t, cut.snapshotExistsOnDisk(cacheDir, hash, commitHash, pc))
}

func TestClear_ExistingCacheNonExistingProduct(t *testing.T) {
	c := testutil.UnitTest(t)
	folderPath := t.TempDir()
	repo := initGitRepo(t, folderPath, false)
	existingCodeIssues := []snyk.Issue{
		{
			GlobalIdentity: uuid.New().String(),
		},
	}

	cacheDir := filepath.Join(xdg.CacheHome, CacheFolder)
	hash := hashedFolderPath(util.Murmur(folderPath))

	commitHash, err := vcs.HeadRefHashForRepo(repo)
	assert.NoError(t, err)
	pc := product.ProductCode
	cut := NewGitPersistenceProvider(c.Logger(), vcs.NewGitWrapper())

	err = cut.Add(folderPath, commitHash, existingCodeIssues, pc)
	cut.Clear(folderPath)

	assert.Nil(t, err)
	assert.Empty(t, cut.cache)
	assert.False(t, cut.snapshotExistsOnDisk(cacheDir, hash, commitHash, pc))
}

func TestClearIssues_ExistingCacheExistingProduct(t *testing.T) {
	c := testutil.UnitTest(t)
	folderPath := t.TempDir()
	repo := initGitRepo(t, folderPath, false)
	existingCodeIssues := []snyk.Issue{
		{
			GlobalIdentity: uuid.New().String(),
		},
	}

	cacheDir := filepath.Join(xdg.CacheHome, CacheFolder)
	hash := hashedFolderPath(util.Murmur(folderPath))

	commitHash, err := vcs.HeadRefHashForRepo(repo)
	assert.NoError(t, err)
	pc := product.ProductCode
	cut := NewGitPersistenceProvider(c.Logger(), vcs.NewGitWrapper())

	err = cut.Add(folderPath, commitHash, existingCodeIssues, pc)
	assert.NoError(t, err)

	err = cut.ClearForProduct(folderPath, commitHash, pc)
	assert.NoError(t, err)

	assert.Empty(t, cut.cache[hash][pc])
	assert.False(t, cut.snapshotExistsOnDisk(cacheDir, hash, commitHash, pc))
}

func TestClearIssues_ExistingCacheNonExistingProduct(t *testing.T) {
	c := testutil.UnitTest(t)
	folderPath := t.TempDir()
	repo := initGitRepo(t, folderPath, false)
	existingCodeIssues := []snyk.Issue{
		{
			GlobalIdentity: uuid.New().String(),
		},
	}

	cacheDir := filepath.Join(filepath.Join(folderPath, ".git", CacheFolder))
	hash := hashedFolderPath(util.Murmur(folderPath))

	commitHash, err := vcs.HeadRefHashForRepo(repo)
	assert.NoError(t, err)
	pc := product.ProductCode
	cut := NewGitPersistenceProvider(c.Logger(), vcs.NewGitWrapper())

	err = cut.Add(folderPath, commitHash, existingCodeIssues, pc)
	assert.NoError(t, err)

	err = cut.ClearForProduct(folderPath, commitHash, product.ProductUnknown)
	assert.Error(t, err)

	assert.NotEmpty(t, cut.cache)
	assert.NotEmpty(t, cut.cache[hash][pc])
	assert.True(t, cut.snapshotExistsOnDisk(cacheDir, hash, commitHash, pc))
}

func TestClearIssues_NonExistingCacheNonExistingProduct(t *testing.T) {
	c := testutil.UnitTest(t)
	folderPath := t.TempDir()
	repo := initGitRepo(t, folderPath, false)
	existingCodeIssues := []snyk.Issue{
		{
			GlobalIdentity: uuid.New().String(),
		},
	}

	cacheDir := filepath.Join(filepath.Join(folderPath, ".git", CacheFolder))
	hash := hashedFolderPath(util.Murmur(folderPath))

	commitHash, err := vcs.HeadRefHashForRepo(repo)
	assert.NoError(t, err)
	pc := product.ProductCode
	cut := NewGitPersistenceProvider(c.Logger(), vcs.NewGitWrapper())

	err = cut.Add(folderPath, commitHash, existingCodeIssues, pc)
	assert.NoError(t, err)

	invalidPath := "/invalid/folder/path"
	err = cut.ClearForProduct(invalidPath, commitHash, product.ProductUnknown)
	assert.Error(t, err)

	assert.NotEmpty(t, cut.cache)
	assert.True(t, cut.snapshotExistsOnDisk(cacheDir, hash, commitHash, pc))
}

func TestCreateOrAppendToCache_NewCache(t *testing.T) {
	c := testutil.UnitTest(t)
	folderPath := t.TempDir()
	repo := initGitRepo(t, folderPath, false)

	hash := hashedFolderPath(util.Murmur(folderPath))

	commitHash, err := vcs.HeadRefHashForRepo(repo)
	assert.NoError(t, err)
	pc := product.ProductCode

	cut := NewGitPersistenceProvider(c.Logger(), vcs.NewGitWrapper())
	cut.createOrAppendToCache(hash, commitHash, pc)

	assert.NotEmpty(t, cut.cache)
}

func TestCreateOrAppendToCache_ExistingCacheSameProductSameHash(t *testing.T) {
	c := testutil.UnitTest(t)
	folderPath := t.TempDir()
	repo := initGitRepo(t, folderPath, false)

	hash := hashedFolderPath(util.Murmur(folderPath))

	commitHash, err := vcs.HeadRefHashForRepo(repo)
	assert.NoError(t, err)
	pc := product.ProductCode

	cut := NewGitPersistenceProvider(c.Logger(), vcs.NewGitWrapper())
	cut.createOrAppendToCache(hash, commitHash, pc)
	cut.createOrAppendToCache(hash, commitHash, pc)

	assert.Equal(t, commitHash, cut.cache[hash][pc])
}

func TestCreateOrAppendToCache_ExistingCacheDifferentProductSameHash(t *testing.T) {
	c := testutil.UnitTest(t)
	folderPath := t.TempDir()
	repo := initGitRepo(t, folderPath, false)

	hash := hashedFolderPath(util.Murmur(folderPath))

	commitHash, err := vcs.HeadRefHashForRepo(repo)
	assert.NoError(t, err)
	pc := product.ProductCode
	po := product.ProductOpenSource

	cut := NewGitPersistenceProvider(c.Logger(), vcs.NewGitWrapper())
	cut.createOrAppendToCache(hash, commitHash, pc)
	cut.createOrAppendToCache(hash, commitHash, po)

	assert.Equal(t, commitHash, cut.cache[hash][pc])
	assert.Equal(t, commitHash, cut.cache[hash][po])
}

func TestCreateOrAppendToCache_ExistingCacheDifferentProductDifferentHash(t *testing.T) {
	c := testutil.UnitTest(t)
	folderPath := t.TempDir()
	initGitRepo(t, folderPath, false)

	hash := hashedFolderPath(util.Murmur(folderPath))

	pcCommitHash := "eab0f18c4432b2a41e0f8e6c9831fe84be92b3db"
	poCommitHash := "wwwwf18c4432b2a41e0f8e6c9831fe33be92b3db"
	pc := product.ProductCode
	po := product.ProductOpenSource

	cut := NewGitPersistenceProvider(c.Logger(), vcs.NewGitWrapper())
	cut.createOrAppendToCache(hash, pcCommitHash, pc)
	cut.createOrAppendToCache(hash, poCommitHash, po)

	assert.Equal(t, pcCommitHash, cut.cache[hash][pc])
	assert.Equal(t, poCommitHash, cut.cache[hash][po])
}

func TestCreateOrAppendToCache_ExistingCacheDifferentPathDifferentProductDifferentHash(t *testing.T) {
	c := testutil.UnitTest(t)
	folderPath := t.TempDir()
	initGitRepo(t, folderPath, false)
	hash := hashedFolderPath(util.Murmur(folderPath))

	otherFolderPath := "/home/myusr/newrepo"
	otherHashPath := hashedFolderPath(util.Murmur(otherFolderPath))
	pcCommitHash := "eab0f18c4432b2a41e0f8e6c9831fe84be92b3db"
	poCommitHash := "wwwwf18c4432b2a41e0f8e6c9831fe33be92b3db"
	pc := product.ProductCode
	po := product.ProductOpenSource

	cut := NewGitPersistenceProvider(c.Logger(), vcs.NewGitWrapper())
	cut.createOrAppendToCache(hash, pcCommitHash, pc)
	cut.createOrAppendToCache(otherHashPath, poCommitHash, po)

	assert.Equal(t, pcCommitHash, cut.cache[hash][pc])
	assert.Equal(t, poCommitHash, cut.cache[otherHashPath][po])
}

func TestEnsureCacheDirExists_DefaultCase(t *testing.T) {
	c := testutil.UnitTest(t)
	folderPath := t.TempDir()
	initGitRepo(t, folderPath, false)

	expectedCacheDir := filepath.Join(filepath.Join(folderPath, ".git", CacheFolder))
	cut := NewGitPersistenceProvider(c.Logger(), vcs.NewGitWrapper())

	actualCacheDir, err := cut.ensureCacheDirExists(folderPath)

	assert.NoError(t, err)
	assert.Empty(t, cut.cache)
	assert.Equal(t, expectedCacheDir, actualCacheDir)
}

func TestExists_ExistsInCacheButNotInFs(t *testing.T) {
	c := testutil.UnitTest(t)
	folderPath := t.TempDir()
	hash := hashedFolderPath(util.Murmur(folderPath))
	repo := initGitRepo(t, folderPath, false)
	existingCodeIssues := []snyk.Issue{
		{
			GlobalIdentity: uuid.New().String(),
		},
	}
	cacheDir := filepath.Join(filepath.Join(folderPath, ".git"), CacheFolder)

	commitHash, err := vcs.HeadRefHashForRepo(repo)
	assert.NoError(t, err)

	pc := product.ProductCode
	cut := NewGitPersistenceProvider(c.Logger(), vcs.NewGitWrapper())

	err = cut.Add(folderPath, commitHash, existingCodeIssues, pc)
	assert.NoError(t, err)
	err = os.RemoveAll(cacheDir)
	assert.NoError(t, err)

	exists := cut.Exists(folderPath, commitHash, pc)
	assert.False(t, exists)
	fileExists := issuesFileExists(cacheDir, hash, commitHash, pc)
	assert.False(t, fileExists)
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

func issuesFileExists(cacheDir string, hash hashedFolderPath, newCommitHash string, p product.Product) bool {
	newIssuesFile := getLocalFilePath(cacheDir, hash, newCommitHash, p)
	_, err := os.Stat(newIssuesFile)
	return err == nil
}
