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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/adrg/xdg"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/constants"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
	"github.com/snyk/snyk-ls/internal/vcs"
)

func TestInit_Empty(t *testing.T) {
	c := testutil.UnitTest(t)
	dir := types.FilePath(c.Engine().GetConfiguration().GetString(constants.DataHome))
	initGitRepo(t, dir, false)
	expectedCacheDir := filepath.Join(filepath.Join(string(dir), CacheFolder))
	cut := NewGitPersistenceProvider(c.Logger(), c.Engine().GetConfiguration())
	err := cut.Init([]types.FilePath{dir})
	assert.NoError(t, err)
	actualCacheDir := snykCacheDir(c.Engine().GetConfiguration())
	assert.NoError(t, err)
	assert.Empty(t, cut.cache)
	assert.Equal(t, expectedCacheDir, actualCacheDir)
}

func TestInit_NotEmpty(t *testing.T) {
	c := testutil.UnitTest(t)
	conf := c.Engine().GetConfiguration()
	folderPath := types.FilePath(conf.GetString(constants.DataHome))
	repo := initGitRepo(t, folderPath, false)

	issueList := []types.Issue{
		&snyk.Issue{
			GlobalIdentity: uuid.New().String(),
		},
	}
	expectedCacheDir := filepath.Join(filepath.Join(string(folderPath), CacheFolder))
	hash := hashedFolderPath(util.Sha256First16Hash(string(folderPath)))

	commitHash, err := vcs.HeadRefHashForRepo(repo)
	assert.NoError(t, err)
	p := product.ProductCode

	cut := NewGitPersistenceProvider(c.Logger(), conf)

	// Here we call Add before init to make sure we have files already created
	cacheDir := filepath.Join(string(folderPath), CacheFolder)
	err = os.MkdirAll(cacheDir, 0700)
	assert.NoError(t, err)
	err = cut.persistToDisk(cacheDir, hash, commitHash, p, issueList)
	assert.NoError(t, err)
	err = cut.Init([]types.FilePath{folderPath})
	assert.NoError(t, err)
	actualCacheDir := snykCacheDir(conf)
	assert.NoError(t, err)
	assert.Equal(t, commitHash, cut.cache[hash][p])
	assert.Equal(t, expectedCacheDir, actualCacheDir)
}

func TestInit_NotEmpty_ExpiredCache(t *testing.T) {
	c := testutil.UnitTest(t)
	conf := c.Engine().GetConfiguration()
	folderPath := types.FilePath(conf.GetString(constants.DataHome))
	repo := initGitRepo(t, folderPath, false)

	issueList := []types.Issue{
		&snyk.Issue{
			GlobalIdentity: uuid.New().String(),
		},
	}
	expectedCacheDir := filepath.Join(filepath.Join(string(folderPath), CacheFolder))
	hash := hashedFolderPath(util.Sha256First16Hash(string(folderPath)))

	commitHash, err := vcs.HeadRefHashForRepo(repo)
	assert.NoError(t, err)
	p := product.ProductCode

	cut := NewGitPersistenceProvider(c.Logger(), conf)
	ExpirationInSeconds = 2
	cacheDir := filepath.Join(string(folderPath), CacheFolder)
	err = os.MkdirAll(cacheDir, 0700)
	assert.NoError(t, err)
	err = cut.persistToDisk(cacheDir, hash, commitHash, p, issueList)
	assert.NoError(t, err)
	time.Sleep(3 * time.Second)

	err = cut.Init([]types.FilePath{folderPath})
	assert.NoError(t, err)
	actualCacheDir := snykCacheDir(conf)
	assert.NoError(t, err)
	assert.Empty(t, cut.cache)
	localFilePath := getLocalFilePath(cacheDir, hash, commitHash, p)
	assert.NoFileExists(t, localFilePath)
	assert.Equal(t, expectedCacheDir, actualCacheDir)
}

func TestAdd_NewCommit(t *testing.T) {
	c := testutil.UnitTest(t)
	conf := c.Engine().GetConfiguration()
	folderPath := types.FilePath(conf.GetString(constants.DataHome))
	repo := initGitRepo(t, folderPath, false)

	issueList := []types.Issue{
		&snyk.Issue{
			GlobalIdentity: uuid.New().String(),
		},
	}
	hash := hashedFolderPath(util.Sha256First16Hash(string(folderPath)))

	commitHash, err := vcs.HeadRefHashForRepo(repo)
	assert.NoError(t, err)
	p := product.ProductCode

	cut := NewGitPersistenceProvider(c.Logger(), conf)

	err = cut.Init([]types.FilePath{folderPath})
	assert.NoError(t, err)
	err = cut.Add(folderPath, commitHash, issueList, p)
	assert.NoError(t, err)

	list, err := cut.GetPersistedIssueList(folderPath, p)
	assert.NoError(t, err)

	assert.NotEmpty(t, list)
	assert.Equal(t, commitHash, cut.cache[hash][p])
}

func TestAdd_ExistingCommit_ShouldNotOverrideExistingSnapshots(t *testing.T) {
	c := testutil.UnitTest(t)
	conf := c.Engine().GetConfiguration()
	folderPath := types.FilePath(conf.GetString(constants.DataHome))
	repo := initGitRepo(t, folderPath, false)

	issueList := []types.Issue{
		&snyk.Issue{
			GlobalIdentity: uuid.New().String(),
		},
	}
	newIssueList := []types.Issue{
		&snyk.Issue{
			GlobalIdentity: uuid.New().String(),
		},
	}

	commitHash, err := vcs.HeadRefHashForRepo(repo)
	assert.NoError(t, err)

	p := product.ProductCode

	cut := NewGitPersistenceProvider(c.Logger(), conf)
	err = cut.Init([]types.FilePath{folderPath})
	assert.NoError(t, err)

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
	conf := c.Engine().GetConfiguration()
	folderPath := types.FilePath(conf.GetString(constants.DataHome))
	repo := initGitRepo(t, folderPath, true)

	issueList := []types.Issue{
		&snyk.Issue{
			GlobalIdentity: uuid.New().String(),
		},
	}
	newIssueList := []types.Issue{
		&snyk.Issue{
			GlobalIdentity: uuid.New().String(),
		},
	}

	commitHash, err := vcs.HeadRefHashForRepo(repo)
	assert.NoError(t, err)

	p := product.ProductCode

	cut := NewGitPersistenceProvider(c.Logger(), conf)

	err = cut.Init([]types.FilePath{folderPath})
	assert.NoError(t, err)

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
	cacheDir := filepath.Join(string(folderPath), CacheFolder)
	hash := hashedFolderPath(util.Sha256First16Hash(string(folderPath)))
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
	conf := c.Engine().GetConfiguration()
	folderPath := types.FilePath(conf.GetString(constants.DataHome))
	repo := initGitRepo(t, folderPath, false)

	issueList := []types.Issue{
		&snyk.Issue{
			GlobalIdentity: uuid.New().String(),
		},
	}

	hash := hashedFolderPath(util.Sha256First16Hash(string(folderPath)))
	commitHash, err := vcs.HeadRefHashForRepo(repo)
	assert.NoError(t, err)
	p := product.ProductCode
	cut := NewGitPersistenceProvider(c.Logger(), conf)

	err = cut.Init([]types.FilePath{folderPath})
	assert.NoError(t, err)

	err = cut.Add(folderPath, commitHash, issueList, p)
	assert.NoError(t, err)
	actualCommitHash, err := cut.getCommitHashForProduct(folderPath, p)

	assert.NoError(t, err)
	assert.Equal(t, cut.cache[hash][p], actualCommitHash)
}

func TestGetPersistedIssueList_ReturnsValidIssueListForProduct(t *testing.T) {
	c := testutil.UnitTest(t)
	conf := c.Engine().GetConfiguration()
	folderPath := types.FilePath(conf.GetString(constants.DataHome))
	repo := initGitRepo(t, folderPath, false)
	existingCodeIssues := []types.Issue{
		&snyk.Issue{
			GlobalIdentity: uuid.New().String(),
		},
	}
	existingOssIssues := []types.Issue{
		&snyk.Issue{
			GlobalIdentity: uuid.New().String(),
		},
	}

	commitHash, err := vcs.HeadRefHashForRepo(repo)
	assert.NoError(t, err)
	pc := product.ProductCode
	po := product.ProductOpenSource
	cut := NewGitPersistenceProvider(c.Logger(), c.Engine().GetConfiguration())
	err = cut.Init([]types.FilePath{folderPath})
	assert.NoError(t, err)
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
	conf := c.Engine().GetConfiguration()
	folderPath := types.FilePath(conf.GetString(constants.DataHome))
	repo := initGitRepo(t, folderPath, false)

	existingCodeIssues := []types.Issue{
		&snyk.Issue{
			GlobalIdentity: uuid.New().String(),
		},
	}

	commitHash, err := vcs.HeadRefHashForRepo(repo)
	assert.NoError(t, err)
	cacheDir := filepath.Join(xdg.CacheHome, CacheFolder)
	hash := hashedFolderPath(util.Sha256First16Hash(string(folderPath)))
	assert.NoError(t, err)
	pc := product.ProductCode
	cut := NewGitPersistenceProvider(c.Logger(), c.Engine().GetConfiguration())
	err = cut.Init([]types.FilePath{folderPath})
	assert.NoError(t, err)
	err = cut.Add(folderPath, commitHash, existingCodeIssues, pc)
	assert.NoError(t, err)

	cut.Clear([]types.FilePath{folderPath}, false)

	assert.Empty(t, cut.cache)
	assert.False(t, cut.snapshotExistsOnDisk(cacheDir, hash, commitHash, pc))
}

func TestClear_ExistingCacheNonExistingProduct(t *testing.T) {
	c := testutil.UnitTest(t)
	conf := c.Engine().GetConfiguration()
	folderPath := types.FilePath(conf.GetString(constants.DataHome))
	repo := initGitRepo(t, folderPath, false)
	existingCodeIssues := []types.Issue{
		&snyk.Issue{
			GlobalIdentity: uuid.New().String(),
		},
	}

	cacheDir := filepath.Join(xdg.CacheHome, CacheFolder)
	hash := hashedFolderPath(util.Sha256First16Hash(string(folderPath)))

	commitHash, err := vcs.HeadRefHashForRepo(repo)
	assert.NoError(t, err)
	pc := product.ProductCode
	cut := NewGitPersistenceProvider(c.Logger(), c.Engine().GetConfiguration())
	err = cut.Init([]types.FilePath{folderPath})
	assert.NoError(t, err)
	err = cut.Add(folderPath, commitHash, existingCodeIssues, pc)
	assert.NoError(t, err)
	cut.Clear([]types.FilePath{folderPath}, false)

	assert.Empty(t, cut.cache)
	assert.False(t, cut.snapshotExistsOnDisk(cacheDir, hash, commitHash, pc))
}

func TestClear_ExpiredCache(t *testing.T) {
	c := testutil.UnitTest(t)
	conf := c.Engine().GetConfiguration()
	folderPath := types.FilePath(conf.GetString(constants.DataHome))
	repo := initGitRepo(t, folderPath, false)

	expiredIssueList := []types.Issue{
		&snyk.Issue{
			GlobalIdentity: uuid.New().String(),
		},
	}
	existingIssueList := []types.Issue{
		&snyk.Issue{
			GlobalIdentity: uuid.New().String(),
		},
	}

	commitHash, err := vcs.HeadRefHashForRepo(repo)
	assert.NoError(t, err)
	expiredProduct := product.ProductCode
	existingProduct := product.ProductOpenSource

	cut := NewGitPersistenceProvider(c.Logger(), c.Engine().GetConfiguration())
	// override expiration to be 2 seconds instead of 12 hours
	ExpirationInSeconds = 2

	err = cut.Init([]types.FilePath{folderPath})
	assert.NoError(t, err)

	err = cut.Add(folderPath, commitHash, expiredIssueList, expiredProduct)
	assert.NoError(t, err)

	time.Sleep(3 * time.Second)
	err = cut.Add(folderPath, commitHash, existingIssueList, existingProduct)
	assert.NoError(t, err)
	cut.Clear([]types.FilePath{folderPath}, true)

	expiredActualIssueList, err := cut.GetPersistedIssueList(folderPath, expiredProduct)
	assert.Error(t, err)
	existingActualIssueList, err := cut.GetPersistedIssueList(folderPath, existingProduct)
	assert.NoError(t, err)
	assert.Empty(t, expiredActualIssueList)
	assert.NotEmpty(t, existingActualIssueList)
}

func TestCreateOrAppendToCache_NewCache(t *testing.T) {
	c := testutil.UnitTest(t)
	conf := c.Engine().GetConfiguration()
	folderPath := types.FilePath(conf.GetString(constants.DataHome))
	repo := initGitRepo(t, folderPath, false)

	hash := hashedFolderPath(util.Sha256First16Hash(string(folderPath)))

	commitHash, err := vcs.HeadRefHashForRepo(repo)
	assert.NoError(t, err)
	pc := product.ProductCode

	cut := NewGitPersistenceProvider(c.Logger(), c.Engine().GetConfiguration())
	cut.createOrAppendToCache(hash, commitHash, pc)

	assert.NotEmpty(t, cut.cache)
}

func TestCreateOrAppendToCache_ExistingCacheSameProductSameHash(t *testing.T) {
	c := testutil.UnitTest(t)
	conf := c.Engine().GetConfiguration()
	folderPath := types.FilePath(conf.GetString(constants.DataHome))
	repo := initGitRepo(t, folderPath, false)

	hash := hashedFolderPath(util.Sha256First16Hash(string(folderPath)))

	commitHash, err := vcs.HeadRefHashForRepo(repo)
	assert.NoError(t, err)
	pc := product.ProductCode

	cut := NewGitPersistenceProvider(c.Logger(), c.Engine().GetConfiguration())
	cut.createOrAppendToCache(hash, commitHash, pc)
	cut.createOrAppendToCache(hash, commitHash, pc)

	assert.Equal(t, commitHash, cut.cache[hash][pc])
}

func TestCreateOrAppendToCache_ExistingCacheDifferentProductSameHash(t *testing.T) {
	c := testutil.UnitTest(t)
	conf := c.Engine().GetConfiguration()
	folderPath := types.FilePath(conf.GetString(constants.DataHome))
	repo := initGitRepo(t, folderPath, false)

	hash := hashedFolderPath(util.Sha256First16Hash(string(folderPath)))

	commitHash, err := vcs.HeadRefHashForRepo(repo)
	assert.NoError(t, err)
	pc := product.ProductCode
	po := product.ProductOpenSource

	cut := NewGitPersistenceProvider(c.Logger(), c.Engine().GetConfiguration())
	cut.createOrAppendToCache(hash, commitHash, pc)
	cut.createOrAppendToCache(hash, commitHash, po)

	assert.Equal(t, commitHash, cut.cache[hash][pc])
	assert.Equal(t, commitHash, cut.cache[hash][po])
}

func TestCreateOrAppendToCache_ExistingCacheDifferentProductDifferentHash(t *testing.T) {
	c := testutil.UnitTest(t)
	conf := c.Engine().GetConfiguration()
	folderPath := types.FilePath(conf.GetString(constants.DataHome))
	initGitRepo(t, folderPath, false)

	hash := hashedFolderPath(util.Sha256First16Hash(string(folderPath)))

	pcCommitHash := "eab0f18c4432b2a41e0f8e6c9831fe84be92b3db"
	poCommitHash := "wwwwf18c4432b2a41e0f8e6c9831fe33be92b3db"
	pc := product.ProductCode
	po := product.ProductOpenSource

	cut := NewGitPersistenceProvider(c.Logger(), c.Engine().GetConfiguration())
	cut.createOrAppendToCache(hash, pcCommitHash, pc)
	cut.createOrAppendToCache(hash, poCommitHash, po)

	assert.Equal(t, pcCommitHash, cut.cache[hash][pc])
	assert.Equal(t, poCommitHash, cut.cache[hash][po])
}

func TestCreateOrAppendToCache_ExistingCacheDifferentPathDifferentProductDifferentHash(t *testing.T) {
	c := testutil.UnitTest(t)
	conf := c.Engine().GetConfiguration()
	folderPath := types.FilePath(conf.GetString(constants.DataHome))
	initGitRepo(t, folderPath, false)
	hash := hashedFolderPath(util.Sha256First16Hash(string(folderPath)))

	otherFolderPath := "/home/myusr/newrepo"
	otherHashPath := hashedFolderPath(util.Sha256First16Hash(otherFolderPath))
	pcCommitHash := "eab0f18c4432b2a41e0f8e6c9831fe84be92b3db"
	poCommitHash := "wwwwf18c4432b2a41e0f8e6c9831fe33be92b3db"
	pc := product.ProductCode
	po := product.ProductOpenSource

	cut := NewGitPersistenceProvider(c.Logger(), c.Engine().GetConfiguration())
	cut.createOrAppendToCache(hash, pcCommitHash, pc)
	cut.createOrAppendToCache(otherHashPath, poCommitHash, po)

	assert.Equal(t, pcCommitHash, cut.cache[hash][pc])
	assert.Equal(t, poCommitHash, cut.cache[otherHashPath][po])
}

func TestEnsureCacheDirExists_DefaultCase(t *testing.T) {
	c := testutil.UnitTest(t)
	conf := c.Engine().GetConfiguration()
	folderPath := types.FilePath(conf.GetString(constants.DataHome))
	initGitRepo(t, folderPath, false)

	expectedCacheDir := filepath.Join(filepath.Join(string(folderPath), CacheFolder))
	cut := NewGitPersistenceProvider(c.Logger(), c.Engine().GetConfiguration())

	actualCacheDir, err := cut.ensureCacheDirExists()

	assert.NoError(t, err)
	assert.Empty(t, cut.cache)
	assert.Equal(t, expectedCacheDir, actualCacheDir)
}

func TestExists_ExistsInCacheButNotInFs(t *testing.T) {
	c := testutil.UnitTest(t)
	conf := c.Engine().GetConfiguration()
	folderPath := types.FilePath(conf.GetString(constants.DataHome))
	hash := hashedFolderPath(util.Sha256First16Hash(string(folderPath)))
	repo := initGitRepo(t, folderPath, false)
	existingCodeIssues := []types.Issue{
		&snyk.Issue{
			GlobalIdentity: uuid.New().String(),
		},
	}
	cacheDir := filepath.Join(string(folderPath), CacheFolder)

	commitHash, err := vcs.HeadRefHashForRepo(repo)
	assert.NoError(t, err)

	pc := product.ProductCode
	cut := NewGitPersistenceProvider(c.Logger(), conf)
	err = cut.Init([]types.FilePath{folderPath})
	assert.NoError(t, err)
	err = cut.Add(folderPath, commitHash, existingCodeIssues, pc)
	assert.NoError(t, err)
	err = os.RemoveAll(cacheDir)
	assert.NoError(t, err)

	exists := cut.Exists(folderPath, commitHash, pc)
	assert.False(t, exists)
	fileExists := issuesFileExists(cacheDir, hash, commitHash, pc)
	assert.False(t, fileExists)
}

func initGitRepo(t *testing.T, repoPath types.FilePath, isModified bool) *git.Repository {
	t.Helper()
	repo, err := git.PlainInit(string(repoPath), false)
	assert.NoError(t, err)

	absoluteFileName := filepath.Join(string(repoPath), "testFile.txt")
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

	testfile2 := filepath.Join(string(repoPath), "testFile2.txt")
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
