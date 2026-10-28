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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestCheckoutHandler_ShouldCheckout(t *testing.T) {
	engine := testutil.UnitTest(t)
	repoPath := types.FilePath(t.TempDir())
	_, _ = initGitRepo(t, repoPath, false)
	ch := NewCheckoutHandler(engine.GetConfiguration())

	err := ch.CheckoutBaseBranch(engine.GetLogger(), getFolderConfig(repoPath))
	assert.NotNil(t, ch.CleanupFunc())
	assert.NotNil(t, ch.Repo())
	assert.NotEmpty(t, ch.BaseFolderPath())

	ch.CleanupFunc()()
	assert.NoError(t, err)
}

func TestCheckoutHandler_InvalidGitRepo(t *testing.T) {
	engine := testutil.UnitTest(t)
	repoPath := types.FilePath(t.TempDir())
	ch := NewCheckoutHandler(engine.GetConfiguration())

	err := ch.CheckoutBaseBranch(engine.GetLogger(), getFolderConfig(repoPath))
	assert.Error(t, err)
	assert.Nil(t, ch.CleanupFunc())
	assert.Nil(t, ch.Repo())
	assert.Empty(t, ch.BaseFolderPath())
}

func TestCheckoutHandler_AlreadyCreated(t *testing.T) {
	engine := testutil.UnitTest(t)
	repoPath := types.FilePath(t.TempDir())
	_, _ = initGitRepo(t, repoPath, false)

	ch := NewCheckoutHandler(engine.GetConfiguration())

	err := ch.CheckoutBaseBranch(engine.GetLogger(), getFolderConfig(repoPath))
	assert.NoError(t, err)
	assert.NotNil(t, ch.CleanupFunc())
	assert.NotNil(t, ch.Repo())
	assert.NotEmpty(t, ch.BaseFolderPath())

	firstRunPath := ch.BaseFolderPath()
	firstRunRepo := ch.Repo()

	err = ch.CheckoutBaseBranch(engine.GetLogger(), getFolderConfig(repoPath))
	assert.NoError(t, err)
	assert.NotNil(t, ch.CleanupFunc())
	assert.NotEmpty(t, ch.Repo())
	assert.NotEmpty(t, ch.BaseFolderPath())

	assert.Equal(t, firstRunRepo, ch.Repo())
	assert.Equal(t, firstRunPath, ch.BaseFolderPath())
	ch.CleanupFunc()()
}

func getFolderConfig(path types.FilePath) *types.FolderConfig {
	return &types.FolderConfig{
		FolderPath: path,
	}
}

func TestCheckoutHandler_SubfolderPath(t *testing.T) {
	engine := testutil.UnitTest(t)
	repoRootPath := types.FilePath(t.TempDir())
	repo, _ := initGitRepo(t, repoRootPath, false)

	// Create a subfolder in the repo
	subfolderName := "subproject"
	subfolderPath := types.FilePath(filepath.Join(string(repoRootPath), subfolderName))
	err := os.Mkdir(string(subfolderPath), 0755)
	require.NoError(t, err)

	// Create a file in the subfolder and commit it
	testFile := filepath.Join(string(subfolderPath), "test.txt")
	err = os.WriteFile(testFile, []byte("subfolder test data"), 0600)
	require.NoError(t, err)

	worktree, err := repo.Worktree()
	require.NoError(t, err)
	_, err = worktree.Add(filepath.Join(subfolderName, "test.txt"))
	require.NoError(t, err)
	_, err = worktree.Commit("Add subfolder test file", &git.CommitOptions{
		Author: &object.Signature{Name: t.Name()},
	})
	require.NoError(t, err)

	// Checkout handler with subfolder as FolderPath
	ch := NewCheckoutHandler(engine.GetConfiguration())
	err = ch.CheckoutBaseBranch(engine.GetLogger(), getFolderConfig(subfolderPath))
	require.NoError(t, err)

	// Verify the base folder path points to the subfolder in the cloned repo
	baseFolderPath := ch.BaseFolderPath()
	assert.NotEmpty(t, baseFolderPath)

	// The base folder path should be the temp clone root with subfolder path appended
	assert.True(t, strings.Contains(string(baseFolderPath), subfolderName),
		"base folder path should include subfolder name: %s", string(baseFolderPath))

	// Verify the subfolder content exists in the cloned location
	subfolderFile := filepath.Join(string(baseFolderPath), "test.txt")
	_, err = os.Stat(subfolderFile)
	assert.NoError(t, err, "subfolder content should exist at the expected path")

	ch.CleanupFunc()()
}

func TestCheckoutHandler_RootPath(t *testing.T) {
	engine := testutil.UnitTest(t)
	repoPath := types.FilePath(t.TempDir())
	_, _ = initGitRepo(t, repoPath, false)

	// Checkout handler with repo root as FolderPath
	ch := NewCheckoutHandler(engine.GetConfiguration())
	err := ch.CheckoutBaseBranch(engine.GetLogger(), getFolderConfig(repoPath))
	require.NoError(t, err)

	// Verify the base folder path points to the temp clone root (no subfolder)
	baseFolderPath := ch.BaseFolderPath()
	assert.NotEmpty(t, baseFolderPath)

	// For root workspaces, the base folder path should just be the clone temp root
	// The temp root will have subdirectories and files from the repo
	testFile := filepath.Join(string(baseFolderPath), "testFile.txt")
	_, err = os.Stat(testFile)
	assert.NoError(t, err, "root checkout should place repo content directly in base folder path")

	ch.CleanupFunc()()
}
