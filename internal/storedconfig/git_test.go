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

package storedconfig

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/types"
)

// initializeTestGitRepo creates a Git repository with an initial commit (required for branches to actually exist)
// and specified branches.
func initializeTestGitRepo(t *testing.T, repoDir string, branches []string) {
	t.Helper()

	// Initialize Git repo with first branch as initial branch
	cmd := exec.Command("git", "init", "--initial-branch="+branches[0])
	cmd.Dir = repoDir
	err := cmd.Run()
	require.NoError(t, err)

	// Configure git user for commits (required on Windows and CI)
	cmd = exec.Command("git", "config", "user.email", "test@example.com")
	cmd.Dir = repoDir
	err = cmd.Run()
	require.NoError(t, err)

	cmd = exec.Command("git", "config", "user.name", "Test User")
	cmd.Dir = repoDir
	err = cmd.Run()
	require.NoError(t, err)

	// Create and commit a file (required for branches to exist)
	testFile := filepath.Join(repoDir, "test.txt")
	err = os.WriteFile(testFile, []byte("test content"), 0644)
	require.NoError(t, err)

	cmd = exec.Command("git", "add", ".")
	cmd.Dir = repoDir
	err = cmd.Run()
	require.NoError(t, err)

	cmd = exec.Command("git", "commit", "-m", "initial commit")
	cmd.Dir = repoDir
	err = cmd.Run()
	require.NoError(t, err)

	// Create additional branches
	for _, branch := range branches[1:] {
		cmd = exec.Command("git", "checkout", "-b", branch)
		cmd.Dir = repoDir
		err = cmd.Run()
		require.NoError(t, err)
	}
}

func Test_enrichFromGit_ReturnsLocalBranchesEvenWithoutMainOrMaster(t *testing.T) {
	// Create a temporary test Git repository with an initial commit and branches
	tempDir := t.TempDir()
	branches := []string{"feature-branch", "develop"}
	initializeTestGitRepo(t, tempDir, branches)

	logger := zerolog.New(zerolog.NewTestWriter(t))

	folderConfig := &types.FolderConfig{
		FolderPath: types.FilePath(tempDir),
	}

	// Act
	folderConfig = enrichFromGit(&logger, folderConfig)

	// Should have local branches
	require.NotNil(t, folderConfig)
	assert.ElementsMatch(t, branches, folderConfig.LocalBranches)

	// Base branch should be empty since we couldn't determine it
	assert.Empty(t, folderConfig.BaseBranch)
}

func Test_getBaseBranch_ReturnsErrorWhenNoDefaultBranch(t *testing.T) {
	// Create a temporary directory for the test repo
	tempDir := t.TempDir()

	// Initialize repo
	repo, err := git.PlainInit(tempDir, false)
	require.NoError(t, err)

	// Test with branches that are neither main nor master
	localBranches := []string{"feature-branch", "develop", "release"}

	// Should return error when no main/master branch exists
	_, err = getBaseBranch(repo, localBranches)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "could not determine base branch")
}

func Test_getBaseBranch_UsesInitDefaultBranchWhenSet(t *testing.T) {
	// Create a test Git repository with an initial commit and branches
	tempDir := t.TempDir()
	testDefaultBranch := "new-default-trunk-branch"
	branches := []string{"main", "master", testDefaultBranch, "feature"}
	initializeTestGitRepo(t, tempDir, branches)

	// Set init.defaultBranch in the repo config
	cmd := exec.Command("git", "config", "init.defaultBranch", testDefaultBranch)
	cmd.Dir = tempDir
	err := cmd.Run()
	require.NoError(t, err)

	// Open the repository
	repo, err := git.PlainOpen(tempDir)
	require.NoError(t, err)

	// Act
	baseBranch, err := getBaseBranch(repo, branches)
	require.NoError(t, err)

	// Assert we return the default branch
	assert.Equal(t, testDefaultBranch, baseBranch)
}

func Test_getBaseBranch_FallsBackToMasterWhenMainNotPresent(t *testing.T) {
	// Create a test Git repository with an initial commit and branches (including master but not main)
	tempDir := t.TempDir()
	branches := []string{"master", "feature-branch", "develop"}
	initializeTestGitRepo(t, tempDir, branches)

	// Open the repository
	repo, err := git.PlainOpen(tempDir)
	require.NoError(t, err)

	// Act
	baseBranch, err := getBaseBranch(repo, branches)
	require.NoError(t, err)

	// Assert we fall back to master (since it exists) and init.defaultBranch & main are not present
	assert.Equal(t, "master", baseBranch)
}
