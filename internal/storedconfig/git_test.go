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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/types"
)

func Test_getFromGit_ReturnsLocalBranchesEvenWithoutMainOrMaster(t *testing.T) {
	// Create a temporary directory for the test repo
	tempDir := t.TempDir()

	// Initialize a new git repo
	cmd := exec.Command("git", "init")
	cmd.Dir = tempDir
	err := cmd.Run()
	require.NoError(t, err)

	// Configure git user for commits (required on Windows and CI)
	cmd = exec.Command("git", "config", "user.email", "test@example.com")
	cmd.Dir = tempDir
	err = cmd.Run()
	require.NoError(t, err)

	cmd = exec.Command("git", "config", "user.name", "Test User")
	cmd.Dir = tempDir
	err = cmd.Run()
	require.NoError(t, err)

	// Create and commit a file
	testFile := filepath.Join(tempDir, "test.txt")
	err = os.WriteFile(testFile, []byte("test content"), 0644)
	require.NoError(t, err)

	cmd = exec.Command("git", "add", ".")
	cmd.Dir = tempDir
	err = cmd.Run()
	require.NoError(t, err)

	cmd = exec.Command("git", "commit", "-m", "initial commit")
	cmd.Dir = tempDir
	err = cmd.Run()
	require.NoError(t, err)

	// Create a branch that is neither main nor master
	cmd = exec.Command("git", "checkout", "-b", "feature-branch")
	cmd.Dir = tempDir
	err = cmd.Run()
	require.NoError(t, err)

	// Create another branch
	cmd = exec.Command("git", "checkout", "-b", "develop")
	cmd.Dir = tempDir
	err = cmd.Run()
	require.NoError(t, err)

	// Delete main and master branches if they exist
	// This ensures we test the scenario where neither exists
	cmd = exec.Command("git", "branch", "-D", "main")
	cmd.Dir = tempDir
	_ = cmd.Run() // Ignore error if branch doesn't exist

	cmd = exec.Command("git", "branch", "-D", "master")
	cmd.Dir = tempDir
	_ = cmd.Run() // Ignore error if branch doesn't exist

	// Test getFromGit
	folderConfig, err := getFromGit(types.FilePath(tempDir))

	// Should not return an error anymore
	assert.NoError(t, err)
	assert.NotNil(t, folderConfig)

	// Should have local branches
	assert.NotEmpty(t, folderConfig.LocalBranches)
	assert.Contains(t, folderConfig.LocalBranches, "feature-branch")
	assert.Contains(t, folderConfig.LocalBranches, "develop")

	// Base branch should be empty since we couldn't determine it
	assert.Empty(t, folderConfig.BaseBranch)
}

func Test_getBaseBranch_ReturnsErrorWhenNoDefaultBranch(t *testing.T) {
	// Create a temporary directory for the test repo
	tempDir := t.TempDir()

	// Initialize repo
	repo, err := git.PlainInit(tempDir, false)
	require.NoError(t, err)

	repoConfig, err := repo.Config()
	require.NoError(t, err)

	// Test with branches that are neither main nor master
	localBranches := []string{"feature-branch", "develop", "release"}

	// Should return error when no main/master branch exists
	_, err = getBaseBranch(repoConfig, repoConfig.Raw.Section("snyk").Subsection(tempDir), localBranches)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "could not determine base branch")
}
