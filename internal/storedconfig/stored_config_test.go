/*
 * 2025 Snyk Limited
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
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/storage"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

func Test_GetOrCreateFolderConfig_shouldStoreEverythingInStorageFile(t *testing.T) {
	conf, storageFile := SetupConfigurationWithStorage(t)
	path := types.FilePath(t.TempDir())
	dir, err := os.UserHomeDir()
	require.NoError(t, err)

	nop := zerolog.Nop()

	// act
	actual, err := GetOrCreateFolderConfig(conf, path, &nop)
	require.NoError(t, err)
	actual.ReferenceFolderPath = types.FilePath(dir)
	err = UpdateFolderConfig(conf, actual, &nop)
	require.NoError(t, err)

	// verify
	require.Equal(t, path, actual.FolderPath)
	scJson := conf.GetString(ConfigMainKey)
	var sc StoredConfig
	err = json.Unmarshal([]byte(scJson), &sc)
	require.NoError(t, err)
	require.Equal(t, actual, sc.FolderConfigs[util.GenerateFolderConfigKey(path)])

	bytes, err := os.ReadFile(storageFile)
	require.NoError(t, err)
	require.Greater(t, len(bytes), 0)
}

func Test_GetOrCreateFolderConfig_shouldIntegrateGitBranchInformation(t *testing.T) {
	dir := types.FilePath(t.TempDir())
	logger := zerolog.New(zerolog.NewTestWriter(t))
	repo, err := SetupCustomTestRepo(t, dir, "https://github.com/snyk-labs/nodejs-goof", "", &logger)
	require.NoError(t, err)

	conf, _ := SetupConfigurationWithStorage(t)

	// Act
	actual, err := GetOrCreateFolderConfig(conf, repo, &logger)
	require.NoError(t, err)

	// Verify we got branches
	require.Greater(t, len(actual.LocalBranches), 0)
}

func Test_GetOrCreateFolderConfig_shouldReturnExistingFolderConfig(t *testing.T) {
	conf, _ := SetupConfigurationWithStorage(t)
	path := types.FilePath(t.TempDir())
	scanCommandConfig := types.ScanCommandConfig{
		PreScanCommand:              "/a",
		PreScanOnlyReferenceFolder:  false,
		PostScanCommand:             "/b",
		PostScanOnlyReferenceFolder: false,
	}
	expected := &types.FolderConfig{
		FolderPath: path,
		ReferenceFolderPath: types.FilePath(
			t.TempDir(),
		),
		AdditionalParameters: []string{"--additional-param=asdf", "--additional-param2=add"},
		LocalBranches:        []string{"main", "master"},
		BaseBranch:           "main",
		ScanCommandConfig: map[product.Product]types.ScanCommandConfig{
			product.ProductOpenSource: scanCommandConfig,
		},
	}

	logger := zerolog.New(zerolog.NewTestWriter(t))
	err := UpdateFolderConfig(conf, expected, &logger)
	require.NoError(t, err)

	// Act
	actual, err := GetOrCreateFolderConfig(conf, path, &logger)
	require.NoError(t, err)

	// Verify the stored config is what we tried to write.
	require.Equal(t, expected, actual)
}

func Test_GetOrCreateFolderConfig_shouldReturnLocalBranchesEvenWithoutBaseBranch(t *testing.T) {
	// Create a temporary test Git repository with an initial commit and branches
	branches := []string{"feature-branch", "develop"}
	tempDir := t.TempDir()
	initializeTestGitRepo(t, tempDir, branches)

	conf, _ := SetupConfigurationWithStorage(t)

	logger := zerolog.New(zerolog.NewTestWriter(t))

	// Test GetOrCreateFolderConfig
	folderConfig, err := GetOrCreateFolderConfig(conf, types.FilePath(tempDir), &logger)

	// Should not return an error
	require.NoError(t, err)
	require.NotNil(t, folderConfig)

	// Should have local branches from Git
	assert.ElementsMatch(t, branches, folderConfig.LocalBranches)

	// Base branch should be empty since we couldn't determine it
	assert.Empty(t, folderConfig.BaseBranch)
}

func Test_GetOrCreateFolderConfig_GitLocalBranchesTakePriorityOverStoredConfig(t *testing.T) {
	// Create a temporary test Git repository with an initial commit and branches
	tempDir := t.TempDir()
	gitBranches := []string{"main", "git-feature", "git-develop"}
	initializeTestGitRepo(t, tempDir, gitBranches)

	// Create a stored config with outdated branch info
	conf, _ := SetupConfigurationWithStorage(t)
	storedConfig := &types.FolderConfig{
		FolderPath:    types.FilePath(tempDir),
		LocalBranches: []string{"old-main", "old-feature"},
		BaseBranch:    "old-main",
	}
	logger := zerolog.New(zerolog.NewTestWriter(t))
	err := UpdateFolderConfig(conf, storedConfig, &logger)
	require.NoError(t, err)

	// Act
	folderConfig, err := GetOrCreateFolderConfig(conf, types.FilePath(tempDir), &logger)
	require.NoError(t, err)
	require.NotNil(t, folderConfig)

	// Git local branches should take priority - we should get fresh branches from Git
	assert.ElementsMatch(t, gitBranches, folderConfig.LocalBranches)
}

func Test_GetOrCreateFolderConfig_StoredConfigBaseBranchNotOverwrittenByGit(t *testing.T) {
	// Create a temporary test Git repository with an initial commit and main branch
	tempDir := t.TempDir()
	initializeTestGitRepo(t, tempDir, []string{"main"})

	// Set a specific default branch in Git config
	cmd := exec.Command("git", "config", "init.defaultBranch", "git-default-branch")
	cmd.Dir = tempDir
	err := cmd.Run()
	require.NoError(t, err)

	// Create stored config with a different base branch than Git default
	conf, _ := SetupConfigurationWithStorage(t)
	storedBaseBranch := "some-stored-base-branch"
	storedConfig := &types.FolderConfig{
		FolderPath: types.FilePath(tempDir),
		BaseBranch: storedBaseBranch,
	}
	logger := zerolog.New(zerolog.NewTestWriter(t))
	err = UpdateFolderConfig(conf, storedConfig, &logger)
	require.NoError(t, err)

	// Act
	folderConfig, err := GetOrCreateFolderConfig(conf, types.FilePath(tempDir), &logger)
	require.NoError(t, err)
	require.NotNil(t, folderConfig)

	// Stored config base branch should be preserved, not overwritten by Git default
	assert.Equal(t, storedBaseBranch, folderConfig.BaseBranch)
}

func SetupConfigurationWithStorage(t *testing.T) (configuration.Configuration, string) {
	t.Helper()
	conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	storageFile := SetupStorage(t, conf)
	return conf, storageFile
}

func SetupStorage(t *testing.T, conf configuration.Configuration) string {
	t.Helper()
	conf.PersistInStorage(ConfigMainKey)
	tempDir := t.TempDir()
	storageFile := filepath.Join(tempDir, "testStorage")

	// Ensure the parent directory exists
	if err := os.MkdirAll(filepath.Dir(storageFile), 0755); err != nil {
		require.NoError(t, err)
	}

	s, err := storage.NewStorageWithCallbacks(storage.WithStorageFile(storageFile))
	require.NoError(t, err)
	conf.SetStorage(s)
	return storageFile
}
