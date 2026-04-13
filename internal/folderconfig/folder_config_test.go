/*
 * © 2025-2026 Snyk Limited
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

package folderconfig

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/internal/storage"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_GetFolderConfigWithOptions_shouldIntegrateGitBranchInformation(t *testing.T) {
	dir := types.FilePath(t.TempDir())
	logger := zerolog.New(zerolog.NewTestWriter(t))
	repo, err := SetupCustomTestRepo(t, dir, "https://github.com/snyk-labs/nodejs-goof", "", &logger, false)
	require.NoError(t, err)

	conf, _ := SetupConfigurationWithStorage(t)

	// Act
	actual := GetFolderConfigWithOptions(conf, repo, &logger, GetFolderConfigOptions{EnrichFromGit: true})

	// Verify we got branches (from configuration)
	snap := types.ReadFolderConfigSnapshot(conf, actual.FolderPath)
	require.Greater(t, len(snap.LocalBranches), 0)
}

func Test_GetFolderConfigWithOptions_shouldReturnLocalBranchesEvenWithoutBaseBranch(t *testing.T) {
	// Create a temporary test Git repository with an initial commit and branches
	branches := []string{"feature-branch", "develop"}
	tempDir := t.TempDir()
	initializeTestGitRepo(t, tempDir, branches)

	conf, _ := SetupConfigurationWithStorage(t)

	logger := zerolog.New(zerolog.NewTestWriter(t))

	// Act
	folderConfig := GetFolderConfigWithOptions(conf, types.FilePath(tempDir), &logger, GetFolderConfigOptions{EnrichFromGit: true})

	// Should not return an error
	require.NotNil(t, folderConfig)

	// Should have local branches from Git (stored in configuration)
	snap := types.ReadFolderConfigSnapshot(conf, folderConfig.FolderPath)
	assert.ElementsMatch(t, branches, snap.LocalBranches)

	// Base branch should be empty since we couldn't determine it
	assert.Empty(t, snap.BaseBranch)
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

	// Ensure the parent directory exists and create empty storage file
	if err := os.MkdirAll(filepath.Dir(storageFile), 0755); err != nil {
		require.NoError(t, err)
	}
	if err := os.WriteFile(storageFile, []byte("{}"), 0644); err != nil {
		require.NoError(t, err)
	}

	s, err := storage.NewStorageWithCallbacks(storage.WithStorageFile(storageFile))
	require.NoError(t, err)
	conf.SetStorage(s)
	return storageFile
}
