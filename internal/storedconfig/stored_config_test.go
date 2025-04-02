/*
 * © 2025 Snyk Limited
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
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/storage"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_GetOrCreateFolderConfig_shouldStoreEverythingInStorageFile(t *testing.T) {
	conf, storageFile := SetupConfigurationWithStorage(t)
	path := types.FilePath("/testPath")
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
	require.Equal(t, actual, sc.FolderConfigs[path])

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

	actual, err := GetOrCreateFolderConfig(conf, repo, nil)

	require.NoError(t, err)
	require.Greater(t, len(actual.LocalBranches), 0)
}

func Test_GetOrCreateFolderConfig_shouldReturnExistingFolderConfig(t *testing.T) {
	conf, _ := SetupConfigurationWithStorage(t)
	path := types.FilePath("/testPath")
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

	nop := zerolog.Nop()
	err := UpdateFolderConfig(conf, expected, &nop)
	require.NoError(t, err)
	actual, err := GetOrCreateFolderConfig(conf, path, nil)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
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
