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
	conf, storageFile := setupConfigurationWithStorage(t)
	path := "/testPath"
	dir, err := os.UserHomeDir()
	require.NoError(t, err)
	preCommandMap := map[product.Product]types.Pair{
		product.ProductOpenSource: {First: "preCommand.exe", Second: true},
	}

	// act
	actual, err := GetOrCreateFolderConfig(conf, path)
	require.NoError(t, err)
	actual.PreScanCommandPath = preCommandMap
	require.NoError(t, err)
	actual.ReferenceFolderPath = dir
	err = UpdateFolderConfig(conf, actual)
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
	dir := t.TempDir()
	logger := zerolog.New(zerolog.NewTestWriter(t))
	repo, err := SetupCustomTestRepo(t, dir, "https://github.com/snyk-labs/nodejs-goof", "", &logger)
	require.NoError(t, err)

	conf, _ := setupConfigurationWithStorage(t)

	actual, err := GetOrCreateFolderConfig(conf, repo)

	require.NoError(t, err)
	require.Greater(t, len(actual.LocalBranches), 0)
}

func setupConfigurationWithStorage(t *testing.T) (configuration.Configuration, string) {
	t.Helper()
	conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	storageFile := filepath.Join(t.TempDir(), "testStorage")
	s, err := storage.NewStorageWithCallbacks(storage.WithStorageFile(storageFile))
	require.NoError(t, err)
	conf.PersistInStorage(ConfigMainKey)
	conf.SetStorage(s)
	return conf, storageFile
}
