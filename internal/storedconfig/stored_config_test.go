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

func Test_mergeFolderConfigs(t *testing.T) {
	t.Run("different folder paths should return first", func(t *testing.T) {
		first := &types.FolderConfig{
			FolderPath:           "/path1",
			AdditionalParameters: []string{"--param1=value1"},
			LocalBranches:        []string{"branch1"},
			BaseBranch:           "main",
		}

		second := &types.FolderConfig{
			FolderPath:           "/path2",
			AdditionalParameters: []string{"--param2=value2"},
			LocalBranches:        []string{"branch2"},
			BaseBranch:           "develop",
		}

		result := mergeFolderConfigs(first, second)

		require.Equal(t, first, result)
		require.Equal(t, 1, len(result.AdditionalParameters))
		require.Equal(t, "--param1=value1", result.AdditionalParameters[0])
		require.Equal(t, 1, len(result.LocalBranches))
		require.Equal(t, "main", result.BaseBranch)
	})
	t.Run("same folder paths with complete merging", func(t *testing.T) {
		scanCommandConfig1 := types.ScanCommandConfig{
			PreScanCommand: "/cmd1",
		}

		scanCommandConfig2 := types.ScanCommandConfig{
			PreScanCommand: "/cmd2",
		}

		first := &types.FolderConfig{
			FolderPath:           "/path1",
			AdditionalParameters: []string{"--param1=value1"},
			LocalBranches:        nil,
			BaseBranch:           "",
			ScanCommandConfig: map[product.Product]types.ScanCommandConfig{
				product.ProductOpenSource: scanCommandConfig1,
			},
			ReferenceFolderPath: "",
		}

		second := &types.FolderConfig{
			FolderPath:           "/path1",
			AdditionalParameters: []string{"--param2=value2"},
			LocalBranches:        []string{"branch2"},
			BaseBranch:           "develop",
			ScanCommandConfig: map[product.Product]types.ScanCommandConfig{
				product.ProductOpenSource: scanCommandConfig2,
			},
			ReferenceFolderPath: "/ref/path",
		}

		result := mergeFolderConfigs(first, second)

		// Check that it's still the first object (modified)
		require.Equal(t, first, result)

		// Check additional parameters are merged
		require.Equal(t, 2, len(result.AdditionalParameters))
		require.Contains(t, result.AdditionalParameters, "--param1=value1")
		require.Contains(t, result.AdditionalParameters, "--param2=value2")

		// Check other fields are taken from second
		require.Equal(t, second.LocalBranches, result.LocalBranches)
		require.Equal(t, second.BaseBranch, result.BaseBranch)
		require.Equal(t, second.ScanCommandConfig, result.ScanCommandConfig)
		require.Equal(t, second.ReferenceFolderPath, result.ReferenceFolderPath)
	})
	t.Run("parameter deduplication", func(t *testing.T) {
		first := &types.FolderConfig{
			FolderPath:           "/path1",
			AdditionalParameters: []string{"--param1=value1", "--param2=valueA"},
		}

		second := &types.FolderConfig{
			FolderPath:           "/path1",
			AdditionalParameters: []string{"--param2=valueB", "--param3=value3"},
		}

		result := mergeFolderConfigs(first, second)

		// Should have 3 parameters (param2 from second should be ignored)
		require.Equal(t, 3, len(result.AdditionalParameters))
		require.Contains(t, result.AdditionalParameters, "--param1=value1")
		require.Contains(t, result.AdditionalParameters, "--param2=valueA") // first takes precedence
		require.Contains(t, result.AdditionalParameters, "--param3=value3")
	})
	t.Run("partial merging", func(t *testing.T) {
		scanCommandConfig1 := types.ScanCommandConfig{
			PreScanCommand: "/cmd1",
		}

		first := &types.FolderConfig{
			FolderPath:           "/path1",
			AdditionalParameters: []string{"--param1=value1"},
			LocalBranches:        []string{"branch1"},
			BaseBranch:           "main",
			ScanCommandConfig: map[product.Product]types.ScanCommandConfig{
				product.ProductOpenSource: scanCommandConfig1,
			},
			ReferenceFolderPath: "/ref/path1",
		}

		second := &types.FolderConfig{
			FolderPath:           "/path1",
			AdditionalParameters: []string{"--param2=value2"},
			LocalBranches:        nil, // nil, should not replace
			BaseBranch:           "",  // empty, should not replace
			ScanCommandConfig:    nil, // nil, should not replace
			ReferenceFolderPath:  "",  // empty, should not replace
		}

		result := mergeFolderConfigs(first, second)

		// Check that fields from second didn't overwrite first when they were nil/empty
		require.Equal(t, 2, len(result.AdditionalParameters)) // Additional params still merge
		require.Equal(t, first.LocalBranches, result.LocalBranches)
		require.Equal(t, first.BaseBranch, result.BaseBranch)
		require.Equal(t, first.ScanCommandConfig, result.ScanCommandConfig)
		require.Equal(t, first.ReferenceFolderPath, result.ReferenceFolderPath)
	})
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
