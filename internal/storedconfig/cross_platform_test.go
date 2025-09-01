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
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/types"
)

func Test_GetOrCreateFolderConfig_CrossPlatformPaths(t *testing.T) {
	tests := []struct {
		name         string
		inputPath    types.FilePath
		expectedPath types.FilePath
	}{
		{
			name:         "Unix path without trailing slash",
			inputPath:    "/Users/foo/project",
			expectedPath: "/Users/foo/project/",
		},
		{
			name:         "Unix path with trailing slash",
			inputPath:    "/Users/foo/project/",
			expectedPath: "/Users/foo/project/",
		},
		{
			name:         "Windows path without trailing slash",
			inputPath:    `C:\Users\foo\project`,
			expectedPath: "C:/Users/foo/project/",
		},
		{
			name:         "Windows path with trailing backslash",
			inputPath:    `C:\Users\foo\project\`,
			expectedPath: "C:/Users/foo/project/",
		},
		{
			name:         "Mixed separators",
			inputPath:    `C:\Users/foo\project`,
			expectedPath: "C:/Users/foo/project/",
		},
		{
			name:         "Path with whitespace",
			inputPath:    "  /Users/foo/project  ",
			expectedPath: "/Users/foo/project/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf, _ := SetupConfigurationWithStorage(t)
			logger := zerolog.New(zerolog.NewTestWriter(t))

			// Act
			folderConfig, err := GetOrCreateFolderConfig(conf, tt.inputPath, &logger)

			// Assert
			require.NoError(t, err)
			require.NotNil(t, folderConfig)
			require.Equal(t, tt.expectedPath, folderConfig.FolderPath)

			// Verify the config is stored with the normalized path as key
			sc, err := GetStoredConfig(conf, &logger)
			require.NoError(t, err)
			require.NotNil(t, sc.FolderConfigs[tt.expectedPath])
			require.Equal(t, folderConfig, sc.FolderConfigs[tt.expectedPath])
		})
	}
}

func Test_GetOrCreateFolderConfig_SameLogicalPathDifferentFormats(t *testing.T) {
	conf, _ := SetupConfigurationWithStorage(t)
	logger := zerolog.New(zerolog.NewTestWriter(t))

	// Different representations of the same logical path
	paths := []types.FilePath{
		`C:\Users\foo\project`,
		`C:\Users\foo\project\`,
		`C:/Users/foo/project`,
		`C:/Users/foo/project/`,
		`  C:\Users\foo\project  `, // with whitespace
	}

	expectedNormalizedPath := types.FilePath("C:/Users/foo/project/")
	var firstConfig *types.FolderConfig

	for i, path := range paths {
		t.Run(string(path), func(t *testing.T) {
			// Act
			folderConfig, err := GetOrCreateFolderConfig(conf, path, &logger)

			// Assert
			require.NoError(t, err)
			require.NotNil(t, folderConfig)
			require.Equal(t, expectedNormalizedPath, folderConfig.FolderPath)

			if i == 0 {
				firstConfig = folderConfig
			} else {
				// All paths should resolve to the same config object
				require.Equal(t, firstConfig, folderConfig)
			}
		})
	}

	// Verify only one entry exists in storage
	sc, err := GetStoredConfig(conf, &logger)
	require.NoError(t, err)
	require.Len(t, sc.FolderConfigs, 1)
	require.NotNil(t, sc.FolderConfigs[expectedNormalizedPath])
}
