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

package storedconfig

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/types"
)

func Test_GetOrCreateFolderConfig_CrossPlatformPaths(t *testing.T) {
	// Create one temporary directory for testing
	tempDir := t.TempDir()

	// Calculate the expected normalized path for the base case
	basePath := types.FilePath(tempDir)
	expectedNormalizedPath := types.PathKey(basePath)

	tests := []struct {
		name                string
		inputPath           types.FilePath
		shouldMatchBasePath bool
	}{
		{
			name:                "Base path (no modifications)",
			inputPath:           basePath,
			shouldMatchBasePath: true,
		},
		{
			name:                "Path with trailing slash",
			inputPath:           types.FilePath(tempDir + "/"),
			shouldMatchBasePath: true,
		},
		{
			name:                "Path with whitespace",
			inputPath:           types.FilePath("  " + tempDir + "  "),
			shouldMatchBasePath: true,
		},
		{
			name:                "Path with mixed separators (Unix style)",
			inputPath:           types.FilePath(tempDir + "/subdir"),
			shouldMatchBasePath: false,
		},
		{
			name:                "Path with mixed separators (Windows style)",
			inputPath:           types.FilePath(tempDir + "\\subdir"),
			shouldMatchBasePath: false,
		},
		{
			name:                "Path with mixed separators and trailing slash",
			inputPath:           types.FilePath(tempDir + "/subdir/"),
			shouldMatchBasePath: false,
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

			// Calculate the expected normalized path for this specific input
			expectedPath := types.PathKey(tt.inputPath)
			require.Equal(t, expectedPath, folderConfig.FolderPath)

			// For paths that should normalize to the same result as the base case, verify they do
			if tt.shouldMatchBasePath {
				require.Equal(t, expectedNormalizedPath, expectedPath,
					"Path variations should normalize to the same result as the base case")
			}

			// Verify the config is stored with the normalized path as key
			sc, err := GetStoredConfig(conf, &logger, true)
			require.NoError(t, err)
			normalizedKey := types.PathKey(tt.inputPath)
			require.NotNil(t, sc.FolderConfigs[normalizedKey])
			require.Equal(t, folderConfig, sc.FolderConfigs[normalizedKey])
		})
	}
}
