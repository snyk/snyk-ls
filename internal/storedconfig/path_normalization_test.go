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
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

func Test_GetOrCreateFolderConfig_PathNormalization(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name      string
		inputPath types.FilePath
	}{
		{
			name:      "Path without trailing slash",
			inputPath: types.FilePath(tempDir),
		},
		{
			name:      "Path with trailing slash",
			inputPath: types.FilePath(tempDir + "/"),
		},
		{
			name:      "Path with whitespace",
			inputPath: types.FilePath("  " + tempDir + "  "),
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
			// Expect the normalized path (with trimmed whitespace)
			expectedPath := util.GenerateFolderConfigKey(tt.inputPath)
			require.Equal(t, expectedPath, folderConfig.FolderPath)

			// Verify the config is stored with the normalized path as key
			sc, err := GetStoredConfig(conf, &logger)
			require.NoError(t, err)
			normalizedKey := util.GenerateFolderConfigKey(tt.inputPath)
			require.NotNil(t, sc.FolderConfigs[normalizedKey])
			require.Equal(t, folderConfig, sc.FolderConfigs[normalizedKey])
		})
	}
}

func Test_GenerateFolderConfigKey_PathNormalization(t *testing.T) {
	// Test path normalization behavior without requiring paths to exist
	tests := []struct {
		name     string
		input    types.FilePath
		expected types.FilePath
	}{
		{
			name:     "Unix path without trailing slash",
			input:    "/Users/test/project",
			expected: types.FilePath(filepath.Clean("/Users/test/project")),
		},
		{
			name:     "Unix path with trailing slash",
			input:    "/Users/test/project/",
			expected: types.FilePath(filepath.Clean("/Users/test/project/")),
		},
		{
			name:     "Path with whitespace",
			input:    "  /Users/test/project  ",
			expected: types.FilePath(filepath.Clean("/Users/test/project")),
		},
		{
			name:     "Root path Unix",
			input:    "/",
			expected: types.FilePath(filepath.Clean("/")),
		},
		{
			name:     "Windows path with backslashes",
			input:    "C:\\Users\\test\\project",
			expected: types.FilePath(filepath.Clean("C:\\Users\\test\\project")),
		},
		{
			name:     "Windows path with mixed separators",
			input:    "C:\\Users/test\\project/",
			expected: types.FilePath(filepath.Clean("C:\\Users/test\\project/")),
		},
		{
			name:     "Root path Windows",
			input:    "C:\\",
			expected: types.FilePath(filepath.Clean("C:\\")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := util.GenerateFolderConfigKey(tt.input)
			require.Equal(t, tt.expected, result, "Path normalization should preserve original separators without adding trailing slash")
		})
	}
}
