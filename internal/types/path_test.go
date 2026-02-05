/*
 * © 2026 Snyk Limited
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

package types

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPathKey(t *testing.T) {
	// Create one temporary directory for valid test cases
	tempDir := t.TempDir()

	tests := []struct {
		name     string
		input    FilePath
		expected FilePath
	}{
		{
			name:     "Path without trailing slash",
			input:    FilePath(tempDir),
			expected: FilePath(tempDir),
		},
		{
			name:     "Path with trailing slash",
			input:    FilePath(tempDir + "/"),
			expected: FilePath(tempDir),
		},
		{
			name:     "Windows path with backslashes",
			input:    FilePath(tempDir + "\\"),
			expected: FilePath(filepath.Clean(tempDir + "\\")),
		},
		{
			name:     "Path with whitespace",
			input:    FilePath("  " + tempDir + "  "),
			expected: FilePath(tempDir),
		},
		{
			name:     "Empty path",
			input:    "",
			expected: "",
		},
		{
			name:     "Whitespace only",
			input:    "   ",
			expected: "",
		},
		{
			name:     "Root path Unix",
			input:    "/",
			expected: FilePath(filepath.Clean("/")),
		},
		{
			name:     "Root path Windows",
			input:    `C:\`,
			expected: FilePath(filepath.Clean(`C:\`)),
		},
		{
			name:     "Path with parent directory normalized",
			input:    "/Users/foo/../bar",
			expected: FilePath(filepath.Clean("/Users/foo/../bar")),
		},
		{
			name:     "Path with current and parent directory normalized",
			input:    "/Users/foo/./../bar",
			expected: FilePath(filepath.Clean("/Users/foo/./../bar")),
		},
		{
			name:     "Path with semicolon (normalized)",
			input:    "/Users/foo; rm -rf /",
			expected: FilePath(filepath.Clean("/Users/foo; rm -rf /")),
		},
		{
			name:     "Relative path",
			input:    "Users/foo/project",
			expected: FilePath(filepath.Clean("Users/foo/project")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := PathKey(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// testCase represents a common test case for path validation
type pathTestCase struct {
	name        string
	input       FilePath
	expectError bool
	errorMsg    string
}

// runValidationTest runs a validation test with the given validator function
func runValidationTest(t *testing.T, validator func(FilePath) error, testCases []pathTestCase) {
	t.Helper()
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			err := validator(tt.input)
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// createCommonTestCases creates the shared test cases for both validation functions
func createCommonTestCases(tempDir string) []pathTestCase {
	return []pathTestCase{
		{
			name:        "Valid path",
			input:       FilePath(tempDir),
			expectError: false,
		},
	}
}

func TestValidatePathLenient(t *testing.T) {
	tempDir := t.TempDir()

	// Create common test cases with path validation error prefix
	testCases := createCommonTestCases(tempDir)

	// Add lenient path specific test cases
	testCases = append(testCases, pathTestCase{
		name:        "Empty path allowed",
		input:       "",
		expectError: false,
	})

	// Add Windows UNC admin share test cases - verify we support $ character in UNC admin share paths
	// These test that the $ character is allowed in Windows UNC administrative share paths (e.g., \\server\C$\path)
	testCases = append(testCases,
		pathTestCase{
			name:        "Windows UNC admin share C$ - supports $ character",
			input:       "\\\\localhost\\C$\\Users\\test",
			expectError: false,
		},
		pathTestCase{
			name:        "Windows UNC admin share D$ - supports $ character",
			input:       "\\\\server\\D$\\path\\to\\file",
			expectError: false,
		},
		pathTestCase{
			name:        "Windows UNC admin share with forward slashes - supports $ character",
			input:       "//localhost/C$/Users/test",
			expectError: false,
		},
	)

	runValidationTest(t, ValidatePathLenient, testCases)
}

func TestValidatePathStrict(t *testing.T) {
	tempDir := t.TempDir()

	// Create common test cases with path validation error prefix
	testCases := createCommonTestCases(tempDir)

	// Add strict path specific test case
	testCases = append(testCases, pathTestCase{
		name:        "Empty path not allowed",
		input:       "",
		expectError: true,
		errorMsg:    "path cannot be empty, got: ''",
	})

	runValidationTest(t, ValidatePathStrict, testCases)
}
func Test_PathKey_PathNormalization(t *testing.T) {
	// Test path normalization behavior without requiring paths to exist
	tests := []struct {
		name     string
		input    FilePath
		expected FilePath
	}{
		{
			name:     "Unix path without trailing slash",
			input:    "/Users/test/project",
			expected: FilePath(filepath.Clean("/Users/test/project")),
		},
		{
			name:     "Unix path with trailing slash",
			input:    "/Users/test/project/",
			expected: FilePath(filepath.Clean("/Users/test/project/")),
		},
		{
			name:     "Path with whitespace",
			input:    "  /Users/test/project  ",
			expected: FilePath(filepath.Clean("/Users/test/project")),
		},
		{
			name:     "Root path Unix",
			input:    "/",
			expected: FilePath(filepath.Clean("/")),
		},
		{
			name:     "Windows path with backslashes",
			input:    "C:\\Users\\test\\project",
			expected: FilePath(filepath.Clean("C:\\Users\\test\\project")),
		},
		{
			name:     "Windows path with mixed separators",
			input:    "C:\\Users/test\\project/",
			expected: FilePath(filepath.Clean("C:\\Users/test\\project/")),
		},
		{
			name:     "Root path Windows",
			input:    "C:\\",
			expected: FilePath(filepath.Clean("C:\\")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := PathKey(tt.input)
			assert.Equal(t, tt.expected, result, "Path normalization should preserve original separators without adding trailing slash")
		})
	}
}

func TestValidatePathWithExistenceTypes(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name      string
		path      FilePath
		existence ExistenceType
		expectErr bool
	}{
		{
			name:      "Directory exists as directory",
			path:      FilePath(tempDir),
			existence: ExistAsDirectory,
			expectErr: false,
		},
		{
			name:      "Directory exists as file or directory",
			path:      FilePath(tempDir),
			existence: ExistAsFileOrDirectory,
			expectErr: false,
		},
		{
			name:      "Directory fails as file",
			path:      FilePath(tempDir),
			existence: ExistAsFile,
			expectErr: true,
		},
		{
			name:      "Non-existent path fails as directory",
			path:      "/non/existent/path",
			existence: ExistAsDirectory,
			expectErr: true,
		},
		{
			name:      "Non-existent path passes with no check",
			path:      "/non/existent/path",
			existence: NoCheck,
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := PathValidationOptions{
				AllowEmpty: false,
				Existence:  tt.existence,
			}
			err := ValidatePath(tt.path, options)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
