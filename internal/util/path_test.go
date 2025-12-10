package util

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/types"
)

func TestPathKey(t *testing.T) {
	// Create one temporary directory for valid test cases
	tempDir := t.TempDir()

	tests := []struct {
		name     string
		input    types.FilePath
		expected types.FilePath
	}{
		{
			name:     "Path without trailing slash",
			input:    types.FilePath(tempDir),
			expected: types.FilePath(tempDir),
		},
		{
			name:     "Path with trailing slash",
			input:    types.FilePath(tempDir + "/"),
			expected: types.FilePath(tempDir),
		},
		{
			name:     "Windows path with backslashes",
			input:    types.FilePath(tempDir + "\\"),
			expected: types.FilePath(filepath.Clean(tempDir + "\\")),
		},
		{
			name:     "Path with whitespace",
			input:    types.FilePath("  " + tempDir + "  "),
			expected: types.FilePath(tempDir),
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
			expected: types.FilePath(filepath.Clean("/")),
		},
		{
			name:     "Root path Windows",
			input:    `C:\`,
			expected: types.FilePath(filepath.Clean(`C:\`)),
		},
		{
			name:     "Path with parent directory normalized",
			input:    "/Users/foo/../bar",
			expected: types.FilePath(filepath.Clean("/Users/foo/../bar")),
		},
		{
			name:     "Path with current and parent directory normalized",
			input:    "/Users/foo/./../bar",
			expected: types.FilePath(filepath.Clean("/Users/foo/./../bar")),
		},
		{
			name:     "Path with semicolon (normalized)",
			input:    "/Users/foo; rm -rf /",
			expected: types.FilePath(filepath.Clean("/Users/foo; rm -rf /")),
		},
		{
			name:     "Relative path",
			input:    "Users/foo/project",
			expected: types.FilePath(filepath.Clean("Users/foo/project")),
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
type testCase struct {
	name        string
	input       types.FilePath
	expectError bool
	errorMsg    string
}

// runValidationTest runs a validation test with the given validator function
func runValidationTest(t *testing.T, validator func(types.FilePath) error, testCases []testCase) {
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
func createCommonTestCases(tempDir string) []testCase {
	return []testCase{
		{
			name:        "Valid path",
			input:       types.FilePath(tempDir),
			expectError: false,
		},
	}
}

func TestValidatePathLenient(t *testing.T) {
	tempDir := t.TempDir()

	// Create common test cases with path validation error prefix
	testCases := createCommonTestCases(tempDir)

	// Add lenient path specific test cases
	testCases = append(testCases, testCase{
		name:        "Empty path allowed",
		input:       "",
		expectError: false,
	})

	runValidationTest(t, ValidatePathLenient, testCases)
}

func TestValidatePathStrict(t *testing.T) {
	tempDir := t.TempDir()

	// Create common test cases with path validation error prefix
	testCases := createCommonTestCases(tempDir)

	// Add strict path specific test case
	testCases = append(testCases, testCase{
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
			result := PathKey(tt.input)
			assert.Equal(t, tt.expected, result, "Path normalization should preserve original separators without adding trailing slash")
		})
	}
}

func TestValidatePathWithExistenceTypes(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name      string
		path      types.FilePath
		existence ExistenceType
		expectErr bool
	}{
		{
			name:      "Directory exists as directory",
			path:      types.FilePath(tempDir),
			existence: ExistAsDirectory,
			expectErr: false,
		},
		{
			name:      "Directory exists as file or directory",
			path:      types.FilePath(tempDir),
			existence: ExistAsFileOrDirectory,
			expectErr: false,
		},
		{
			name:      "Directory fails as file",
			path:      types.FilePath(tempDir),
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
