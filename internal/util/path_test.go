package util

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/types"
)

func TestGenerateFolderConfigKey(t *testing.T) {
	// Create one temporary directory for valid test cases
	tempDir := t.TempDir()

	tests := []struct {
		name     string
		input    types.FilePath
		expected types.FilePath
	}{
		{
			name:     "Unix path without trailing slash",
			input:    types.FilePath(tempDir),
			expected: types.FilePath(tempDir),
		},
		{
			name:     "Unix path with trailing slash",
			input:    types.FilePath(tempDir + "/"),
			expected: types.FilePath(tempDir),
		},
		{
			name:     "Windows path without trailing slash",
			input:    types.FilePath(tempDir),
			expected: types.FilePath(tempDir),
		},
		{
			name:     "Windows path with trailing backslash",
			input:    types.FilePath(tempDir + "\\"),
			expected: types.FilePath(filepath.Clean(tempDir + "\\")),
		},
		{
			name:     "Windows path with trailing forward slash",
			input:    types.FilePath(tempDir + "/"),
			expected: types.FilePath(tempDir),
		},
		{
			name:     "Mixed separators",
			input:    types.FilePath(tempDir),
			expected: types.FilePath(tempDir),
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
			name:     "Invalid path with path traversal",
			input:    "/Users/foo/../malicious",
			expected: "",
		},
		{
			name:     "Invalid path with obfuscated traversal",
			input:    "/Users/foo/./../malicious",
			expected: "",
		},
		{
			name:     "Invalid path with encoded traversal",
			input:    "/Users/foo%2e%2e/malicious",
			expected: "",
		},
		{
			name:     "Invalid path with command injection",
			input:    "/Users/foo; rm -rf /",
			expected: "",
		},
		{
			name:     "Relative path",
			input:    "Users/foo/project",
			expected: types.FilePath(filepath.Clean("Users/foo/project")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GenerateFolderConfigKey(tt.input)
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
func createCommonTestCases(tempDir string, errorPrefix string) []testCase {
	return []testCase{
		{
			name:        "Valid absolute path",
			input:       types.FilePath(tempDir),
			expectError: false,
		},
		{
			name:        "Relative path not allowed",
			input:       "Users/foo/project",
			expectError: true,
			errorMsg:    errorPrefix + "path must be absolute",
		},
		{
			name:        "Command injection semicolon",
			input:       "/Users/foo; rm -rf /",
			expectError: true,
			errorMsg:    errorPrefix + "dangerous character detected",
		},
		{
			name:        "Command injection ampersand",
			input:       "/Users/foo & echo pwned",
			expectError: true,
			errorMsg:    errorPrefix + "dangerous character detected",
		},
		{
			name:        "Command injection backtick",
			input:       "/Users/foo `whoami`",
			expectError: true,
			errorMsg:    errorPrefix + "dangerous character detected",
		},
		{
			name:        "Command injection dollar",
			input:       "/Users/foo $(whoami)",
			expectError: true,
			errorMsg:    errorPrefix + "dangerous character detected",
		},
		{
			name:        "Command injection double quote",
			input:       "/Users/foo\" && rm -rf /",
			expectError: true,
			errorMsg:    errorPrefix + "dangerous character detected",
		},
		{
			name:        "Command injection single quote",
			input:       "/Users/foo' && rm -rf /",
			expectError: true,
			errorMsg:    errorPrefix + "dangerous character detected",
		},
	}
}

func TestValidatePathLenient(t *testing.T) {
	tempDir := t.TempDir()

	// Create common test cases with path validation error prefix
	testCases := createCommonTestCases(tempDir, "path validation failed: ")

	// Add lenient path specific test case
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
	testCases := createCommonTestCases(tempDir, "path validation failed: ")

	// Add strict path specific test case
	testCases = append(testCases, testCase{
		name:        "Empty path not allowed",
		input:       "",
		expectError: true,
		errorMsg:    "path validation failed: path cannot be empty",
	})

	runValidationTest(t, ValidatePathStrict, testCases)
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
			result := GenerateFolderConfigKey(tt.input)
			assert.Equal(t, tt.expected, result, "Path normalization should preserve original separators without adding trailing slash")
		})
	}
}
