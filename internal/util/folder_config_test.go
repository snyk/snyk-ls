package util

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/types"
)

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
			name:        "Path traversal detected",
			input:       "/Users/foo/../malicious",
			expectError: true,
			errorMsg:    errorPrefix + "path traversal detected",
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

func TestValidateReferenceFolderPath(t *testing.T) {
	tempDir := t.TempDir()

	// Create common test cases with reference folder path error prefix
	testCases := createCommonTestCases(tempDir, "reference folder path validation failed: ")

	// Add reference folder path specific test case
	testCases = append(testCases, testCase{
		name:        "Empty path allowed",
		input:       "",
		expectError: false,
	})

	runValidationTest(t, ValidateReferenceFolderPath, testCases)
}

func TestValidateFolderPath(t *testing.T) {
	tempDir := t.TempDir()

	// Create common test cases with folder path error prefix
	testCases := createCommonTestCases(tempDir, "folder path validation failed: ")

	// Add folder path specific test case
	testCases = append(testCases, testCase{
		name:        "Empty path not allowed",
		input:       "",
		expectError: true,
		errorMsg:    "folder path validation failed: path cannot be empty",
	})

	runValidationTest(t, ValidateFolderPath, testCases)
}
