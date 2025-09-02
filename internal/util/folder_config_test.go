package util

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/types"
)

func TestValidateReferenceFolderPath(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()

	tests := []struct {
		name        string
		input       types.FilePath
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Valid absolute path",
			input:       types.FilePath(tempDir),
			expectError: false,
		},
		{
			name:        "Empty path allowed",
			input:       "",
			expectError: false,
		},
		{
			name:        "Path traversal detected",
			input:       "/Users/foo/../malicious",
			expectError: true,
			errorMsg:    "path traversal detected",
		},
		{
			name:        "Relative path not allowed",
			input:       "Users/foo/project",
			expectError: true,
			errorMsg:    "path must be absolute",
		},
		{
			name:        "Command injection semicolon",
			input:       "/Users/foo; rm -rf /",
			expectError: true,
			errorMsg:    "dangerous character detected",
		},
		{
			name:        "Command injection ampersand",
			input:       "/Users/foo & echo pwned",
			expectError: true,
			errorMsg:    "dangerous character detected",
		},
		{
			name:        "Command injection backtick",
			input:       "/Users/foo `whoami`",
			expectError: true,
			errorMsg:    "dangerous character detected",
		},
		{
			name:        "Command injection dollar",
			input:       "/Users/foo $(whoami)",
			expectError: true,
			errorMsg:    "dangerous character detected",
		},
		{
			name:        "Command injection double quote",
			input:       "/Users/foo\" && rm -rf /",
			expectError: true,
			errorMsg:    "dangerous character detected",
		},
		{
			name:        "Command injection single quote",
			input:       "/Users/foo' && rm -rf /",
			expectError: true,
			errorMsg:    "dangerous character detected",
		},
		{
			name:        "Non-existent path",
			input:       "/non/existent/path",
			expectError: true,
			errorMsg:    "does not exist or is not accessible",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateReferenceFolderPath(tt.input)
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

func TestValidateFolderPath(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()

	tests := []struct {
		name        string
		input       types.FilePath
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Valid absolute path",
			input:       types.FilePath(tempDir),
			expectError: false,
		},
		{
			name:        "Empty path not allowed",
			input:       "",
			expectError: true,
			errorMsg:    "path cannot be empty",
		},
		{
			name:        "Path traversal detected",
			input:       "/Users/foo/../malicious",
			expectError: true,
			errorMsg:    "path traversal detected",
		},
		{
			name:        "Relative path not allowed",
			input:       "Users/foo/project",
			expectError: true,
			errorMsg:    "path must be absolute",
		},
		{
			name:        "Command injection semicolon",
			input:       "/Users/foo; rm -rf /",
			expectError: true,
			errorMsg:    "dangerous character detected",
		},
		{
			name:        "Command injection double quote",
			input:       "/Users/foo\" && rm -rf /",
			expectError: true,
			errorMsg:    "dangerous character detected",
		},
		{
			name:        "Command injection single quote",
			input:       "/Users/foo' && rm -rf /",
			expectError: true,
			errorMsg:    "dangerous character detected",
		},
		{
			name:        "Non-existent path",
			input:       "/non/existent/path",
			expectError: true,
			errorMsg:    "does not exist or is not accessible",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFolderPath(tt.input)
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
