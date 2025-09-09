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
