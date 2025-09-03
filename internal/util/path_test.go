package util

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/types"
)

func TestGenerateFolderConfigKey(t *testing.T) {
	tests := []struct {
		name     string
		input    types.FilePath
		expected types.FilePath
	}{
		{
			name:     "Unix path without trailing slash",
			input:    "/Users/foo/project",
			expected: "/Users/foo/project",
		},
		{
			name:     "Unix path with trailing slash",
			input:    "/Users/foo/project/",
			expected: "/Users/foo/project",
		},
		{
			name:     "Windows path without trailing slash",
			input:    `C:\Users\foo\project`,
			expected: "C:/Users/foo/project",
		},
		{
			name:     "Windows path with trailing backslash",
			input:    `C:\Users\foo\project\`,
			expected: "C:/Users/foo/project",
		},
		{
			name:     "Windows path with trailing forward slash",
			input:    `C:\Users\foo\project/`,
			expected: "C:/Users/foo/project",
		},
		{
			name:     "Mixed separators",
			input:    `C:\Users\foo\project`,
			expected: "C:/Users/foo/project",
		},
		{
			name:     "Path with whitespace",
			input:    "  /Users/foo/project  ",
			expected: "/Users/foo/project",
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
			expected: "/",
		},
		{
			name:     "Root path Windows",
			input:    `C:\`,
			expected: "C:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GenerateFolderConfigKey(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
