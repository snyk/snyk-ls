package mcp_extension

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_verifyCommandArgument(t *testing.T) {
	testCases := []struct {
		name     string
		input    any
		expected bool
	}{
		{
			name:     "Full path to python with version",
			input:    "/usr/bin/python3.12",
			expected: true,
		},
		{
			name:     "Full path to python with full version",
			input:    "/usr/local/bin/python3.12.4",
			expected: true,
		},
		{
			name:     "Windows path to python with version and exe",
			input:    "C:\\Python\\python3.11.9.exe",
			expected: true,
		},
		{
			name:     "Windows path to python with exe",
			input:    "C:\\Python310\\python.exe",
			expected: true,
		},
		{
			name:     "python with version",
			input:    "python3",
			expected: true,
		},
		{
			name:     "just python",
			input:    "python",
			expected: true,
		},
		{
			name:     "some other program",
			input:    "/some/other/program",
			expected: false,
		},
		{
			name:     "just python with .exe",
			input:    "python.exe",
			expected: true,
		},
		{
			name:     "another program",
			input:    "not-python",
			expected: false,
		},
		{
			name:     "nil input",
			input:    nil,
			expected: false,
		},
		{
			name:     "non-string input",
			input:    12345,
			expected: true, // as per current implementation
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := verifyCommandArgument(tc.input)
			assert.Equal(t, tc.expected, actual)
		})
	}
}
