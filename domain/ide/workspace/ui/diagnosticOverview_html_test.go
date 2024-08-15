package ui

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestDiagnosticOverview_normalizeFilePath(t *testing.T) {
	// Parse file path to be rendered in the UI
	tests := []struct {
		name       string
		filePath   string
		folderPath string
		expected   string
	}{
		{
			name:       "unix path",
			filePath:   "/Users/cata/git/playground/dex/server/deviceflowhandlers.go",
			folderPath: "/Users/cata/git/playground/dex",
			expected:   "dex/server/deviceflowhandlers.go",
		},
		// TODO: add Windows cases
		{
			name:       "(win) path",
			filePath:   "C:\\Users\\cata\\git\\playground\\dex\\server\\deviceflowhandlers.go",
			folderPath: "C:\\Users\\cata\\git\\playground\\dex",
			expected:   "dex\\server\\deviceflowhandlers.go",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			skipReason := "filepath is os dependent"
			prefix := "C:"

			if strings.HasPrefix(tc.folderPath, prefix) {
				testutil.OnlyOnWindows(t, skipReason)
			} else {
				testutil.NotOnWindows(t, skipReason)
			}

			actual := normalizeFilePath(tc.filePath, tc.folderPath)
			assert.Equal(t, tc.expected, actual)
		})
	}
}
