package util

import (
	"strings"

	"github.com/snyk/snyk-ls/internal/types"
)

// NormalizePath converts to forward slashes, trims whitespace, and removes trailing slashes (except root)
func NormalizePath(p types.FilePath) types.FilePath {
	s := strings.TrimSpace(string(p))
	if s == "" {
		return ""
	}
	// Convert all backslashes to forward slashes for cross-platform consistency
	s = strings.ReplaceAll(s, "\\", "/")
	// Remove trailing slashes for non-root paths
	if s != "/" {
		s = strings.TrimRight(s, "/")
	}
	return types.FilePath(s)
}
