package util

import (
	"strings"

	"github.com/snyk/snyk-ls/internal/types"
)

// NormalizePath converts to forward slashes, trims whitespace, and ensures a trailing slash
func NormalizePath(p types.FilePath) types.FilePath {
	s := strings.TrimSpace(string(p))
	if s == "" {
		return ""
	}
	// Convert all backslashes to forward slashes for cross-platform consistency
	s = strings.ReplaceAll(s, "\\", "/")
	if !strings.HasSuffix(s, "/") {
		s += "/"
	}
	return types.FilePath(s)
}
