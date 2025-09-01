package util

import (
	"strings"

	"github.com/snyk/snyk-ls/internal/types"
)

// GenerateFolderConfigKey creates a normalized key for folder config storage
// This ensures consistent cross-platform map keys while preserving original paths
func GenerateFolderConfigKey(p types.FilePath) types.FilePath {
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
