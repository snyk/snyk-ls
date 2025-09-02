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
	// Add trailing slash if missing
	if s != "" && s != "/" && !strings.HasSuffix(s, "/") {
		s = s + "/"
	}
	return types.FilePath(s)
}
