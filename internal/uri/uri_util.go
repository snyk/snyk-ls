package uri

import (
	"path/filepath"
	"runtime"
	"strings"

	sglsp "github.com/sourcegraph/go-lsp"
)

func PathFromUri(uri sglsp.DocumentURI) string {
	var path = strings.TrimPrefix(string(uri), "file://")
	if runtime.GOOS == "windows" {
		path = strings.TrimPrefix(path, "/")
	}
	return filepath.Clean(strings.TrimPrefix(path, "file:"))
}

func PathToUri(path string) sglsp.DocumentURI {
	return sglsp.DocumentURI("file://" + path)
}

func FolderContains(folderPath string, path string) bool {
	return strings.HasPrefix(path, folderPath)
}
