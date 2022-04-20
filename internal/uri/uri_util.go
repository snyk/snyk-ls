package uri

import (
	"strings"

	sglsp "github.com/sourcegraph/go-lsp"
)

func PathFromUri(uri sglsp.DocumentURI) string {
	var path = strings.TrimPrefix(string(uri), "file://")
	return strings.TrimPrefix(path, "file:")
}

func PathToUri(path string) sglsp.DocumentURI {
	return sglsp.DocumentURI("file://" + path)
}

func FolderContains(folderPath string, path string) bool {
	return strings.HasPrefix(path, folderPath)
}
