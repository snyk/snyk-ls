package uri

import (
	"strings"

	sglsp "github.com/sourcegraph/go-lsp"
	"go.lsp.dev/uri"
)

const fileScheme = "file://"
const eclipseWorkspaceFolderScheme = "file:"

func FolderContains(folderPath string, path string) bool {
	return strings.HasPrefix(path, folderPath)
}

//todo can we create a path domain type?
// PathFromUri converts the given uri to a file path
func PathFromUri(documentURI sglsp.DocumentURI) string {
	u := string(documentURI)
	if !strings.HasPrefix(u, fileScheme) && strings.HasPrefix(u, eclipseWorkspaceFolderScheme) {
		u = strings.Replace(u, eclipseWorkspaceFolderScheme, fileScheme, 1)
	}
	return uri.New(u).Filename()
}

// PathToUri converts a path to a DocumentURI
func PathToUri(path string) sglsp.DocumentURI {
	return sglsp.DocumentURI(uri.File(path))
}
