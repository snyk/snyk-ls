package uri

import (
	"path/filepath"
	"runtime"
	"strings"

	sglsp "github.com/sourcegraph/go-lsp"
)

const uncPrefix = "//"
const uriPrefix = "file://"
const eclipseWorkspaceFolderPrefix = "file:"

// PathFromUri converts the given uri to a file path
// `file:///C:/a/a.txt` is converted to `C:\a\a.txt` on Windows
// `file:/root/a` is converted to `/root/a` on Linux and macOS. This is necessary due to Eclipse sending wrong URI
// `file:///root is converted to `/root` on Linux and macOS
func PathFromUri(uri sglsp.DocumentURI) string {
	var path = strings.TrimPrefix(string(uri), uriPrefix)
	if runtime.GOOS == "windows" &&
		!strings.HasPrefix(path, uncPrefix) { // UNC path
		path = strings.TrimPrefix(path, "/") // /C:/... --> C:/...
	}
	return filepath.Clean(strings.TrimPrefix(path, eclipseWorkspaceFolderPrefix))
}

func PathToUri(path string) sglsp.DocumentURI {
	if runtime.GOOS == "windows" &&
		!strings.HasPrefix(path, "//") {
		path = "/" + path // this is highly dubious - maybe only works for Java on Windows
	}
	return sglsp.DocumentURI("file://" + filepath.ToSlash(path))
}

func FolderContains(folderPath string, path string) bool {
	return strings.HasPrefix(path, folderPath)
}
