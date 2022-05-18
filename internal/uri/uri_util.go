package uri

import (
	"path/filepath"
	"runtime"
	"strings"
	"unicode"

	sglsp "github.com/sourcegraph/go-lsp"
)

const fileScheme = "file://"
const eclipseWorkspaceFolderScheme = "file:"

func FolderContains(folderPath string, path string) bool {
	return strings.HasPrefix(path, folderPath)
}

// PathFromUri converts the given uri to a file path
// `file:///C:/a/a.txt` is converted to `C:\a\a.txt` on Windows
// `file://a/a.txt` is converted to `\\a\a.txt` on Windows
// `file:/root/a` is converted to `/root/a` on Linux and macOS. This is necessary due to Eclipse sending wrong URI
// `file:///root is converted to `/root` on Linux and macOS
func PathFromUri(uri sglsp.DocumentURI) string {
	var path = removeScheme(uri)
	if isWindows() && isDriveURI(uri) { // UNC path
		path = strings.TrimPrefix(path, "/") // /C:/... --> C:/...
	}
	return filepath.Clean(path)
}

// PathToUri converts a path to a DocumentURI
// "/var/log.txt" -> "file:///var/log.txt"
// "//var/log.txt -> "file:///var/log.txt
// Windows:"C:/var/log.txt" -> "file:///C:/var/log.txt"
// Windows:"C:\var\log.txt" -> "file:///C:/var/log.txt"
// Windows:"\\var\log.txt" -> "file://var/log.txt"
// Windows:"//var\log.txt" -> "file://var/log.txt"
func PathToUri(path string) sglsp.DocumentURI {
	if isWindows() {
		if isDrivePath(path) {
			path = "/" + filepath.Clean(path)
		} else {
			// "//share/d$/folder/file" -> "share/d$/folder/file
			path = strings.TrimPrefix(path, "//")
			// "\\share\d$\folder\file" -> "share/d$/folder/file
			path = strings.TrimPrefix(path, "\\\\")
		}
	}
	return sglsp.DocumentURI("file://" + filepath.Clean(filepath.ToSlash(path)))
}

func isWindows() bool {
	return runtime.GOOS == "windows"
}

func isDrivePath(path string) bool {
	sep := path[2]
	return len(path) > 2 && unicode.IsLetter(rune(path[0])) && path[1] == ':' && (sep == '/' || sep == '\\')
}

func isDriveURI(uri sglsp.DocumentURI) bool {
	prefixLength := len(fileScheme) + 1 // file:// + / [C:/...]
	return len(uri) > prefixLength && isDrivePath(string(uri[prefixLength:]))
}

func removeScheme(uri sglsp.DocumentURI) string {
	var path = strings.TrimPrefix(string(uri), fileScheme)
	path = strings.TrimPrefix(path, eclipseWorkspaceFolderScheme)
	return path
}
