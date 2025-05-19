/*
 * ©2022-2025 Snyk Limited All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package uri

import (
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"

	sglsp "github.com/sourcegraph/go-lsp"
	"go.lsp.dev/uri"

	"github.com/snyk/snyk-ls/internal/types"
)

const fileScheme = "file://"
const uncFileScheme = "file:////"
const eclipseWorkspaceFolderScheme = "file:"

var rangeFragmentRegexp = regexp.MustCompile(`^(.+)://((.*)@)?(.+?)(:(\d*))?/?((.*)\?)?((.*)#)L?(\d+)(?:,(\d+))?(-L?(\d+)(?:,(\d+))?)?`)

// Cache for storing case sensitivity results by path
var (
	caseSensitivityCache    = make(map[string]bool)
	caseSensitivityCacheMux sync.RWMutex
)

// For testing - allows us to mock os.Create
var osCreate = os.Create

func FolderContains(folderPath types.FilePath, path types.FilePath) bool {
	filePathSeparator := string(filepath.Separator)
	cleanPath := filepath.Clean(string(path))
	cleanFolderPath := filepath.Clean(string(folderPath))
	if !strings.HasSuffix(cleanFolderPath, filePathSeparator) {
		cleanFolderPath += filePathSeparator
	}

	// Check if the path is on a case-insensitive filesystem
	if isCaseInsensitivePath(cleanPath) {
		cleanPath = strings.ToLower(cleanPath)
		cleanFolderPath = strings.ToLower(cleanFolderPath)
	}

	return strings.HasPrefix(cleanPath, cleanFolderPath) ||
		strings.HasPrefix(cleanPath+filePathSeparator, cleanFolderPath)
}

// PathFromUri converts the given uri to a file path
func PathFromUri(documentURI sglsp.DocumentURI) types.FilePath {
	u := string(documentURI)

	// Check if path is UNC file path. In this case return it.
	uncPath := pathFromUNCUri(u)
	if uncPath != "" {
		return uncPath
	}

	if !strings.HasPrefix(u, fileScheme) && strings.HasPrefix(u, eclipseWorkspaceFolderScheme) {
		u = strings.Replace(u, eclipseWorkspaceFolderScheme, fileScheme, 1)
	}

	return types.FilePath(uri.New(u).Filename())
}

// pathFromUNCUri checks if the provided file URI represents a UNC path.
func pathFromUNCUri(uri string) types.FilePath {
	if runtime.GOOS != "windows" || !strings.HasPrefix(uri, fileScheme) {
		return ""
	}
	if strings.HasPrefix(uri, uncFileScheme) {
		uri = strings.Replace(uri, uncFileScheme, fileScheme, 1)
	}

	parsedURI, err := url.Parse(uri)
	if err != nil {
		return ""
	}

	if parsedURI.Scheme != "file" {
		return ""
	}

	// A non-empty Host indicates a UNC path
	if len(parsedURI.Host) > 0 {
		uncPath := fmt.Sprintf(`\\%s%s`, parsedURI.Host, parsedURI.Path)
		// Convert slashes to backslashes
		return types.FilePath(filepath.Clean(uncPath))
	}

	return ""
}

// PathToUri converts a path to a DocumentURI
func PathToUri(path types.FilePath) sglsp.DocumentURI {
	// in case of UNC file path. uri.File returns file://// which IDEs can't interpret correctly
	// file://// is still a valid UNC, but we have to replace with file:// for the IDEs to interpret it correctly
	parsedUri := uri.File(string(path))
	uriAsString := string(parsedUri)
	if strings.HasPrefix(uriAsString, uncFileScheme) {
		uriAsString = strings.Replace(uriAsString, uncFileScheme, fileScheme, 1)
	}
	return sglsp.DocumentURI(uriAsString)
}

func IsUriDirectory(documentURI sglsp.DocumentURI) bool {
	workspaceUri := PathFromUri(documentURI)
	return IsDirectory(workspaceUri)
}

func IsDirectory(path types.FilePath) bool {
	stat, err := os.Stat(string(path))
	if err != nil {
		return false
	}
	return stat.IsDir()
}

func IsRegularFile(path types.FilePath) bool {
	stat, err := os.Stat(string(path))
	return err == nil && stat.Mode().IsRegular()
}

func IsDotSnykFile(uri sglsp.DocumentURI) bool {
	return strings.HasSuffix(string(uri), ".snyk")
}

// isCaseInsensitivePath checks if a path is on a case-insensitive filesystem
func isCaseInsensitivePath(path string) bool {
	// Windows is always case-insensitive
	if runtime.GOOS == "windows" {
		return true
	}

	// Normalize the path to a directory
	dirPath := path
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		dirPath = filepath.Dir(path)
	}

	// If the path doesn't exist, use the current directory
	if _, err := os.Stat(dirPath); err != nil {
		dirPath = "."
	}

	// Convert to absolute path for better caching
	absPath, err := filepath.Abs(dirPath)
	if err != nil {
		absPath = dirPath
	}

	// Get the filesystem root for this path
	// This is important because different mounts can have different case sensitivity settings
	root := filepath.VolumeName(absPath)
	if root == "" {
		// For POSIX systems, use the first directory component
		parts := strings.Split(absPath, string(filepath.Separator))
		root = string(filepath.Separator)
		if len(parts) > 1 && parts[1] != "" {
			root = filepath.Join(root, parts[1])
		}
	}

	// Check cache first
	caseSensitivityCacheMux.RLock()
	if result, exists := caseSensitivityCache[root]; exists {
		caseSensitivityCacheMux.RUnlock()
		return result
	}
	caseSensitivityCacheMux.RUnlock()

	isInsensitive := isCaseInsensitive(root)

	// Store result in cache
	caseSensitivityCacheMux.Lock()
	caseSensitivityCache[root] = isInsensitive
	caseSensitivityCacheMux.Unlock()

	return isInsensitive
}

// Range gives a position in a document. All attributes are 0-based
type Range struct {
	StartLine int
	EndLine   int
	StartChar int
	EndChar   int
}

// AddRangeToUri adds a fragment to the URI to allow for exact navigation
// A range of Start Line 0, Char 1, End Line 1, Char 10
// translates to file://..#L1,2-L2,11. This is similar to vscode
// see e.g. https://github.com/microsoft/vscode/blob/b51955e4c878c8facdd775709740c8aa5d1192d6/src/vs/platform/opener/common/opener.ts#L162
func AddRangeToUri(u sglsp.DocumentURI, r Range) sglsp.DocumentURI {
	if rangeFragmentRegexp.Match([]byte(u)) || strings.HasSuffix(string(u), "/") {
		return u
	}
	startChar := int(math.Max(1, float64(r.StartChar+1)))
	endChar := int(math.Max(1, float64(r.EndChar+1)))
	startLine := int(math.Max(1, float64(r.StartLine+1)))
	endLine := int(math.Max(1, float64(r.EndLine+1)))
	return sglsp.DocumentURI(fmt.Sprintf("%s#%d,%d-%d,%d", u, startLine, startChar, endLine, endChar))
}
