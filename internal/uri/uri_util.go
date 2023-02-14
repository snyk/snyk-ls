/*
 * © 2022 Snyk Limited All rights reserved.
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
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"
	"go.lsp.dev/uri"
)

const fileScheme = "file://"
const eclipseWorkspaceFolderScheme = "file:"

var rangeFragmentRegexp = regexp.MustCompile(`^(.+)://((.*)@)?(.+?)(:(\d*))?/?((.*)\?)?((.*)#)L?(\d+)(?:,(\d+))?(-L?(\d+)(?:,(\d+))?)?`)

func FolderContains(folderPath string, path string) bool {
	filePathSeparator := string(filepath.Separator)
	cleanPath := filepath.Clean(path)
	cleanFolderPath := filepath.Clean(folderPath)
	if !strings.HasSuffix(cleanFolderPath, filePathSeparator) {
		cleanFolderPath += filePathSeparator
	}
	log.Trace().Str("folderPath", cleanFolderPath).Str("path", cleanPath).Msg("FolderContains")
	return strings.HasPrefix(cleanPath, cleanFolderPath) ||
		strings.HasPrefix(cleanPath+filePathSeparator, cleanFolderPath)
}

// todo can we create a path domain type?
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

func IsDirectory(documentURI sglsp.DocumentURI) bool {
	workspaceUri := PathFromUri(documentURI)
	return isDirectory(workspaceUri)
}

func isDirectory(path string) bool {
	stat, err := os.Stat(path)
	if err != nil {
		log.Err(err).Err(err).Msg("Error while checking file")
		return false
	}
	return stat.IsDir()
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
