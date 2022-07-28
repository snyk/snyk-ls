package uri

import (
	"fmt"
	"math"
	"os"
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

func IsDirectory(documentURI sglsp.DocumentURI) bool {
	workspaceUri := PathFromUri(documentURI)
	stat, err := os.Stat(workspaceUri)
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
	return sglsp.DocumentURI(fmt.Sprintf("%s#L%d,%d-L%d,%d", u, startLine, startChar, endLine, endChar))
}
