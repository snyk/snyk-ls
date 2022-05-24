package uri

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
)

var dir, _ = os.Getwd()

func TestPathFromUri(t *testing.T) {
	u := PathToUri(dir + "/asdf")
	u = lsp.DocumentURI(strings.Replace(string(u), "file://", "file:", 1))
	assert.Equal(t, filepath.Clean(dir+"/asdf"), PathFromUri(u)) // Eclipse case
}

func TestFolderContains(t *testing.T) {
	assert.True(t, FolderContains("C:/folder/", "C:/folder/file"))
	assert.True(t, FolderContains("C:/folder/", "C:/folder/subfolder/file"))
	assert.False(t, FolderContains("C:/folder/", "C:/otherFolder/file"))
	assert.False(t, FolderContains("C:/folder/", "D:/folder/file"))
}
