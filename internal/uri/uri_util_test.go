package uri

import (
	"os"
	"testing"

	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/testutil"
)

var dir, _ = os.Getwd()

func TestPathFromUri(t *testing.T) {
	testutil.NotOnWindows(t, "different behaviour for uris")
	assert.Equal(t, dir+"/asdf", PathFromUri(lsp.DocumentURI("file://"+dir+"/asdf")))
	assert.Equal(t, dir+"/asdf", PathFromUri(lsp.DocumentURI("file:"+dir+"/asdf"))) // Eclipse case
}

func TestFolderContains(t *testing.T) {
	assert.True(t, FolderContains("C:/folder/", "C:/folder/file"))
	assert.True(t, FolderContains("C:/folder/", "C:/folder/subfolder/file"))
	assert.False(t, FolderContains("C:/folder/", "C:/otherFolder/file"))
	assert.False(t, FolderContains("C:/folder/", "D:/folder/file"))
}
