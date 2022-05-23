package uri

import (
	"testing"

	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestPathFromUri(t *testing.T) {
	testutil.NotOnWindows(t, "different behaviour for uris")
	assert.Equal(t, "asdf", PathFromUri("file://asdf"))
	assert.Equal(t, "asdf", PathFromUri("file:asdf"))
}

func TestPathFromUri_OnWindows(t *testing.T) {
	testutil.OnlyOnWindows(t, "windows specific paths are tested")
	assert.Equal(t, "C:\\folder\\test", PathFromUri("file:///C:/folder/test"))
	assert.Equal(t, "\\\\shares\\c$\\test", PathFromUri("file://shares/c$/test"))
}

func TestPathToUri_OnWindows(t *testing.T) {
	testutil.OnlyOnWindows(t, "windows specific paths are tested")
	assert.Equal(t, lsp.DocumentURI("file:///C:/folder/file"), PathToUri("C:\\folder\\file"))
	assert.Equal(t, lsp.DocumentURI("file:///C:/folder/file"), PathToUri("C:/folder/file"))
	assert.Equal(t, lsp.DocumentURI("file://shares/c$/folder/file"), PathToUri("//shares/c$/folder/file"))
}

func TestPathToUri(t *testing.T) {
	assert.Equal(t, lsp.DocumentURI("file://asdf"), PathToUri("asdf"))
	assert.Equal(t, lsp.DocumentURI("file:///asdf"), PathToUri("//asdf"))
}

func TestFolderContains(t *testing.T) {
	assert.True(t, FolderContains("C:/folder/", "C:/folder/file"))
	assert.True(t, FolderContains("C:/folder/", "C:/folder/subfolder/file"))
	assert.False(t, FolderContains("C:/folder/", "C:/otherFolder/file"))
	assert.False(t, FolderContains("C:/folder/", "D:/folder/file"))
}

func TestIsDrivePath(t *testing.T) {
	assert.True(t, isDrivePath("C:/"))
	assert.True(t, isDrivePath("C:/folder/file"))
	assert.True(t, isDrivePath("D:/folder/file"))
	assert.True(t, isDrivePath("D:\\folder\\file"))
	assert.False(t, isDrivePath("//folder/file"))
	assert.False(t, isDrivePath("\\\\UNC\\folder\\file"))
	assert.False(t, isDrivePath("/C:/folder/file"))
}

func TestIsDriveURI(t *testing.T) {
	assert.False(t, isDriveURI("/C:/folder/file"))
	assert.False(t, isDriveURI("C:/folder/file"))
	assert.False(t, isDriveURI("C:\\folder\\file"))
	assert.False(t, isDriveURI("\\\\folder\\file"))
	assert.False(t, isDriveURI("/folder/file"))
	assert.False(t, isDriveURI("file:///folder/file"))
	assert.True(t, isDriveURI("file:///C:/folder/file"))
	assert.True(t, isDriveURI("file:///D:/folder/file"))
}
