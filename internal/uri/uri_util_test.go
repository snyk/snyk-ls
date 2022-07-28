package uri

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/domain/snyk"
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

func TestUri_AddRangeToUri(t *testing.T) {
	t.Run("range with 0 start line, should be changed to 1", func(t *testing.T) {
		r := getTestRange()
		actual := string(AddRangeToUri("file://asdf", r))
		assert.Equal(t, "file://asdf#L1,6-L2,11", actual)
	})
	t.Run("range with 0 end line, should be changed to 1", func(t *testing.T) {
		r := getTestRange()
		r.End.Line = 0
		actual := string(AddRangeToUri("file://asdf", r))
		assert.Equal(t, "file://asdf#L1,6-L1,11", actual)
	})
	t.Run("range with 0 start char, should be changed to 1", func(t *testing.T) {
		r := getTestRange()
		r.Start.Character = 0
		actual := string(AddRangeToUri("file://asdf", r))
		assert.Equal(t, "file://asdf#L1,1-L2,11", actual)
	})
	t.Run("range with 0 end char, should be changed to 1", func(t *testing.T) {
		r := getTestRange()
		r.End.Character = 0
		actual := string(AddRangeToUri("file://asdf", r))
		assert.Equal(t, "file://asdf#L1,6-L2,1", actual)
	})
	t.Run("range ending with `/` should not be changed", func(t *testing.T) {
		r := getTestRange()
		r.End.Character = 0
		actual := string(AddRangeToUri("file://asdf/", r))
		assert.Equal(t, "file://asdf/", actual)
	})
	t.Run("range already having a location fragment should not be changed", func(t *testing.T) {
		r := getTestRange()
		r.End.Character = 0
		actual := string(AddRangeToUri("file://asdf#L1,1-L1,1", r))
		assert.Equal(t, "file://asdf#L1,1-L1,1", actual)
	})
}

func getTestRange() snyk.Range {
	r := snyk.Range{
		Start: snyk.Position{
			Line:      0,
			Character: 5,
		},
		End: snyk.Position{
			Line:      1,
			Character: 10,
		},
	}
	return r
}
