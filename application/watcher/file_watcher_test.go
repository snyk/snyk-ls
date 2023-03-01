package watcher_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/watcher"
	uri2 "github.com/snyk/snyk-ls/internal/uri"
)

func Test_WhenFileUnchanged_FileIsNotDirty(t *testing.T) {
	// Arrange
	t.Parallel()
	w := watcher.NewFileWatcher()
	uri := uri2.PathToUri("path/to/file")

	// Act
	isDirty := w.IsDirty(uri)

	// Assert
	assert.False(t, isDirty)
}

func Test_WhenFileSaved_FileIsNotDirty(t *testing.T) {
	// Arrange
	t.Parallel()
	w := watcher.NewFileWatcher()
	uri := uri2.PathToUri("path/to/file")
	w.SetFileAsChanged(uri)

	// Act
	w.SetFileAsSaved(uri)

	// Assert
	assert.False(t, w.IsDirty(uri))
}

func Test_WhenFileChanged_FileIsDirty(t *testing.T) {
	// Arrange
	t.Parallel()
	w := watcher.NewFileWatcher()
	uri := uri2.PathToUri("path/to/file")

	// Act
	w.SetFileAsChanged(uri)

	// Assert
	assert.True(t, w.IsDirty(uri))
}
