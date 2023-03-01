package watcher

import (
	"sync"

	sglsp "github.com/sourcegraph/go-lsp"
)

// FileWatcher is a simple in-memory file watcher that keeps track of files that were changed but not saved.
type FileWatcher struct {
	files map[sglsp.DocumentURI]bool
	m     sync.RWMutex
}

func NewFileWatcher() *FileWatcher {
	return &FileWatcher{
		files: make(map[sglsp.DocumentURI]bool),
	}
}

// SetFileAsChanged marks the file as having unsaved changes. Calling SetFileAsSaved will mark the file as "clean" again.
func (w *FileWatcher) SetFileAsChanged(uri sglsp.DocumentURI) {
	w.m.Lock()
	defer w.m.Unlock()
	w.files[uri] = true
}

// IsDirty returns true if the file has unsaved changes.
func (w *FileWatcher) IsDirty(uri sglsp.DocumentURI) bool {
	w.m.RLock()
	defer w.m.RUnlock()
	return w.files[uri]
}

// SetFileAsSaved marks the file as "clean".
func (w *FileWatcher) SetFileAsSaved(uri sglsp.DocumentURI) {
	w.m.Lock()
	defer w.m.Unlock()
	delete(w.files, uri)
}
