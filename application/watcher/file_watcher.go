package watcher

import (
	"sync"

	sglsp "github.com/sourcegraph/go-lsp"
)

type FileWatcher struct {
	files map[sglsp.DocumentURI]bool
	m     sync.RWMutex
}

func NewFileWatcher() *FileWatcher {
	return &FileWatcher{
		files: make(map[sglsp.DocumentURI]bool),
	}
}

func (w *FileWatcher) FileChanged(uri sglsp.DocumentURI) {
	w.m.Lock()
	defer w.m.Unlock()
	w.files[uri] = true
}

func (w *FileWatcher) IsDirty(uri sglsp.DocumentURI) bool {
	w.m.RLock()
	defer w.m.RUnlock()
	return w.files[uri]
}

func (w *FileWatcher) FileSaved(uri sglsp.DocumentURI) {
	w.m.Lock()
	defer w.m.Unlock()
	delete(w.files, uri)
}
