package workspace

import (
	"context"
	"sync"

	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/domain/observability/performance"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/uri"
)

//todo can we do without a singleton?
var instance *Workspace
var mutex = &sync.Mutex{}

// Workspace represents the highest entity in an IDE that contains code. A workspace may contain multiple folders
type Workspace struct {
	mutex        sync.Mutex
	folders      map[string]*Folder
	instrumentor performance.Instrumentor
}

func New(instrumentor performance.Instrumentor) *Workspace {
	return &Workspace{
		folders:      make(map[string]*Folder, 0),
		instrumentor: instrumentor,
	}
}

//todo can we move to di?
func Get() *Workspace {
	mutex.Lock()
	defer mutex.Unlock()
	return instance
}

func Set(w *Workspace) {
	mutex.Lock()
	defer mutex.Unlock()
	instance = w
}

func (w *Workspace) DeleteFolder(folder string) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	delete(w.folders, folder)
}

func (w *Workspace) AddFolder(f *Folder) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	if w.folders == nil {
		w.folders = map[string]*Folder{}
	}
	w.folders[f.Path()] = f
}

func (w *Workspace) GetFolderContaining(path string) (folder *Folder) {
	for _, folder := range w.folders {
		if folder.Contains(path) {
			return folder
		}
	}
	return nil
}

func (w *Workspace) ScanWorkspace(ctx context.Context) {
	notification.Send(sglsp.ShowMessageParams{Type: sglsp.Info, Message: "Workspace scan started."})

	for _, folder := range w.folders {
		go folder.ScanFolder(ctx)
	}
}

func (w *Workspace) ProcessFolderChange(ctx context.Context, params lsp.DidChangeWorkspaceFoldersParams) {
	for _, folder := range params.Event.Removed {
		w.DeleteFolder(uri.PathFromUri(folder.Uri))
	}
	for _, folder := range params.Event.Added {
		f := NewFolder(uri.PathFromUri(folder.Uri), folder.Name, di.Scanner(), di.HoverService())
		w.AddFolder(f)
	}
	w.ScanWorkspace(ctx)
}
