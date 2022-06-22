package workspace

import (
	"context"
	"sync"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/di"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/preconditions"
	"github.com/snyk/snyk-ls/lsp"
)

var instance *Workspace
var mutex = &sync.Mutex{}

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

func New() *Workspace {
	return &Workspace{workspaceFolders: make(map[string]*Folder, 0)}
}

func (w *Workspace) DeleteFolder(folder string) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	delete(w.workspaceFolders, folder)
}

func (w *Workspace) AddFolder(f *Folder) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	if w.workspaceFolders == nil {
		w.workspaceFolders = map[string]*Folder{}
	}
	w.workspaceFolders[f.path] = f
}

func (w *Workspace) GetFolder(path string) (folder *Folder) {
	for _, folder := range w.workspaceFolders {
		if folder.Contains(path) {
			return folder
		}
	}
	return nil
}

func (w *Workspace) GetDiagnostics(ctx context.Context, path string) []lsp.Diagnostic {
	// serve from cache
	method := "Workspace.GetDiagnostics"
	s := di.Instrumentor().NewTransaction(ctx, method, method)
	defer di.Instrumentor().Finish(s)

	folder := w.GetFolder(path)

	if folder == nil {
		log.Warn().Str("method", method).Msgf("No workspace folder configured for %s", path)
		return []lsp.Diagnostic{}
	}

	diagnosticSlice := folder.DocumentDiagnosticsFromCache(path)
	if len(diagnosticSlice) > 0 {
		log.Info().Str("method", method).Msgf("Cached: Diagnostics for %s", path)
		return diagnosticSlice
	}

	folder.FetchAllRegisteredDocumentDiagnostics(s.Context(), path, lsp.ScanLevelFile)
	return folder.DocumentDiagnosticsFromCache(path)
}

func (w *Workspace) Scan(ctx context.Context) {
	method := "domain.ide.Workspace.Scan"
	s := di.Instrumentor().NewTransaction(ctx, method, method)
	defer di.Instrumentor().Finish(s)

	preconditions.EnsureReadyForAnalysisAndWait(ctx)
	notification.Send(sglsp.ShowMessageParams{Type: sglsp.Info, Message: "Workspace scan started"})
	defer notification.Send(sglsp.ShowMessageParams{Type: sglsp.Info, Message: "Workspace scan completed"})

	var wg sync.WaitGroup
	for _, folder := range w.workspaceFolders {
		wg.Add(1)
		go folder.Scan(s.Context(), &wg)
	}

	wg.Wait()
	log.Info().Str("method", "Workspace").
		Msg("Workspace scan completed")
}
