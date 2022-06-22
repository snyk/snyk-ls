package workspace

import (
	"context"
	"fmt"
	"sync"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/di"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/iac"
	"github.com/snyk/snyk-ls/internal/observability/ux"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/lsp"
	"github.com/snyk/snyk-ls/oss"
)

// todo: do we really need this?
func (f *Folder) ClearDiagnosticsCache(filePath string) {
	f.documentDiagnosticCache.Delete(filePath)
	f.ClearScannedStatus()
}

func (f *Folder) DocumentDiagnosticsFromCache(file string) []lsp.Diagnostic {
	diagnostics := f.documentDiagnosticCache.Get(file)
	if diagnostics == nil {
		return nil
	}
	return diagnostics.([]lsp.Diagnostic)
}

func (f *Folder) FetchAllRegisteredDocumentDiagnostics(ctx context.Context, path string, level lsp.ScanLevel) map[string][]lsp.Diagnostic {
	method := "ide.workspace.Folder.FetchAllRegisteredDocumentDiagnostics"

	log.Info().Str("method", method).Msg("started.")
	defer log.Info().Str("method", method).Msg("done.")

	var diagnostics = map[string][]lsp.Diagnostic{}

	p := progress.NewTracker(false)
	p.Begin(fmt.Sprintf("Scanning for issues in %s", path), "")
	di.Analytics().AnalysisIsTriggered(
		ux.AnalysisIsTriggeredProperties{
			AnalysisType:    ux.GetEnabledAnalysisTypes(),
			TriggeredByUser: false,
		},
	)
	defer p.End(fmt.Sprintf("Scan complete. Found %d issues.", len(diagnostics)))

	wg := sync.WaitGroup{}

	var dChan chan lsp.DiagnosticResult
	hoverChan := hover.Channel()

	if level == lsp.ScanLevelWorkspace {
		dChan = make(chan lsp.DiagnosticResult, 10000)
		f.workspaceLevelFetch(ctx, path, p, &wg, dChan, hoverChan)
	} else {
		dChan = make(chan lsp.DiagnosticResult, 10000)
		f.fileLevelFetch(ctx, path, p, &wg, dChan, hoverChan)
	}
	log.Debug().
		Str("method", "fetchAllRegisteredDocumentDiagnostics").
		Msg("waiting for goroutines.")
	wg.Wait()
	log.Debug().
		Str("method", "fetchAllRegisteredDocumentDiagnostics").
		Msg("finished waiting for goroutines.")

	return f.processResults(dChan, diagnostics)
}

func (f *Folder) workspaceLevelFetch(ctx context.Context, path string, p *progress.Tracker, wg *sync.WaitGroup, dChan chan lsp.DiagnosticResult, hoverChan chan hover.DocumentHovers) {
	if config.CurrentConfig().IsSnykIacEnabled() {
		wg.Add(1)
		go iac.ScanWorkspace(ctx, f.cli, uri.PathToUri(path), wg, dChan, hoverChan)
		p.Report(10)
	}
	if config.CurrentConfig().IsSnykOssEnabled() {
		wg.Add(1)
		go oss.ScanWorkspace(ctx, f.cli, uri.PathToUri(path), wg, dChan, hoverChan)
		p.Report(20)
	}
	if config.CurrentConfig().IsSnykCodeEnabled() {
		f.doSnykCodeWorkspaceScan(ctx, wg, dChan, hoverChan)
		p.Report(80)
	}
}

func (f *Folder) doSnykCodeWorkspaceScan(ctx context.Context, wg *sync.WaitGroup, dChan chan lsp.DiagnosticResult, hoverChan chan hover.DocumentHovers) {
	//files, err := getWorkspaceFiles(workspacePath)
	files, err := f.parent.GetFolder(f.path).Files()
	if err != nil {
		log.Warn().
			Err(err).
			Str("method", "doSnykCodeWorkspaceScan").
			Str("workspacePath", f.path).
			Msg("error getting workspace files")
	}
	di.SnykCode().ScanWorkspace(ctx, files, f.path, wg, dChan, hoverChan)
}

func (f *Folder) fileLevelFetch(ctx context.Context, path string, p *progress.Tracker, wg *sync.WaitGroup, dChan chan lsp.DiagnosticResult, hoverChan chan hover.DocumentHovers) {
	if config.CurrentConfig().IsSnykIacEnabled() {
		wg.Add(1)
		go iac.ScanFile(ctx, f.cli, uri.PathToUri(path), wg, dChan, hoverChan)
		p.Report(10)
	}
	if config.CurrentConfig().IsSnykOssEnabled() {
		wg.Add(1)
		go oss.ScanFile(ctx, f.cli, uri.PathToUri(path), wg, dChan, hoverChan)
		p.Report(20)
	}
	if config.CurrentConfig().IsSnykCodeEnabled() {
		f.doSnykCodeWorkspaceScan(ctx, wg, dChan, hoverChan)
		p.Report(80)
	}
}

func (f *Folder) processResults(
	dChan chan lsp.DiagnosticResult,
	diagnostics map[string][]lsp.Diagnostic,
) map[string][]lsp.Diagnostic {
	for {
		select {
		case result := <-dChan:
			log.Trace().
				Str("method", "fetchAllRegisteredDocumentDiagnostics").
				Str("uri", string(result.Uri)).
				Msg("reading diag from chan.")

			if result.Err != nil {
				log.Err(result.Err).Str("method", "fetchAllRegisteredDocumentDiagnostics")
				di.ErrorReporter().CaptureError(result.Err)
				break
			}
			pathFromUri := uri.PathFromUri(result.Uri)
			diagnostics[pathFromUri] = append(diagnostics[pathFromUri], result.Diagnostics...)
			f.AddToCache(diagnostics)

		default: // return results once channels are empty
			log.Debug().
				Str("method", "fetchAllRegisteredDocumentDiagnostics").
				Msg("done reading diags.")

			return diagnostics
		}
	}
}

func (f *Folder) AddToCache(diagnostics map[string][]lsp.Diagnostic) {
	// add all diagnostics to cache
	for filePath := range diagnostics {
		f.documentDiagnosticCache.Put(filePath, diagnostics[filePath])
	}
}
