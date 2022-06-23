package workspace

import (
	"context"
	"fmt"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/di"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/iac"
	"github.com/snyk/snyk-ls/internal/notification"
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

func (f *Folder) FetchAllRegisteredDocumentDiagnostics(ctx context.Context, path string, level lsp.ScanLevel) {
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

	if level == lsp.ScanLevelWorkspace {
		f.workspaceLevelFetch(ctx, path, p, f.processResults)
	} else {
		f.fileLevelFetch(ctx, path, p, f.processResults)
	}
}

func (f *Folder) workspaceLevelFetch(ctx context.Context, path string, p *progress.Tracker, output func(issues map[string][]lsp.Diagnostic, hovers []hover.DocumentHovers)) {
	if config.CurrentConfig().IsSnykIacEnabled() {
		go iac.ScanWorkspace(ctx, f.cli, uri.PathToUri(path), output)
		p.Report(10)
	}
	if config.CurrentConfig().IsSnykOssEnabled() {
		go oss.ScanWorkspace(ctx, f.cli, uri.PathToUri(path), output)
		p.Report(20)
	}
	if config.CurrentConfig().IsSnykCodeEnabled() {
		f.doSnykCodeWorkspaceScan(ctx, output)
		go p.Report(30)
	}
}

func (f *Folder) doSnykCodeWorkspaceScan(ctx context.Context, output func(issues map[string][]lsp.Diagnostic, hovers []hover.DocumentHovers)) {
	files, err := f.parent.GetFolder(f.path).Files()
	if err != nil {
		log.Warn().
			Err(err).
			Str("method", "doSnykCodeWorkspaceScan").
			Str("workspacePath", f.path).
			Msg("error getting workspace files")
	}
	di.SnykCode().ScanWorkspace(ctx, files, f.path, output)
}

func (f *Folder) fileLevelFetch(ctx context.Context, path string, p *progress.Tracker, output func(issues map[string][]lsp.Diagnostic, hovers []hover.DocumentHovers)) {
	if config.CurrentConfig().IsSnykIacEnabled() {
		go iac.ScanFile(ctx, f.cli, uri.PathToUri(path), output)
		p.Report(10)
	}
	if config.CurrentConfig().IsSnykOssEnabled() {
		go oss.ScanFile(ctx, f.cli, uri.PathToUri(path), output)
		p.Report(20)
	}
	if config.CurrentConfig().IsSnykCodeEnabled() {
		f.doSnykCodeWorkspaceScan(ctx, output)
		p.Report(80)
	}
}

func (f *Folder) processResults(diagnostics map[string][]lsp.Diagnostic, hovers []hover.DocumentHovers) {
	f.processDiagnostics(diagnostics)
	f.processHovers(hovers)
}

func (f *Folder) processDiagnostics(diagnostics map[string][]lsp.Diagnostic) {
	// add all diagnostics to cache
	for filePath := range diagnostics {
		f.documentDiagnosticCache.Put(filePath, diagnostics[filePath])
		notification.Send(lsp.PublishDiagnosticsParams{
			URI:         uri.PathToUri(filePath),
			Diagnostics: diagnostics[filePath],
		})
	}
}

func (f *Folder) processHovers(hovers []hover.DocumentHovers) {
	for _, h := range hovers {
		select {
		case di.HoverService().Channel() <- h:
		}
	}
}
