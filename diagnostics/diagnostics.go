package diagnostics

import (
	"fmt"
	"sync"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/code"
	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/di"
	"github.com/snyk/snyk-ls/error_reporting"
	"github.com/snyk/snyk-ls/iac"
	"github.com/snyk/snyk-ls/internal/cli"
	"github.com/snyk/snyk-ls/internal/concurrency"
	"github.com/snyk/snyk-ls/internal/hover"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/lsp"
	"github.com/snyk/snyk-ls/oss"
)

var (
	documentDiagnosticCache concurrency.AtomicMap
	Cli                     cli.Executor
)

func init() {
	documentDiagnosticCache = concurrency.AtomicMap{}
	Cli = cli.SnykCli{}
}

func ClearDiagnosticsCache(documentURI sglsp.DocumentURI) {
	documentDiagnosticCache.Delete(documentURI)
}

func ClearWorkspaceFolderDiagnostics(folder lsp.WorkspaceFolder) {
	f := func(u interface{}, value interface{}) bool {
		path := uri.PathFromUri(u.(sglsp.DocumentURI))
		folderPath := uri.PathFromUri(folder.Uri)
		if uri.FolderContains(folderPath, path) {
			documentDiagnosticCache.Delete(u)
			log.Debug().Str("method", "ClearWorkspaceFolderDiagnostics").Str("path", path).Str("workspaceFolder", folderPath).Msg("Cleared diagnostics.")
		}
		return true
	}
	documentDiagnosticCache.Range(f)
	removeFolderFromScanned(folder)
	log.Debug().Str("method", "ClearWorkspaceFolderDiagnostics").Str("workspaceFolder", string(folder.Uri)).Msg("Removed")
}

func ClearEntireDiagnosticsCache() {
	documentDiagnosticCache.ClearAll()
}

func DocumentDiagnosticsFromCache(file sglsp.DocumentURI) []lsp.Diagnostic {
	diagnostics := documentDiagnosticCache.Get(file)
	if diagnostics == nil {
		return nil
	}
	return diagnostics.([]lsp.Diagnostic)
}

func GetDiagnostics(documentURI sglsp.DocumentURI) []lsp.Diagnostic {
	// serve from cache
	diagnosticSlice := DocumentDiagnosticsFromCache(documentURI)
	if len(diagnosticSlice) > 0 {
		log.Info().Str("method", "GetDiagnostics").Msgf("Cached: Diagnostics for %s", documentURI)
		return diagnosticSlice
	}

	diagnostics := fetchAllRegisteredDocumentDiagnostics(documentURI, lsp.ScanLevelFile)
	addToCache(diagnostics)
	cache := DocumentDiagnosticsFromCache(documentURI)
	return cache
}

func fetchAllRegisteredDocumentDiagnostics(documentURI sglsp.DocumentURI, level lsp.ScanLevel) map[sglsp.DocumentURI][]lsp.Diagnostic {
	log.Info().
		Str("method", "fetchAllRegisteredDocumentDiagnostics").
		Msg("started.")

	defer log.Info().
		Str("method", "fetchAllRegisteredDocumentDiagnostics").
		Msg("done.")

	var diagnostics = map[sglsp.DocumentURI][]lsp.Diagnostic{}

	p := progress.NewTracker(false)
	p.Begin(fmt.Sprintf("Scanning for issues in %s", uri.PathFromUri(documentURI)), "")
	defer p.End(fmt.Sprintf("Scan complete. Found %d issues.", len(diagnostics)))

	wg := sync.WaitGroup{}

	var dChan chan lsp.DiagnosticResult
	hoverChan := hover.Channel()

	if level == lsp.ScanLevelWorkspace {
		dChan = make(chan lsp.DiagnosticResult, 10000)
		workspaceLevelFetch(documentURI, p, &wg, dChan, hoverChan)
	} else {
		dChan = make(chan lsp.DiagnosticResult, 10000)
		fileLevelFetch(documentURI, p, &wg, dChan, hoverChan)
	}
	wg.Wait()
	log.Debug().
		Str("method", "fetchAllRegisteredDocumentDiagnostics").
		Msg("finished waiting for goroutines.")

	return processResults(dChan, diagnostics)
}

func workspaceLevelFetch(workspaceURI sglsp.DocumentURI, p *progress.Tracker, wg *sync.WaitGroup, dChan chan lsp.DiagnosticResult, hoverChan chan lsp.Hover) {
	if config.CurrentConfig.IsSnykIacEnabled() {
		wg.Add(1)
		go iac.ScanWorkspace(Cli, workspaceURI, wg, dChan, hoverChan)
		p.Report(10)
	}
	if config.CurrentConfig.IsSnykOssEnabled() {
		wg.Add(1)
		go oss.ScanWorkspace(Cli, workspaceURI, wg, dChan, hoverChan)
		p.Report(20)
	}
	if config.CurrentConfig.IsSnykCodeEnabled() {
		files, err := getWorkspaceFiles(workspaceURI)
		if err != nil {
			log.Warn().
				Err(err).
				Str("method", "workspaceLevelFetch").
				Str("workspaceURI", string(workspaceURI)).
				Msg("error getting workspace files")
		}
		di.SnykCode.ScanWorkspace(files, workspaceURI, wg, dChan, hoverChan)
		p.Report(80)
	}
}


func fileLevelFetch(documentURI sglsp.DocumentURI, p *progress.Tracker, wg *sync.WaitGroup, dChan chan lsp.DiagnosticResult, hoverChan chan lsp.Hover) {
	if config.CurrentConfig.IsSnykCodeEnabled() {
		di.SnykCode.ScanFile(documentURI, wg, dChan, hoverChan)
	}
	if config.CurrentConfig.IsSnykIacEnabled() {
		wg.Add(1)
		go iac.ScanFile(Cli, documentURI, wg, dChan, hoverChan)
	}
	if config.CurrentConfig.IsSnykOssEnabled() {
		wg.Add(1)
		go oss.ScanFile(Cli, documentURI, wg, dChan, hoverChan)
	}
	p.Report(80)
}

func processResults(
	dChan chan lsp.DiagnosticResult,
	diagnostics map[sglsp.DocumentURI][]lsp.Diagnostic,
) map[sglsp.DocumentURI][]lsp.Diagnostic {
	for {
		select {
		case result := <-dChan:
			log.Trace().
				Str("method", "fetchAllRegisteredDocumentDiagnostics").
				Str("uri", string(result.Uri)).
				Msg("reading diag from chan.")

			if result.Err != nil {
				log.Err(result.Err).Str("method", "fetchAllRegisteredDocumentDiagnostics")
				error_reporting.CaptureError(result.Err)
				break
			}
			diagnostics[result.Uri] = append(diagnostics[result.Uri], result.Diagnostics...)
			documentDiagnosticCache.Put(result.Uri, diagnostics)

		default: // return results once channels are empty
			log.Debug().
				Str("method", "fetchAllRegisteredDocumentDiagnostics").
				Msg("done reading diags.")

			return diagnostics
		}
	}
}

func addToCache(diagnostics map[sglsp.DocumentURI][]lsp.Diagnostic) {
	// add all diagnostics to cache
	for documentURI := range diagnostics {
		documentDiagnosticCache.Put(documentURI, diagnostics[documentURI])
	}
}
