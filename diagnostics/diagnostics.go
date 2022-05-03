package diagnostics

import (
	"fmt"
	"sync"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/code"
	"github.com/snyk/snyk-ls/config/environment"
	"github.com/snyk/snyk-ls/error_reporting"
	"github.com/snyk/snyk-ls/iac"
	"github.com/snyk/snyk-ls/internal/cli"
	"github.com/snyk/snyk-ls/internal/hover"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/lsp"
	"github.com/snyk/snyk-ls/oss"
)

var (
	diagnosticsMutex        = &sync.Mutex{}
	registeredDocuments     = map[sglsp.DocumentURI]bool{}
	documentDiagnosticCache = map[sglsp.DocumentURI][]lsp.Diagnostic{}
	SnykCode                code.SnykCodeService
	Cli                     cli.Executor = cli.SnykCli{}
)

func ClearDiagnosticsCache(uri sglsp.DocumentURI) {
	diagnosticsMutex.Lock()
	delete(documentDiagnosticCache, uri)
	diagnosticsMutex.Unlock()
}

func ClearWorkspaceFolderDiagnostics(folder lsp.WorkspaceFolder) {
	diagnosticsMutex.Lock()
	for u := range documentDiagnosticCache {
		path := uri.PathFromUri(u)
		folderPath := uri.PathFromUri(folder.Uri)
		if uri.FolderContains(folderPath, path) {
			delete(documentDiagnosticCache, u)
			log.Debug().Str("method", "ClearWorkspaceFolderDiagnostics").Str("path", path).Str("workspaceFolder", folderPath).Msg("Cleared diagnostics.")
		}
	}
	diagnosticsMutex.Unlock()
	removeFolderFromScanned(folder)
	log.Debug().Str("method", "ClearWorkspaceFolderDiagnostics").Str("workspaceFolder", string(folder.Uri)).Msg("Removed")
}

func ClearEntireDiagnosticsCache() {
	diagnosticsMutex.Lock()
	documentDiagnosticCache = map[sglsp.DocumentURI][]lsp.Diagnostic{}
	diagnosticsMutex.Unlock()
}

func ClearRegisteredDocuments() {
	registeredDocsMutex.Lock()
	registeredDocuments = map[sglsp.DocumentURI]bool{}
	registeredDocsMutex.Unlock()
}

func RegisterDocument(file sglsp.TextDocumentItem) {
	documentURI := file.URI
	if !(code.IsSupported(documentURI) ||
		iac.IsSupported(documentURI) ||
		oss.IsSupported(documentURI)) {
		return
	}
	registeredDocsMutex.Lock()
	registeredDocuments[documentURI] = true
	registeredDocsMutex.Unlock()
}

func UnRegisterDocument(file sglsp.DocumentURI) {
	registeredDocsMutex.Lock()
	delete(registeredDocuments, file)
	registeredDocsMutex.Unlock()
}

func DocumentDiagnosticsFromCache(file sglsp.DocumentURI) []lsp.Diagnostic {
	diagnosticsMutex.Lock()
	defer diagnosticsMutex.Unlock()
	return documentDiagnosticCache[file]
}

func GetDiagnostics(uri sglsp.DocumentURI) []lsp.Diagnostic {
	// serve from cache
	diagnosticsMutex.Lock()
	diagnosticSlice := documentDiagnosticCache[uri]
	diagnosticsMutex.Unlock()
	if len(diagnosticSlice) > 0 {
		log.Info().Str("method", "GetDiagnostics").Msgf("Cached: Diagnostics for %s", uri)
		return diagnosticSlice
	}

	var diagnostics = fetchAllRegisteredDocumentDiagnostics(uri, lsp.ScanLevelFile)
	addToCache(diagnostics)
	diagnosticsMutex.Lock()
	defer diagnosticsMutex.Unlock()
	cache := documentDiagnosticCache[uri]
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
	var bundles = make([]*code.BundleImpl, 0, 10)

	p := progress.New(fmt.Sprintf("Scanning for issues in %s", uri.PathFromUri(documentURI)), "", false)
	progress.BeginProgress(p, progress.ProgressChannel)
	defer progress.EndProgress(p.Token, fmt.Sprintf("Scan complete. Found %d issues.", len(diagnostics)), progress.ProgressChannel)

	wg := sync.WaitGroup{}

	var dChan chan lsp.DiagnosticResult
	hoverChan := hover.Channel()

	if level == lsp.ScanLevelWorkspace {
		dChan = make(chan lsp.DiagnosticResult, 3*len(registeredDocuments))
		workspaceLevelFetch(documentURI, environment.CurrentEnabledProducts, bundles, &wg, dChan, hoverChan)
	} else {
		dChan = make(chan lsp.DiagnosticResult, 3)
		fileLevelFetch(documentURI, environment.CurrentEnabledProducts, bundles, &wg, dChan, hoverChan)
	}
	progress.ReportProgress(p.Token, 50, progress.ProgressChannel)
	wg.Wait()
	log.Debug().
		Str("method", "fetchAllRegisteredDocumentDiagnostics").
		Msg("finished waiting for goroutines.")

	return processResults(dChan, hoverChan, diagnostics)
}

func workspaceLevelFetch(
	documentURI sglsp.DocumentURI,
	enabledProducts environment.EnabledProducts,
	bundles []*code.BundleImpl,
	wg *sync.WaitGroup,
	dChan chan lsp.DiagnosticResult,
	hoverChan chan lsp.Hover,
) {
	if enabledProducts.Iac {
		wg.Add(1)
		go iac.ScanWorkspace(Cli, documentURI, wg, dChan, hoverChan)
	}
	if enabledProducts.OpenSource {
		wg.Add(1)
		go oss.ScanWorkspace(Cli, documentURI, wg, dChan, hoverChan)
	}
	if enabledProducts.Code {
		registeredDocsMutex.Lock()
		var bundleDocs = registeredDocuments
		registeredDocsMutex.Unlock()
		// we need a pointer to the array of bundle pointers to be able to grow it
		createOrExtendBundles(bundleDocs, &bundles)
		for _, myBundle := range bundles {
			wg.Add(1)
			go myBundle.FetchDiagnosticsData(string(documentURI), wg, dChan, hoverChan)
		}
	}
}

func fileLevelFetch(
	documentURI sglsp.DocumentURI,
	enabledProducts environment.EnabledProducts,
	bundles []*code.BundleImpl,
	wg *sync.WaitGroup,
	dChan chan lsp.DiagnosticResult,
	hoverChan chan lsp.Hover,
) {
	if enabledProducts.Code {
		var bundleDocs = map[sglsp.DocumentURI]bool{}
		bundleDocs[documentURI] = true
		RegisterDocument(sglsp.TextDocumentItem{URI: documentURI})
		createOrExtendBundles(bundleDocs, &bundles)
		wg.Add(1)
		go bundles[0].FetchDiagnosticsData(string(documentURI), wg, dChan, hoverChan)
	}
	if enabledProducts.Iac {
		wg.Add(1)
		go iac.ScanFile(Cli, documentURI, wg, dChan, hoverChan)
	}
	if enabledProducts.OpenSource {
		wg.Add(1)
		go oss.ScanFile(Cli, documentURI, wg, dChan, hoverChan)
	}
}

func processResults(
	dChan chan lsp.DiagnosticResult,
	hoverChan chan lsp.Hover,
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
			diagnosticsMutex.Lock()
			diagnostics[result.Uri] = append(diagnostics[result.Uri], result.Diagnostics...)
			documentDiagnosticCache[result.Uri] = diagnostics[result.Uri]
			diagnosticsMutex.Unlock()

		default: // return results once channels are empty
			log.Debug().
				Str("method", "fetchAllRegisteredDocumentDiagnostics").
				Msg("done reading diags.")

			return diagnostics
		}
	}
}

func createOrExtendBundles(documents map[sglsp.DocumentURI]bool, bundles *[]*code.BundleImpl) {
	// we need a pointer to the array of bundle pointers to be able to grow it
	log.Debug().Str("method", "createOrExtendBundles").Msg("started")
	defer log.Debug().Str("method", "createOrExtendBundles").Msg("done")
	var bundle *code.BundleImpl
	toAdd := documents
	bundleIndex := len(*bundles) - 1
	var bundleFull bool
	for len(toAdd) > 0 {
		if bundleIndex == -1 || bundleFull {
			bundle = createBundle(bundles)
			log.Debug().Int("bundleCount", len(*bundles)).Msg("created new bundle")
		} else {
			bundle = (*bundles)[bundleIndex]
			log.Debug().Int("bundleCount", len(*bundles)).Msg("re-using bundle ")
		}
		toAdd = bundle.AddToBundleDocuments(toAdd).Files
		if len(toAdd) > 0 {
			log.Debug().Int("bundleCount", len(*bundles)).Msgf("File count: %d", len(bundle.BundleDocuments))
			bundleFull = true
		}
	}
}

func createBundle(bundles *[]*code.BundleImpl) *code.BundleImpl {
	bundle := code.BundleImpl{SnykCode: SnykCode}
	*bundles = append(*bundles, &bundle)
	return &bundle
}

func addToCache(diagnostics map[sglsp.DocumentURI][]lsp.Diagnostic) {
	// add all diagnostics to cache
	diagnosticsMutex.Lock()
	for documentURI := range diagnostics {
		documentDiagnosticCache[documentURI] = diagnostics[documentURI]
	}

	diagnosticsMutex.Unlock()
}
