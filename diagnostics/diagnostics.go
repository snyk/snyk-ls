package diagnostics

import (
	"context"
	"fmt"
	"sync"

	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/code"
	"github.com/snyk/snyk-ls/config/environment"
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

const snykCodeServiceKey = "service"

var (
	registeredDocuments     concurrency.AtomicMap
	documentDiagnosticCache concurrency.AtomicMap
	snykCode                concurrency.AtomicMap
	Cli                     cli.Executor
	logger                  = environment.Logger
)

func init() {
	registeredDocuments = concurrency.AtomicMap{}
	documentDiagnosticCache = concurrency.AtomicMap{}
	snykCode = concurrency.AtomicMap{}
	Cli = cli.SnykCli{}
}

func SnykCode() code.SnykCodeService {
	var sc code.SnykCodeService
	if snykCode.Contains(snykCodeServiceKey) {
		sc = snykCode.Get(snykCodeServiceKey).(code.SnykCodeService)
	}
	return sc
}

func SetSnykCodeService(service code.SnykCodeService) {
	snykCode.Put(snykCodeServiceKey, service)
}

func ClearSnykCodeService() {
	snykCode.ClearAll()
}

func ClearDiagnosticsCache(documentURI sglsp.DocumentURI) {
	documentDiagnosticCache.Delete(documentURI)
}

func ClearWorkspaceFolderDiagnostics(ctx context.Context, folder lsp.WorkspaceFolder) {
	f := func(u interface{}, value interface{}) bool {
		path := uri.PathFromUri(u.(sglsp.DocumentURI))
		folderPath := uri.PathFromUri(folder.Uri)
		if uri.FolderContains(folderPath, path) {
			documentDiagnosticCache.Delete(u)
			logger.
				WithField("method", "ClearWorkspaceFolderDiagnostics").
				WithField("path", path).
				WithField("workspaceFolder", folderPath).
				Debug(ctx, "Cleared diagnostics")
		}
		return true
	}
	documentDiagnosticCache.Range(f)
	removeFolderFromScanned(folder)
	logger.
		WithField("method", "ClearWorkspaceFolderDiagnostics").
		WithField("workspaceFolder", folder.Uri).
		Debug(ctx, "Removed")
}

func ClearEntireDiagnosticsCache() {
	documentDiagnosticCache.ClearAll()
}

func ClearRegisteredDocuments() {
	registeredDocuments.ClearAll()
}

func RegisterDocument(file sglsp.TextDocumentItem) {
	documentURI := file.URI
	if !(code.IsSupported(documentURI) ||
		iac.IsSupported(documentURI) ||
		oss.IsSupported(documentURI)) {
		return
	}
	registeredDocuments.Put(documentURI, true)
}

func UnRegisterDocument(file sglsp.DocumentURI) {
	registeredDocuments.Delete(file)
}

func DocumentDiagnosticsFromCache(file sglsp.DocumentURI) []lsp.Diagnostic {
	diagnostics := documentDiagnosticCache.Get(file)
	if diagnostics == nil {
		return nil
	}
	return diagnostics.([]lsp.Diagnostic)
}

func GetDiagnostics(ctx context.Context, documentURI sglsp.DocumentURI) []lsp.Diagnostic {
	// serve from cache
	diagnosticSlice := DocumentDiagnosticsFromCache(documentURI)
	if len(diagnosticSlice) > 0 {
		logger.
			WithField("method", "GetDiagnostics").
			WithField("documentURI", documentURI).
			Debug(ctx, "Cached diagnostics found")
		return diagnosticSlice
	}

	diagnostics := fetchAllRegisteredDocumentDiagnostics(context.Background(), documentURI, lsp.ScanLevelFile)
	addToCache(diagnostics)
	cache := DocumentDiagnosticsFromCache(documentURI)
	return cache
}

func fetchAllRegisteredDocumentDiagnostics(
	ctx context.Context,
	documentURI sglsp.DocumentURI,
	level lsp.ScanLevel,
) map[sglsp.DocumentURI][]lsp.Diagnostic {

	logger.
		WithField("method", "fetchAllRegisteredDocumentDiagnostics").
		WithField("documentURI", documentURI).
		Info(ctx, "started")

	defer logger.
		WithField("method", "fetchAllRegisteredDocumentDiagnostics").
		WithField("documentURI", documentURI).
		Info(ctx, "done")

	var diagnostics = map[sglsp.DocumentURI][]lsp.Diagnostic{}
	var bundles = make([]*code.BundleImpl, 0, 10)

	p := progress.New(fmt.Sprintf("Scanning for issues in %s", uri.PathFromUri(documentURI)), "", false)
	progress.BeginProgress(p, progress.Channel)
	defer progress.EndProgress(p.Token, fmt.Sprintf("Scan complete. Found %d issues.", len(diagnostics)), progress.Channel)

	wg := sync.WaitGroup{}

	var dChan chan lsp.DiagnosticResult
	hoverChan := hover.Channel()

	if level == lsp.ScanLevelWorkspace {
		dChan = make(chan lsp.DiagnosticResult, 10000)
		workspaceLevelFetch(ctx, documentURI, environment.CurrentEnabledProducts, bundles, &wg, dChan, hoverChan)
	} else {
		dChan = make(chan lsp.DiagnosticResult, 10000)
		fileLevelFetch(ctx, documentURI, environment.CurrentEnabledProducts, bundles, &wg, dChan, hoverChan)
	}
	progress.ReportProgress(p.Token, 50, progress.Channel)
	wg.Wait()

	logger.
		WithField("method", "fetchAllRegisteredDocumentDiagnostics").
		WithField("documentURI", documentURI).
		Debug(ctx, "finished waiting for goroutines")

	return processResults(ctx, dChan, diagnostics)
}

func workspaceLevelFetch(
	ctx context.Context,
	documentURI sglsp.DocumentURI,
	enabledProducts environment.EnabledProducts,
	bundles []*code.BundleImpl,
	wg *sync.WaitGroup,
	dChan chan lsp.DiagnosticResult,
	hoverChan chan lsp.Hover,
) {
	if enabledProducts.Iac.Get() {
		wg.Add(1)
		go iac.ScanWorkspace(ctx, Cli, documentURI, wg, dChan, hoverChan)
	}
	if enabledProducts.OpenSource.Get() {
		wg.Add(1)
		go oss.ScanWorkspace(ctx, Cli, documentURI, wg, dChan, hoverChan)
	}
	if enabledProducts.Code.Get() {
		var bundleDocs = ToDocumentURIMap(&registeredDocuments)
		// we need a pointer to the array of bundle pointers to be able to grow it
		createOrExtendBundles(ctx, bundleDocs, &bundles)
		for _, myBundle := range bundles {
			wg.Add(1)
			go myBundle.FetchDiagnosticsData(ctx, string(documentURI), wg, dChan, hoverChan)
		}
	}
}

// ToDocumentURIMap Copies the atomic map over to a typed map
func ToDocumentURIMap(input *concurrency.AtomicMap) map[sglsp.DocumentURI]bool {
	output := map[sglsp.DocumentURI]bool{}
	f := func(key interface{}, value interface{}) bool {
		output[key.(sglsp.DocumentURI)] = value.(bool)
		return true
	}
	input.Range(f)
	return output
}

func fileLevelFetch(
	ctx context.Context,
	documentURI sglsp.DocumentURI,
	enabledProducts environment.EnabledProducts,
	bundles []*code.BundleImpl,
	wg *sync.WaitGroup,
	dChan chan lsp.DiagnosticResult,
	hoverChan chan lsp.Hover,
) {
	if enabledProducts.Code.Get() {
		var bundleDocs = map[sglsp.DocumentURI]bool{}
		bundleDocs[documentURI] = true
		RegisterDocument(sglsp.TextDocumentItem{URI: documentURI})
		createOrExtendBundles(ctx, bundleDocs, &bundles)
		wg.Add(1)
		go bundles[0].FetchDiagnosticsData(ctx, string(documentURI), wg, dChan, hoverChan)
	}
	if enabledProducts.Iac.Get() {
		wg.Add(1)
		go iac.ScanFile(ctx, Cli, documentURI, wg, dChan, hoverChan)
	}
	if enabledProducts.OpenSource.Get() {
		wg.Add(1)
		go oss.ScanFile(ctx, Cli, documentURI, wg, dChan, hoverChan)
	}
}

func processResults(
	ctx context.Context,
	dChan chan lsp.DiagnosticResult,
	diagnostics map[sglsp.DocumentURI][]lsp.Diagnostic,
) map[sglsp.DocumentURI][]lsp.Diagnostic {
	for {
		select {
		case result := <-dChan:
			logger.
				WithField("method", "processResults").
				WithField("documentURI", string(result.Uri)).
				Trace(ctx, "reading diag from chan.")

			if result.Err != nil {
				logger.
					WithField("method", "processResults").
					WithField("documentURI", string(result.Uri)).
					WithError(result.Err).
					Error(ctx, "started")
				error_reporting.CaptureError(result.Err)
				break
			}
			diagnostics[result.Uri] = append(diagnostics[result.Uri], result.Diagnostics...)
			documentDiagnosticCache.Put(result.Uri, diagnostics)

		default: // return results once channels are empty
			logger.
				WithField("method", "processResults").
				Debug(ctx, "done reading diagnostics")

			return diagnostics
		}
	}
}

func createOrExtendBundles(ctx context.Context, documents map[sglsp.DocumentURI]bool, bundles *[]*code.BundleImpl) {
	// we need a pointer to the array of bundle pointers to be able to grow it
	logger.WithField("method", "createOrExtendBundles").Info(ctx, "started")
	defer logger.WithField("method", "createOrExtendBundles").Info(ctx, "done")

	var bundle *code.BundleImpl
	toAdd := documents
	bundleIndex := len(*bundles) - 1
	var bundleFull bool
	for len(toAdd) > 0 {
		if bundleIndex == -1 || bundleFull {
			bundle = createBundle(bundles)
			logger.WithField("method", "createOrExtendBundles").
				WithField("bundleCount", len(*bundles)).
				Debug(ctx, "created new bundle")
		} else {
			bundle = (*bundles)[bundleIndex]
			logger.WithField("method", "createOrExtendBundles").
				WithField("bundleCount", len(*bundles)).
				Debug(ctx, "extending bundle")
		}
		toAdd = bundle.AddToBundleDocuments(ctx, toAdd).Files
		if len(toAdd) > 0 {
			logger.WithField("method", "createOrExtendBundles").
				WithField("bundleCount", len(*bundles)).
				WithField("fileCount", len(bundle.BundleDocuments)).
				Debug(ctx, "filled up bundle")
			bundleFull = true
		}
	}
}

func createBundle(bundles *[]*code.BundleImpl) *code.BundleImpl {
	bundle := code.BundleImpl{SnykCode: SnykCode()}
	*bundles = append(*bundles, &bundle)
	return &bundle
}

func addToCache(diagnostics map[sglsp.DocumentURI][]lsp.Diagnostic) {
	// add all diagnostics to cache
	for documentURI := range diagnostics {
		documentDiagnosticCache.Put(documentURI, diagnostics[documentURI])
	}
}
