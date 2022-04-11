package diagnostics

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/code"
	"github.com/snyk/snyk-ls/iac"
	"github.com/snyk/snyk-ls/lsp"
	"github.com/snyk/snyk-ls/oss"
)

var (
	registeredDocuments     = map[sglsp.DocumentURI]sglsp.TextDocumentItem{}
	documentDiagnosticCache = map[sglsp.DocumentURI][]lsp.Diagnostic{}
	bundles                 []*code.BundleImpl
	SnykCode                code.SnykCodeService
	mutex                   = &sync.Mutex{}
)

func ClearDiagnosticsCache(uri sglsp.DocumentURI) {
	delete(documentDiagnosticCache, uri)
}

func UpdateDocument(uri sglsp.DocumentURI, changes []sglsp.TextDocumentContentChangeEvent) {
	file := registeredDocuments[uri]
	for i := range changes {
		change := changes[i]
		file.Text = change.Text
	}
	registeredDocuments[uri] = file
}

func RegisterDocument(file sglsp.TextDocumentItem) {
	registeredDocuments[file.URI] = file
}

func UnRegisterDocument(file sglsp.DocumentURI) {
	delete(registeredDocuments, file)
}

func registerAllFilesFromWorkspace(workspaceUri sglsp.DocumentURI) error {
	workspace, err := filepath.Abs(strings.ReplaceAll(
		string(workspaceUri),
		"file://", ""),
	)

	if err != nil {
		return err
	}

	return filepath.Walk(workspace, func(path string, info fs.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}

		content, _ := os.ReadFile(path)
		file := sglsp.TextDocumentItem{
			URI:  sglsp.DocumentURI("file://" + path),
			Text: string(content),
		}

		mutex.Lock()
		RegisterDocument(file)
		mutex.Unlock()

		return err
	})
}

func workspaceDiagnostics(workspaceUri sglsp.DocumentURI, wg *sync.WaitGroup) {
	defer wg.Done()

	var diagnostics map[sglsp.DocumentURI][]lsp.Diagnostic
	var codeLenses map[sglsp.DocumentURI][]sglsp.CodeLens

	err := registerAllFilesFromWorkspace(workspaceUri)
	if err != nil {
		log.Error().Err(err).
			Str("method", "workspaceDiagnostics").
			Msg("Error occurred while registering files from workspace")
	}

	diagnostics, codeLenses = fetchAllRegisteredDocumentDiagnostics(workspaceUri, ScanWorkspace)
	addToCache(diagnostics, codeLenses)
}

func Workspace(workspaceFolders []lsp.WorkspaceFolders) {
	var wg sync.WaitGroup

	for _, workspace := range workspaceFolders {
		wg.Add(1)
		go workspaceDiagnostics(workspace.Uri, &wg)
	}

	wg.Wait()
	log.Info().Str("method", "Workspace").
		Msg("Workspace scan completed")
}

func GetDiagnostics(rootUri sglsp.DocumentURI) []lsp.Diagnostic {
	// serve from cache
	diagnosticSlice := documentDiagnosticCache[rootUri]
	if len(diagnosticSlice) > 0 {
		log.Info().Str("method", "GetDiagnostics").
			Msgf("Cached: Diagnostics for %s", rootUri)

		return diagnosticSlice
	}

	var diagnostics map[sglsp.DocumentURI][]lsp.Diagnostic
	var codeLenses map[sglsp.DocumentURI][]sglsp.CodeLens

	diagnostics, codeLenses = fetchAllRegisteredDocumentDiagnostics(rootUri, ScanFile)
	addToCache(diagnostics, codeLenses)

	return documentDiagnosticCache[rootUri]
}

func fetchAllRegisteredDocumentDiagnostics(rootUri sglsp.DocumentURI, level ScanLevel) (map[sglsp.DocumentURI][]lsp.Diagnostic, map[sglsp.DocumentURI][]sglsp.CodeLens) {
	log.Info().
		Str("method", "fetchAllRegisteredDocumentDiagnostics").
		Msg("started.")

	defer log.Info().
		Str("method", "fetchAllRegisteredDocumentDiagnostics").
		Msg("done.")

	var diagnostics = map[sglsp.DocumentURI][]lsp.Diagnostic{}
	var codeLenses []sglsp.CodeLens

	createOrExtendBundles(registeredDocuments)

	wg := sync.WaitGroup{}
	bundleCount := len(bundles)
	wg.Add(2 + bundleCount)

	dChan := make(chan lsp.DiagnosticResult, len(registeredDocuments))
	clChan := make(chan lsp.CodeLensResult, len(registeredDocuments))

	for _, myBundle := range bundles {
		go myBundle.FetchDiagnosticsData(string(rootUri), &wg, dChan, clChan)
	}

	if level == ScanWorkspace {
		go iac.ScanWorkspace(rootUri, &wg, dChan, clChan)
		go oss.ScanWorkspace(rootUri, &wg, dChan, clChan)
	} else {
		go iac.ScanFile(rootUri, &wg, dChan, clChan)
		go oss.ScanFile(registeredDocuments[rootUri], &wg, dChan, clChan)
	}

	wg.Wait()
	log.Debug().
		Str("method", "fetchAllRegisteredDocumentDiagnostics").
		Msg("finished waiting for goroutines.")

	for {
		select {
		case result := <-dChan:
			log.Trace().
				Str("method", "fetchAllRegisteredDocumentDiagnostics").
				Str("uri", string(result.Uri)).
				Msg("reading diag from chan.")

			logError(result.Err, "fetchAllRegisteredDocumentDiagnostics")

			diagnostics[result.Uri] = append(diagnostics[result.Uri], result.Diagnostics...)
			documentDiagnosticCache[result.Uri] = diagnostics[result.Uri]

		case result := <-clChan:
			log.Trace().
				Str("method", "fetchAllRegisteredDocumentDiagnostics").
				Str("uri", string(result.Uri)).
				Msg("reading lens from chan.")

			logError(result.Err, "fetchAllRegisteredDocumentDiagnostics")

			codeLenses = append(codeLenses, result.CodeLenses...)
			codeLenseCache[result.Uri] = codeLenses

		default: // return results once channels are empty
			log.Debug().
				Str("method", "fetchAllRegisteredDocumentDiagnostics").
				Msg("done reading diags & lenses.")

			return diagnostics, codeLenseCache
		}
	}
}

func createOrExtendBundles(documents map[sglsp.DocumentURI]sglsp.TextDocumentItem) {
	var bundle *code.BundleImpl
	toAdd := documents
	bundleIndex := len(bundles) - 1
	var bundleFull bool
	for len(toAdd) > 0 {
		if bundleIndex == -1 || bundleFull {
			bundle = createBundle()
			log.Debug().Int("bundleCount", len(bundles)).Str("bundle", bundle.BundleHash).Msg("created new bundle")
		} else {
			bundle = bundles[bundleIndex]
			log.Debug().Int("bundleCount", len(bundles)).Str("bundle", bundle.BundleHash).Msg("re-using bundle ")
		}
		toAdd = bundle.AddToBundleDocuments(toAdd).Files
		if len(toAdd) > 0 {
			bundleFull = true
		}
	}
}

func createBundle() *code.BundleImpl {
	bundle := code.BundleImpl{SnykCode: SnykCode}
	bundles = append(bundles, &bundle)
	return &bundle
}

func addToCache(diagnostics map[sglsp.DocumentURI][]lsp.Diagnostic, codeLenses map[sglsp.DocumentURI][]sglsp.CodeLens) {
	// add all diagnostics to cache
	for uri := range diagnostics {
		documentDiagnosticCache[uri] = diagnostics[uri]
	}

	// add all code lenses to cache
	for uri := range codeLenses {
		codeLenseCache[uri] = codeLenses[uri]
	}
}

func logError(err error, method string) {
	if err != nil {
		log.Err(err).Str("method", method)
	}
}
