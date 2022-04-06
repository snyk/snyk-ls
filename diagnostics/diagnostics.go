package diagnostics

import (
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
	"github.com/snyk/snyk-ls/util"
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

func getDocAbsolutePath(docUri sglsp.DocumentURI) (string, error) {
	absolutePath, err := filepath.Abs(strings.ReplaceAll(string(docUri), "file://", ""))
	if err != nil {
		return "", err
	}

	log.Debug().Msg("OSS: Absolute Path: " + absolutePath)
	return absolutePath, nil
}

func RegisterAllFilesFromWorkspace(workspaceUri sglsp.DocumentURI) error {
	dir, err := getDocAbsolutePath(workspaceUri)
	if err != nil {
		return err
	}

	return filepath.Walk(dir,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			filePath := "file://" + path

			if info, err := os.Stat(path); err == nil && !info.IsDir() {
				dat, err := os.ReadFile(path)
				if err != nil {
					return err
				}

				log.Info().Msgf("Registering document %v", path)

				mutex.Lock()
				RegisterDocument(sglsp.TextDocumentItem{URI: sglsp.DocumentURI(filePath), Text: string(dat)})
				mutex.Unlock()
			}

			return nil
		})
}

func GetDiagnostics(rootUri sglsp.DocumentURI, level util.ScanLevel) []lsp.Diagnostic {
	// serve from cache
	diagnosticSlice := documentDiagnosticCache[rootUri]
	if len(diagnosticSlice) > 0 {
		return diagnosticSlice
	}

	var diagnostics map[sglsp.DocumentURI][]lsp.Diagnostic
	var codeLenses map[sglsp.DocumentURI][]sglsp.CodeLens

	if level == util.WorkspaceLevel {
		err := RegisterAllFilesFromWorkspace(rootUri)
		if err != nil {
			log.Error().Err(err).Str("method", "GetDiagnostics").Msg("Error occurred while registering files from workspace")
		}

		diagnostics, codeLenses = fetchAllWorkspaceDiagnostics(rootUri)
	} else {
		diagnostics, codeLenses = fetchAllRegisteredDocumentDiagnostics(rootUri)
	}

	// add all diagnostics to cache
	for uri := range diagnostics {
		documentDiagnosticCache[uri] = diagnostics[uri]
	}

	// add all code lenses to cache
	for uri := range codeLenses {
		codeLenseCache[uri] = codeLenses[uri]
	}

	return documentDiagnosticCache[rootUri]
}

func fetchAllWorkspaceDiagnostics(rootUri sglsp.DocumentURI) (map[sglsp.DocumentURI][]lsp.Diagnostic, map[sglsp.DocumentURI][]sglsp.CodeLens) {
	log.Debug().Str("method", "fetchAllWorkspaceDiagnostics").Msg("started.")
	defer log.Info().Str("method", "fetchAllWorkspaceDiagnostics").Msg("done.")

	var diagnostics = map[sglsp.DocumentURI][]lsp.Diagnostic{}
	var codeLenses []sglsp.CodeLens

	createOrExtendBundles(registeredDocuments)
	bundleCount := len(bundles)

	dChan := make(chan lsp.DiagnosticResult, len(registeredDocuments))
	clChan := make(chan lsp.CodeLensResult, len(registeredDocuments))

	wg := sync.WaitGroup{}
	wg.Add(2 + bundleCount)

	for _, myBundle := range bundles {
		log.Info().Msg("bundle")
		go myBundle.FetchDiagnosticsData(string(rootUri), &wg, dChan, clChan)
	}

	go iac.ScanWorkspace(rootUri, &wg, dChan, clChan)
	go oss.ScanWorkspace(rootUri, &wg, dChan, clChan)
	wg.Wait()
	log.Debug().Str("method", "fetchAllWorkspaceDiagnostics").Msg("finished waiting for goroutines.")

	for {
		select {
		case result := <-dChan:
			log.Trace().Str("method", "fetchAllWorkspaceDiagnostics").Str("uri", string(result.Uri)).Msg("reading diag from chan.")
			logError(result.Err, "fetchAllWorkspaceDiagnostics")
			diagnostics[result.Uri] = append(diagnostics[result.Uri], result.Diagnostics...)
			documentDiagnosticCache[result.Uri] = diagnostics[result.Uri]
		case result := <-clChan:
			log.Trace().Str("method", "fetchAllRegisteredDocumentDiagnostics").Str("uri", string(result.Uri)).Msg("reading lens from chan.")
			logError(result.Err, "fetchAllRegisteredDocumentDiagnostics")
			codeLenses = append(codeLenses, result.CodeLenses...)
			codeLenseCache[result.Uri] = codeLenses
		default: // return results once channels are empty
			log.Debug().Str("method", "fetchAllRegisteredDocumentDiagnostics").Msg("done reading diags & lenses.")
			return diagnostics, codeLenseCache
		}
	}
}

func fetchAllRegisteredDocumentDiagnostics(rootUri sglsp.DocumentURI) (map[sglsp.DocumentURI][]lsp.Diagnostic, map[sglsp.DocumentURI][]sglsp.CodeLens) {
	log.Debug().Str("method", "fetchAllRegisteredDocumentDiagnostics").Msg("started.")
	defer log.Debug().Str("method", "fetchAllRegisteredDocumentDiagnostics").Msg("done.")
	var diagnostics = map[sglsp.DocumentURI][]lsp.Diagnostic{}
	var codeLenses []sglsp.CodeLens

	wg := sync.WaitGroup{}
	dChan := make(chan lsp.DiagnosticResult, len(registeredDocuments))
	clChan := make(chan lsp.CodeLensResult, len(registeredDocuments))

	createOrExtendBundles(registeredDocuments)

	bundleCount := len(bundles)
	wg.Add(2 + bundleCount)

	for _, myBundle := range bundles {
		log.Info().Msg("bundle")
		go myBundle.FetchDiagnosticsData(string(rootUri), &wg, dChan, clChan)
	}

	go iac.ScanFile(rootUri, &wg, dChan, clChan)
	go oss.ScanFile(registeredDocuments[rootUri], &wg, dChan, clChan)
	wg.Wait()
	log.Debug().Str("method", "fetchAllRegisteredDocumentDiagnostics").Msg("finished waiting for goroutines.")

	for {
		select {
		case result := <-dChan:
			log.Trace().Str("method", "fetchAllRegisteredDocumentDiagnostics").Str("uri", string(result.Uri)).Msg("reading diag from chan.")
			logError(result.Err, "fetchAllRegisteredDocumentDiagnostics")
			diagnostics[result.Uri] = append(diagnostics[result.Uri], result.Diagnostics...)
			documentDiagnosticCache[result.Uri] = diagnostics[result.Uri]
		case result := <-clChan:
			log.Trace().Str("method", "fetchAllRegisteredDocumentDiagnostics").Str("uri", string(result.Uri)).Msg("reading lens from chan.")
			logError(result.Err, "fetchAllRegisteredDocumentDiagnostics")
			codeLenses = append(codeLenses, result.CodeLenses...)
			codeLenseCache[result.Uri] = codeLenses
		default: // return results once channels are empty
			log.Debug().Str("method", "fetchAllRegisteredDocumentDiagnostics").Msg("done reading diags & lenses.")
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

func logError(err error, method string) {
	if err != nil {
		log.Err(err).Str("method", method)
	}
}
