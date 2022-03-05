package code

import (
	"path/filepath"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-lsp/lsp"
	"github.com/snyk/snyk-lsp/util"
)

var (
	// TODO get via filters request
	// extensions":[".java",".aspx",".cs",".cls",".ejs",".es",".es6",".htm",".html",".js",".jsx",".ts",".tsx",".vue",".py",".erb",".haml",".rb",".rhtml",".slim",".go",".c",".cc",".cpp",".cxx",".h",".hpp",".hxx",".php",".phtml"]
	extensions = map[string]bool{
		".java":  true,
		".aspx":  true,
		".cs":    true,
		".cls":   true,
		".ejs":   true,
		".es":    true,
		".es6":   true,
		".htm":   true,
		".html":  true,
		".js":    true,
		".jsx":   true,
		".ts":    true,
		".tsx":   true,
		".vue":   true,
		".py":    true,
		".erb":   true,
		".haml":  true,
		".rb":    true,
		".rhtml": true,
		".slim":  true,
		".go":    true,
		".c":     true,
		".cc":    true,
		".cpp":   true,
		".cxx":   true,
		".h":     true,
		".hpp":   true,
		".hxx":   true,
		".php":   true,
		".phtml": true,
	}
)

type BundleImpl struct {
	Backend         BackendService
	bundleHash      string
	bundleDocuments map[sglsp.DocumentURI]File
	missingFiles    []sglsp.DocumentURI
}

type SnykAnalysisTimeoutError struct {
	msg string
}

func (e SnykAnalysisTimeoutError) Error() string {
	return e.msg
}

func (b *BundleImpl) createBundleFromSource(files map[sglsp.DocumentURI]sglsp.TextDocumentItem) error {
	b.addToBundleDocuments(files)
	var err error
	if len(b.bundleDocuments) > 0 {
		b.bundleHash, b.missingFiles, err = b.Backend.CreateBundle(b.bundleDocuments)
	}
	return err
}

func (b *BundleImpl) addToBundleDocuments(files map[sglsp.DocumentURI]sglsp.TextDocumentItem) {
	if b.bundleDocuments == nil {
		b.bundleDocuments = make(map[sglsp.DocumentURI]File)
	}
	for uri, doc := range files {
		if extensions[filepath.Ext(string(uri))] {
			const maxFileSize = 1024*4096 - 1000 // 4MB, -1000 just to be safe
			if (b.bundleDocuments[uri] == File{} && len(doc.Text) > 0 && len(doc.Text) < maxFileSize) {
				b.bundleDocuments[uri] = File{
					Hash:    util.Hash(doc.Text),
					Content: doc.Text,
				}
			}
		}
	}
}

func (b *BundleImpl) extendBundleFromSource(files map[sglsp.DocumentURI]sglsp.TextDocumentItem) error {
	var err error
	b.addToBundleDocuments(files)
	var removeFiles []sglsp.DocumentURI
	// todo determine which files to change
	if len(b.bundleDocuments) > 0 {
		b.bundleHash, b.missingFiles, err = b.Backend.ExtendBundle(b.bundleHash, b.bundleDocuments, removeFiles)
	}
	return err
}

func (b *BundleImpl) DiagnosticData(
	registeredDocuments map[sglsp.DocumentURI]sglsp.TextDocumentItem,
	wg *sync.WaitGroup,
	dChan chan lsp.DiagnosticResult,
	clChan chan lsp.CodeLensResult,
) {
	defer wg.Done()
	defer log.Debug().Str("method", "DiagnosticData").Msg("done.")
	log.Debug().Str("method", "DiagnosticData").Msg("started.")
	var err error

	if b.bundleHash == "" {
		// we don't have missing files, as we're creating from source
		err = b.createBundleFromSource(registeredDocuments)
		if err != nil {
			log.Error().Err(err).Str("method", "DiagnosticData").Msg("error while creating bundle...")
			dChan <- lsp.DiagnosticResult{Err: err}
			return
		}
	} else {
		// we don't have missing files, as we're creating from source
		err := b.extendBundleFromSource(registeredDocuments)
		if err != nil {
			log.Error().Err(err).Str("method", "DiagnosticData").Msg("error extending bundle...")
			dChan <- lsp.DiagnosticResult{Err: err}
			return
		}
	}

	if len(b.bundleDocuments) > 0 {
		for {
			start := time.Now()
			diags, lenses, status, err := b.Backend.RetrieveDiagnostics(b.bundleHash, []sglsp.DocumentURI{}, 0)
			if err != nil {
				log.Error().Err(err).Str("method", "DiagnosticData").Msg("error retrieving diagnostics...")
				dChan <- lsp.DiagnosticResult{Err: err}
				return
			}

			if status == "COMPLETE" {
				for u, d := range diags {
					log.Debug().Str("method", "DiagnosticData").Msg("sending diagnostics...")
					dChan <- lsp.DiagnosticResult{
						Uri:         u,
						Diagnostics: d,
						Err:         err,
					}
				}

				for u, l := range lenses {
					log.Debug().Str("method", "DiagnosticData").Msg("sending code lenses...")
					clChan <- lsp.CodeLensResult{
						Uri:        u,
						CodeLenses: l,
						Err:        err,
					}
				}
				return
			}
			if time.Since(start) > 120*time.Second {
				err = SnykAnalysisTimeoutError{msg: "Analysis Call Timed out."}
				log.Error().Err(err).Str("method", "DiagnosticData").Msg("timeout...")
				dChan <- lsp.DiagnosticResult{Err: err}
			}
			time.Sleep(1 * time.Second)
		}
	}
}
