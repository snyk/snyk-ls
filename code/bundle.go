package code

import (
	"path/filepath"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/lsp"
	"github.com/snyk/snyk-ls/util"
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
		".kt":    true,
		".kts":   true,
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

const (
	maxFileSize         = 1024 * 128
	maxBundleSize       = 1024 * 1024 * 4
	jsonOverheadRequest = len("{\"files\":{}}")
	jsonUriOverhead     = len("\"\":{}")
	jsonHashSizePerFile = len("\"hash\":\"0123456789012345678901234567890123456789012345678901234567890123\"")
	jsonContentOverhead = len(",\"content\":\"\"")
	jsonOverheadPerFile = jsonUriOverhead + jsonContentOverhead
)

type BundleImpl struct {
	Backend         BackendService
	bundleHash      string
	bundleDocuments map[sglsp.DocumentURI]File
	missingFiles    []sglsp.DocumentURI
}

type FilesNotAdded struct {
	bundle *BundleImpl
	files  map[sglsp.DocumentURI]sglsp.TextDocumentItem
}

type SnykAnalysisTimeoutError struct {
	msg string
}

func (e SnykAnalysisTimeoutError) Error() string {
	return e.msg
}

func (b *BundleImpl) createBundleFromSource() error {
	var err error
	if len(b.bundleDocuments) > 0 {
		b.bundleHash, b.missingFiles, err = b.Backend.CreateBundle(b.bundleDocuments)
	}
	return err
}

func (b *BundleImpl) addToBundleDocuments(files map[sglsp.DocumentURI]sglsp.TextDocumentItem) FilesNotAdded {
	if b.bundleDocuments == nil {
		b.bundleDocuments = make(map[sglsp.DocumentURI]File)
	}

	var nonAddedFiles = make(map[sglsp.DocumentURI]sglsp.TextDocumentItem)
	for _, doc := range files {
		if extensions[filepath.Ext(string(doc.URI))] {
			if len(doc.Text) > 0 && len(doc.Text) <= maxFileSize {
				file := b.getFileFrom(doc)
				if b.canAdd(doc) {
					log.Debug().Str("uri", string(doc.URI)).Str("bundle", b.bundleHash).Msg("added to bundle")
					b.bundleDocuments[doc.URI] = file
				} else {
					log.Debug().Str("uri", string(doc.URI)).Str("bundle", b.bundleHash).Msg("not added to bundle")
					nonAddedFiles[doc.URI] = doc
				}
			}
		}
	}
	if len(nonAddedFiles) > 0 {
		return FilesNotAdded{bundle: b, files: nonAddedFiles}
	} else {
		return FilesNotAdded{}
	}
}

func (b *BundleImpl) getFileFrom(doc sglsp.TextDocumentItem) File {
	return File{
		Hash:    util.Hash(doc.Text),
		Content: doc.Text,
	}
}

func (b *BundleImpl) canAdd(doc sglsp.TextDocumentItem) bool {
	return b.getTotalDocPayloadSize(doc.URI, b.getFileFrom(doc))+b.getSize() < maxBundleSize
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

	filesNotAdded := b.addToBundleDocuments(registeredDocuments)
	if filesNotAdded.files != nil {
		return // TODO bundle split!
	}

	if b.bundleHash == "" {
		err := b.createBundleFromSource()
		if err != nil {
			log.Error().Err(err).Str("method", "DiagnosticData").Msg("error while creating bundle...")
			dChan <- lsp.DiagnosticResult{Err: err}
			return
		}
	} else {
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

func (b *BundleImpl) getSize() int {
	if len(b.bundleDocuments) == 0 {
		return 0
	}
	jsonCommasForFiles := len(b.bundleDocuments) - 1
	var size = jsonOverheadRequest + jsonCommasForFiles // if more than one file, they are separated by commas in the req
	for uri, file := range b.bundleDocuments {
		size += b.getTotalDocPayloadSize(uri, file)
	}
	return size
}

func (b *BundleImpl) getTotalDocPayloadSize(uri sglsp.DocumentURI, file File) int {
	return jsonHashSizePerFile + jsonOverheadPerFile + len([]byte(uri)) + len([]byte(file.Content))
}
