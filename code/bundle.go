package code

import (
	"path/filepath"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/config/environment"
	"github.com/snyk/snyk-ls/lsp"
	"github.com/snyk/snyk-ls/util"
)

var (
	// TODO get via filters request [ROAD-803]
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
	jsonOverheadRequest = "{\"files\":{}}"
	jsonUriOverhead     = "\"\":{}"
	jsonHashSizePerFile = "\"hash\":\"0123456789012345678901234567890123456789012345678901234567890123\""
	jsonContentOverhead = ",\"content\":\"\""
	jsonOverheadPerFile = jsonUriOverhead + jsonContentOverhead
)

func getTotalDocPayloadSize(uri sglsp.DocumentURI, file File) int {
	return len(jsonHashSizePerFile) + len(jsonOverheadPerFile) + len([]byte(uri)) + len([]byte(file.Content))
}

type BundleImpl struct {
	SnykCode        SnykCodeService
	BundleHash      string
	BundleDocuments map[sglsp.DocumentURI]File
	missingFiles    []sglsp.DocumentURI
}

type FilesNotAdded struct {
	Files map[sglsp.DocumentURI]sglsp.TextDocumentItem
}

type SnykAnalysisTimeoutError struct {
	msg string
}

func (e SnykAnalysisTimeoutError) Error() string {
	return e.msg
}

func (b *BundleImpl) createBundleFromSource() error {
	var err error
	if len(b.BundleDocuments) > 0 {
		b.BundleHash, b.missingFiles, err = b.SnykCode.CreateBundle(b.BundleDocuments)
		log.Trace().Str("method", "createBundleFromSource").Str("bundleHash", b.BundleHash).Msg("created bundle on backend")
	}
	return err
}

func (b *BundleImpl) AddToBundleDocuments(files map[sglsp.DocumentURI]sglsp.TextDocumentItem) FilesNotAdded {
	if b.BundleDocuments == nil {
		b.BundleDocuments = make(map[sglsp.DocumentURI]File)
	}

	var nonAddedFiles = make(map[sglsp.DocumentURI]sglsp.TextDocumentItem)

	for _, doc := range files {
		if !extensions[filepath.Ext(string(doc.URI))] || !(len(doc.Text) > 0 && len(doc.Text) <= maxFileSize) {
			continue
		}

		file := b.getFileFrom(doc)
		if b.canAdd(doc) {
			log.Trace().Str("uri", string(doc.URI)).Str("bundle", b.BundleHash).Msg("added to bundle")
			b.BundleDocuments[doc.URI] = file
			continue
		}

		log.Trace().Str("uri", string(doc.URI)).Str("bundle", b.BundleHash).Msg("not added to bundle")
		nonAddedFiles[doc.URI] = doc
	}

	if len(nonAddedFiles) > 0 {
		return FilesNotAdded{Files: nonAddedFiles}
	}

	return FilesNotAdded{}
}

func (b *BundleImpl) getFileFrom(doc sglsp.TextDocumentItem) File {
	return File{
		Hash:    util.Hash(doc.Text),
		Content: doc.Text,
	}
}

func (b *BundleImpl) canAdd(doc sglsp.TextDocumentItem) bool {
	return getTotalDocPayloadSize(doc.URI, b.getFileFrom(doc))+b.getSize() < maxBundleSize
}

func (b *BundleImpl) extendBundleFromSource() error {
	var removeFiles []sglsp.DocumentURI
	var err error

	if len(b.BundleDocuments) > 0 {
		b.BundleHash, b.missingFiles, err = b.SnykCode.ExtendBundle(b.BundleHash, b.BundleDocuments, removeFiles)
		log.Trace().Str("method", "extendBundleFromSource").Str("bundleHash", b.BundleHash).Msg("extended bundle on backend")
	}
	return err
}

func (b *BundleImpl) DiagnosticData(
	wg *sync.WaitGroup,
	dChan chan lsp.DiagnosticResult,
	clChan chan lsp.CodeLensResult,
) {
	defer wg.Done()
	defer log.Debug().Str("method", "DiagnosticData").Msg("done.")

	log.Debug().Str("method", "DiagnosticData").Msg("started.")

	err := b.uploadDocuments()
	if err != nil {
		log.Error().Err(err).Str("method", "DiagnosticData").Msg("error creating/extending bundle...")
		dChan <- lsp.DiagnosticResult{Err: err}
		return
	}

	b.retrieveAnalysis(dChan, clChan)
}

func (b *BundleImpl) retrieveAnalysis(dChan chan lsp.DiagnosticResult, clChan chan lsp.CodeLensResult) {
	if len(b.BundleDocuments) > 0 {
		for {
			start := time.Now()
			diags, lenses, status, err := b.SnykCode.RunAnalysis(b.BundleHash, []sglsp.DocumentURI{}, 0)
			if err != nil {
				log.Error().Err(err).Str("method", "DiagnosticData").Msg("error retrieving diagnostics...")
				dChan <- lsp.DiagnosticResult{Err: err}
				return
			}

			if status == "COMPLETE" {
				for u, d := range diags {
					log.Trace().Str("method", "retrieveAnalysis").Str("bundleHash", b.BundleHash).Str("uri", string(u)).Msg("sending diagnostics...")
					dChan <- lsp.DiagnosticResult{
						Uri:         u,
						Diagnostics: d,
						Err:         err,
					}
				}

				for u, l := range lenses {
					log.Trace().Str("method", "retrieveAnalysis").Str("bundleHash", b.BundleHash).Str("uri", string(u)).Msg("sending code lenses...")
					clChan <- lsp.CodeLensResult{
						Uri:        u,
						CodeLenses: l,
						Err:        err,
					}
				}
				return
			}
			if time.Since(start) > environment.SnykCodeTimeout() {
				err = SnykAnalysisTimeoutError{msg: "Analysis Call Timed out."}
				log.Error().Err(err).Str("method", "DiagnosticData").Msg("timeout...")
				dChan <- lsp.DiagnosticResult{Err: err}
			}
			time.Sleep(1 * time.Second)
		}
	}
}

func (b *BundleImpl) uploadDocuments() error {
	if b.BundleHash == "" {
		return b.createBundleFromSource()
	}

	return b.extendBundleFromSource()
}

func (b *BundleImpl) getSize() int {
	if len(b.BundleDocuments) == 0 {
		return 0
	}
	jsonCommasForFiles := len(b.BundleDocuments) - 1
	var size = jsonOverheadRequest + jsonCommasForFiles // if more than one file, they are separated by commas in the req
	for uri, file := range b.BundleDocuments {
		size += getTotalDocPayloadSize(uri, file)
	}
	return size
}
