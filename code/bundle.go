package code

import (
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/config/environment"
	"github.com/snyk/snyk-ls/internal/uri"
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
	maxFileSize         = 1024 * 1024
	maxBundleSize       = 1024 * 1024 * 4
	jsonOverheadRequest = "{\"files\":{}}"
	jsonUriOverhead     = "\"\":{}"
	jsonHashSizePerFile = "\"hash\":\"0123456789012345678901234567890123456789012345678901234567890123\""
	jsonContentOverhead = ",\"content\":\"\""
	jsonOverheadPerFile = jsonUriOverhead + jsonContentOverhead
)

func getTotalDocPayloadSize(uri string, content []byte) int {
	return len(jsonHashSizePerFile) + len(jsonOverheadPerFile) + len([]byte(uri)) + len(content)
}

type BundleImpl struct {
	SnykCode        SnykCodeService
	BundleHash      string
	BundleDocuments map[sglsp.DocumentURI]File
	missingFiles    []sglsp.DocumentURI
}

type FilesNotAdded struct {
	Files map[sglsp.DocumentURI]bool
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

func (b *BundleImpl) AddToBundleDocuments(files map[sglsp.DocumentURI]bool) FilesNotAdded {
	if b.BundleDocuments == nil {
		b.BundleDocuments = make(map[sglsp.DocumentURI]File)
	}

	var nonAddedFiles = make(map[sglsp.DocumentURI]bool)
	for documentURI := range files {
		if !extensions[filepath.Ext(string(documentURI))] {
			continue
		}

		path := uri.PathFromUri(documentURI)
		fileContent, err := os.ReadFile(path)
		if err != nil {
			log.Error().Err(err).Msg("could not load content of file " + path)
			continue
		}

		if !(len(fileContent) > 0 && len(fileContent) <= maxFileSize) {
			continue
		}

		file := b.getFileFrom(fileContent)
		if b.canAdd(string(documentURI), fileContent) {
			log.Trace().Str("uri1", string(documentURI)).Str("bundle", b.BundleHash).Msg("added to bundle")
			b.BundleDocuments[documentURI] = file
			continue
		}

		log.Trace().Str("uri1", string(documentURI)).Str("bundle", b.BundleHash).Msg("not added to bundle")
		nonAddedFiles[documentURI] = true
	}

	if len(nonAddedFiles) > 0 {
		return FilesNotAdded{Files: nonAddedFiles}
	}
	return FilesNotAdded{}
}

func (b *BundleImpl) getFileFrom(content []byte) File {
	return File{
		Hash:    util.Hash(content),
		Content: string(content),
	}
}

func (b *BundleImpl) canAdd(uri string, content []byte) bool {
	return getTotalDocPayloadSize(uri, content)+b.getSize() < maxBundleSize
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

func (b *BundleImpl) FetchDiagnosticsData(
	rootPath string,
	wg *sync.WaitGroup,
	dChan chan lsp.DiagnosticResult,
	hoverChan chan lsp.Hover,
) {
	defer wg.Done()
	defer log.Debug().Str("method", "FetchDiagnosticsData").Msg("done.")

	log.Debug().Str("method", "FetchDiagnosticsData").Msg("started.")

	err := b.uploadDocuments()
	if err != nil {
		log.Error().Err(err).Str("method", "FetchDiagnosticsData").Msg("error creating/extending bundle...")
		dChan <- lsp.DiagnosticResult{Err: err}
		return
	}

	b.retrieveAnalysis(rootPath, dChan, hoverChan)
}

func (b *BundleImpl) retrieveAnalysis(
	rootPath string,
	dChan chan lsp.DiagnosticResult,
	hoverChan chan lsp.Hover,
) {
	if len(b.BundleDocuments) <= 0 {
		return
	}

	for {
		start := time.Now()
		diags, hovers, status, err := b.SnykCode.RunAnalysis(
			b.BundleHash,
			getShardKey(rootPath, environment.Token()),
			[]sglsp.DocumentURI{},
			0)

		if err != nil {
			log.Error().Err(err).
				Str("method", "DiagnosticData").Msg("error retrieving diagnostics...")
			dChan <- lsp.DiagnosticResult{Err: err}
			return
		}

		if status == "COMPLETE" {
			for u, d := range diags {
				log.Trace().Str("method", "retrieveAnalysis").Str("bundleHash", b.BundleHash).
					Str("uri1", string(u)).
					Msg("sending diagnostics...")

				dChan <- lsp.DiagnosticResult{
					Uri:         u,
					Diagnostics: d,
					Err:         err,
				}
			}
			sendHoversViaChan(hovers, hoverChan)

			return
		}

		if time.Since(start) > environment.SnykeCodeAnalysisTimeout() {
			err = SnykAnalysisTimeoutError{msg: "Analysis Call Timed out."}
			log.Error().Err(err).Str("method", "DiagnosticData").Msg("timeout...")
			dChan <- lsp.DiagnosticResult{Err: err}
		}
		time.Sleep(1 * time.Second)
	}
}

func sendHoversViaChan(hovers map[sglsp.DocumentURI][]lsp.HoverDetails, hoverChan chan lsp.Hover) {
	for uri, hover := range hovers {
		hoverChan <- lsp.Hover{
			Uri:   uri,
			Hover: hover,
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
	var size = len(jsonOverheadRequest) + jsonCommasForFiles // if more than one file, they are separated by commas in the req
	for uri, file := range b.BundleDocuments {
		size += getTotalDocPayloadSize(string(uri), []byte(file.Content))
	}
	return size
}

func getShardKey(rootPath string, authToken string) string {
	if len(rootPath) > 0 {
		return util.Hash([]byte(rootPath))
	}
	if len(authToken) > 0 {
		return util.Hash([]byte(authToken))
	}

	return ""
}
