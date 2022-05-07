package code

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"time"

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
	maxFileSize               = 1024 * 1024
	maxBundleSize             = 1024 * 1024 * 4
	jsonOverheadRequest       = "{\"files\":{}}"
	jsonOverHeadRequestLength = len(jsonOverheadRequest)
	jsonUriOverhead           = "\"\":{}"
	jsonHashSizePerFile       = "\"hash\":\"0123456789012345678901234567890123456789012345678901234567890123\""
	jsonContentOverhead       = ",\"content\":\"\""
	jsonOverheadPerFile       = jsonUriOverhead + jsonContentOverhead
)

func getTotalDocPayloadSize(documentURI string, content []byte) int {
	return len(jsonHashSizePerFile) + len(jsonOverheadPerFile) + len([]byte(documentURI)) + len(content)
}

type BundleImpl struct {
	SnykCode         SnykCodeService
	BundleHash       string
	BundleDocuments  map[sglsp.DocumentURI]File
	missingFiles     []sglsp.DocumentURI
	allDocumentsSize int
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

func (b *BundleImpl) createBundleFromSource(ctx context.Context) error {
	var err error
	if len(b.BundleDocuments) > 0 {
		b.BundleHash, b.missingFiles, err = b.SnykCode.CreateBundle(ctx, b.BundleDocuments)
		logger.
			WithField("method", "createBundleFromSource").
			WithField("bundleHash", b.BundleHash).
			Trace(ctx, "created bundle on backend")
	}
	return err
}

func (b *BundleImpl) AddToBundleDocuments(ctx context.Context, files map[sglsp.DocumentURI]bool) FilesNotAdded {
	if b.BundleDocuments == nil {
		b.BundleDocuments = make(map[sglsp.DocumentURI]File)
	}

	var nonAddedFiles = make(map[sglsp.DocumentURI]bool)
	for documentURI := range files {
		if !IsSupported(documentURI) {
			continue
		}

		path := uri.PathFromUri(documentURI)
		fileContent, err := os.ReadFile(path)
		if err != nil {
			logger.
				WithField("method", "AddToBundleDocuments").
				WithField("bundleHash", b.BundleHash).
				WithField("path", path).
				WithError(err).
				Trace(ctx, "could not load file")
			continue
		}

		if !(len(fileContent) > 0 && len(fileContent) <= maxFileSize) {
			continue
		}

		file := b.getFileFrom(fileContent)
		if b.canAdd(string(documentURI), fileContent) { // todo check if it should be path or document uri
			logger.
				WithField("method", "AddToBundleDocuments").
				WithField("bundleHash", b.BundleHash).
				WithField("uri1", string(documentURI)).
				Trace(ctx, "added to bundle")
			b.BundleDocuments[documentURI] = file
			continue
		}

		logger.
			WithField("method", "AddToBundleDocuments").
			WithField("bundleHash", b.BundleHash).
			WithField("uri1", string(documentURI)).
			Trace(ctx, "not added to bundle")
		nonAddedFiles[documentURI] = true
	}

	if len(nonAddedFiles) > 0 {
		return FilesNotAdded{Files: nonAddedFiles}
	}
	return FilesNotAdded{}
}

func IsSupported(documentURI sglsp.DocumentURI) bool {
	return extensions[filepath.Ext(uri.PathFromUri(documentURI))]
}

func (b *BundleImpl) getFileFrom(content []byte) File {
	return File{
		Hash:    util.Hash(content),
		Content: string(content),
	}
}

func (b *BundleImpl) canAdd(uri string, content []byte) bool {
	docPayloadSize := getTotalDocPayloadSize(uri, content)
	newSize := docPayloadSize + b.getSize()
	b.allDocumentsSize += docPayloadSize
	return newSize < maxBundleSize
}

func (b *BundleImpl) extendBundleFromSource(ctx context.Context) error {
	var removeFiles []sglsp.DocumentURI
	var err error
	if len(b.BundleDocuments) > 0 {
		b.BundleHash, b.missingFiles, err = b.SnykCode.ExtendBundle(ctx, b.BundleHash, b.BundleDocuments, removeFiles)
		logger.
			WithField("method", "extendBundleFromSource").
			WithField("bundleHash", b.BundleHash).
			Trace(ctx, "extended bundle on backend")
	}
	return err
}

func (b *BundleImpl) FetchDiagnosticsData(
	ctx context.Context,
	rootPath string,
	wg *sync.WaitGroup,
	dChan chan lsp.DiagnosticResult,
	hoverChan chan lsp.Hover,
) {
	defer wg.Done()
	defer logger.
		WithField("method", "FetchDiagnosticsData").
		WithField("bundleHash", b.BundleHash).
		Debug(ctx, "Done")
	logger.
		WithField("method", "FetchDiagnosticsData").
		WithField("bundleHash", b.BundleHash).
		Debug(ctx, "Started")

	err := b.uploadDocuments(ctx)
	if err != nil {
		logger.
			WithField("method", "FetchDiagnosticsData").
			WithField("bundleHash", b.BundleHash).
			WithError(err).
			Error(ctx, "Couldn't create/extend bundle")
		dChan <- lsp.DiagnosticResult{Err: err}
		return
	}

	b.retrieveAnalysis(ctx, rootPath, dChan, hoverChan)
}

func (b *BundleImpl) retrieveAnalysis(
	ctx context.Context,
	rootPath string,
	dChan chan lsp.DiagnosticResult,
	hoverChan chan lsp.Hover,
) {
	if len(b.BundleDocuments) <= 0 {
		return
	}

	for {
		start := time.Now()
		diags, hovers, status, err := b.SnykCode.RunAnalysis(ctx,
			b.BundleHash,
			getShardKey(rootPath, environment.Token()),
			[]sglsp.DocumentURI{},
			0)

		if err != nil {
			logger.
				WithField("method", "retrieveAnalysis").
				WithField("bundleHash", b.BundleHash).
				WithError(err).
				Error(ctx, "Couldn't retrieve diagnostics")
			dChan <- lsp.DiagnosticResult{Err: err}
			return
		}

		if status == "COMPLETE" {
			for u, d := range diags {
				logger.
					WithField("method", "retrieveAnalysis").
					WithField("bundleHash", b.BundleHash).
					WithField("uri", string(u)).
					Trace(ctx, "sending diagnostics")

				dChan <- lsp.DiagnosticResult{
					Uri:         u,
					Diagnostics: d,
					Err:         err,
				}
			}
			sendHoversViaChan(hovers, hoverChan)

			return
		}

		if time.Since(start) > environment.SnykCodeAnalysisTimeout(ctx) {
			err = SnykAnalysisTimeoutError{msg: "Analysis Call Timed out."}
			logger.
				WithField("method", "retrieveAnalysis").
				WithField("bundleHash", b.BundleHash).
				WithError(err).
				Error(ctx, "Analysis timed out")
			dChan <- lsp.DiagnosticResult{Err: err}
		}
		time.Sleep(1 * time.Second)
	}
}

func sendHoversViaChan(hovers map[sglsp.DocumentURI][]lsp.HoverDetails, hoverChan chan lsp.Hover) {
	for documentURI, hover := range hovers {
		hoverChan <- lsp.Hover{
			Uri:   documentURI,
			Hover: hover,
		}
	}
}

func (b *BundleImpl) uploadDocuments(ctx context.Context) error {
	if b.BundleHash == "" {
		return b.createBundleFromSource(ctx)
	}

	return b.extendBundleFromSource(ctx)
}

func (b *BundleImpl) getSize() int {
	if len(b.BundleDocuments) == 0 {
		return 0
	}
	jsonCommasForFiles := len(b.BundleDocuments) - 1
	var size = jsonOverHeadRequestLength + jsonCommasForFiles // if more than one file, they are separated by commas in the req
	return size + b.allDocumentsSize
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
