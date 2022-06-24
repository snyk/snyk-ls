package workspace

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
	ignore "github.com/sabhiram/go-gitignore"

	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/concurrency"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/internal/util"
	"github.com/snyk/snyk-ls/lsp"
)

type FolderStatus int
type ProductLine string
type ProductLineAttributes map[string]interface{}

const (
	Unscanned FolderStatus = iota
	Scanned   FolderStatus = iota

	SnykCode       ProductLine = "Snyk Code"
	SnykOpenSource ProductLine = "Snyk Open Source"
	SnykIac        ProductLine = "Snyk IaC"
)

// Folder contains files that can be scanned,
//it orchestrates snyk scans and provides a caching layer to avoid unnecessary computing
type Folder struct {
	path                    string
	name                    string
	status                  FolderStatus
	productLineAttributes   map[ProductLine]ProductLineAttributes
	ignorePatterns          []string
	documentDiagnosticCache concurrency.AtomicMap
	scanner                 snyk.Scanner
	hoverService            hover.Service
}

func NewFolder(path string, name string, scanner snyk.Scanner, hoverService hover.Service) *Folder {
	folder := Folder{
		scanner:               scanner,
		path:                  path,
		name:                  name,
		status:                Unscanned,
		productLineAttributes: make(map[ProductLine]ProductLineAttributes),
		hoverService:          hoverService,
	}
	folder.productLineAttributes[SnykCode] = ProductLineAttributes{}
	folder.productLineAttributes[SnykIac] = ProductLineAttributes{}
	folder.productLineAttributes[SnykOpenSource] = ProductLineAttributes{}
	folder.documentDiagnosticCache = concurrency.AtomicMap{}
	return &folder
}

func (f *Folder) Files() (filePaths []string, err error) {
	workspace, err := filepath.Abs(f.path)

	if err != nil {
		return filePaths, err
	}

	if f.ignorePatterns == nil {
		_, err = f.loadIgnorePatterns()
		if err != nil {
			return filePaths, err
		}
	}

	gitIgnore := ignore.CompileIgnoreLines(f.ignorePatterns...)
	err = filepath.WalkDir(workspace, func(path string, dirEntry os.DirEntry, _ error) error {
		if dirEntry == nil || dirEntry.IsDir() {
			if util.Ignored(gitIgnore, path) {
				return filepath.SkipDir
			}
			return nil
		}

		if util.Ignored(gitIgnore, path) {
			return nil
		}

		filePaths = append(filePaths, path)
		return err
	})
	if err != nil {
		return filePaths, err
	}
	return filePaths, nil
}

func (f *Folder) IsScanned() bool {
	return f.status == Scanned
}

func (f *Folder) ClearScannedStatus() {
	f.status = Unscanned
}

func (f *Folder) SetStatus(status FolderStatus) {
	f.status = status
}

func (f *Folder) ScanFolder(ctx context.Context) {
	f.scan(ctx, f.path)
	f.status = Scanned
}

func (f *Folder) ScanFile(ctx context.Context, path string) {
	f.scan(ctx, path)
}

func (f *Folder) GetProductAttribute(productLine ProductLine, name string) interface{} {
	return f.productLineAttributes[productLine][name]
}

func (f *Folder) AddProductAttribute(productLine ProductLine, name string, value interface{}) {
	f.productLineAttributes[productLine][name] = value
}

func (f *Folder) Contains(path string) bool {
	return uri.FolderContains(f.path, path)
}

// todo: can we manage the cache internally without leaking it, e.g. by using as a key an MD5 hash rather than a path and defining a TTL?
func (f *Folder) ClearDiagnosticsCache(filePath string) {
	f.documentDiagnosticCache.Delete(filePath)
	f.ClearScannedStatus()
}

func (f *Folder) scan(ctx context.Context, path string) {
	diagnosticSlice := f.documentDiagnosticsFromCache(path)
	if len(diagnosticSlice) > 0 {
		log.Info().Str("method", "domain.ide.workspace.folder.scan").Msgf("Cached results found: Skipping scan for %s", path)
		return
	}

	codeFiles, err := f.Files()
	if err != nil {
		log.Warn().
			Err(err).
			Str("method", "doSnykCodeWorkspaceScan").
			Str("workspacePath", f.path).
			Msg("error getting workspace files")
	}
	//todo f.path & codeFiles need to go away, for that we need to unify the code interface & iac/oss
	f.scanner.Scan(ctx, path, f.processResults, f.path, codeFiles)
}

func (f *Folder) documentDiagnosticsFromCache(file string) []lsp.Diagnostic {
	diagnostics := f.documentDiagnosticCache.Get(file)
	if diagnostics == nil {
		return nil
	}
	return diagnostics.([]lsp.Diagnostic)
}

func (f *Folder) processResults(diagnostics map[string][]lsp.Diagnostic, hovers []hover.DocumentHovers) {
	f.processDiagnostics(diagnostics)
	f.processHovers(hovers)
}

func (f *Folder) processDiagnostics(diagnostics map[string][]lsp.Diagnostic) {
	// add all diagnostics to cache
	for filePath := range diagnostics {
		f.documentDiagnosticCache.Put(filePath, diagnostics[filePath])
		notification.Send(lsp.PublishDiagnosticsParams{
			URI:         uri.PathToUri(filePath),
			Diagnostics: diagnostics[filePath],
		})
	}
}

func (f *Folder) processHovers(hovers []hover.DocumentHovers) {
	for _, h := range hovers {
		select {
		case f.hoverService.Channel() <- h:
		}
	}
}

func (f *Folder) loadIgnorePatterns() (patterns []string, err error) {
	var ignores = ""
	log.Debug().
		Str("method", "loadIgnorePatterns").
		Str("workspace", f.path).
		Msg("searching for ignore files")
	err = filepath.WalkDir(f.path, func(path string, dirEntry os.DirEntry, _ error) error {
		if dirEntry == nil || dirEntry.IsDir() {
			return nil
		}

		if !(strings.HasSuffix(path, ".gitignore") || strings.HasSuffix(path, ".dcignore")) {
			return nil
		}
		log.Debug().Str("method", "loadIgnorePatterns").Str("file", path).Msg("found ignore file")
		content, err := os.ReadFile(path)
		if err != nil {
			log.Err(err).Msg("Can't read" + path)
		}
		ignores += string(content)
		return err
	})

	if err != nil {
		return nil, err
	}

	patterns = strings.Split(ignores, "\n")
	f.ignorePatterns = patterns
	log.Debug().Interface("ignorePatterns", patterns).Msg("Loaded and set ignore patterns")
	return patterns, nil
}

func (f *Folder) Path() string         { return f.path }
func (f *Folder) Name() string         { return f.name }
func (f *Folder) Status() FolderStatus { return f.status }
