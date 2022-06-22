package workspace

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	ignore "github.com/sabhiram/go-gitignore"

	"github.com/snyk/snyk-ls/internal/cli"
	"github.com/snyk/snyk-ls/internal/concurrency"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/internal/util"
	"github.com/snyk/snyk-ls/lsp"
)

func NewFolder(path string, name string, parent *Workspace) *Folder {
	folder := Folder{
		parent:                parent,
		path:                  path,
		name:                  name,
		status:                Unscanned,
		productLineAttributes: make(map[ProductLine]ProductLineAttributes),
	}
	folder.productLineAttributes[SnykCode] = ProductLineAttributes{}
	folder.productLineAttributes[SnykIac] = ProductLineAttributes{}
	folder.productLineAttributes[SnykOpenSource] = ProductLineAttributes{}
	folder.documentDiagnosticCache = concurrency.AtomicMap{}
	folder.cli = cli.SnykCli{}
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

func (f *Folder) SetStatus(status WorkspaceFolderStatus) {
	f.status = status
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

func (f *Folder) Scan(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	// TODO: don't return issues, handle sending diagnostics from the product line
	issues := f.FetchAllRegisteredDocumentDiagnostics(ctx, f.path, lsp.ScanLevelWorkspace)
	f.AddToCache(issues)
	f.status = Scanned
	for documentURI, d := range issues {
		// todo: get rid of lsp type
		notification.Send(lsp.PublishDiagnosticsParams{
			URI:         uri.PathToUri(documentURI),
			Diagnostics: d,
		})
	}
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

func (f *Folder) Path() string                  { return f.path }
func (f *Folder) Name() string                  { return f.name }
func (f *Folder) Status() WorkspaceFolderStatus { return f.status }
