package workspace

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	ignore "github.com/sabhiram/go-gitignore"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/concurrency"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/internal/util"
	"github.com/snyk/snyk-ls/presentation/lsp"
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
	mutex                   sync.Mutex
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
	f.mutex.Lock()
	if f.ignorePatterns == nil {
		_, err = f.loadIgnorePatterns()
		if err != nil {
			return filePaths, err
		}
	}

	gitIgnore := ignore.CompileIgnoreLines(f.ignorePatterns...)
	f.mutex.Unlock()
	err = filepath.WalkDir(workspace, func(path string, dirEntry os.DirEntry, err error) error {
		if err != nil {
			log.Debug().
				Str("method", "Files - walker").
				Str("path", path).
				Err(err).
				Msg("error traversing files")
			return nil
		}
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
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return f.status == Scanned
}

func (f *Folder) ClearScannedStatus() {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.status = Unscanned
}

func (f *Folder) SetStatus(status FolderStatus) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.status = status
}

func (f *Folder) ScanFolder(ctx context.Context) {
	f.scan(ctx, f.path)
	f.mutex.Lock()
	defer f.mutex.Unlock()
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
	issuesSlice := f.documentDiagnosticsFromCache(path)
	if issuesSlice != nil {
		log.Info().Str("method", "domain.ide.workspace.folder.scan").Msgf("Cached results found: Skipping scan for %s", path)
		f.processResults(issuesSlice)
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

func (f *Folder) documentDiagnosticsFromCache(file string) []snyk.Issue {
	issues := f.documentDiagnosticCache.Get(file)
	if issues == nil {
		return nil
	}
	return issues.([]snyk.Issue)
}

func (f *Folder) processResults(issues []snyk.Issue) {
	method := "processResults"
	log.Debug().Str("method", method).Int("issues to be processed", len(issues)).Send()
	var issuesByFile = map[string][]snyk.Issue{}

	for _, issue := range issues {
		log.Debug().Str("method", method).Str("affectedFilePath", issue.AffectedFilePath).Str("ID", issue.ID).Msg("starting processing")
		currentIssues := f.documentDiagnosticCache.Get(issue.AffectedFilePath)
		needsToRefreshCache := issuesByFile[issue.AffectedFilePath] == nil
		if needsToRefreshCache || currentIssues == nil {
			log.Debug().Str("method", method).Str("affectedFilePath", issue.AffectedFilePath).Str("ID", issue.ID).Msg("Creating new issue array for path")
			currentIssues = []snyk.Issue{}
		}
		currentIssues = append(currentIssues.([]snyk.Issue), issue)
		log.Debug().Str("method", method).Str("affectedFilePath", issue.AffectedFilePath).Str("ID", issue.ID).Msg("added to issue array")

		f.documentDiagnosticCache.Put(issue.AffectedFilePath, currentIssues)
		log.Debug().Str("method", method).Str("affectedFilePath", issue.AffectedFilePath).Str("ID", issue.ID).Msg("updated cache")
		issuesByFile[issue.AffectedFilePath] = currentIssues.([]snyk.Issue)
	}

	f.processDiagnostics(issuesByFile)
	f.processHovers(issuesByFile)
}

func (f *Folder) processDiagnostics(issuesByFile map[string][]snyk.Issue) {
	for path, issues := range issuesByFile {
		log.Debug().Str("method", "processDiagnostics").Str("affectedFilePath", path).Int("issueCount", len(issues)).Send()
		notification.Send(lsp.PublishDiagnosticsParams{
			URI:         uri.PathToUri(path),
			Diagnostics: toDiagnostic(issues),
		})
	}
}

func (f *Folder) processHovers(issuesByFile map[string][]snyk.Issue) {
	for path, issues := range issuesByFile {
		f.hoverService.Channel() <- toHoversDocument(path, issues)
	}
}

func toHoversDocument(path string, i []snyk.Issue) hover.DocumentHovers {
	return hover.DocumentHovers{
		Uri:   uri.PathToUri(path),
		Hover: toHovers(i),
	}
}

func toHovers(issues []snyk.Issue) (hovers []hover.Hover[hover.Context]) {
	for _, i := range issues {
		message := ""
		if len(i.LegacyMessage) > 0 {
			message = i.LegacyMessage
		} else {
			message = i.Message
		}
		hovers = append(hovers, hover.Hover[hover.Context]{
			Id:      i.ID,
			Range:   toLspRange(i.Range),
			Message: message,
			Context: i,
		})
	}
	return hovers
}

func toDiagnostic(issues []snyk.Issue) (diagnostics []lsp.Diagnostic) {
	for _, issue := range issues {
		diagnostics = append(diagnostics, lsp.Diagnostic{
			Range:    toLspRange(issue.Range),
			Severity: toSeverity(issue.Severity),
			Code:     issue.ID,
			Source:   "LS Server",
			Message:  issue.Message,
		})
	}
	return diagnostics
}

func toSeverity(severity snyk.Severity) sglsp.DiagnosticSeverity {
	switch severity {
	case snyk.Critical:
		return sglsp.Error
	case snyk.High:
		return sglsp.Error
	case snyk.Medium:
		return sglsp.Warning
	case snyk.Low:
		return sglsp.Information
	}
	return sglsp.Info
}

func toLspRange(r snyk.Range) sglsp.Range {
	return sglsp.Range{
		Start: toLspPosition(r.Start),
		End:   toLspPosition(r.End),
	}
}

func toLspPosition(p snyk.Position) sglsp.Position {
	return sglsp.Position{
		Line:      p.Line,
		Character: p.Character,
	}
}

func (f *Folder) loadIgnorePatterns() (patterns []string, err error) {
	var ignores = ""
	log.Debug().
		Str("method", "loadIgnorePatterns").
		Str("workspace", f.path).
		Msg("searching for ignore files")
	err = filepath.WalkDir(f.path, func(path string, dirEntry os.DirEntry, err error) error {
		if err != nil {
			log.Debug().
				Str("method", "loadIgnorePatterns - walker").
				Str("path", path).
				Err(err).
				Msg("error traversing files")
			return nil
		}
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
