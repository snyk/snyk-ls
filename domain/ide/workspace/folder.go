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

const (
	Unscanned FolderStatus = iota
	Scanned   FolderStatus = iota
)

// Folder contains files that can be scanned,
//it orchestrates snyk scans and provides a caching layer to avoid unnecessary computing
type Folder struct {
	path                    string
	name                    string
	status                  FolderStatus
	productAttributes       map[snyk.Product]snyk.ProductAttributes
	ignorePatterns          []string
	documentDiagnosticCache concurrency.AtomicMap
	scanner                 snyk.Scanner
	hoverService            hover.Service
	mutex                   sync.Mutex
}

func NewFolder(path string, name string, scanner snyk.Scanner, hoverService hover.Service) *Folder {
	folder := Folder{
		scanner:           scanner,
		path:              path,
		name:              name,
		status:            Unscanned,
		productAttributes: make(map[snyk.Product]snyk.ProductAttributes),
		hoverService:      hoverService,
	}
	folder.productAttributes[snyk.ProductCode] = snyk.ProductAttributes{}
	folder.productAttributes[snyk.ProductInfrastructureAsCode] = snyk.ProductAttributes{}
	folder.productAttributes[snyk.ProductOpenSource] = snyk.ProductAttributes{}
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
				Str("method", "domain.ide.workspace.Folder.Files").
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
	codeFiles, err := f.Files()
	if err != nil {
		log.Warn().
			Err(err).
			Str("method", "domain.ide.workspace.Folder.ScanFolder").
			Str("workspacePath", f.path).
			Msg("error getting workspace files")
	}
	f.scan(ctx, f.path, codeFiles)
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.status = Scanned
}

func (f *Folder) ScanFile(ctx context.Context, path string) {
	f.scan(ctx, path, []string{path})
}

func (f *Folder) GetProductAttribute(product snyk.Product, name string) interface{} {
	return f.productAttributes[product][name]
}

func (f *Folder) AddProductAttribute(product snyk.Product, name string, value interface{}) {
	f.productAttributes[product][name] = value
}

func (f *Folder) Contains(path string) bool {
	return uri.FolderContains(f.path, path)
}

// todo: can we manage the cache internally without leaking it, e.g. by using as a key an MD5 hash rather than a path and defining a TTL?
func (f *Folder) ClearDiagnosticsCache(filePath string) {
	f.documentDiagnosticCache.Delete(filePath)
	f.ClearScannedStatus()
}

func (f *Folder) scan(ctx context.Context, path string, codeFiles []string) {
	issuesSlice := f.documentDiagnosticsFromCache(path)
	if issuesSlice != nil {
		log.Info().Str("method", "domain.ide.workspace.folder.scan").Msgf("Cached results found: Skipping scan for %s", path)
		f.processResults(issuesSlice)
		return
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
	var issuesByFile = map[string][]snyk.Issue{}
	dedupMap := f.createDedupMap()
	for _, issue := range issues {
		cachedIssues := f.documentDiagnosticCache.Get(issue.AffectedFilePath)
		if cachedIssues == nil {
			cachedIssues = []snyk.Issue{}
		}
		if !dedupMap[f.getUniqueIssueID(issue)] {
			cachedIssues = append(cachedIssues.([]snyk.Issue), issue)
		}
		f.documentDiagnosticCache.Put(issue.AffectedFilePath, cachedIssues)
		issuesByFile[issue.AffectedFilePath] = cachedIssues.([]snyk.Issue)
	}

	f.processDiagnostics(issuesByFile)
	f.processHovers(issuesByFile)
}

func (f *Folder) createDedupMap() (dedupMap map[string]bool) {
	dedupMap = make(map[string]bool)
	f.documentDiagnosticCache.Range(func(key interface{}, value interface{}) bool {
		issues := value.([]snyk.Issue)
		for _, issue := range issues {
			uniqueID := f.getUniqueIssueID(issue)
			dedupMap[uniqueID] = true
		}
		return true
	})
	return dedupMap
}

func (f *Folder) getUniqueIssueID(issue snyk.Issue) string {
	uniqueID := issue.ID + "|" + issue.AffectedFilePath
	return uniqueID
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
		var codeDescription lsp.CodeDescription
		switch issue.Product { //nolint:exhaustive
		case snyk.ProductOpenSource:
			codeDescription = lsp.CodeDescription{Href: lsp.Uri("https://security.snyk.io/vuln/" + issue.ID)}
		case snyk.ProductInfrastructureAsCode:
			codeDescription = lsp.CodeDescription{Href: lsp.Uri("https://snyk.io/security-rules/" + issue.ID)}
		default:
			codeDescription = lsp.CodeDescription{}
		}

		diagnostics = append(diagnostics, lsp.Diagnostic{
			Range:           toLspRange(issue.Range),
			Severity:        toSeverity(issue.Severity),
			Code:            issue.ID,
			Source:          string(issue.Product),
			Message:         issue.Message,
			CodeDescription: codeDescription,
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
