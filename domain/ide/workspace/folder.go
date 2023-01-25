/*
 * © 2022 Snyk Limited All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package workspace

import (
	"context"
	"strings"
	"sync"

	"github.com/puzpuzpuz/xsync"
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/uri"
)

type FolderStatus int

const (
	Unscanned FolderStatus = iota
	Scanned   FolderStatus = iota
)

// Folder contains files that can be scanned,
// it orchestrates snyk scans and provides a caching layer to avoid unnecessary computing
type Folder struct {
	path                    string
	name                    string
	status                  FolderStatus
	documentDiagnosticCache *xsync.MapOf[string, []snyk.Issue]
	scanner                 snyk.Scanner
	hoverService            hover.Service
	mutex                   sync.Mutex
}

func NewFolder(path string, name string, scanner snyk.Scanner, hoverService hover.Service) *Folder {
	folder := Folder{
		scanner:      scanner,
		path:         strings.TrimSuffix(path, "/"),
		name:         name,
		status:       Unscanned,
		hoverService: hoverService,
	}
	folder.documentDiagnosticCache = xsync.NewMapOf[[]snyk.Issue]()
	return &folder
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

func (f *Folder) Contains(path string) bool {
	return uri.FolderContains(f.path, path)
}

// ClearDiagnosticsFromFile will clear all diagnostics of a file from memory, and send a notification to the client
// with empty diagnostics results for the specific file
func (f *Folder) ClearDiagnosticsFromFile(filePath string) {
	// todo: can we manage the cache internally without leaking it, e.g. by using as a key an MD5 hash rather than a path and defining a TTL?
	f.documentDiagnosticCache.Delete(filePath)
	notification.Send(lsp.PublishDiagnosticsParams{
		URI:         uri.PathToUri(filePath),
		Diagnostics: []lsp.Diagnostic{},
	})
	f.ClearScannedStatus()
}

func (f *Folder) ClearDiagnosticsFromPathRecursively(removedPath string) {
	f.documentDiagnosticCache.Range(func(key string, value []snyk.Issue) bool {
		if strings.Contains(key, removedPath) {
			f.ClearDiagnosticsFromFile(key)
		}

		return true // Continue the iteration
	})
}

func (f *Folder) scan(ctx context.Context, path string) {
	const method = "domain.ide.workspace.folder.scan"
	if !f.IsTrusted() {
		log.Warn().Str("path", path).Str("method", method).Msg("skipping scan of untrusted path")
		return
	}
	issuesSlice := f.DocumentDiagnosticsFromCache(path)
	if issuesSlice != nil {
		log.Info().Str("method", method).Msgf("Cached results found: Skipping scan for %s", path)
		f.processResults(issuesSlice)
		return
	}

	f.scanner.Scan(ctx, path, f.processResults, f.path)
}

func (f *Folder) DocumentDiagnosticsFromCache(file string) []snyk.Issue {
	issues, _ := f.documentDiagnosticCache.Load(file)
	if issues == nil {
		return nil
	}
	return issues
}

func (f *Folder) processResults(issues []snyk.Issue) {
	dedupMap := f.createDedupMap()

	// TODO: perform issue diffing (current <-> newly reported)
	// Update diagnostic cache
	for _, issue := range issues {
		cachedIssues, _ := f.documentDiagnosticCache.Load(issue.AffectedFilePath)
		if cachedIssues == nil {
			cachedIssues = []snyk.Issue{}
		}

		if !dedupMap[f.getUniqueIssueID(issue)] {
			cachedIssues = append(cachedIssues, issue)
		}

		f.documentDiagnosticCache.Store(issue.AffectedFilePath, cachedIssues)
	}

	// Filter and publish cached diagnostics
	f.FilterAndPublishCachedDiagnostics()
}

func (f *Folder) FilterAndPublishCachedDiagnostics() {
	issuesByFile := f.filterCachedDiagnostics()
	f.publishDiagnostics(issuesByFile)
}

func (f *Folder) filterCachedDiagnostics() (fileIssues map[string][]snyk.Issue) {
	logger := log.With().Str("method", "processResults").Logger()

	var issuesByFile = map[string][]snyk.Issue{}
	if f.documentDiagnosticCache.Size() == 0 {
		return issuesByFile
	}

	logger.Debug().Msgf("Filtering issues by severity: %v", config.CurrentConfig().FilterSeverity())

	supportedIssueTypes := config.CurrentConfig().GetDisplayableIssueTypes()
	f.documentDiagnosticCache.Range(func(filePath string, issues []snyk.Issue) bool {
		// Consider doing the loop body in parallel for performance (and use a thread-safe map)
		filteredIssues := filterIssues(issues, supportedIssueTypes)
		issuesByFile[filePath] = filteredIssues
		return true
	})

	return issuesByFile
}

func filterIssues(issues []snyk.Issue, supportedIssueTypes map[product.FilterableIssueType]bool) []snyk.Issue {
	logger := log.With().Str("method", "filterIssues").Logger()
	filteredIssues := make([]snyk.Issue, 0)

	for _, issue := range issues {
		// Logging here might hurt performance, should benchmark if filtering is slow
		if isVisibleSeverity(issue) && supportedIssueTypes[issue.GetFilterableIssueType()] {
			logger.Trace().Msgf("Including visible severity issue: %v", issue)
			filteredIssues = append(filteredIssues, issue)
		} else {
			logger.Trace().Msgf("Filtering out issue %v", issue)
		}
	}
	return filteredIssues
}

func isVisibleSeverity(issue snyk.Issue) bool {
	switch issue.Severity {
	case snyk.Critical:
		return config.CurrentConfig().FilterSeverity().Critical
	case snyk.High:
		return config.CurrentConfig().FilterSeverity().High
	case snyk.Medium:
		return config.CurrentConfig().FilterSeverity().Medium
	case snyk.Low:
		return config.CurrentConfig().FilterSeverity().Low
	}
	return false
}

func (f *Folder) publishDiagnostics(issuesByFile map[string][]snyk.Issue) {
	f.sendDiagnostics(issuesByFile)
	f.sendHovers(issuesByFile)
	f.sendScanResults(issuesByFile)
}

func (f *Folder) createDedupMap() (dedupMap map[string]bool) {
	dedupMap = make(map[string]bool)
	f.documentDiagnosticCache.Range(func(key string, value []snyk.Issue) bool {
		issues := value
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

func (f *Folder) sendDiagnostics(issuesByFile map[string][]snyk.Issue) {
	for path, issues := range issuesByFile {
		f.sendDiagnosticsForFile(path, issues)
	}
}

func (f *Folder) sendDiagnosticsForFile(path string, issues []snyk.Issue) {
	log.Debug().Str("method", "sendDiagnosticsForFile").Str("affectedFilePath", path).Int("issueCount",
		len(issues)).Send()
	notification.Send(lsp.PublishDiagnosticsParams{
		URI:         uri.PathToUri(path),
		Diagnostics: converter.ToDiagnostics(issues),
	})
}

func (f *Folder) sendHovers(issuesByFile map[string][]snyk.Issue) {
	for path, issues := range issuesByFile {
		f.sendHoversForFile(path, issues)
	}
}

func (f *Folder) sendHoversForFile(path string, issues []snyk.Issue) {
	f.hoverService.Channel() <- converter.ToHoversDocument(path, issues)
}

func (f *Folder) Path() string         { return f.path }
func (f *Folder) Name() string         { return f.name }
func (f *Folder) Status() FolderStatus { return f.status }

func (f *Folder) IssuesFor(filePath string, requestedRange snyk.Range) (matchingIssues []snyk.Issue) {
	method := "domain.ide.workspace.folder.getCodeActions"
	issues := f.DocumentDiagnosticsFromCache(filePath)
	for _, issue := range issues {
		if issue.Range.Overlaps(requestedRange) {
			log.Debug().Str("method", method).Msg("appending code action for issue " + issue.String())
			matchingIssues = append(matchingIssues, issue)
		}
	}

	log.Debug().Str("method", method).Msgf(
		"found %d code actions for %s, %s",
		len(matchingIssues),
		filePath,
		requestedRange,
	)
	return matchingIssues
}

func (f *Folder) AllIssuesFor(filePath string) (matchingIssues []snyk.Issue) {
	return f.DocumentDiagnosticsFromCache(filePath)
}

func (f *Folder) ClearDiagnostics() {
	f.documentDiagnosticCache.Range(func(key string, _ []snyk.Issue) bool {
		// we must republish empty diagnostics for all files that were reported with diagnostics
		notification.Send(lsp.PublishDiagnosticsParams{
			URI:         uri.PathToUri(key),
			Diagnostics: []lsp.Diagnostic{},
		})
		f.documentDiagnosticCache.Delete(key)
		return true
	})
}

func (f *Folder) ClearDiagnosticsByIssueType(removedType product.FilterableIssueType) {
	f.documentDiagnosticCache.Range(func(filePath string, previousIssues []snyk.Issue) bool {
		newIssues := []snyk.Issue{}
		for _, issue := range previousIssues {
			if issue.GetFilterableIssueType() != removedType {
				newIssues = append(newIssues, issue)
			}
		}

		if len(previousIssues) != len(newIssues) { // Only send diagnostics update when issues were removed
			f.documentDiagnosticCache.Store(filePath, newIssues)
			f.sendDiagnosticsForFile(filePath, newIssues)
			f.sendHoversForFile(filePath, newIssues)
		}

		return true
	})
}

func (f *Folder) IsTrusted() bool {
	if !config.CurrentConfig().IsTrustedFolderFeatureEnabled() {
		return true
	}

	for _, path := range config.CurrentConfig().TrustedFolders() {
		if strings.HasPrefix(f.path, path) {
			return true
		}
	}
	return false
}

func (f *Folder) sendScanResults(issuesByFile map[string][]snyk.Issue) {
	var codeIssues []lsp.ScanIssue
	for _, issues := range issuesByFile {
		for _, issue := range issues {
			additionalData, ok := issue.AdditionalData.(snyk.CodeIssueData)
			if !ok {
				continue // skip non-code issues
			}

			exampleCommitFixes := make([]lsp.ExampleCommitFix, 0, len(additionalData.ExampleCommitFixes))
			for i := range additionalData.ExampleCommitFixes {
				lines := make([]lsp.CommitChangeLine, 0, len(additionalData.ExampleCommitFixes[i].Lines))
				for j := range additionalData.ExampleCommitFixes[i].Lines {
					lines = append(lines, lsp.CommitChangeLine{
						Line:       additionalData.ExampleCommitFixes[i].Lines[j].Line,
						LineNumber: additionalData.ExampleCommitFixes[i].Lines[j].LineNumber,
						LineChange: additionalData.ExampleCommitFixes[i].Lines[j].LineChange,
					})
				}
				exampleCommitFixes = append(exampleCommitFixes, lsp.ExampleCommitFix{
					CommitURL: additionalData.ExampleCommitFixes[i].CommitURL,
					Lines:     lines,
				})
			}
			codeIssues = append(codeIssues, lsp.ScanIssue{
				Id:       issue.ID,
				Title:    "Title",
				Severity: issue.Severity.String(),
				FilePath: issue.AffectedFilePath,
				AdditionalData: lsp.CodeIssueData{
					Message:            issue.Message,
					Rule:               additionalData.Rule,
					RepoDatasetSize:    additionalData.RepoDatasetSize,
					ExampleCommitFixes: exampleCommitFixes,
					CWE:                additionalData.CWE,
					IsSecurityType:     additionalData.IsSecurityType,
					Text:               additionalData.Text,
					Cols:               additionalData.Cols,
					Rows:               additionalData.Rows,

					// TODO - fill these with real data
					Markers: nil,
					LeadURL: "",
				},
			})
		}
	}
	// TODO Make this generic
	notification.Send(lsp.SnykScanParams{
		Status:     lsp.Success,
		Product:    "code",
		FolderPath: f.Path(),
		Issues:     codeIssues,
	})
}
