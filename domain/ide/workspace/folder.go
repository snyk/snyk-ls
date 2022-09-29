/*
 * Copyright 2022 Snyk Ltd.
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
	"sync"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/concurrency"
	"github.com/snyk/snyk-ls/internal/notification"
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
	productAttributes       map[snyk.Product]snyk.ProductAttributes
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

func (f *Folder) scan(ctx context.Context, path string) {
	issuesSlice := f.DocumentDiagnosticsFromCache(path)
	if issuesSlice != nil {
		log.Info().Str("method", "domain.ide.workspace.folder.scan").Msgf("Cached results found: Skipping scan for %s", path)
		f.processResults(issuesSlice)
		return
	}

	f.scanner.Scan(ctx, path, f.processResults, f.path)
}

func (f *Folder) DocumentDiagnosticsFromCache(file string) []snyk.Issue {
	issues := f.documentDiagnosticCache.Get(file)
	if issues == nil {
		return nil
	}
	return issues.([]snyk.Issue)
}

func (f *Folder) processResults(issues []snyk.Issue) {
	var issuesByFile = map[string][]snyk.Issue{}
	dedupMap := f.createDedupMap()

	// TODO: perform issue diffing (current <-> newly reported)
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
			Diagnostics: converter.ToDiagnostics(issues),
		})
	}
}

func (f *Folder) processHovers(issuesByFile map[string][]snyk.Issue) {
	for path, issues := range issuesByFile {
		f.hoverService.Channel() <- converter.ToHoversDocument(path, issues)
	}
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
	f.documentDiagnosticCache.Range(func(key interface{}, value interface{}) bool {
		file := key.(string)
		// we must republish empty diagnostics for all files that were reported with diagnostics
		notification.Send(lsp.PublishDiagnosticsParams{
			URI:         uri.PathToUri(file),
			Diagnostics: []lsp.Diagnostic{},
		})
		return true
	})

	f.documentDiagnosticCache.ClearAll()
}
