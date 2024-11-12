/*
 * © 2022-2024 Snyk Limited
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
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/domain/snyk"
	delta2 "github.com/snyk/snyk-ls/domain/snyk/delta"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"

	"github.com/snyk/snyk-ls/internal/delta"

	"github.com/puzpuzpuz/xsync/v3"

	"github.com/snyk/snyk-ls/internal/types"

	gafanalytics "github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/instrumentation"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/infrastructure/analytics"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/uri"
)

var (
	_ snyk.CacheProvider = (*Folder)(nil)
)

const (
	Unscanned types.FolderStatus = iota
	Scanned   types.FolderStatus = iota
)

// TODO: 3: Extract reporting logic to a separate service

// Folder contains files that can be scanned,
// it orchestrates snyk scans and provides a caching layer to avoid unnecessary computing
type Folder struct {
	path                    string
	name                    string
	status                  types.FolderStatus
	documentDiagnosticCache *xsync.MapOf[string, []snyk.Issue]
	scanner                 scanner.Scanner
	hoverService            hover.Service
	mutex                   sync.RWMutex
	scanNotifier            scanner.ScanNotifier
	notifier                noti.Notifier
	c                       *config.Config
	scanPersister           persistence.ScanSnapshotPersister
}

func (f *Folder) Issue(key string) snyk.Issue {
	var foundIssue snyk.Issue
	f.documentDiagnosticCache.Range(func(filePath string, issues []snyk.Issue) bool {
		for _, i := range issues {
			if i.AdditionalData.GetKey() == key {
				foundIssue = i
				return false
			}
		}
		return true
	})

	if foundIssue.ID == "" {
		if issueProvider, ok := f.scanner.(snyk.IssueProvider); ok {
			foundIssue = issueProvider.Issue(key)
		}
	}
	return foundIssue
}

func (f *Folder) Issues() snyk.IssuesByFile {
	// we want both global issues (OSS and IaC at the moment) and scanner-local issues (Code at the moment)
	// so we get the global issues first, then append the scanner-local issues
	issues := snyk.IssuesByFile{}
	f.documentDiagnosticCache.Range(func(path string, value []snyk.Issue) bool {
		if f.Contains(path) {
			issues[path] = value
		} else {
			f.c.Logger().Error().Msg(fmt.Sprintf("issue found in cache that does not pertain to folder, path: %v", path))
		}
		return true
	})
	// scanner-local issues: if the scanner is an IssueProvider, we append the issues it knows about
	issueProvider, scannerIsIssueProvider := f.scanner.(snyk.IssueProvider)
	if scannerIsIssueProvider {
		cachedScannerIssues := issueProvider.Issues()
		for path, issuesForPath := range cachedScannerIssues {
			if f.Contains(path) {
				issues[path] = append(issues[path], issuesForPath...)
			}
		}
	}
	return issues
}

func (f *Folder) IssuesByProduct() snyk.ProductIssuesByFile {
	issuesForProduct := snyk.ProductIssuesByFile{
		product.ProductOpenSource:           snyk.IssuesByFile{},
		product.ProductCode:                 snyk.IssuesByFile{},
		product.ProductInfrastructureAsCode: snyk.IssuesByFile{},
		product.ProductContainer:            snyk.IssuesByFile{},
	}
	for path, issues := range f.Issues() {
		if !f.Contains(path) {
			f.c.Logger().Error().Msg("issue found in cache that does not pertain to folder")
			continue
		}
		for _, issue := range issues {
			p := issue.Product
			issuesForProduct[p][path] = append(issuesForProduct[p][path], issue)
		}
	}
	return issuesForProduct
}

func (f *Folder) IssuesForFile(file string) []snyk.Issue {
	// try to delegate to scanners first
	var issues []snyk.Issue
	if issueProvider, ok := f.scanner.(snyk.IssueProvider); ok {
		issues = append(issues, issueProvider.IssuesForFile(file)...)
	}
	globalIssues, ok := f.documentDiagnosticCache.Load(file)
	if ok {
		issues = append(issues, globalIssues...)
	}
	return issues
}

func (f *Folder) IsProviderFor(_ product.FilterableIssueType) bool {
	// it either caches itself, or uses the global folder caching mechanism
	return true
}

func (f *Folder) RegisterCacheRemovalHandler(handler func(path string)) {
	if cacheProvider, isCacheProvider := f.scanner.(snyk.CacheProvider); isCacheProvider {
		cacheProvider.RegisterCacheRemovalHandler(handler)
	}
}

func (f *Folder) Clear() {
	issuesByFile := f.Issues()
	for path := range issuesByFile {
		f.ClearIssues(path)
	}
	f.clearScannedStatus()
}

func (f *Folder) ClearIssues(path string) {
	// send global cache evictions
	f.documentDiagnosticCache.Range(func(path string, _ []snyk.Issue) bool {
		f.documentDiagnosticCache.Delete(path)
		f.sendEmptyDiagnosticForFile(path) // this is done automatically by the scanner removal handler (we hope)
		return true
	})
	// let scanner-local cache handle its own stuff
	if cacheProvider, isCacheProvider := f.scanner.(snyk.CacheProvider); isCacheProvider {
		if f.Contains(path) {
			cacheProvider.ClearIssues(path)
		}
	}

	// hovers must be deleted, too
	f.hoverService.DeleteHover(path)
}

func (f *Folder) clearScannedStatus() {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.status = Unscanned
}

func (f *Folder) ClearDiagnosticsByIssueType(removedType product.FilterableIssueType) {
	f.documentDiagnosticCache.Range(func(filePath string, previousIssues []snyk.Issue) bool {
		newIssues := make([]snyk.Issue, 0)
		for _, issue := range previousIssues {
			if issue.GetFilterableIssueType() != removedType {
				newIssues = append(newIssues, issue)
			}
		}

		if len(previousIssues) != len(newIssues) {
			if f.Contains(filePath) {
				f.documentDiagnosticCache.Store(filePath, newIssues)
				f.sendDiagnosticsForFile(filePath, newIssues)
				f.sendHoversForFile(filePath, newIssues)
			} else {
				panic("this should never happen")
			}
		}

		return true
	})

	// a scanner is always tied to FilterableIssueTypes. So we get the product, and check if the scanner is a
	// cacheProvider for the removed issue type. Then we iterate over the issues to remove the paths contained in
	// this folder from the scanner.
	if cacheProvider, isCacheProvider := f.scanner.(snyk.CacheProvider); isCacheProvider && cacheProvider.IsProviderFor(removedType) {
		issuesByFile := cacheProvider.Issues()
		for path := range issuesByFile {
			if f.Contains(path) {
				cacheProvider.ClearIssues(path)
			}
		}
	}
}

func NewFolder(
	c *config.Config,
	path string,
	name string,
	scanner scanner.Scanner,
	hoverService hover.Service,
	scanNotifier scanner.ScanNotifier,
	notifier noti.Notifier,
	scanPersister persistence.ScanSnapshotPersister,
) *Folder {
	folder := Folder{
		scanner:       scanner,
		path:          strings.TrimSuffix(path, "/"),
		name:          name,
		status:        Unscanned,
		hoverService:  hoverService,
		scanNotifier:  scanNotifier,
		notifier:      notifier,
		c:             c,
		scanPersister: scanPersister,
	}
	folder.documentDiagnosticCache = xsync.NewMapOf[string, []snyk.Issue]()
	if cacheProvider, isCacheProvider := scanner.(snyk.CacheProvider); isCacheProvider {
		cacheProvider.RegisterCacheRemovalHandler(folder.sendEmptyDiagnosticForFile)
	}
	return &folder
}

func (f *Folder) sendEmptyDiagnosticForFile(path string) {
	config.CurrentConfig().Logger().Debug().Str("filePath", path).Msg("sending empty diagnostic for file")
	f.sendDiagnosticsForFile(path, []snyk.Issue{})
}

func (f *Folder) IsScanned() bool {
	f.mutex.RLock()
	defer f.mutex.RUnlock()
	return f.status == Scanned
}

func (f *Folder) SetStatus(status types.FolderStatus) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.status = status
}

func (f *Folder) ScanFolder(ctx context.Context) {
	f.scan(ctx, f.path)
	f.mutex.Lock()
	f.status = Scanned
	f.mutex.Unlock()
}

func (f *Folder) ScanFile(ctx context.Context, path string) {
	f.scan(ctx, path)
}

func (f *Folder) Contains(path string) bool {
	return uri.FolderContains(f.path, path)
}

func (f *Folder) scan(ctx context.Context, path string) {
	const method = "domain.ide.workspace.folder.scan"
	if !f.IsTrusted() {
		f.c.Logger().Warn().Str("path", path).Str("method", method).Msg("skipping scan of untrusted path")
		return
	}
	f.scanner.Scan(ctx, path, f.processResults, f.path)
}

func (f *Folder) processResults(scanData snyk.ScanData) {
	if scanData.Err != nil {
		f.sendScanError(scanData.Product, scanData.Err)
		return
	}
	// this also updates the severity counts in scan data, therefore we pass a pointer
	f.updateGlobalCacheAndSeverityCounts(&scanData)

	go sendAnalytics(&scanData)

	// Filter and publish cached diagnostics
	f.FilterAndPublishDiagnostics(scanData.Product)
}

func (f *Folder) sendScanError(product product.Product, err error) {
	f.scanNotifier.SendError(product, f.path, err.Error())
	f.c.Logger().Err(err).
		Str("method", "processResults").
		Str("product", string(product)).
		Msg("Product returned an error")
	f.notifier.SendErrorDiagnostic(f.path, err)
}

func (f *Folder) updateGlobalCacheAndSeverityCounts(scanData *snyk.ScanData) {
	var newCache = snyk.IssuesByFile{}
	var dedupMap = map[string]bool{}
	for _, issue := range scanData.Issues {
		if !f.Contains(issue.AffectedFilePath) {
			panic("issue found in scanData " + issue.AffectedFilePath + " that does not pertain to folder: " + f.path)
		}
		uniqueIssueID := f.getUniqueIssueID(issue)

		// only update global cache if we don't have scanner-local cache
		cacheProvider, isCacheProvider := f.scanner.(snyk.CacheProvider)
		if isCacheProvider && cacheProvider.IsProviderFor(issue.GetFilterableIssueType()) {
			// we expect the cache provider to do their own cache management and deduplication, but need deduplication for
			// severity counts here, too
			if !dedupMap[uniqueIssueID] {
				dedupMap[uniqueIssueID] = true
			}
			continue
		}

		// let's first remove the cache entry
		f.mutex.Lock()
		f.documentDiagnosticCache.Delete(issue.AffectedFilePath)
		f.mutex.Unlock()

		// global cache deduplication
		cachedIssues, found := newCache[issue.AffectedFilePath]
		if !found {
			cachedIssues = []snyk.Issue{}
		}

		if !dedupMap[uniqueIssueID] {
			dedupMap[uniqueIssueID] = true
			cachedIssues = append(cachedIssues, issue)
		}
		newCache[issue.AffectedFilePath] = cachedIssues
	}

	for path, issues := range newCache {
		f.mutex.Lock()
		f.documentDiagnosticCache.Store(path, issues)
		f.mutex.Unlock()
	}
}

func sendAnalytics(data *snyk.ScanData) {
	c := config.CurrentConfig()

	logger := c.Logger().With().Str("method", "folder.sendAnalytics").Logger()
	if data.Product == "" {
		logger.Debug().Any("data", data).Msg("Skipping analytics for empty product")
		return
	}

	if data.Err != nil {
		logger.Debug().Err(data.Err).Msg("Skipping analytics for error")
		return
	}

	// this information is not filled automatically, so we need to collect it
	categories := setupCategories(data, c)
	targetId, err := instrumentation.GetTargetId(data.Path, instrumentation.AutoDetectedTargetId)
	if err != nil {
		logger.Err(err).Msg("Error creating the Target Id")
	}
	summary := createTestSummary(data, c)

	param := types.AnalyticsEventParam{
		InteractionType: "Scan done",
		Category:        categories,
		Status:          string(gafanalytics.Success),
		TargetId:        targetId,
		TimestampMs:     data.TimestampFinished.UnixMilli(),
		DurationMs:      int64(data.DurationMs),
		Extension:       map[string]any{"is_delta_scan": data.IsDeltaScan},
	}

	ic := analytics.PayloadForAnalyticsEventParam(c, param)

	// test specific data is not handled in the PayloadForAnalytics helper
	// and must be added explicitly
	ic.SetTestSummary(summary)

	analyticsData, err := gafanalytics.GetV2InstrumentationObject(ic)
	if err != nil {
		logger.Err(err).Msg("Error creating the instrumentation collection object")
		return
	}

	v2InstrumentationData, err := json.Marshal(analyticsData)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to marshal analytics")
	}

	err = analytics.SendAnalyticsToAPI(c, v2InstrumentationData)
	if err != nil {
		logger.Err(err).Msg("Error sending analytics to API: " + string(v2InstrumentationData))
		return
	}
}

func setupCategories(data *snyk.ScanData, c *config.Config) []string {
	args := []string{data.Product.ToProductCodename(), "test"}
	args = append(args, c.CliSettings().AdditionalOssParameters...)
	categories := instrumentation.DetermineCategory(args, c.Engine())
	return categories
}

func createTestSummary(data *snyk.ScanData, c *config.Config) json_schemas.TestSummary {
	logger := c.Logger().With().Str("method", "folder.createTestSummary").Logger()
	sic := data.GetSeverityIssueCounts()
	testSummary := json_schemas.TestSummary{Type: string(data.Product)}

	if len(sic) == 0 {
		logger.Debug().Msgf("no scan issues found for product %v", string(data.Product))
		return testSummary
	}

	var results []json_schemas.TestSummaryResult
	results = appendTestResults(sic, results, snyk.Critical)
	results = appendTestResults(sic, results, snyk.High)
	results = appendTestResults(sic, results, snyk.Medium)
	results = appendTestResults(sic, results, snyk.Low)

	testSummary.Results = results

	return testSummary
}

func appendTestResults(sic snyk.SeverityIssueCounts, results []json_schemas.TestSummaryResult,
	severity snyk.Severity) []json_schemas.TestSummaryResult {
	if ic, exists := sic[severity]; exists {
		results = append(results, json_schemas.TestSummaryResult{
			Severity: severity.String(),
			Total:    ic.Total,
			Open:     ic.Open,
			Ignored:  ic.Ignored,
		})
	}
	return results
}

func (f *Folder) FilterAndPublishDiagnostics(p product.Product) {
	issueByProduct := f.IssuesByProduct()

	productIssuesByFile, err := f.getDelta(issueByProduct, p)
	if err != nil {
		// Error can only be returned from delta analysis. Other non delta scans are skipped with no errors.
		deltaErr := fmt.Errorf("couldn't determine the difference between current and base branch for %s scan. %w", p.ToProductNamesString(), err)
		f.sendScanError(p, deltaErr)
		return
	}
	filteredIssues := f.filterDiagnostics(productIssuesByFile[p])
	f.publishDiagnostics(p, filteredIssues)
}

// Error can only be returned from delta analysis. Other non delta scans are skipped with no errors.
func (f *Folder) getDelta(productIssueByFile snyk.ProductIssuesByFile, p product.Product) (snyk.ProductIssuesByFile, error) {
	logger := f.c.Logger().With().Str("method", "getDelta").Logger()
	if !f.c.IsDeltaFindingsEnabled() {
		return productIssueByFile, nil
	}

	if len(productIssueByFile[p]) == 0 {
		// If no issues found in current branch scan. We can't have deltas.
		return productIssueByFile, nil
	}

	baseIssueList, err := f.scanPersister.GetPersistedIssueList(f.path, p)
	if err != nil {
		logger.Err(err).Msg("Error getting persisted issue list")
		return nil, delta.ErrNoDeltaCalculated
	}

	currentFlatIssueList := getFlatIssueList(productIssueByFile, p)
	baseFindingIdentifiable := make([]delta.Identifiable, len(baseIssueList))
	for i := range baseIssueList {
		baseFindingIdentifiable[i] = &baseIssueList[i]
	}
	currentFindingIdentifiable := make([]delta.Identifiable, len(currentFlatIssueList))
	for i := range currentFlatIssueList {
		currentFindingIdentifiable[i] = &currentFlatIssueList[i]
	}

	df := delta2.NewDeltaFinderForProduct(p)
	diff, err := df.Diff(baseFindingIdentifiable, currentFindingIdentifiable)

	if err != nil {
		logger.Error().Err(err).Msg("couldn't calculate delta")
		return productIssueByFile, delta.ErrNoDeltaCalculated
	}

	deltaSnykIssues := make([]snyk.Issue, len(diff))
	for i := range diff {
		issue, ok := diff[i].(*snyk.Issue)
		if !ok {
			continue
		}
		deltaSnykIssues[i] = *issue
	}
	productIssueByFile[p] = getIssuePerFileFromFlatList(deltaSnykIssues)

	return productIssueByFile, nil
}

func getFlatIssueList(productIssueByFile snyk.ProductIssuesByFile, p product.Product) []snyk.Issue {
	issueByFile := productIssueByFile[p]
	var currentFlatIssueList []snyk.Issue
	for _, issueList := range issueByFile {
		currentFlatIssueList = append(currentFlatIssueList, issueList...)
	}
	return currentFlatIssueList
}

func getIssuePerFileFromFlatList(issueList []snyk.Issue) snyk.IssuesByFile {
	issueByFile := make(snyk.IssuesByFile)
	for _, issue := range issueList {
		list, exists := issueByFile[issue.AffectedFilePath]
		if !exists {
			list = []snyk.Issue{issue}
		} else {
			list = append(list, issue)
		}
		issueByFile[issue.AffectedFilePath] = list
	}
	return issueByFile
}

func (f *Folder) filterDiagnostics(issues snyk.IssuesByFile) snyk.IssuesByFile {
	supportedIssueTypes := config.CurrentConfig().DisplayableIssueTypes()
	filteredIssuesByFile := f.FilterIssues(issues, supportedIssueTypes)
	return filteredIssuesByFile
}

func (f *Folder) FilterIssues(issues snyk.IssuesByFile, supportedIssueTypes map[product.FilterableIssueType]bool) snyk.IssuesByFile {
	logger := f.c.Logger().With().Str("method", "FilterIssues").Logger()

	filteredIssues := snyk.IssuesByFile{}
	for path, issueSlice := range issues {
		if !f.Contains(path) {
			logger.Error().Msg("issue found in cache that does not pertain to folder")
			continue
		}
		for _, issue := range issueSlice {
			// Logging here will spam the logs
			if isVisibleSeverity(issue) && supportedIssueTypes[issue.GetFilterableIssueType()] {
				filteredIssues[path] = append(filteredIssues[path], issue)
			}
		}
	}
	return filteredIssues
}

func isVisibleSeverity(issue snyk.Issue) bool {
	logger := config.CurrentConfig().Logger().With().Str("method", "isVisibleSeverity").Logger()

	filterSeverity := config.CurrentConfig().FilterSeverity()
	logger.Debug().Interface("filterSeverity", filterSeverity).Msg("Filtering issues by severity")

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

func (f *Folder) publishDiagnostics(product product.Product, issuesByFile snyk.IssuesByFile) {
	f.sendHovers(issuesByFile)
	f.sendDiagnostics(issuesByFile)
	f.sendSuccess(product)
}

func (f *Folder) getUniqueIssueID(issue snyk.Issue) string {
	uniqueID := issue.AdditionalData.GetKey()
	return uniqueID
}

func (f *Folder) sendDiagnostics(issuesByFile snyk.IssuesByFile) {
	for path, issues := range issuesByFile {
		f.sendDiagnosticsForFile(path, issues)
	}
}

func (f *Folder) sendDiagnosticsForFile(path string, issues []snyk.Issue) {
	f.c.Logger().Debug().
		Str("method", "sendDiagnosticsForFile").
		Str("affectedFilePath", path).Int("issueCount", len(issues)).Send()

	f.notifier.Send(types.PublishDiagnosticsParams{
		URI:         uri.PathToUri(path),
		Diagnostics: converter.ToDiagnostics(issues),
	})
}

func (f *Folder) sendHovers(issuesByFile snyk.IssuesByFile) {
	for path, issues := range issuesByFile {
		f.sendHoversForFile(path, issues)
	}
}

func (f *Folder) sendHoversForFile(path string, issues []snyk.Issue) {
	f.hoverService.Channel() <- converter.ToHoversDocument(path, issues)
}

func (f *Folder) Path() string { return f.path }

func (f *Folder) Uri() lsp.DocumentURI { return uri.PathToUri(f.path) }

func (f *Folder) Name() string { return f.name }

func (f *Folder) Status() types.FolderStatus { return f.status }

func (f *Folder) IssuesForRange(filePath string, requestedRange snyk.Range) (matchingIssues []snyk.Issue) {
	method := "domain.ide.workspace.folder.getCodeActions"
	if !f.Contains(filePath) {
		panic("this folder should not be asked to handle " + filePath)
	}

	issues := f.IssuesForFile(filePath)
	for _, issue := range issues {
		if issue.Range.Overlaps(requestedRange) {
			f.c.Logger().Debug().Str("method", method).Msg("appending code action for issue " + issue.String())
			matchingIssues = append(matchingIssues, issue)
		}
	}

	f.c.Logger().Debug().Str("method", method).Msgf(
		"found %d code actions for %s, %s",
		len(matchingIssues),
		filePath,
		requestedRange,
	)
	return matchingIssues
}

func (f *Folder) IsTrusted() bool {
	if !config.CurrentConfig().IsTrustedFolderFeatureEnabled() {
		return true
	}
	for _, path := range config.CurrentConfig().TrustedFolders() {
		if uri.FolderContains(path, f.path) {
			return true
		}
	}
	return false
}

func (f *Folder) sendSuccess(processedProduct product.Product) {
	if processedProduct != "" {
		f.scanNotifier.SendSuccess(processedProduct, f.Path())
	} else {
		f.scanNotifier.SendSuccessForAllProducts(f.Path())
	}
}
