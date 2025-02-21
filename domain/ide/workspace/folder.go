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

	"github.com/snyk/snyk-ls/domain/scanstates"
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
	path                    types.FilePath
	name                    string
	status                  types.FolderStatus
	documentDiagnosticCache *xsync.MapOf[types.FilePath, []types.Issue]
	scanner                 scanner.Scanner
	hoverService            hover.Service
	mutex                   sync.RWMutex
	scanNotifier            scanner.ScanNotifier
	notifier                noti.Notifier
	c                       *config.Config
	scanPersister           persistence.ScanSnapshotPersister
	scanStateAggregator     scanstates.Aggregator
}

func (f *Folder) ScanResultProcessor() types.ScanResultProcessor {
	return f.ProcessResults
}

func (f *Folder) Issue(key string) types.Issue {
	var foundIssue types.Issue
	f.documentDiagnosticCache.Range(func(filePath types.FilePath, issues []types.Issue) bool {
		for _, i := range issues {
			if i.GetAdditionalData().GetKey() == key {
				foundIssue = i
				return false
			}
		}
		return true
	})

	if foundIssue == nil || foundIssue.GetID() == "" {
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
	f.documentDiagnosticCache.Range(func(path types.FilePath, value []types.Issue) bool {
		filePath := path
		if f.Contains(filePath) {
			issues[filePath] = value
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
			p := issue.GetProduct()
			issuesForProduct[p][path] = append(issuesForProduct[p][path], issue)
		}
	}
	return issuesForProduct
}

func (f *Folder) IssuesForFile(path types.FilePath) []types.Issue {
	// try to delegate to scanners first
	var issues []types.Issue
	if issueProvider, ok := f.scanner.(snyk.IssueProvider); ok {
		issues = append(issues, issueProvider.IssuesForFile(path)...)
	}
	globalIssues, ok := f.documentDiagnosticCache.Load(path)
	if ok {
		issues = append(issues, globalIssues...)
	}
	return issues
}

func (f *Folder) IsProviderFor(_ product.FilterableIssueType) bool {
	// it either caches itself, or uses the global folder caching mechanism
	return true
}

func (f *Folder) RegisterCacheRemovalHandler(handler func(path types.FilePath)) {
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

func (f *Folder) ClearIssues(path types.FilePath) {
	// Delete hovers
	for p := range f.IssuesByProduct() {
		for filePath := range f.IssuesByProduct()[p] {
			if filePath != path {
				continue
			}
			f.hoverService.DeleteHover(p, path)
		}
	}

	f.documentDiagnosticCache.Delete(path)
	f.sendEmptyDiagnosticForFile(path) // this is done automatically by the scanner removal handler (we hope)

	// let scanner-local cache handle its own stuff
	if cacheProvider, isCacheProvider := f.scanner.(snyk.CacheProvider); isCacheProvider {
		if f.Contains(path) {
			cacheProvider.ClearIssues(path)
		}
	}
}

func (f *Folder) clearScannedStatus() {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.status = Unscanned
}

func (f *Folder) ClearDiagnosticsByIssueType(removedType product.FilterableIssueType) {
	f.documentDiagnosticCache.Range(func(filePath types.FilePath, previousIssues []types.Issue) bool {
		newIssues := make([]types.Issue, 0)
		for _, issue := range previousIssues {
			if issue.GetFilterableIssueType() != removedType {
				newIssues = append(newIssues, issue)
			}
		}

		if len(previousIssues) != len(newIssues) {
			if f.Contains(filePath) {
				f.documentDiagnosticCache.Store(filePath, newIssues)
				f.sendDiagnosticsForFile(filePath, newIssues)
				f.sendHoversForFile(removedType.ToProduct(), filePath, newIssues)
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
	path types.FilePath,
	name string,
	scanner scanner.Scanner,
	hoverService hover.Service,
	scanNotifier scanner.ScanNotifier,
	notifier noti.Notifier,
	scanPersister persistence.ScanSnapshotPersister,
	scanStateAggregator scanstates.Aggregator,
) *Folder {
	folder := Folder{
		scanner:             scanner,
		path:                types.FilePath(strings.TrimSuffix(string(path), "/")),
		name:                name,
		status:              Unscanned,
		hoverService:        hoverService,
		scanNotifier:        scanNotifier,
		notifier:            notifier,
		c:                   c,
		scanPersister:       scanPersister,
		scanStateAggregator: scanStateAggregator,
	}
	folder.documentDiagnosticCache = xsync.NewMapOf[types.FilePath, []types.Issue]()
	if cacheProvider, isCacheProvider := scanner.(snyk.CacheProvider); isCacheProvider {
		cacheProvider.RegisterCacheRemovalHandler(folder.sendEmptyDiagnosticForFile)
	}
	return &folder
}

func (f *Folder) sendEmptyDiagnosticForFile(path types.FilePath) {
	f.c.Logger().Debug().Str("filePath", string(path)).Msg("sending empty diagnostic for file")
	f.sendDiagnosticsForFile(path, []types.Issue{})
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

func (f *Folder) ScanFile(ctx context.Context, path types.FilePath) {
	f.scan(ctx, path)
}

func (f *Folder) Contains(path types.FilePath) bool {
	return uri.FolderContains(f.path, path)
}

func (f *Folder) scan(ctx context.Context, path types.FilePath) {
	const method = "domain.ide.workspace.folder.scan"
	if !f.IsTrusted() {
		f.c.Logger().Warn().Str("path", string(path)).Str("method", method).Msg("skipping scan of untrusted path")
		return
	}
	f.scanner.Scan(ctx, path, f.ProcessResults, f.path)
}

func (f *Folder) ProcessResults(ctx context.Context, scanData types.ScanData) {
	if scanData.Err != nil {
		f.sendScanError(scanData.Product, scanData.Err)
		return
	}

	// this also updates the severity counts in scan data, therefore we pass a pointer
	f.updateGlobalCacheAndSeverityCounts(&scanData)

	go sendAnalytics(f.c, &scanData)

	// Filter and publish cached diagnostics
	f.FilterAndPublishDiagnostics(scanData.Product)
}

func (f *Folder) sendScanError(product product.Product, err error) {
	f.scanNotifier.SendError(product, f.path, err.Error())
	f.c.Logger().Err(err).
		Str("method", "ProcessResults").
		Str("product", string(product)).
		Msg("Product returned an error")
	f.notifier.SendErrorDiagnostic(f.path, err)
}

func (f *Folder) updateGlobalCacheAndSeverityCounts(scanData *types.ScanData) {
	if !scanData.UpdateGlobalCache {
		return
	}
	var newCache = snyk.IssuesByFile{}
	var dedupMap = map[string]bool{}
	for _, issue := range scanData.Issues {
		if !f.Contains(issue.GetAffectedFilePath()) {
			msg := "issue found in scanData " + issue.GetAffectedFilePath() + " that does not pertain to folder: " + f.path
			panic(msg)
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
		f.documentDiagnosticCache.Delete(issue.GetAffectedFilePath())
		f.mutex.Unlock()

		// global cache deduplication
		cachedIssues, found := newCache[issue.GetAffectedFilePath()]
		if !found {
			cachedIssues = []types.Issue{}
		}

		if !dedupMap[uniqueIssueID] {
			dedupMap[uniqueIssueID] = true
			cachedIssues = append(cachedIssues, issue)
		}
		newCache[issue.GetAffectedFilePath()] = cachedIssues
	}

	for path, issues := range newCache {
		f.mutex.Lock()
		f.documentDiagnosticCache.Store(path, issues)
		f.mutex.Unlock()
	}
}

func sendAnalytics(c *config.Config, data *types.ScanData) {
	logger := c.Logger().With().Str("method", "folder.sendAnalytics").Logger()
	if !data.SendAnalytics {
		return
	}
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
	targetId, err := instrumentation.GetTargetId(string(data.Path), instrumentation.AutoDetectedTargetId)
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

func setupCategories(data *types.ScanData, c *config.Config) []string {
	args := []string{data.Product.ToProductCodename(), "test"}
	args = append(args, c.CliSettings().AdditionalOssParameters...)
	categories := instrumentation.DetermineCategory(args, c.Engine())
	return categories
}

func createTestSummary(data *types.ScanData, c *config.Config) json_schemas.TestSummary {
	logger := c.Logger().With().Str("method", "folder.createTestSummary").Logger()
	sic := data.GetSeverityIssueCounts()
	testSummary := json_schemas.TestSummary{Type: string(data.Product)}

	if len(sic) == 0 {
		logger.Debug().Msgf("no scan issues found for product %v", string(data.Product))
		return testSummary
	}

	var results []json_schemas.TestSummaryResult
	results = appendTestResults(sic, results, types.Critical)
	results = appendTestResults(sic, results, types.High)
	results = appendTestResults(sic, results, types.Medium)
	results = appendTestResults(sic, results, types.Low)

	testSummary.Results = results

	return testSummary
}

func appendTestResults(sic types.SeverityIssueCounts, results []json_schemas.TestSummaryResult,
	severity types.Severity) []json_schemas.TestSummaryResult {
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
	issueByFile := f.IssuesByProduct()[p]

	// Trigger publishDiagnostics for all issues in Cache.
	// Filtered issues will be sent with an empty slice if no issues exist.
	filteredIssues := f.filterDiagnostics(issueByFile)
	filteredIssuesToSend := snyk.IssuesByFile{}

	for path := range f.IssuesByProduct()[p] {
		filteredIssuesToSend[path] = []types.Issue{}
	}

	for path, issues := range filteredIssues {
		filteredIssuesToSend[path] = issues
	}
	f.publishDiagnostics(p, filteredIssuesToSend)
}

func (f *Folder) GetDelta(p product.Product) (snyk.IssuesByFile, error) {
	logger := f.c.Logger().With().Str("method", "getDelta").Logger()
	issueByFile := f.IssuesByProduct()[p]

	if len(issueByFile) == 0 {
		// If no issues found in current branch scan. We can't have deltas.
		return issueByFile, nil
	}

	baseIssueList, err := f.scanPersister.GetPersistedIssueList(f.path, p)
	if err != nil {
		return nil, err
	}

	baseFindingIdentifiable := make([]delta.Identifiable, len(baseIssueList))
	for i := range baseIssueList {
		baseFindingIdentifiable[i] = baseIssueList[i]
	}

	currentFlatIssueList := getFlatIssueList(issueByFile)
	currentFindingIdentifiable := make([]delta.Identifiable, len(currentFlatIssueList))
	for i := range currentFlatIssueList {
		currentFindingIdentifiable[i] = currentFlatIssueList[i]
	}

	df := delta2.NewDeltaFinderForProduct(p)
	enrichedIssues, err := df.DiffAndEnrich(baseFindingIdentifiable, currentFindingIdentifiable)

	if err != nil {
		logger.Error().Err(err).Msg("couldn't calculate delta")
		return issueByFile, err
	}

	deltaSnykIssues := []types.Issue{}
	for i := range enrichedIssues {
		identifiable := enrichedIssues[i]
		if identifiable == nil || !identifiable.GetIsNew() {
			continue
		}

		issue, ok := identifiable.(types.Issue)
		if ok && issue != nil {
			deltaSnykIssues = append(deltaSnykIssues, issue)
		}
	}
	issueByFile = getIssuePerFileFromFlatList(deltaSnykIssues)

	return issueByFile, nil
}

func getFlatIssueList(issueByFile snyk.IssuesByFile) []types.Issue {
	var currentFlatIssueList []types.Issue
	for _, issueList := range issueByFile {
		currentFlatIssueList = append(currentFlatIssueList, issueList...)
	}
	return currentFlatIssueList
}

func getIssuePerFileFromFlatList(issueList []types.Issue) snyk.IssuesByFile {
	issueByFile := make(snyk.IssuesByFile)
	for _, issue := range issueList {
		if issue == nil {
			continue
		}
		list, exists := issueByFile[issue.GetAffectedFilePath()]
		if !exists {
			list = []types.Issue{issue}
		} else {
			list = append(list, issue)
		}
		issueByFile[issue.GetAffectedFilePath()] = list
	}
	return issueByFile
}

func (f *Folder) filterDiagnostics(issues snyk.IssuesByFile) snyk.IssuesByFile {
	supportedIssueTypes := f.c.DisplayableIssueTypes()
	filteredIssuesByFile := f.FilterIssues(issues, supportedIssueTypes)
	return filteredIssuesByFile
}

func (f *Folder) GetDeltaForAllProducts(supportedIssueTypes map[product.FilterableIssueType]bool) []types.Issue {
	var deltaList []types.Issue
	for filterableIssueType, enabled := range supportedIssueTypes {
		// analyze deltas for code only for code security
		if !enabled || filterableIssueType == product.FilterableIssueTypeCodeQuality {
			continue
		}
		p := filterableIssueType.ToProduct()
		deltaIssueByFile, err := f.GetDelta(p)
		if err == nil {
			deltaList = append(deltaList, getFlatIssueList(deltaIssueByFile)...)
		}
	}
	return deltaList
}

func (f *Folder) FilterIssues(
	issues snyk.IssuesByFile,
	supportedIssueTypes map[product.FilterableIssueType]bool,
) snyk.IssuesByFile {
	logger := f.c.Logger().With().Str("method", "FilterIssues").Logger()
	filteredIssues := snyk.IssuesByFile{}

	if f.c.IsDeltaFindingsEnabled() {
		deltaForAllProducts := f.GetDeltaForAllProducts(supportedIssueTypes)
		issues = getIssuePerFileFromFlatList(deltaForAllProducts)
	}

	for path, issueSlice := range issues {
		if !f.Contains(path) {
			logger.Error().Msg("issue found in cache that does not pertain to folder")
			continue
		}
		for _, issue := range issueSlice {
			// Logging here will spam the logs
			if isVisibleSeverity(f.c, issue) && supportedIssueTypes[issue.GetFilterableIssueType()] {
				filteredIssues[path] = append(filteredIssues[path], issue)
			}
		}
	}
	return filteredIssues
}

func isVisibleSeverity(c *config.Config, issue types.Issue) bool {
	logger := c.Logger().With().Str("method", "isVisibleSeverity").Logger()

	filterSeverity := c.FilterSeverity()
	logger.Debug().Interface("filterSeverity", filterSeverity).Msg("Filtering issues by severity")

	switch issue.GetSeverity() {
	case types.Critical:
		return c.FilterSeverity().Critical
	case types.High:
		return c.FilterSeverity().High
	case types.Medium:
		return c.FilterSeverity().Medium
	case types.Low:
		return c.FilterSeverity().Low
	}
	return false
}

func (f *Folder) publishDiagnostics(p product.Product, issuesByFile snyk.IssuesByFile) {
	f.scanStateAggregator.SummaryEmitter().Emit(f.scanStateAggregator.StateSnapshot())
	f.sendHovers(p, issuesByFile)
	f.sendDiagnostics(issuesByFile)
	deltaErr := f.hasDeltaError(p)
	if deltaErr != nil {
		f.sendScanError(p, deltaErr)
	} else {
		f.sendSuccess(p)
	}
}

func (f *Folder) hasDeltaError(p product.Product) error {
	if f.c.IsDeltaFindingsEnabled() {
		return f.scanStateAggregator.GetScanErr(f.path, p, true)
	}
	return nil
}

func (f *Folder) getUniqueIssueID(issue types.Issue) string {
	uniqueID := issue.GetAdditionalData().GetKey()
	return uniqueID
}

func (f *Folder) sendDiagnostics(issuesByFile snyk.IssuesByFile) {
	for path, issues := range issuesByFile {
		f.sendDiagnosticsForFile(path, issues)
	}
}

func (f *Folder) sendDiagnosticsForFile(path types.FilePath, issues []types.Issue) {
	f.c.Logger().Debug().
		Str("method", "sendDiagnosticsForFile").
		Str("affectedFilePath", string(path)).Int("issueCount", len(issues)).Send()

	f.notifier.Send(types.PublishDiagnosticsParams{
		URI:         uri.PathToUri(path),
		Diagnostics: converter.ToDiagnostics(issues),
	})
}

func (f *Folder) sendHovers(p product.Product, issuesByFile snyk.IssuesByFile) {
	for path, issues := range issuesByFile {
		if len(issues) == 0 {
			f.hoverService.DeleteHover(p, path)
		} else {
			f.sendHoversForFile(p, path, issues)
		}
	}
}

func (f *Folder) sendHoversForFile(p product.Product, path types.FilePath, issues []types.Issue) {
	f.hoverService.Channel() <- converter.ToHoversDocument(p, path, issues)
}

func (f *Folder) Path() types.FilePath { return f.path }

func (f *Folder) Uri() lsp.DocumentURI { return uri.PathToUri(f.path) }

func (f *Folder) Name() string { return f.name }

func (f *Folder) Status() types.FolderStatus { return f.status }

func (f *Folder) IssuesForRange(path types.FilePath, r types.Range) (matchingIssues []types.Issue) {
	method := "domain.ide.workspace.folder.getCodeActions"
	if !f.Contains(path) {
		panic("this folder should not be asked to handle " + path)
	}

	issues := f.IssuesForFile(path)
	for _, issue := range issues {
		if issue.GetRange().Overlaps(r) {
			f.c.Logger().Debug().Str("method", method).Msg("appending code action for issue " + issue.String())
			matchingIssues = append(matchingIssues, issue)
		}
	}

	f.c.Logger().Debug().Str("method", method).Msgf(
		"found %d code actions for %s, %s",
		len(matchingIssues),
		path,
		r,
	)
	return matchingIssues
}

func (f *Folder) IsTrusted() bool {
	if !f.c.IsTrustedFolderFeatureEnabled() {
		return true
	}
	for _, path := range f.c.TrustedFolders() {
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
