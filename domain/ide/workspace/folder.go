/*
 * © 2022-2026 Snyk Limited
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

// Package workspace implements an LSP workspace
package workspace

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/samber/lo"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk"
	delta2 "github.com/snyk/snyk-ls/domain/snyk/delta"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"
	context2 "github.com/snyk/snyk-ls/internal/context"

	"github.com/snyk/snyk-ls/internal/delta"

	"github.com/puzpuzpuz/xsync/v3"

	"github.com/snyk/snyk-ls/internal/types"

	gafanalytics "github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/instrumentation"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"

	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/infrastructure/analytics"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/uri"
)

var (
	_ snyk.CacheProvider                 = (*Folder)(nil)
	_ snyk.CachedIssuePaths              = (*Folder)(nil)
	_ snyk.IssueByCodeActionUUIDProvider = (*Folder)(nil)
	_ snyk.FilteringIssueProvider        = (*Folder)(nil)
	_ delta2.Provider                    = (*Folder)(nil)

	// hoverProductsAll is the fixed set of products for which DeleteHover may have state; used instead of
	// walking IssuesByProduct() (which rehydrates the full cache on bolt).
	hoverProductsAll = []product.Product{
		product.ProductOpenSource,
		product.ProductCode,
		product.ProductInfrastructureAsCode,
		product.ProductSecrets,
	}
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
	pendingEmptyDiagnostics *xsync.MapOf[types.FilePath, struct{}]
	scanner                 scanner.Scanner
	hoverService            hover.Service
	mutex                   sync.RWMutex
	scanNotifier            scanner.ScanNotifier
	notifier                noti.Notifier
	conf                    configuration.Configuration
	logger                  *zerolog.Logger
	scanPersister           persistence.ScanSnapshotPersister
	scanStateAggregator     scanstates.Aggregator
	featureFlagService      featureflag.Service
	configResolver          types.ConfigResolverInterface
	engine                  workflow.Engine
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

// IssueByCodeActionUUID delegates to the folder scanner when it implements IssueByCodeActionUUIDProvider
// (e.g. Code/OSS IssueCache with T1 index; IDE-1940 cp11r.6).
func (f *Folder) IssueByCodeActionUUID(id uuid.UUID) types.Issue {
	if id == uuid.Nil {
		return nil
	}
	if p, ok := f.scanner.(snyk.IssueByCodeActionUUIDProvider); ok {
		return p.IssueByCodeActionUUID(id)
	}
	return nil
}

func (f *Folder) Issues() snyk.IssuesByFile {
	// Union of paths from document cache and scanner (CachedPaths), then one decode per path.
	// Avoids scanner.Issues() → IssueCache.Issues() → BoltBackend.GetAll on large caches (cp11r.7).
	// Order per path matches the historical layout: global (document) issues first, then scanner-local.
	issues := snyk.IssuesByFile{}
	for _, path := range f.CachedPaths() {
		if !f.Contains(path) {
			f.logger.Error().Msg(fmt.Sprintf("issue found in cache that does not pertain to folder, path: %v", path))
			continue
		}
		var merged []types.Issue
		if globalIssues, ok := f.documentDiagnosticCache.Load(path); ok {
			merged = append(merged, globalIssues...)
		}
		if issueProvider, ok := f.scanner.(snyk.IssueProvider); ok {
			merged = append(merged, issueProvider.IssuesForFile(path)...)
		}
		if len(merged) > 0 {
			issues[path] = merged
		}
	}
	return issues
}

// CachedPaths returns unique file paths that have cached issues (document cache and/or scanner-local cache)
// without building the full Issues() map. Used by cp11r.7 to avoid BoltBackend.GetAll on hot paths.
func (f *Folder) CachedPaths() []types.FilePath {
	seen := make(map[types.FilePath]struct{})
	var out []types.FilePath
	f.documentDiagnosticCache.Range(func(path types.FilePath, _ []types.Issue) bool {
		if f.Contains(path) {
			if _, ok := seen[path]; !ok {
				seen[path] = struct{}{}
				out = append(out, path)
			}
		}
		return true
	})
	if pl, ok := f.scanner.(snyk.CachedIssuePaths); ok {
		for _, p := range pl.CachedPaths() {
			if !f.Contains(p) {
				continue
			}
			if _, exists := seen[p]; exists {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	} else if ip, ok := f.scanner.(snyk.IssueProvider); ok {
		for p := range ip.Issues() {
			if !f.Contains(p) {
				continue
			}
			if _, exists := seen[p]; exists {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out
}

func (f *Folder) IssuesByProduct() snyk.ProductIssuesByFile {
	issuesForProduct := snyk.ProductIssuesByFile{
		product.ProductOpenSource:           snyk.IssuesByFile{},
		product.ProductCode:                 snyk.IssuesByFile{},
		product.ProductInfrastructureAsCode: snyk.IssuesByFile{},
		product.ProductSecrets:              snyk.IssuesByFile{},
	}
	for _, path := range f.CachedPaths() {
		if !f.Contains(path) {
			f.logger.Error().Msg("issue found in cache that does not pertain to folder")
			continue
		}
		for _, issue := range f.IssuesForFile(path) {
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
	for _, path := range f.CachedPaths() {
		f.ClearIssues(path)
	}
	f.clearScannedStatus()
}

func (f *Folder) ClearIssues(path types.FilePath) {
	for _, p := range hoverProductsAll {
		f.hoverService.DeleteHover(p, path)
	}

	f.documentDiagnosticCache.Delete(path)
	f.markForEmptyDiagnostic(path)

	// let scanner-local cache handle its own stuff
	if cacheProvider, isCacheProvider := f.scanner.(snyk.CacheProvider); isCacheProvider {
		if f.Contains(path) {
			cacheProvider.ClearIssues(path)
		}
	}
}

// ClearIssuesByType lets a Folder satisfy snyk.CacheProvider end-to-end. It only
// touches the scanner-local cache for the matching product (no docCache wipe and
// no markForEmptyDiagnostic) because the caller is removing one product's findings,
// not the file as a whole — see Folder.ClearDiagnosticsByIssueType.
func (f *Folder) ClearIssuesByType(removedType product.FilterableIssueType, path types.FilePath) {
	if cacheProvider, isCacheProvider := f.scanner.(snyk.CacheProvider); isCacheProvider {
		if f.Contains(path) {
			cacheProvider.ClearIssuesByType(removedType, path)
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
	//
	// We MUST use ClearIssuesByType here, not ClearIssues: DelegatingConcurrentScanner /
	// TestScanner are multi-product CacheProviders, and ClearIssues(path) wipes every
	// product's cache at the given path. That would collateral-clear Code/IaC/Secrets
	// findings whenever an OSS-typed type is removed (and vice versa). ClearIssuesByType
	// only touches the child cache(s) that actually own removedType.
	if cacheProvider, isCacheProvider := f.scanner.(snyk.CacheProvider); isCacheProvider && cacheProvider.IsProviderFor(removedType) {
		if pl, ok := f.scanner.(snyk.CachedIssuePaths); ok {
			for _, path := range pl.CachedPaths() {
				if f.Contains(path) {
					cacheProvider.ClearIssuesByType(removedType, path)
				}
			}
		} else {
			issuesByFile := cacheProvider.Issues()
			for path := range issuesByFile {
				if f.Contains(path) {
					cacheProvider.ClearIssuesByType(removedType, path)
				}
			}
		}
	}
}

func NewFolder(
	path types.FilePath,
	name string,
	sc scanner.Scanner,
	hoverService hover.Service,
	scanNotifier scanner.ScanNotifier,
	notifier noti.Notifier,
	scanPersister persistence.ScanSnapshotPersister,
	scanStateAggregator scanstates.Aggregator,
	featureFlagService featureflag.Service,
	configResolver types.ConfigResolverInterface,
	engine workflow.Engine,
) *Folder {
	if _, isIssueProvider := sc.(snyk.IssueProvider); isIssueProvider {
		if _, ok := sc.(snyk.CachedIssuePaths); !ok {
			panic(fmt.Sprintf("workspace: scanner %T implements IssueProvider but not CachedIssuePaths (required for path enumeration without full cache reads)", sc))
		}
	}
	logger := engine.GetLogger()
	folder := Folder{
		scanner:             sc,
		path:                types.PathKey(path),
		name:                name,
		status:              Unscanned,
		hoverService:        hoverService,
		scanNotifier:        scanNotifier,
		notifier:            notifier,
		conf:                engine.GetConfiguration(),
		logger:              logger,
		scanPersister:       scanPersister,
		scanStateAggregator: scanStateAggregator,
		featureFlagService:  featureFlagService,
		configResolver:      configResolver,
		engine:              engine,
	}
	folder.documentDiagnosticCache = xsync.NewMapOf[types.FilePath, []types.Issue]()
	folder.pendingEmptyDiagnostics = xsync.NewMapOf[types.FilePath, struct{}]()
	if cacheProvider, isCacheProvider := sc.(snyk.CacheProvider); isCacheProvider {
		cacheProvider.RegisterCacheRemovalHandler(folder.markForEmptyDiagnostic)
	}

	return &folder
}

func (f *Folder) markForEmptyDiagnostic(path types.FilePath) {
	// IssueCache keeps a single cacheRemovalHandler (last RegisterCacheRemovalHandler wins).
	// With a shared DelegatingConcurrentScanner, multiple Folders register on the same
	// underlying caches; whichever handler is active runs for every eviction path. Without
	// this Contains() guard, a folder could enqueue a sibling's paths and postScanAction would
	// publish empty publishDiagnostics for URIs outside this folder, wiping the sibling's
	// just-published real issues in the IDE.
	if !f.Contains(path) {
		return
	}
	f.logger.Debug().Str("filePath", string(path)).Msg("marking file for empty diagnostic")
	f.pendingEmptyDiagnostics.Store(path, struct{}{})
}

func (f *Folder) postScanAction() {
	f.pendingEmptyDiagnostics.Range(func(path types.FilePath, _ struct{}) bool {
		f.pendingEmptyDiagnostics.Delete(path)
		if len(f.IssuesForFile(path)) == 0 {
			f.logger.Debug().Str("filePath", string(path)).Msg("sending empty diagnostic for file")
			f.sendDiagnosticsForFile(path, []types.Issue{})
		}
		return true
	})

	// Send the final HTML and tree view again, just in case the trigger was missed due to timing issues.
	f.scanStateAggregator.SummaryEmitter().Emit(f.scanStateAggregator.StateSnapshot())
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
		f.logger.Warn().Str("path", string(path)).Str("method", method).Msg("skipping scan of untrusted path")
		return
	}
	// TODO: move to DI
	folderConfig := config.GetFolderConfigFromEngine(f.engine, f.configResolver, f.path, f.logger)
	ctx = context2.NewContextWithFolderConfig(ctx, folderConfig)
	f.scanner.Scan(ctx, path, f.ProcessResults, f.postScanAction)
}

func (f *Folder) ProcessResults(ctx context.Context, scanData types.ScanData) {
	if scanData.Err != nil {
		f.sendScanError(scanData.Product, scanData.Err)
		return
	}

	// this also updates the severity counts in scan data, therefore we pass a pointer
	f.updateGlobalCacheAndSeverityCounts(&scanData)

	if err := f.enrichCachedIssuesWithDelta(scanData.Product); err != nil {
		f.logger.Debug().Err(err).
			Str("method", "ProcessResults").
			Str("product", string(scanData.Product)).
			Msg("failed to enrich cached issues with delta")
	}

	if scanData.IsReferenceScan && !f.IsDeltaFindingsEnabled() {
		return
	}

	go sendAnalytics(ctx, f.engine, f.configResolver, f.logger, &scanData)

	// Filter and publish cached diagnostics
	f.FilterAndPublishDiagnostics(scanData.Product)
}

func (f *Folder) sendScanError(product product.Product, err error) {
	f.scanNotifier.SendError(product, f.path, err.Error())
	f.logger.Err(err).
		Str("method", "ProcessResults").
		Str("product", string(product)).
		Msg("Product returned an error")
	f.notifier.SendErrorDiagnostic(f.path, err)
}

func (f *Folder) updateGlobalCacheAndSeverityCounts(scanData *types.ScanData) {
	if !scanData.UpdateGlobalCache {
		return
	}
	// OSS issues live in the scanner's IssueCache (memory or bolt); strip any legacy OSS rows from the per-file map
	// so Folder.Issues() does not double-count after CLIScanner became a CacheProvider.
	if scanData.Product == product.ProductOpenSource {
		f.stripIssuesOfProductFromDocumentCache(product.ProductOpenSource)
	}
	newCache := snyk.IssuesByFile{}
	dedupMap := map[string]bool{}
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

func (f *Folder) stripIssuesOfProductFromDocumentCache(p product.Product) {
	f.documentDiagnosticCache.Range(func(filePath types.FilePath, issues []types.Issue) bool {
		filtered := make([]types.Issue, 0, len(issues))
		for _, issue := range issues {
			if issue.GetProduct() != p {
				filtered = append(filtered, issue)
			}
		}
		if len(filtered) == len(issues) {
			return true
		}
		f.mutex.Lock()
		if len(filtered) == 0 {
			f.documentDiagnosticCache.Delete(filePath)
		} else {
			f.documentDiagnosticCache.Store(filePath, filtered)
		}
		f.mutex.Unlock()
		return true
	})
}

func sendAnalytics(ctx context.Context, engine workflow.Engine, configResolver types.ConfigResolverInterface, logger *zerolog.Logger, data *types.ScanData) {
	log := logger.With().Str("method", "folder.sendAnalytics").Logger()
	if !data.SendAnalytics {
		return
	}
	if data.Product == "" {
		log.Debug().Any("data", data).Msg("Skipping analytics for empty product")
		return
	}

	if data.Err != nil {
		log.Debug().Err(data.Err).Msg("Skipping analytics for error")
		return
	}

	// this information is not filled automatically, so we need to collect it
	folderConfig := config.GetFolderConfigFromEngine(engine, configResolver, data.Path, logger)
	categories := setupCategories(data, configResolver, engine, folderConfig)
	targetId, err := instrumentation.GetTargetId(string(data.Path), instrumentation.AutoDetectedTargetId)
	if err != nil {
		log.Err(err).Msg("Error creating the Target Id")
	}
	summary := createTestSummary(data, engine.GetConfiguration(), logger)

	extension := map[string]any{"is_delta_scan": data.IsDeltaScan}

	scanSource, ok := context2.ScanSourceFromContext(ctx)
	if ok {
		extension["scan_source"] = scanSource.String()
	}

	deltaScanType, ok := context2.DeltaScanTypeFromContext(ctx)
	if ok {
		extension["scan_type"] = deltaScanType.String()
	}

	param := types.AnalyticsEventParam{
		InteractionType: "Scan done",
		Category:        categories,
		Status:          string(gafanalytics.Success),
		TargetId:        targetId,
		TimestampMs:     data.TimestampFinished.UnixMilli(),
		DurationMs:      int64(data.Duration),
		Extension:       extension,
	}

	ic := analytics.PayloadForAnalyticsEventParam(engine, configResolver.GetString(types.SettingDeviceId, nil), param)

	// test specific data is not handled in the PayloadForAnalytics helper
	// and must be added explicitly
	ic.SetTestSummary(summary)

	analyticsData, err := gafanalytics.GetV2InstrumentationObject(ic)
	if err != nil {
		log.Err(err).Msg("Error creating the instrumentation collection object")
		return
	}

	v2InstrumentationData, err := json.Marshal(analyticsData)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal analytics")
	}

	folderOrg, err := config.FolderOrganizationForSubPath(config.GetWorkspace(engine.GetConfiguration()), engine.GetConfiguration(), data.Path, logger)
	if err != nil {
		log.Warn().Str("path", string(data.Path)).Err(err).Msg("Cannot send analytics: failed to get folder organization")
		return
	}
	err = analytics.SendAnalyticsToAPI(engine, configResolver.GetString(types.SettingDeviceId, nil), folderOrg, v2InstrumentationData)
	if err != nil {
		log.Err(err).Msg("Error sending analytics to API: " + string(v2InstrumentationData))
		return
	}
}

func setupCategories(data *types.ScanData, configResolver types.ConfigResolverInterface, engine workflow.Engine, folderConfig *types.FolderConfig) []string {
	args := []string{data.Product.ToProductCodename(), "test"}
	if params := configResolver.GetStringSlice(types.SettingCliAdditionalOssParameters, folderConfig); len(params) > 0 {
		args = append(args, params...)
	}
	categories := instrumentation.DetermineCategory(args, engine)
	return categories
}

func createTestSummary(data *types.ScanData, conf configuration.Configuration, logger *zerolog.Logger) json_schemas.TestSummary {
	log := logger.With().Str("method", "folder.createTestSummary").Logger()
	sic := data.GetSeverityIssueCounts()
	testSummary := json_schemas.TestSummary{Type: string(data.Product)}

	if len(sic) == 0 {
		log.Debug().Msgf("no scan issues found for product %v", string(data.Product))
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
	severity types.Severity,
) []json_schemas.TestSummaryResult {
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
	issuesByProduct := f.IssuesByProduct()

	filteredIssuesToSend := make(snyk.ProductIssuesByFile)
	for productName, issueByFile := range issuesByProduct {
		filteredIssues := f.filterDiagnostics(issueByFile)

		// filterDiagnostics removes empty paths, so we must loop through the list of paths and add empty slices back in,
		// as they represent the file potentially used to have diagnostics, but no longer does.
		productIssues := make(snyk.IssuesByFile, len(issueByFile))
		for path := range issueByFile {
			if filtered, ok := filteredIssues[path]; ok {
				productIssues[path] = filtered
			} else {
				productIssues[path] = []types.Issue{}
			}
		}
		filteredIssuesToSend[productName] = productIssues
	}

	f.publishDiagnostics(p, filteredIssuesToSend)
}

// GetDelta returns cached issues filtered by IsNew for the given product.
// Issues are enriched with IsNew at scan time via enrichCachedIssuesWithDelta
func (f *Folder) GetDelta(p product.Product) snyk.IssuesByFile {
	issueByFile := f.IssuesByProduct()[p]
	return filterByIsNew(issueByFile)
}

// enrichCachedIssuesWithDelta runs the delta computation once and stamps IsNew on cached issue pointers in-place.
// This must be called after scan results are stored in the cache (via updateGlobalCacheAndSeverityCounts).
func (f *Folder) enrichCachedIssuesWithDelta(p product.Product) error {
	logger := f.logger.With().
		Str("method", "enrichCachedIssuesWithDelta").
		Str("folderPath", string(f.path)).
		Str("product", string(p)).
		Logger()

	issueByFile := f.IssuesByProduct()[p]
	if len(issueByFile) == 0 {
		logger.Debug().Msg("no current issues, skipping enrichment")
		return nil
	}

	baseIssueList, err := f.scanPersister.GetPersistedIssueList(f.path, p)
	if err != nil {
		if errors.Is(err, persistence.ErrBaselineDoesntExist) {
			logger.Debug().Msg("delta findings unavailable - no baseline exists yet")
		} else {
			logger.Warn().Err(err).Msg("failed to get persisted issue list, snapshot may be corrupted")
		}
		return err
	}

	logger.Debug().Msgf("base issues count=%d", len(baseIssueList))

	baseFindingIdentifiable := make([]delta.Identifiable, len(baseIssueList))
	for i := range baseIssueList {
		baseFindingIdentifiable[i] = baseIssueList[i]
	}

	currentFlatIssueList := getFlatIssueList(issueByFile)
	logger.Debug().Msgf("current issues count=%d", len(currentFlatIssueList))

	currentFindingIdentifiable := make([]delta.Identifiable, len(currentFlatIssueList))
	for i := range currentFlatIssueList {
		currentFindingIdentifiable[i] = currentFlatIssueList[i]
		currentFindingIdentifiable[i].SetGlobalIdentity("")
	}

	df := delta2.NewDeltaFinderForProduct(p)
	_, err = df.DiffAndEnrich(baseFindingIdentifiable, currentFindingIdentifiable)
	if err != nil {
		logger.Error().Err(err).Msg("couldn't calculate delta for enrichment")
		return err
	}

	logger.Debug().Msg("enriched cached issues with delta IsNew flags")
	return nil
}

func getFlatIssueList(issueByFile snyk.IssuesByFile) []types.Issue {
	var currentFlatIssueList []types.Issue
	for _, issueList := range issueByFile {
		currentFlatIssueList = append(currentFlatIssueList, issueList...)
	}
	return currentFlatIssueList
}

func filterByIsNew(issues snyk.IssuesByFile) snyk.IssuesByFile {
	filtered := snyk.IssuesByFile{}
	for path, issueSlice := range issues {
		for _, issue := range issueSlice {
			if issue != nil && issue.GetIsNew() {
				filtered[path] = append(filtered[path], issue)
			}
		}
	}
	return filtered
}

func (f *Folder) filterDiagnostics(issues snyk.IssuesByFile) snyk.IssuesByFile {
	folderConfig := f.FolderConfigReadOnly()
	supportedIssueTypes := f.displayableIssueTypesForFolder(folderConfig)
	filteredIssuesByFile := f.filterIssuesWithConfig(issues, supportedIssueTypes, folderConfig)
	return filteredIssuesByFile
}

// FilterReason describes why an issue was filtered out
type FilterReason string

const (
	FilterReasonNotFiltered      FilterReason = ""
	FilterReasonUnsupportedType  FilterReason = "unsupported issue type"
	FilterReasonSeverity         FilterReason = "severity filter"
	FilterReasonRiskScore        FilterReason = "risk score threshold"
	FilterReasonIssueViewOptions FilterReason = "issue view options"
)

func (f *Folder) FilterIssues(
	issues snyk.IssuesByFile,
	supportedIssueTypes map[product.FilterableIssueType]bool,
) snyk.IssuesByFile {
	return f.filterIssuesWithConfig(issues, supportedIssueTypes, f.FolderConfigReadOnly())
}

// FilterIssuesForFile loads issues for one file and applies the same filtering as FilterIssues (cp11r.6).
func (f *Folder) FilterIssuesForFile(
	filePath types.FilePath,
	supportedIssueTypes map[product.FilterableIssueType]bool,
) snyk.IssuesByFile {
	single := snyk.IssuesByFile{filePath: f.IssuesForFile(filePath)}
	return f.FilterIssues(single, supportedIssueTypes)
}

// filterContext holds pre-resolved config values for the issue filtering loop.
// Resolving these once per filterIssuesWithConfig call (instead of per-issue) avoids
// repeated viper.AllKeys calls that dominate CPU and memory during scanning.
type filterContext struct {
	severityFilter           types.SeverityFilter
	riskScoreThreshold       int
	riskScoreEnabled         bool
	consistentIgnoresEnabled bool
	issueViewOptions         types.IssueViewOptions
}

func (f *Folder) buildFilterContext(folderConfig *types.FolderConfig) filterContext {
	ctx := filterContext{
		severityFilter:           f.filterSeverityForFolder(folderConfig),
		riskScoreEnabled:         featureflag.UseOsTestWorkflow(folderConfig),
		consistentIgnoresEnabled: folderConfig.GetFeatureFlag(featureflag.SnykCodeConsistentIgnores),
	}
	if ctx.riskScoreEnabled {
		ctx.riskScoreThreshold = f.riskScoreThresholdForFolder(folderConfig)
	}
	if ctx.consistentIgnoresEnabled {
		ctx.issueViewOptions = f.issueViewOptionsForFolder(folderConfig)
	}
	return ctx
}

func (f *Folder) filterIssuesWithConfig(
	issues snyk.IssuesByFile,
	supportedIssueTypes map[product.FilterableIssueType]bool,
	folderConfig *types.FolderConfig,
) snyk.IssuesByFile {
	logger := f.logger.With().Str("method", "FilterIssues").Logger()
	filteredIssues := snyk.IssuesByFile{}
	filterReasonCounts := make(map[FilterReason]int)

	if f.isDeltaFindingsEnabledForFolder(folderConfig) {
		issues = filterByIsNew(issues)
	}

	fCtx := f.buildFilterContext(folderConfig)

	for path, issueSlice := range issues {
		if !f.Contains(path) {
			logger.Error().Msg("issues found in cache that do not pertain to folder")
			continue
		}
		for _, issue := range issueSlice {
			filterReason := isIssueVisible(issue, supportedIssueTypes, &fCtx)
			if filterReason == FilterReasonNotFiltered {
				filteredIssues[path] = append(filteredIssues[path], issue)
			} else {
				filterReasonCounts[filterReason]++
			}
		}
	}

	if len(filterReasonCounts) > 0 {
		logger.Debug().Interface("filterReasons", filterReasonCounts).Msgf("%d issue(s) filtered", lo.Sum(lo.Values(filterReasonCounts)))
	} else {
		logger.Debug().Msg("No issues were filtered out")
	}

	return filteredIssues
}

func isIssueVisible(issue types.Issue, supportedIssueTypes map[product.FilterableIssueType]bool, fCtx *filterContext) FilterReason {
	if !supportedIssueTypes[issue.GetFilterableIssueType()] {
		return FilterReasonUnsupportedType
	}
	if !isVisibleSeverity(issue, &fCtx.severityFilter) {
		return FilterReasonSeverity
	}
	if fCtx.riskScoreEnabled && !isVisibleRiskScore(issue, fCtx.riskScoreThreshold) {
		return FilterReasonRiskScore
	}
	if fCtx.consistentIgnoresEnabled && !isVisibleForIssueViewOptions(issue, &fCtx.issueViewOptions) {
		return FilterReasonIssueViewOptions
	}
	return FilterReasonNotFiltered
}

func isVisibleSeverity(issue types.Issue, filter *types.SeverityFilter) bool {
	switch issue.GetSeverity() {
	case types.Critical:
		return filter.Critical
	case types.High:
		return filter.High
	case types.Medium:
		return filter.Medium
	case types.Low:
		return filter.Low
	}
	return false
}

func isVisibleRiskScore(issue types.Issue, riskScoreThreshold int) bool {
	switch {
	case riskScoreThreshold == 0:
		return true
	case riskScoreThreshold < 0:
		return true
	case riskScoreThreshold > 1000:
		return false
	}

	additionalData := issue.GetAdditionalData()
	ossIssueData, ok := additionalData.(snyk.OssIssueData)
	if !ok {
		return true
	}

	issueRiskScore := ossIssueData.RiskScore
	if issueRiskScore == 0 {
		return true
	}

	return issueRiskScore >= uint16(riskScoreThreshold)
}

func isVisibleForIssueViewOptions(issue types.Issue, opts *types.IssueViewOptions) bool {
	if issue.GetIsIgnored() {
		return opts.IgnoredIssues
	}
	return opts.OpenIssues
}

func (f *Folder) publishDiagnostics(p product.Product, issuesToSendByProduct snyk.ProductIssuesByFile) {
	f.sendHovers(p, issuesToSendByProduct[p])
	f.sendDiagnostics(issuesToSendByProduct.AggregateFromAllProducts(p))
	scanErr := f.scanStateAggregator.GetScanErr(f.path, p, f.IsDeltaFindingsEnabled())
	if scanErr != nil {
		f.sendScanError(p, scanErr)
	} else {
		f.sendSuccess(p)
	}
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
	f.logger.Debug().
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
	// TODO: move to DI
	f.hoverService.Channel() <- converter.ToHoversDocument(f.engine, f.configResolver, p, path, issues, f.FolderConfigReadOnly())
}

func (f *Folder) Path() types.FilePath { return f.path }

func (f *Folder) Uri() lsp.DocumentURI { return uri.PathToUri(f.path) }

func (f *Folder) Name() string { return f.name }

func (f *Folder) Status() types.FolderStatus { return f.status }

// FolderConfigReadOnly returns the FolderConfig for this folder using read-only access
// (no storage writes, no Git enrichment). For operations that need to create or update
// the config, use config.GetFolderConfigFromEngine() directly.
func (f *Folder) FolderConfigReadOnly() *types.FolderConfig {
	// TODO: move to DI
	return config.GetUnenrichedFolderConfigFromEngine(f.engine, f.configResolver, f.path, f.logger)
}

// IsDeltaFindingsEnabled returns whether delta findings is enabled for this folder.
func (f *Folder) IsDeltaFindingsEnabled() bool {
	return f.isDeltaFindingsEnabledForFolder(f.FolderConfigReadOnly())
}

// IsAutoScanEnabled returns whether automatic scanning is enabled for this folder.
func (f *Folder) IsAutoScanEnabled() bool {
	return f.isAutoScanEnabledForFolder(f.FolderConfigReadOnly())
}

// DisplayableIssueTypes returns which issue types are enabled for this folder.
func (f *Folder) DisplayableIssueTypes() map[product.FilterableIssueType]bool {
	return f.displayableIssueTypesForFolder(f.FolderConfigReadOnly())
}

func (f *Folder) IssuesForRange(path types.FilePath, r types.Range) (matchingIssues []types.Issue) {
	method := "domain.ide.workspace.folder.getCodeActions"
	if !f.Contains(path) {
		panic("this folder should not be asked to handle " + path)
	}

	issues := f.IssuesForFile(path)
	for _, issue := range issues {
		if issue.GetRange().Overlaps(r) {
			f.logger.Trace().Str("method", method).Msg("appending code action for issue " + issue.String())
			matchingIssues = append(matchingIssues, issue)
		}
	}

	f.logger.Debug().Str("method", method).Msgf(
		"found %d code actions for %s, %s",
		len(matchingIssues),
		path,
		r,
	)
	return matchingIssues
}

func (f *Folder) IsTrusted() bool {
	if !f.configResolver.GetBool(types.SettingTrustEnabled, nil) {
		return true
	}
	val, _ := f.configResolver.GetValue(types.SettingTrustedFolders, nil)
	trustedFolders, _ := val.([]types.FilePath)
	for _, path := range trustedFolders {
		if uri.FolderContains(path, f.path) {
			return true
		}
	}
	return false
}

func (f *Folder) filterSeverityForFolder(folderConfig *types.FolderConfig) types.SeverityFilter {
	return f.configResolver.FilterSeverityForFolder(folderConfig)
}

func (f *Folder) riskScoreThresholdForFolder(folderConfig *types.FolderConfig) int {
	return f.configResolver.RiskScoreThresholdForFolder(folderConfig)
}

func (f *Folder) issueViewOptionsForFolder(folderConfig *types.FolderConfig) types.IssueViewOptions {
	return f.configResolver.IssueViewOptionsForFolder(folderConfig)
}

func (f *Folder) isDeltaFindingsEnabledForFolder(folderConfig *types.FolderConfig) bool {
	return f.configResolver.IsDeltaFindingsEnabledForFolder(folderConfig)
}

func (f *Folder) isAutoScanEnabledForFolder(folderConfig *types.FolderConfig) bool {
	return f.configResolver.IsAutoScanEnabledForFolder(folderConfig)
}

func (f *Folder) displayableIssueTypesForFolder(folderConfig *types.FolderConfig) map[product.FilterableIssueType]bool {
	return f.configResolver.DisplayableIssueTypesForFolder(folderConfig)
}

func (f *Folder) sendSuccess(processedProduct product.Product) {
	// TODO: move to DI
	folderConfig := config.GetUnenrichedFolderConfigFromEngine(f.engine, f.configResolver, f.path, f.logger)
	if processedProduct != "" {
		f.scanNotifier.SendSuccess(processedProduct, folderConfig)
	} else {
		f.scanNotifier.SendSuccessForAllProducts(folderConfig)
	}
}
