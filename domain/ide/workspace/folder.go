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
	"runtime"
	"strings"
	"sync"

	"github.com/puzpuzpuz/xsync/v3"
	"github.com/rs/zerolog/log"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	noti "github.com/snyk/snyk-ls/domain/ide/notification"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/analytics"
	"github.com/snyk/snyk-ls/internal/lsp"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/uri"
)

type FolderStatus int

const (
	Unscanned FolderStatus = iota
	Scanned   FolderStatus = iota
)

var (
	os = map[string]string{
		"darwin":  "macOS",
		"linux":   "linux",
		"windows": "windows",
	}

	arch = map[string]string{
		"amd64": "x86_64",
		"arm64": "arm64",
		"386":   "386",
	}

	_ snyk.CacheProvider = (*Folder)(nil)
)

// TODO: 3: Extract reporting logic to a separate service

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
	scanNotifier            snyk.ScanNotifier
	notifier                noti.Notifier
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
		if scanner, ok := f.scanner.(snyk.IssueProvider); ok {
			foundIssue = scanner.Issue(key)
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
			panic("issue found in cache that does not pertain to folder")
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
	issuesForProduct := snyk.ProductIssuesByFile{}
	for path, issues := range f.Issues() {
		if !f.Contains(path) {
			panic("issue found in cache that does not pertain to folder")
		}
		for _, issue := range issues {
			p := issue.Product
			productIssuesByFile := issuesForProduct[p]
			if productIssuesByFile == nil {
				productIssuesByFile = snyk.IssuesByFile{}
			}
			productIssuesByFile[path] = append(productIssuesByFile[path], issue)
			issuesForProduct[p] = productIssuesByFile
		}
	}
	return issuesForProduct
}

func (f *Folder) IssuesForFile(file string) []snyk.Issue {
	// try to delegate to scanners first
	var issues []snyk.Issue
	if scanner, ok := f.scanner.(snyk.IssueProvider); ok {
		issues = append(issues, scanner.IssuesForFile(file)...)
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
		newIssues := []snyk.Issue{}
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

func NewFolder(path string, name string, scanner snyk.Scanner, hoverService hover.Service, scanNotifier snyk.ScanNotifier, notifier noti.Notifier) *Folder {
	folder := Folder{
		scanner:      scanner,
		path:         strings.TrimSuffix(path, "/"),
		name:         name,
		status:       Unscanned,
		hoverService: hoverService,
		scanNotifier: scanNotifier,
		notifier:     notifier,
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
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return f.status == Scanned
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

func (f *Folder) scan(ctx context.Context, path string) {
	const method = "domain.ide.workspace.folder.scan"
	if !f.IsTrusted() {
		log.Warn().Str("path", path).Str("method", method).Msg("skipping scan of untrusted path")
		return
	}

	f.scanner.Scan(ctx, path, f.processResults, f.path)
}

func (f *Folder) processResults(scanData snyk.ScanData) {
	if scanData.Err != nil {
		f.scanNotifier.SendError(scanData.Product, f.path)
		log.Err(scanData.Err).
			Str("method", "processResults").
			Str("product", string(scanData.Product)).
			Msg("Product returned an error")
		return
	}

	// this also updates the severity counts in scan data, therefore we pass a pointer
	f.updateGlobalCacheAndSeverityCounts(&scanData)

	go sendAnalytics(&scanData)

	// Filter and publish cached diagnostics
	f.FilterAndPublishDiagnostics(f.IssuesByProduct()[scanData.Product])
}

func (f *Folder) updateGlobalCacheAndSeverityCounts(scanData *snyk.ScanData) {
	var newCache = snyk.IssuesByFile{}
	var dedupMap = map[string]bool{}
	for _, issue := range scanData.Issues {
		if !f.Contains(issue.AffectedFilePath) {
			panic("issue found in scanData that does not pertain to folder")
		}
		uniqueIssueID := f.getUniqueIssueID(issue)

		// only update global cache if we don't have scanner-local cache
		cacheProvider, isCacheProvider := f.scanner.(snyk.CacheProvider)
		if isCacheProvider && cacheProvider.IsProviderFor(issue.GetFilterableIssueType()) {
			// we expect the cache provider to do their own cache management and deduplication, but need deduplication for
			// severity counts here, too
			if !dedupMap[uniqueIssueID] {
				dedupMap[uniqueIssueID] = true
				incrementSeverityCount(scanData, issue)
			}
			continue
		}

		// let's first remove the cache entry
		f.documentDiagnosticCache.Delete(issue.AffectedFilePath)

		// global cache deduplication
		cachedIssues, found := newCache[issue.AffectedFilePath]
		if !found {
			cachedIssues = []snyk.Issue{}
		}

		if !dedupMap[uniqueIssueID] {
			dedupMap[uniqueIssueID] = true
			cachedIssues = append(cachedIssues, issue)
			incrementSeverityCount(scanData, issue)
		}
		newCache[issue.AffectedFilePath] = cachedIssues
	}

	for path, issues := range newCache {
		f.documentDiagnosticCache.Store(path, issues)
	}
}

func incrementSeverityCount(scanData *snyk.ScanData, issue snyk.Issue) {
	issueProduct := issue.Product
	if issueProduct == "" {
		log.Debug().Str("method", "incrementSeverityCount").Msg("Issue product is empty. Setting to unknown")
		issueProduct = "unknown"
	}

	initializeSeverityCountForProduct(scanData, issueProduct)

	severityCount, exists := scanData.SeverityCount[issueProduct]
	if !exists {
		severityCount = snyk.SeverityCount{}
	}

	switch issue.Severity {
	case snyk.Critical:
		severityCount.Critical++
	case snyk.High:
		severityCount.High++
	case snyk.Medium:
		severityCount.Medium++
	case snyk.Low:
		severityCount.Low++
	}

	scanData.SeverityCount[issueProduct] = severityCount // reassign the value to the map
}

func initializeSeverityCountForProduct(scanData *snyk.ScanData, productType product.Product) {
	if scanData.SeverityCount == nil {
		scanData.SeverityCount = make(map[product.Product]snyk.SeverityCount)
	}

	if productType == "" {
		log.Debug().Str("method", "initializeSeverityCountForProduct").Msg("Product is empty. Setting to unknown")
		productType = "unknown"
	}

	if _, exists := scanData.SeverityCount[productType]; !exists {
		scanData.SeverityCount[productType] = snyk.SeverityCount{}
	}
}

func sendAnalytics(data *snyk.ScanData) {
	initializeSeverityCountForProduct(data, data.Product)

	c := config.CurrentConfig()
	gafConfig := c.Engine().GetConfiguration()

	logger := c.Logger().With().Str("method", "folder.sendAnalytics").Logger()
	if data.Product == "" {
		logger.Debug().Any("data", data).Msg("Skipping analytics for empty product")
		return
	}

	if data.Err != nil {
		logger.Debug().Err(data.Err).Msg("Skipping analytics for error")
		return
	}

	scanEvent := json_schemas.ScanDoneEvent{}
	// Populate the fields with data
	scanEvent.Data.Type = "analytics"
	scanEvent.Data.Attributes.DeviceId = c.DeviceID()
	scanEvent.Data.Attributes.Application = "snyk-ls"
	scanEvent.Data.Attributes.ApplicationVersion = config.Version
	scanEvent.Data.Attributes.Os = os[runtime.GOOS]
	scanEvent.Data.Attributes.Arch = arch[runtime.GOARCH]
	scanEvent.Data.Attributes.IntegrationName = gafConfig.GetString(configuration.INTEGRATION_NAME)
	scanEvent.Data.Attributes.IntegrationVersion = gafConfig.GetString(configuration.INTEGRATION_VERSION)
	scanEvent.Data.Attributes.IntegrationEnvironment = gafConfig.GetString(configuration.INTEGRATION_ENVIRONMENT)
	scanEvent.Data.Attributes.IntegrationEnvironmentVersion = gafConfig.GetString(configuration.INTEGRATION_ENVIRONMENT_VERSION)
	scanEvent.Data.Attributes.EventType = "Scan done"
	scanEvent.Data.Attributes.Status = "Success"
	scanEvent.Data.Attributes.ScanType = string(data.Product)
	scanEvent.Data.Attributes.UniqueIssueCount.Critical = data.SeverityCount[data.Product].Critical
	scanEvent.Data.Attributes.UniqueIssueCount.High = data.SeverityCount[data.Product].High
	scanEvent.Data.Attributes.UniqueIssueCount.Medium = data.SeverityCount[data.Product].Medium
	scanEvent.Data.Attributes.UniqueIssueCount.Low = data.SeverityCount[data.Product].Low
	scanEvent.Data.Attributes.DurationMs = fmt.Sprintf("%d", data.DurationMs)
	scanEvent.Data.Attributes.TimestampFinished = data.TimestampFinished

	bytes, err := json.Marshal(scanEvent)
	if err != nil {
		logger.Err(err).Msg("Error marshaling scan event")
		return
	}

	err = analytics.SendAnalyticsToAPI(c, bytes)
	if err != nil {
		logger.Err(err).Msg("Error sending analytics to API")
		return
	}
}

func (f *Folder) FilterAndPublishDiagnostics(issues snyk.IssuesByFile) {
	issuesByFile := f.filterDiagnostics(issues)
	productIssuesByFile := f.groupIssuesByProduct(issuesByFile)
	for p, pIssues := range productIssuesByFile {
		f.publishDiagnostics(p, pIssues)
	}
}

func (f *Folder) groupIssuesByProduct(issuesByFile snyk.IssuesByFile) snyk.ProductIssuesByFile {
	var productIssuesByFile = snyk.ProductIssuesByFile{}
	for path, fileIssues := range issuesByFile {
		if !f.Contains(path) {
			panic("issue found in cache that does not pertain to folder")
		}
		for _, issue := range fileIssues {
			tempIssuesByFile := productIssuesByFile[issue.Product]
			if tempIssuesByFile == nil {
				tempIssuesByFile = snyk.IssuesByFile{}
			}
			tempIssuesByFile[path] = append(tempIssuesByFile[path], issue)
			productIssuesByFile[issue.Product] = tempIssuesByFile
		}
	}
	return productIssuesByFile
}

func (f *Folder) filterDiagnostics(issues snyk.IssuesByFile) snyk.IssuesByFile {
	logger := log.With().Str("method", "filterDiagnostics").Logger()

	filterSeverity := config.CurrentConfig().FilterSeverity()
	logger.Debug().Interface("filterSeverity", filterSeverity).Msg("Filtering issues by severity")

	supportedIssueTypes := config.CurrentConfig().DisplayableIssueTypes()
	filteredIssuesByFile := f.FilterIssues(issues, supportedIssueTypes)
	return filteredIssuesByFile
}

func (f *Folder) FilterIssues(issues snyk.IssuesByFile, supportedIssueTypes map[product.FilterableIssueType]bool) snyk.
	IssuesByFile {
	logger := log.With().Str("method", "FilterIssues").Logger()

	filteredIssues := snyk.IssuesByFile{}
	for path, issueSlice := range issues {
		if !f.Contains(path) {
			panic("issue found in cache that does not pertain to folder")
		}
		for _, issue := range issueSlice {
			// Logging here might hurt performance, should benchmark if filtering is slow
			if isVisibleSeverity(issue) && supportedIssueTypes[issue.GetFilterableIssueType()] {
				logger.Trace().Msgf("Including visible severity issue: %v", issue)
				filteredIssues[path] = append(filteredIssues[path], issue)
			} else {
				logger.Trace().Msgf("Filtering out issue %v", issue)
			}
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

func (f *Folder) publishDiagnostics(product product.Product, issuesByFile snyk.IssuesByFile) {
	f.sendDiagnostics(issuesByFile)
	f.sendScanResults(product, issuesByFile)
	f.sendHovers(issuesByFile) // TODO: this locks up the thread, need to investigate
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
	log.Debug().
		Str("method", "sendDiagnosticsForFile").
		Str("affectedFilePath", path).Int("issueCount", len(issues)).Send()

	f.notifier.Send(lsp.PublishDiagnosticsParams{
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

func (f *Folder) Name() string { return f.name }

func (f *Folder) Status() FolderStatus { return f.status }

func (f *Folder) IssuesForRange(filePath string, requestedRange snyk.Range) (matchingIssues []snyk.Issue) {
	method := "domain.ide.workspace.folder.getCodeActions"
	if !f.Contains(filePath) {
		panic("this folder should not be asked to handle " + filePath)
	}

	issues := f.IssuesForFile(filePath)
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

func (f *Folder) sendScanResults(processedProduct product.Product, issuesByFile snyk.IssuesByFile) {
	var productIssues []snyk.Issue
	for _, issues := range issuesByFile {
		productIssues = append(productIssues, issues...)
	}

	if processedProduct != "" {
		f.scanNotifier.SendSuccess(processedProduct, f.Path(), productIssues)
	} else {
		f.scanNotifier.SendSuccessForAllProducts(f.Path(), productIssues)
	}
}
