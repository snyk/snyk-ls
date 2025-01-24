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

package scanner

import (
	"context"
	"sync"
	"time"

	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/internal/vcs"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/initialize"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

var (
	_ Scanner                  = (*DelegatingConcurrentScanner)(nil)
	_ snyk.InlineValueProvider = (*DelegatingConcurrentScanner)(nil)
	_ PackageScanner           = (*DelegatingConcurrentScanner)(nil)
	_ snyk.CacheProvider       = (*DelegatingConcurrentScanner)(nil)
)

type Scanner interface {
	// Scan scans a workspace folder or file for issues, given its path. 'folderPath' provides a path to a workspace folder, if a file needs to be scanned.
	Scan(
		ctx context.Context,
		path string,
		processResults snyk.ScanResultProcessor,
		folderPath string,
	)
	Init() error
}

type PackageScanner interface {
	ScanPackages(ctx context.Context, config *config.Config, path string, content string)
}

// DelegatingConcurrentScanner is a simple Scanner Implementation that delegates on other scanners asynchronously
type DelegatingConcurrentScanner struct {
	scanners            []snyk.ProductScanner
	initializer         initialize.Initializer
	instrumentor        performance.Instrumentor
	scanNotifier        ScanNotifier
	snykApiClient       snyk_api.SnykApiClient
	authService         authentication.AuthenticationService
	notifier            notification.Notifier
	c                   *config.Config
	scanPersister       persistence.ScanSnapshotPersister
	scanStateAggregator scanstates.Aggregator
}

func (sc *DelegatingConcurrentScanner) Issue(key string) snyk.Issue {
	for _, scanner := range sc.scanners {
		if s, ok := scanner.(snyk.IssueProvider); ok {
			issue := s.Issue(key)
			if issue.ID != "" {
				return issue
			}
		}
	}
	return snyk.Issue{}
}

func (sc *DelegatingConcurrentScanner) Issues() snyk.IssuesByFile {
	issues := make(map[string][]snyk.Issue)
	for _, scanner := range sc.scanners {
		if issueProvider, ok := scanner.(snyk.IssueProvider); ok {
			for filePath, issueSlice := range issueProvider.Issues() {
				issues[filePath] = append(issues[filePath], issueSlice...)
			}
		}
	}
	return issues
}

func (sc *DelegatingConcurrentScanner) IssuesForFile(path string) []snyk.Issue {
	var issues []snyk.Issue
	for _, scanner := range sc.scanners {
		if s, ok := scanner.(snyk.IssueProvider); ok {
			issues = append(issues, s.IssuesForFile(path)...)
		}
	}
	return issues
}

func (sc *DelegatingConcurrentScanner) IssuesForRange(path string, r snyk.Range) []snyk.Issue {
	var issues []snyk.Issue
	for _, scanner := range sc.scanners {
		if s, ok := scanner.(snyk.IssueProvider); ok {
			issues = append(issues, s.IssuesForRange(path, r)...)
		}
	}
	return issues
}

func (sc *DelegatingConcurrentScanner) IsProviderFor(issueType product.FilterableIssueType) bool {
	for _, scanner := range sc.scanners {
		if s, ok := scanner.(snyk.CacheProvider); ok {
			if s.IsProviderFor(issueType) {
				return true
			}
		}
	}
	return false
}

func (sc *DelegatingConcurrentScanner) Clear() {
	for _, productScanner := range sc.scanners {
		if cacheProvider, isCacheProvider := productScanner.(snyk.CacheProvider); isCacheProvider {
			cacheProvider.Clear()
		}
	}
}

func (sc *DelegatingConcurrentScanner) ClearIssues(path string) {
	for _, productScanner := range sc.scanners {
		if cacheProvider, isCacheProvider := productScanner.(snyk.CacheProvider); isCacheProvider {
			cacheProvider.ClearIssues(path)
		}
	}

	for _, productScanner := range sc.scanners {
		// inline values should be cleared, when issues of a file are cleared
		// this *may* already already happen in the previous ClearIssues call, but
		// a scanner can be an InlineValueProvider, without having its own cache (e.g. oss.Scanner)
		if scanner, ok := productScanner.(snyk.InlineValueProvider); ok {
			scanner.ClearInlineValues(path)
		}
	}
}

func (sc *DelegatingConcurrentScanner) ClearInlineValues(path string) {
	for _, scanner := range sc.scanners {
		if s, ok := scanner.(snyk.InlineValueProvider); ok {
			s.ClearInlineValues(path)
		}
	}
}

func (sc *DelegatingConcurrentScanner) RegisterCacheRemovalHandler(handler func(path string)) {
	for _, productScanner := range sc.scanners {
		if cacheProvider, isCacheProvider := productScanner.(snyk.CacheProvider); isCacheProvider {
			cacheProvider.RegisterCacheRemovalHandler(handler)
		}
	}
}

func (sc *DelegatingConcurrentScanner) ScanPackages(ctx context.Context, config *config.Config, path string, content string) {
	if config.Offline() {
		config.Logger().Warn().Str("method", "ScanPackages").Msgf("we are offline, not scanning %s, %s", path, content)
		return
	}

	for _, scanner := range sc.scanners {
		if s, ok := scanner.(PackageScanner); ok {
			s.ScanPackages(ctx, config, path, content)
		}
	}
}

func NewDelegatingScanner(c *config.Config, initializer initialize.Initializer, instrumentor performance.Instrumentor, scanNotifier ScanNotifier, snykApiClient snyk_api.SnykApiClient, authService authentication.AuthenticationService, notifier notification.Notifier, scanPersister persistence.ScanSnapshotPersister, scanStateAggregator scanstates.Aggregator, scanners ...snyk.ProductScanner) Scanner {
	return &DelegatingConcurrentScanner{
		instrumentor:        instrumentor,
		initializer:         initializer,
		scanNotifier:        scanNotifier,
		snykApiClient:       snykApiClient,
		scanners:            scanners,
		authService:         authService,
		notifier:            notifier,
		scanPersister:       scanPersister,
		c:                   c,
		scanStateAggregator: scanStateAggregator,
	}
}

func (sc *DelegatingConcurrentScanner) GetInlineValues(path string, myRange snyk.Range) ([]snyk.InlineValue, error) {
	var values []snyk.InlineValue
	for _, scanner := range sc.scanners {
		if s, ok := scanner.(snyk.InlineValueProvider); ok {
			inlineValues, err := s.GetInlineValues(path, myRange)
			if err != nil {
				sc.c.Logger().Warn().Str("method", "DelegatingConcurrentScanner.getInlineValues").Err(err).
					Msgf("couldn't get inline values from scanner %s", scanner.Product())
				continue
			}
			values = append(values, inlineValues...)
		}
	}
	return values, nil
}

func (sc *DelegatingConcurrentScanner) Init() error {
	err := sc.initializer.Init()
	if err != nil {
		sc.c.Logger().Error().Err(err).Msg("Scanner initialization error")
		return err
	}
	return nil
}

func (sc *DelegatingConcurrentScanner) Scan(
	ctx context.Context,
	path string,
	processResults snyk.ScanResultProcessor,
	folderPath string,
) {
	method := "ide.workspace.folder.DelegatingConcurrentScanner.ScanFile"
	logger := sc.c.Logger().With().Str("method", method).Logger()

	if sc.c.Offline() {
		logger.Warn().Str("method", "ScanPackages").Msgf("we are offline, not scanning %s, %s", folderPath, path)
		return
	}

	authenticated := sc.authService.IsAuthenticated()

	if !authenticated {
		logger.Info().Msgf("Not authenticated, not scanning.")
		return
	}

	tokenChangeChannel := sc.c.TokenChangesChannel()
	done := make(chan bool)
	defer close(done)
	ctx, cancelFunc := context.WithCancel(ctx)
	defer cancelFunc()

	go func() { // This goroutine will listen to token changes and cancel the scans using a context
		select {
		case <-tokenChangeChannel:
			logger.Info().Msg("credentials have changed, canceling scan")
			cancelFunc()
			return
		case <-done: // The done channel prevents the goroutine from leaking after the scan is finished
			return
		}
	}()

	if ctx.Err() != nil {
		logger.Info().Msg("Scan was canceled")
		return
	}

	sc.scanNotifier.SendInProgress(folderPath)
	gitCheckoutHandler := vcs.NewCheckoutHandler()

	waitGroup := &sync.WaitGroup{}
	referenceBranchScanWaitGroup := &sync.WaitGroup{}
	for _, scanner := range sc.scanners {
		if scanner.IsEnabled() {
			waitGroup.Add(1)
			referenceBranchScanWaitGroup.Add(1)
			go func(s snyk.ProductScanner) {
				defer waitGroup.Done()
				span := sc.instrumentor.NewTransaction(context.WithValue(ctx, s.Product(), s), string(s.Product()), method)
				defer sc.instrumentor.Finish(span)
				logger.Info().Msgf("Scanning %s with %T: STARTED", path, s)
				sc.scanStateAggregator.SetScanInProgress(folderPath, scanner.Product(), false)

				scanSpan := sc.instrumentor.StartSpan(span.Context(), "scan")

				// TODO change interface of scan to pass a func (processResults), which would enable products to stream
				foundIssues, scanError := sc.internalScan(scanSpan.Context(), s, path, folderPath)
				sc.instrumentor.Finish(scanSpan)
				sc.scanStateAggregator.SetScanDone(folderPath, scanner.Product(), false, scanError)

				// now process
				data := snyk.ScanData{
					Product:           s.Product(),
					Issues:            foundIssues,
					Err:               scanError,
					DurationMs:        time.Duration(scanSpan.GetDurationMs()),
					TimestampFinished: time.Now().UTC(),
					Path:              folderPath,
					SendAnalytics:     true,
					UpdateGlobalCache: true,
				}
				deltaScanEnabled, deltaScanner := isDeltaScanEnabled(s)
				// in case of delta scans, we add additional fields
				if deltaScanEnabled {
					data.IsDeltaScan = deltaScanner.DeltaScanningEnabled()
				}

				processResults(data)
				go func() {
					defer referenceBranchScanWaitGroup.Done()
					isReferenceScanNeeded := path == folderPath
					if isReferenceScanNeeded {
						sc.scanStateAggregator.SetScanInProgress(folderPath, scanner.Product(), true)
						err := sc.scanBaseBranch(context.Background(), s, folderPath, gitCheckoutHandler)
						sc.scanStateAggregator.SetScanDone(folderPath, scanner.Product(), true, err)
						if err != nil {
							logger.Error().Err(err).Msgf("couldn't scan base branch for folder %s for product %s", folderPath, s.Product())
						}
					}
					data = snyk.ScanData{
						Product:           s.Product(),
						Path:              gitCheckoutHandler.BaseFolderPath(),
						SendAnalytics:     false,
						UpdateGlobalCache: false,
					}
					processResults(data)
				}()

				logger.Info().Msgf("Scanning %s with %T: COMPLETE found %v issues", path, s, len(foundIssues))
			}(scanner)
		} else {
			logger.Debug().Msgf("Skipping scan with %T because it is not enabled", scanner)
		}
	}
	logger.Debug().Msgf("All product scanners started for %s", path)
	waitGroup.Wait()

	go func() {
		if gitCheckoutHandler.CleanupFunc() != nil {
			// Force defer cleanup func to wait until all reference scans are done
			referenceBranchScanWaitGroup.Wait()
			logger.Debug().Msg("Calling cleanup func for base folder")
			gitCheckoutHandler.CleanupFunc()()
		}
	}()

	logger.Debug().Msgf("All product scanners finished for %s", path)
	sc.notifier.Send(types.InlineValueRefresh{})
	sc.notifier.Send(types.CodeLensRefresh{})
	// TODO: handle learn actions centrally instead of in each scanner
}

func isDeltaScanEnabled(s snyk.ProductScanner) (bool, types.DeltaScanner) {
	if deltaScanner, ok := s.(types.DeltaScanner); ok {
		return deltaScanner.DeltaScanningEnabled(), deltaScanner
	}
	return false, nil
}

func (sc *DelegatingConcurrentScanner) internalScan(ctx context.Context, s snyk.ProductScanner, path string, folderPath string) ([]snyk.Issue, error) {
	foundIssues, err := s.Scan(ctx, path, folderPath)
	if err != nil {
		return nil, err
	}

	return foundIssues, nil
}

func (sc *DelegatingConcurrentScanner) scanBaseBranch(ctx context.Context, s snyk.ProductScanner, folderPath string, checkoutHandler *vcs.CheckoutHandler) error {
	logger := sc.c.Logger().With().Str("method", "scanBaseBranch").Logger()

	baseBranchName := vcs.GetBaseBranchName(folderPath)
	headRef, err := vcs.HeadRefHashForBranch(&logger, folderPath, baseBranchName)

	if err != nil {
		logger.Error().Err(err).Msg("couldn't get head ref for base branch")
		return err
	}

	snapshotExists := sc.scanPersister.Exists(folderPath, headRef, s.Product())
	if snapshotExists {
		return nil
	}

	err = checkoutHandler.CheckoutBaseBranch(&logger, folderPath)
	if err != nil {
		logger.Error().Err(err).Msgf("couldn't check out base branch for folderPath %s", folderPath)
	}

	var results []snyk.Issue
	if s.Product() == product.ProductCode {
		results, err = s.Scan(ctx, "", checkoutHandler.BaseFolderPath())
	} else {
		results, err = s.Scan(ctx, checkoutHandler.BaseFolderPath(), "")
	}

	if err != nil {
		logger.Error().Err(err).Msgf("skipping base scan persistence in %s %v", folderPath, err)
		return err
	}

	commitHash, err := vcs.HeadRefHashForRepo(checkoutHandler.Repo())
	if err != nil {
		logger.Error().Err(err).Msg("could not get commit hash for repo in folder " + folderPath)
		return err
	}

	err = sc.scanPersister.Add(folderPath, commitHash, results, s.Product())
	if err != nil {
		logger.Error().Err(err).Msg("could not persist issue list for folder: " + folderPath)
	}

	return nil
}
