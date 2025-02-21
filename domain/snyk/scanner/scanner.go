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

	"github.com/rs/zerolog"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/initialize"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/vcs"
)

var (
	_ Scanner                  = (*DelegatingConcurrentScanner)(nil)
	_ snyk.InlineValueProvider = (*DelegatingConcurrentScanner)(nil)
	_ PackageScanner           = (*DelegatingConcurrentScanner)(nil)
	_ snyk.CacheProvider       = (*DelegatingConcurrentScanner)(nil)
)

type Scanner interface {
	// Scan scans a workspace folder or file for issues, given its path. 'folderPath' provides a path to a workspace folder, if a file needs to be scanned.
	Scan(ctx context.Context, path types.FilePath, processResults types.ScanResultProcessor, folderPath types.FilePath)
	Init() error
}

type PackageScanner interface {
	ScanPackages(ctx context.Context, config *config.Config, path types.FilePath, content string)
}

// DelegatingConcurrentScanner is a simple Scanner Implementation that delegates on other scanners asynchronously
type DelegatingConcurrentScanner struct {
	scanners            []types.ProductScanner
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

func (sc *DelegatingConcurrentScanner) Issue(key string) types.Issue {
	for _, scanner := range sc.scanners {
		if s, ok := scanner.(snyk.IssueProvider); ok {
			issue := s.Issue(key)
			if issue.GetID() != "" {
				return issue
			}
		}
	}
	return nil
}

func (sc *DelegatingConcurrentScanner) Issues() snyk.IssuesByFile {
	issues := make(map[types.FilePath][]types.Issue)
	for _, scanner := range sc.scanners {
		if issueProvider, ok := scanner.(snyk.IssueProvider); ok {
			for filePath, issueSlice := range issueProvider.Issues() {
				issues[filePath] = append(issues[filePath], issueSlice...)
			}
		}
	}
	return issues
}

func (sc *DelegatingConcurrentScanner) IssuesForFile(path types.FilePath) []types.Issue {
	var issues []types.Issue
	for _, scanner := range sc.scanners {
		if s, ok := scanner.(snyk.IssueProvider); ok {
			issues = append(issues, s.IssuesForFile(path)...)
		}
	}
	return issues
}

func (sc *DelegatingConcurrentScanner) IssuesForRange(path types.FilePath, r types.Range) []types.Issue {
	var issues []types.Issue
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

func (sc *DelegatingConcurrentScanner) ClearIssues(path types.FilePath) {
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

func (sc *DelegatingConcurrentScanner) ClearInlineValues(path types.FilePath) {
	for _, scanner := range sc.scanners {
		if s, ok := scanner.(snyk.InlineValueProvider); ok {
			s.ClearInlineValues(path)
		}
	}
}

func (sc *DelegatingConcurrentScanner) RegisterCacheRemovalHandler(handler func(path types.FilePath)) {
	for _, productScanner := range sc.scanners {
		if cacheProvider, isCacheProvider := productScanner.(snyk.CacheProvider); isCacheProvider {
			cacheProvider.RegisterCacheRemovalHandler(handler)
		}
	}
}

func (sc *DelegatingConcurrentScanner) ScanPackages(ctx context.Context, config *config.Config, path types.FilePath, content string) {
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

func NewDelegatingScanner(c *config.Config, initializer initialize.Initializer, instrumentor performance.Instrumentor, scanNotifier ScanNotifier, snykApiClient snyk_api.SnykApiClient, authService authentication.AuthenticationService, notifier notification.Notifier, scanPersister persistence.ScanSnapshotPersister, scanStateAggregator scanstates.Aggregator, scanners ...types.ProductScanner) Scanner {
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

func (sc *DelegatingConcurrentScanner) GetInlineValues(path types.FilePath, myRange types.Range) ([]snyk.InlineValue, error) {
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

func (sc *DelegatingConcurrentScanner) Scan(ctx context.Context, path types.FilePath, processResults types.ScanResultProcessor, folderPath types.FilePath) {
	method := "ide.workspace.folder.DelegatingConcurrentScanner.ScanFile"
	logger := sc.c.Logger().With().Str("method", method).Logger()

	if sc.c.Offline() {
		logger.Warn().Str("method", "ScanPackages").Msgf("we are offline, not scanning %s, %s", folderPath, path)
		return
	}

	ctx, logger = sc.enrichContextAndLogger(ctx, logger)

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
	folderConfig := sc.c.FolderConfig(folderPath)
	gitCheckoutHandler := vcs.NewCheckoutHandler(sc.c.Engine().GetConfiguration())

	waitGroup := &sync.WaitGroup{}
	referenceBranchScanWaitGroup := &sync.WaitGroup{}
	for _, scanner := range sc.scanners {
		if scanner.IsEnabled() {
			waitGroup.Add(1)
			referenceBranchScanWaitGroup.Add(1)
			go func(s types.ProductScanner) {
				defer waitGroup.Done()
				enrichedContext, logger := sc.enrichContextAndLogger(ctx, logger)
				span := sc.instrumentor.NewTransaction(context.WithValue(enrichedContext, s.Product(), s), string(s.Product()), method)
				defer sc.instrumentor.Finish(span)
				logger.Info().Msgf("Scanning %s with %T: STARTED", path, s)
				sc.scanStateAggregator.SetScanInProgress(folderPath, scanner.Product(), false)

				scanSpan := sc.instrumentor.StartSpan(span.Context(), "scan")

				err := sc.executePreScanCommand(span.Context(), sc.c, s.Product(), folderConfig, folderPath, true)
				if err != nil {
					logger.Err(err).Str("path", string(folderPath)).Send()
					sc.scanNotifier.SendError(scanner.Product(), folderPath, err.Error())
					sc.scanStateAggregator.SetScanDone(folderPath, scanner.Product(), false, err)
					return
				}

				// TODO change interface of scan to pass a func (processResults), which would enable products to stream
				foundIssues, scanError := sc.internalScan(scanSpan.Context(), s, path, folderPath, folderConfig)

				// this span allows differentiation between processing time and scan time
				sc.instrumentor.Finish(scanSpan)

				// now process
				data := types.ScanData{
					Product:           s.Product(),
					Issues:            foundIssues,
					Err:               scanError,
					DurationMs:        time.Duration(scanSpan.GetDurationMs()),
					TimestampFinished: time.Now().UTC(),
					Path:              folderPath,
					IsDeltaScan:       sc.c.IsDeltaFindingsEnabled(),
					SendAnalytics:     true,
					UpdateGlobalCache: true,
				}
				processResults(span.Context(), data)

				// trigger base scan in background
				go func() {
					defer referenceBranchScanWaitGroup.Done()
					isSingleFileScan := path != folderPath
					scanTypeCtx := ctx2.NewContextWithDeltaScanType(context.Background(), ctx2.Reference)
					refScanCtx, logger := sc.enrichContextAndLogger(scanTypeCtx, logger)

					// only trigger a base scan if we are scanning an actual working directory. It could also be a
					// single file scan, triggered by e.g. a file save
					if !isSingleFileScan {
						sc.scanStateAggregator.SetScanInProgress(folderPath, scanner.Product(), true)
						err = sc.scanBaseBranch(refScanCtx, s, folderConfig, gitCheckoutHandler)
						if err != nil {
							logger.Error().Err(err).Msgf("couldn't scan base branch for folder %s for product %s", folderPath, s.Product())
						}
						sc.scanStateAggregator.SetScanDone(folderPath, scanner.Product(), true, err)
					}

					if !sc.c.IsDeltaFindingsEnabled() {
						logger.Debug().Msgf("skipping processResults for reference scan %s on folder %s. Delta is disabled", s.Product().ToProductCodename(), folderPath)
						return
					}

					data = types.ScanData{
						Product:           s.Product(),
						SendAnalytics:     false,
						UpdateGlobalCache: false,
						// Err:               err, TODO: should we send the error here?
					}
					processResults(refScanCtx, data)
				}()

				sc.scanStateAggregator.SetScanDone(folderPath, scanner.Product(), false, scanError)
				logger.Info().Msgf("Scanning %s with %T: COMPLETE found %v issues", path, s, len(foundIssues))
			}(scanner)
		} else {
			logger.Debug().Msgf("Skipping scan with %T because it is not enabled", scanner)
		}
	}
	logger.Debug().Msgf("All product scanners started for %s", path)
	waitGroup.Wait()
	referenceBranchScanWaitGroup.Wait()

	defer func() {
		if gitCheckoutHandler.CleanupFunc() != nil {
			// Force defer cleanup func to wait until all reference scans are done
			logger.Debug().Msg("Calling cleanup func for base folder")
			go gitCheckoutHandler.CleanupFunc()()
			logger.Debug().Msgf("All product scanners finished for %s", path)
			sc.notifier.Send(types.InlineValueRefresh{})
			sc.notifier.Send(types.CodeLensRefresh{})
			// TODO: handle learn actions centrally instead of in each scanner
		}
	}()
}

func (sc *DelegatingConcurrentScanner) enrichContextAndLogger(ctx context.Context, logger zerolog.Logger) (context.Context, zerolog.Logger) {
	// by default, scan source is IDE
	scanSource, ok := ctx2.ScanSourceFromContext(ctx)
	if !ok {
		scanSource = ctx2.IDE
		ctx = ctx2.NewContextWithScanSource(ctx, scanSource)
	}

	logger = logger.With().Any("scanSource", scanSource).Logger()

	scanType, ok := ctx2.DeltaScanTypeFromContext(ctx)
	if !ok {
		scanType = ctx2.WorkingDirectory
		ctx = ctx2.NewContextWithDeltaScanType(ctx, scanType)
	}

	logger = logger.With().Any("deltaScanType", scanType).Logger()

	return ctx, logger
}

func (sc *DelegatingConcurrentScanner) internalScan(ctx context.Context, s types.ProductScanner, path types.FilePath, folderPath types.FilePath, folderConfig *types.FolderConfig) ([]types.Issue, error) {
	foundIssues, err := s.Scan(ctx, path, folderPath, folderConfig)
	if err != nil {
		return nil, err
	}

	return foundIssues, nil
}
