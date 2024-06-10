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

package snyk

import (
	"context"
	"sync"
	"time"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/initialize"
	"github.com/snyk/snyk-ls/domain/ide/notification"
	"github.com/snyk/snyk-ls/domain/observability/performance"
	ux2 "github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/lsp"
	"github.com/snyk/snyk-ls/internal/product"
)

var (
	_ Scanner             = (*DelegatingConcurrentScanner)(nil)
	_ InlineValueProvider = (*DelegatingConcurrentScanner)(nil)
	_ PackageScanner      = (*DelegatingConcurrentScanner)(nil)
	_ CacheProvider       = (*DelegatingConcurrentScanner)(nil)
)

type Scanner interface {
	// Scan scans a workspace folder or file for issues, given its path. 'folderPath' provides a path to a workspace folder, if a file needs to be scanned.
	Scan(
		ctx context.Context,
		path string,
		processResults ScanResultProcessor,
		folderPath string,
	)
	Init() error
}

type PackageScanner interface {
	ScanPackages(ctx context.Context, config *config.Config, path string, content string)
}

// DelegatingConcurrentScanner is a simple Scanner Implementation that delegates on other scanners asynchronously
type DelegatingConcurrentScanner struct {
	scanners      []ProductScanner
	initializer   initialize.Initializer
	instrumentor  performance.Instrumentor
	analytics     ux2.Analytics
	scanNotifier  ScanNotifier
	snykApiClient snyk_api.SnykApiClient
	authService   AuthenticationService
	notifier      notification.Notifier
	c             *config.Config
}

func (sc *DelegatingConcurrentScanner) Issue(key string) Issue {
	for _, scanner := range sc.scanners {
		if s, ok := scanner.(IssueProvider); ok {
			issue := s.Issue(key)
			if issue.ID != "" {
				return issue
			}
		}
	}
	return Issue{}
}

func (sc *DelegatingConcurrentScanner) Issues() IssuesByFile {
	issues := make(map[string][]Issue)
	for _, scanner := range sc.scanners {
		if issueProvider, ok := scanner.(IssueProvider); ok {
			for filePath, issueSlice := range issueProvider.Issues() {
				issues[filePath] = append(issues[filePath], issueSlice...)
			}
		}
	}
	return issues
}

func (sc *DelegatingConcurrentScanner) IssuesForFile(path string) []Issue {
	var issues []Issue
	for _, scanner := range sc.scanners {
		if s, ok := scanner.(IssueProvider); ok {
			issues = append(issues, s.IssuesForFile(path)...)
		}
	}
	return issues
}

func (sc *DelegatingConcurrentScanner) IssuesForRange(path string, r Range) []Issue {
	var issues []Issue
	for _, scanner := range sc.scanners {
		if s, ok := scanner.(IssueProvider); ok {
			issues = append(issues, s.IssuesForRange(path, r)...)
		}
	}
	return issues
}

func (sc *DelegatingConcurrentScanner) IsProviderFor(issueType product.FilterableIssueType) bool {
	for _, scanner := range sc.scanners {
		if s, ok := scanner.(CacheProvider); ok {
			if s.IsProviderFor(issueType) {
				return true
			}
		}
	}
	return false
}

func (sc *DelegatingConcurrentScanner) Clear() {
	for _, productScanner := range sc.scanners {
		if cacheProvider, isCacheProvider := productScanner.(CacheProvider); isCacheProvider {
			cacheProvider.Clear()
		}
	}
}

func (sc *DelegatingConcurrentScanner) ClearIssues(path string) {
	for _, productScanner := range sc.scanners {
		if cacheProvider, isCacheProvider := productScanner.(CacheProvider); isCacheProvider {
			cacheProvider.ClearIssues(path)
		}
	}

	for _, productScanner := range sc.scanners {
		// inline values should be cleared, when issues of a file are cleared
		// this *may* already already happen in the previous ClearIssues call, but
		// a scanner can be an InlineValueProvider, without having its own cache (e.g. oss.Scanner)
		if scanner, ok := productScanner.(InlineValueProvider); ok {
			scanner.ClearInlineValues(path)
		}
	}
}

func (sc *DelegatingConcurrentScanner) ClearInlineValues(path string) {
	for _, scanner := range sc.scanners {
		if s, ok := scanner.(InlineValueProvider); ok {
			s.ClearInlineValues(path)
		}
	}
}

func (sc *DelegatingConcurrentScanner) RegisterCacheRemovalHandler(handler func(path string)) {
	for _, productScanner := range sc.scanners {
		if cacheProvider, isCacheProvider := productScanner.(CacheProvider); isCacheProvider {
			cacheProvider.RegisterCacheRemovalHandler(handler)
		}
	}
}

func (sc *DelegatingConcurrentScanner) ScanPackages(ctx context.Context, config *config.Config, path string, content string) {
	for _, scanner := range sc.scanners {
		if s, ok := scanner.(PackageScanner); ok {
			s.ScanPackages(ctx, config, path, content)
		}
	}
}

func NewDelegatingScanner(
	c *config.Config,
	initializer initialize.Initializer,
	instrumentor performance.Instrumentor,
	analytics ux2.Analytics,
	scanNotifier ScanNotifier,
	snykApiClient snyk_api.SnykApiClient,
	authService AuthenticationService,
	notifier notification.Notifier,
	scanners ...ProductScanner,
) Scanner {
	return &DelegatingConcurrentScanner{
		instrumentor:  instrumentor,
		analytics:     analytics,
		initializer:   initializer,
		scanNotifier:  scanNotifier,
		snykApiClient: snykApiClient,
		scanners:      scanners,
		authService:   authService,
		notifier:      notifier,
		c:             c,
	}
}

func (sc *DelegatingConcurrentScanner) GetInlineValues(path string, myRange Range) ([]InlineValue, error) {
	var values []InlineValue
	for _, scanner := range sc.scanners {
		if s, ok := scanner.(InlineValueProvider); ok {
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
	processResults ScanResultProcessor,
	folderPath string,
) {
	method := "ide.workspace.folder.DelegatingConcurrentScanner.ScanFile"
	c := config.CurrentConfig()
	logger := c.Logger().With().Str("method", method).Logger()

	authenticated, err := sc.authService.IsAuthenticated()
	if err != nil {
		logger.Err(err).Msg("Error checking authentication status")
	}

	if !authenticated {
		logger.Info().Msgf("Not authenticated, not scanning.")
		return
	}

	tokenChangeChannel := c.TokenChangesChannel()
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

	analysisTypes := getEnabledAnalysisTypes(sc.scanners)
	if len(analysisTypes) > 0 {
		sc.analytics.AnalysisIsTriggered(
			ux2.AnalysisIsTriggeredProperties{
				AnalysisType:    analysisTypes,
				TriggeredByUser: false,
			},
		)
		sc.scanNotifier.SendInProgress(folderPath)
	}

	waitGroup := &sync.WaitGroup{}
	for _, scanner := range sc.scanners {
		if scanner.IsEnabled() {
			waitGroup.Add(1)
			go func(s ProductScanner) {
				defer waitGroup.Done()
				span := sc.instrumentor.NewTransaction(context.WithValue(ctx, s.Product(), s), string(s.Product()), method)
				defer sc.instrumentor.Finish(span)
				logger.Info().Msgf("Scanning %s with %T: STARTED", path, s)
				// TODO change interface of scan to pass a func (processResults), which would enable products to stream

				scanSpan := sc.instrumentor.StartSpan(span.Context(), "scan")
				foundIssues, err := s.Scan(scanSpan.Context(), path, folderPath)
				sc.instrumentor.Finish(scanSpan)

				// now process
				data := ScanData{
					Product:           s.Product(),
					Issues:            foundIssues,
					Err:               err,
					DurationMs:        scanSpan.GetDurationMs(),
					TimestampFinished: time.Now().UTC(),
				}
				processResults(data)
				logger.Info().Msgf("Scanning %s with %T: COMPLETE found %v issues", path, s, len(foundIssues))
			}(scanner)
		} else {
			logger.Debug().Msgf("Skipping scan with %T because it is not enabled", scanner)
		}
	}
	logger.Debug().Msgf("All product scanners started for %s", path)
	waitGroup.Wait()
	c.Logger().Debug().Msgf("All product scanners finished for %s", path)
	sc.notifier.Send(lsp.InlineValueRefresh{})
	sc.notifier.Send(lsp.CodeLensRefresh{})
	// TODO: handle learn actions centrally instead of in each scanner
}

func getEnabledAnalysisTypes(productScanners []ProductScanner) (analysisTypes []ux2.AnalysisType) {
	for _, ps := range productScanners {
		if !ps.IsEnabled() {
			continue
		}
		if ps.Product() == product.ProductInfrastructureAsCode {
			analysisTypes = append(analysisTypes, ux2.InfrastructureAsCode)
		}
		if ps.Product() == product.ProductOpenSource {
			analysisTypes = append(analysisTypes, ux2.OpenSource)
		}
		if ps.Product() == product.ProductCode {
			if config.CurrentConfig().IsSnykCodeQualityEnabled() || config.CurrentConfig().IsSnykCodeEnabled() {
				analysisTypes = append(analysisTypes, ux2.CodeQuality)
			}
			if config.CurrentConfig().IsSnykCodeSecurityEnabled() || config.CurrentConfig().IsSnykCodeEnabled() {
				analysisTypes = append(analysisTypes, ux2.CodeSecurity)
			}
		}
	}
	return analysisTypes
}
