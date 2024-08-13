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
	"fmt"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/internal/vcs"
	"os"
	"sync"
	"time"

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
	scanners      []snyk.ProductScanner
	initializer   initialize.Initializer
	instrumentor  performance.Instrumentor
	scanNotifier  ScanNotifier
	snykApiClient snyk_api.SnykApiClient
	authService   authentication.AuthenticationService
	notifier      notification.Notifier
	c             *config.Config
	scanPersister persistence.ScanSnapshotPersister
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
	for _, scanner := range sc.scanners {
		if s, ok := scanner.(PackageScanner); ok {
			s.ScanPackages(ctx, config, path, content)
		}
	}
}

func NewDelegatingScanner(c *config.Config, initializer initialize.Initializer, instrumentor performance.Instrumentor, scanNotifier ScanNotifier, snykApiClient snyk_api.SnykApiClient, authService authentication.AuthenticationService, notifier notification.Notifier, scanPersister persistence.ScanSnapshotPersister, scanners ...snyk.ProductScanner) Scanner {
	return &DelegatingConcurrentScanner{
		instrumentor:  instrumentor,
		initializer:   initializer,
		scanNotifier:  scanNotifier,
		snykApiClient: snykApiClient,
		scanners:      scanners,
		authService:   authService,
		notifier:      notifier,
		scanPersister: scanPersister,
		c:             c,
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

	waitGroup := &sync.WaitGroup{}
	for _, scanner := range sc.scanners {
		if scanner.IsEnabled() {
			waitGroup.Add(1)
			go func(s snyk.ProductScanner) {
				defer waitGroup.Done()
				span := sc.instrumentor.NewTransaction(context.WithValue(ctx, s.Product(), s), string(s.Product()), method)
				defer sc.instrumentor.Finish(span)
				logger.Info().Msgf("Scanning %s with %T: STARTED", path, s)
				// TODO change interface of scan to pass a func (processResults), which would enable products to stream

				scanSpan := sc.instrumentor.StartSpan(span.Context(), "scan")

				foundIssues, scanError := sc.internalScan(scanSpan.Context(), s, path, folderPath)
				sc.instrumentor.Finish(scanSpan)

				// now process
				data := snyk.ScanData{
					Product:           s.Product(),
					Issues:            foundIssues,
					Err:               scanError,
					DurationMs:        time.Duration(scanSpan.GetDurationMs()),
					TimestampFinished: time.Now().UTC(),
					Path:              folderPath,
				}

				// in case of delta scans, we add additional fields
				if deltaScanner, ok := s.(types.DeltaScanner); ok {
					data.IsDeltaScan = deltaScanner.DeltaScanningEnabled()
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
	logger.Debug().Msgf("All product scanners finished for %s", path)
	sc.notifier.Send(types.InlineValueRefresh{})
	sc.notifier.Send(types.CodeLensRefresh{})
	// TODO: handle learn actions centrally instead of in each scanner
}

func (sc *DelegatingConcurrentScanner) internalScan(ctx context.Context, s snyk.ProductScanner, path string, folderPath string) (issues []snyk.Issue, err error) {
	logger := sc.c.Logger().With().Str("method", "ide.workspace.folder.DelegatingConcurrentScanner.internalScan").Logger()

	var foundIssues []snyk.Issue
	if sc.c.IsDeltaFindingsEnabled() {
		hasChanges, gitErr := vcs.LocalRepoHasChanges(sc.c.Logger(), folderPath)
		if gitErr != nil {
			logger.Error().Err(gitErr).Msg("couldn't check if working dir is clean")
			return nil, gitErr
		}
		if !hasChanges {
			// If delta is enabled but there are no changes. There can be no delta.
			// else it should start scanning.
			logger.Debug().Msg("skipping scanning. working dir is clean")
			return foundIssues, nil // Returning an empty slice implies that no issues were found
		}
	}

	foundIssues, err = s.Scan(ctx, path, folderPath)
	if err != nil {
		return nil, err
	}

	if sc.c.IsDeltaFindingsEnabled() && len(foundIssues) > 0 {
		err = sc.scanAndPersistBaseBranch(ctx, s, folderPath)
		if err != nil {
			logger.Error().Err(err).Msg("couldn't scan base branch for folder " + folderPath)
			return nil, err
		}
	}
	return foundIssues, nil
}

func (sc *DelegatingConcurrentScanner) scanAndPersistBaseBranch(ctx context.Context, s snyk.ProductScanner, folderPath string) error {
	logger := sc.c.Logger().With().Str("method", "scanAndPersistBaseBranch").Logger()

	baseBranchName := vcs.GetBaseBranchName(folderPath)
	headRef, err := vcs.HeadRefHashForBranch(&logger, folderPath, baseBranchName)

	if err != nil {
		logger.Error().Err(err).Msg("Failed to fetch commit hash for main branch")
		return err
	}

	snapshotExists := sc.scanPersister.Exists(folderPath, headRef, s.Product())
	if snapshotExists {
		return nil
	}

	tmpFolderName := fmt.Sprintf("snyk_delta_%s", vcs.NormalizeBranchName(baseBranchName))
	baseBranchFolderPath, err := os.MkdirTemp("", tmpFolderName)
	logger.Info().Msg("Creating tmp directory for base branch")

	if err != nil {
		logger.Error().Err(err).Msg("Failed to create tmp directory for base branch")
		return err
	}

	repo, err := vcs.Clone(&logger, folderPath, baseBranchFolderPath, baseBranchName)

	if err != nil {
		logger.Error().Err(err).Msg("Failed to clone base branch")
		return err
	}

	defer func() {
		if baseBranchFolderPath == "" {
			return
		}
		err = os.RemoveAll(baseBranchFolderPath)
		logger.Info().Msg("removing base branch tmp dir " + baseBranchFolderPath)

		if err != nil {
			logger.Error().Err(err).Msg("couldn't remove tmp dir " + baseBranchFolderPath)
		}
	}()

	var results []snyk.Issue
	if s.Product() == product.ProductCode {
		results, err = s.Scan(ctx, "", baseBranchFolderPath)
	} else {
		results, err = s.Scan(ctx, baseBranchFolderPath, "")
	}

	if err != nil {
		return err
	}

	commitHash, err := vcs.HeadRefHashForRepo(repo)
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
