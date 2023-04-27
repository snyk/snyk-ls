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

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/initialize"
	"github.com/snyk/snyk-ls/domain/observability/performance"
	ux2 "github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/product"
)

type Scanner interface {
	Scan(
		ctx context.Context,
		path string,
		processResults ScanResultProcessor,
		folderPath string,
	)
}

// DelegatingConcurrentScanner is a simple Scanner Implementation that delegates on other scanners asynchronously
type DelegatingConcurrentScanner struct {
	scanners      []ProductScanner
	initializer   initialize.Initializer
	instrumentor  performance.Instrumentor
	analytics     ux2.Analytics
	scanNotifier  ScanNotifier
	snykApiClient snyk_api.SnykApiClient
	authFunction  func() (string, error)
}

func NewDelegatingScanner(
	initializer initialize.Initializer,
	instrumentor performance.Instrumentor,
	analytics ux2.Analytics,
	scanNotifier ScanNotifier,
	snykApiClient snyk_api.SnykApiClient,
	authFunction func() (string, error),
	scanners ...ProductScanner,
) Scanner {
	return &DelegatingConcurrentScanner{
		instrumentor:  instrumentor,
		analytics:     analytics,
		initializer:   initializer,
		scanNotifier:  scanNotifier,
		snykApiClient: snykApiClient,
		scanners:      scanners,
		authFunction:  authFunction,
	}
}

func (sc *DelegatingConcurrentScanner) Scan(
	ctx context.Context,
	path string,
	processResults ScanResultProcessor,
	folderPath string,
) {
	method := "ide.workspace.folder.DelegatingConcurrentScanner.ScanFile"
	c := config.CurrentConfig()

	err := sc.initializer.Init()
	if err != nil {
		log.Error().Err(err).Msg("Scan initialization error, cancelling scan")
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
			log.Info().Msg("Token was changed, cancelling scan")
			cancelFunc()
			return
		case <-done: // The done channel prevents the goroutine from leaking after the scan is finished
			return
		}
	}()

	// refresh & check auth by issuing a request to the API
	userId, err := sc.authFunction()
	if err != nil {
		if !c.NonEmptyToken() {
			log.Info().Msg("User token is not valid. Cancelling scan")
		} else {
			log.Info().Msg("User is not authenticated, cancelling scan")
		}
		return
	}
	log.Info().Msgf("User authenticated / Credentials refreshed, UserID: %s", userId)

	if ctx.Err() != nil {
		log.Info().Msg("Scan was cancelled")
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
				log.Info().Msgf("Scanning %s with %T: STARTED", path, s)
				// TODO change interface of scan to pass a func (processResults), which would enable products to stream
				foundIssues, err := s.Scan(span.Context(), path, folderPath)
				processResults(s.Product(), foundIssues, err)
				log.Info().Msgf("Scanning %s with %T: COMPLETE found %v issues", path, s, len(foundIssues))
			}(scanner)
		} else {
			log.Debug().Msgf("Skipping scan with %T because it is not enabled", scanner)
		}
	}
	log.Debug().Msgf("All product scanners started for %s", path)
	waitGroup.Wait()
	log.Debug().Msgf("All product scanners finished for %s", path)
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
