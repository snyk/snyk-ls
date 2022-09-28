package snyk

import (
	"context"
	"sync"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/initialize"
	"github.com/snyk/snyk-ls/domain/observability/performance"
	ux2 "github.com/snyk/snyk-ls/domain/observability/ux"
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
	scanners     []ProductScanner
	initializer  initialize.Initializer
	instrumentor performance.Instrumentor
	analytics    ux2.Analytics
}

func NewDelegatingScanner(
	initializer initialize.Initializer,
	instrumentor performance.Instrumentor,
	analytics ux2.Analytics,
	scanners ...ProductScanner,
) Scanner {
	return &DelegatingConcurrentScanner{
		instrumentor: instrumentor,
		analytics:    analytics,
		initializer:  initializer,
		scanners:     scanners,
	}
}

func (sc *DelegatingConcurrentScanner) Scan(
	ctx context.Context,
	path string,
	processResults ScanResultProcessor,
	folderPath string,
) {
	method := "ide.workspace.folder.DelegatingConcurrentScanner.ScanFile"
	done := make(chan bool)
	defer close(done)

	sc.initializer.Init()
	tokenChangeChannel := config.CurrentConfig().TokenChangesChannel()
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

	if !config.CurrentConfig().Authenticated() {
		log.Info().Msg("User is not authenticated, cancelling scan")
		return
	}

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
	}

	waitGroup := &sync.WaitGroup{}
	for _, scanner := range sc.scanners {
		if scanner.IsEnabled() {
			waitGroup.Add(1)
			go func(s ProductScanner) {
				defer waitGroup.Done()
				span := sc.instrumentor.NewTransaction(context.WithValue(ctx, s.Product(), s), string(s.Product()), method)
				defer sc.instrumentor.Finish(span)
				log.Debug().Msgf("Scanning %s with %T: STARTED", path, s)
				// TODO change interface of scan to pass a func (processResults), which would enable products to stream
				foundIssues := s.Scan(span.Context(), path, folderPath)
				processResults(foundIssues)
				log.Debug().Msgf("Scanning %s with %T: COMPLETE found %v issues", path, s, len(foundIssues))
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
		if ps.Product() == ProductInfrastructureAsCode {
			analysisTypes = append(analysisTypes, ux2.InfrastructureAsCode)
		}
		if ps.Product() == ProductOpenSource {
			analysisTypes = append(analysisTypes, ux2.OpenSource)
		}
		if ps.Product() == ProductCode {
			analysisTypes = append(analysisTypes, ux2.CodeSecurity)
		}
	}
	return analysisTypes
}
