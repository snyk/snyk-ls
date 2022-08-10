package snyk

import (
	"context"

	"github.com/rs/zerolog/log"

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

	sc.analytics.AnalysisIsTriggered(
		ux2.AnalysisIsTriggeredProperties{
			AnalysisType:    ux2.GetEnabledAnalysisTypes(),
			TriggeredByUser: false,
		},
	)

	sc.initializer.Init()
	for _, scanner := range sc.scanners {
		if scanner.IsEnabled() {
			go func(s ProductScanner) {
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
}
