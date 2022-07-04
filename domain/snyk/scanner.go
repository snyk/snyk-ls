package snyk

import (
	"context"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/domain/observability/performance"
	ux2 "github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/internal/preconditions"
)

type Scanner interface {
	Scan(
		ctx context.Context,
		path string,
		processResults ScanResultProcessor,
		//todo deliberately calling this garbage because they need to go away - these nonsensical params are here because
		//code and cli based scans have a slightly different modus operandi. We need to unify that and clean this interface
		legacyWorkspacePath string,
		legacyFilesToScan []string,
	)
}

//DelegatingConcurrentScanner is a simple Scanner Implementation that delegates on other scanners asynchronously
type DelegatingConcurrentScanner struct {
	scanners     []ProductLineScanner
	initializer  *preconditions.EnvironmentInitializer
	instrumentor performance.Instrumentor
	analytics    ux2.Analytics
}

func NewDelegatingScanner(
	initializer *preconditions.EnvironmentInitializer,
	instrumentor performance.Instrumentor,
	analytics ux2.Analytics,
	scanners ...ProductLineScanner,
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
	legacyWorkspacePath string,
	legacyFilesToScan []string,
) {
	method := "ide.workspace.folder.DelegatingConcurrentScanner.ScanFile"
	s := sc.instrumentor.NewTransaction(ctx, method, method)
	//TODO this is not correct as it runs async
	defer sc.instrumentor.Finish(s)

	sc.analytics.AnalysisIsTriggered(
		ux2.AnalysisIsTriggeredProperties{
			AnalysisType:    ux2.GetEnabledAnalysisTypes(),
			TriggeredByUser: false,
		},
	)

	//todo split into cli / auth preconditions and push down to appropriate infra layers
	sc.initializer.WaitUntilCLIAndAuthReady(ctx)
	var issues []Issue
	for _, scanner := range sc.scanners {
		if scanner.IsEnabled() {
			go func(s ProductLineScanner) {
				log.Debug().Msgf("Scanning %s with %T: STARTED", path, s)
				foundIssues := s.Scan(ctx, path, legacyWorkspacePath, legacyFilesToScan)
				issues = append(issues, foundIssues...)
				processResults(issues)
				log.Debug().Msgf("Scanning %s with %T: COMPLETE found %v issues", path, s, len(foundIssues))
			}(scanner)
		} else {
			log.Debug().Msgf("Skipping scan with %T because it is not enabled", scanner)
		}
	}
	log.Debug().Msgf("Scanning %s complete", path)
}
