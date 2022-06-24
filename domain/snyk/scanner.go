package snyk

import (
	"context"

	"github.com/snyk/snyk-ls/code"
	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/domain/ide/workspace/deleteme"
	"github.com/snyk/snyk-ls/iac"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/observability/ux"
	"github.com/snyk/snyk-ls/internal/preconditions"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/oss"
)

type Scanner interface {
	Scan(
		ctx context.Context,
		path string,
		processResults deleteme.ResultProcessor,
		//todo deliberately calling this garbage because they need to go away
		naughtyHack1 string,
		naughtyHack2 []string,
	)
}

type DefaultScanner struct {
	snykCodeScanner             *code.Scanner
	infrastructureAsCodeScanner *iac.Scanner
	openSourceScanner           *oss.Scanner
	initializer                 *preconditions.EnvironmentInitializer
	instrumentor                performance.Instrumentor
	analytics                   ux.Analytics
}

func NewDefaultScanner(
	snykCodeScanner *code.Scanner,
	infrastructureAsCodeScanner *iac.Scanner,
	openSourceScanner *oss.Scanner,
	initializer *preconditions.EnvironmentInitializer,
	instrumentor performance.Instrumentor,
	analytics ux.Analytics,
) Scanner {
	return &DefaultScanner{
		instrumentor:                instrumentor,
		analytics:                   analytics,
		snykCodeScanner:             snykCodeScanner,
		infrastructureAsCodeScanner: infrastructureAsCodeScanner,
		openSourceScanner:           openSourceScanner,
		initializer:                 initializer,
	}
}

//todo callback here should be using issues
func (sc *DefaultScanner) Scan(
	ctx context.Context,
	path string,
	processResults deleteme.ResultProcessor,
	//todo deliberately calling this garbage because they need to go away
	naughtyHack1 string,
	naughtyHack2 []string,
) {
	method := "ide.workspace.folder.DefaultScanner.ScanFile"
	s := sc.instrumentor.NewTransaction(ctx, method, method)
	//TODO this is not correct as it runs async
	defer sc.instrumentor.Finish(s)

	sc.analytics.AnalysisIsTriggered(
		ux.AnalysisIsTriggeredProperties{
			AnalysisType:    ux.GetEnabledAnalysisTypes(),
			TriggeredByUser: false,
		},
	)

	//todo split into cli / auth preconditions and push down to appropriate infra layers
	sc.initializer.WaitUntilCLIAndAuthReady(ctx)
	if config.CurrentConfig().IsSnykIacEnabled() {
		go sc.infrastructureAsCodeScanner.ScanFile(ctx, uri.PathToUri(path), processResults)
	}
	if config.CurrentConfig().IsSnykOssEnabled() {
		go sc.openSourceScanner.ScanFile(ctx, uri.PathToUri(path), processResults)
	}
	if config.CurrentConfig().IsSnykCodeEnabled() {
		//todo can we make code receive a path like we do with oss & iac???
		go sc.snykCodeScanner.ScanWorkspace(ctx, naughtyHack2, naughtyHack1, processResults)
	}
}
