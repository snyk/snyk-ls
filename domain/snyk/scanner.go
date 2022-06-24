package snyk

import (
	"context"

	"github.com/snyk/snyk-ls/code"
	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/iac"
	"github.com/snyk/snyk-ls/internal/cli"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/observability/ux"
	"github.com/snyk/snyk-ls/internal/preconditions"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/lsp"
	"github.com/snyk/snyk-ls/oss"
)

type Scanner interface {
	Scan(
		ctx context.Context,
		path string,
		processResults func(diagnostics map[string][]lsp.Diagnostic, hovers []hover.DocumentHovers),
		//todo deliberately calling this garbage because they need to go away
		naughtyHack1 string,
		naughtyHack2 []string,
	)
}

type DefaultScanner struct {
	cli          cli.Executor
	snykCode     code.SnykCode
	instrumentor performance.Instrumentor
	analytics    ux.Analytics
}

func NewDefaultScanner(
	cli cli.Executor,
	snykCode code.SnykCode,
	instrumentor performance.Instrumentor,
	analytics ux.Analytics,
) Scanner {
	return &DefaultScanner{
		cli:          cli,
		instrumentor: instrumentor,
		analytics:    analytics,
		snykCode:     snykCode,
	}
}

//todo callback here should be using issues
func (sc *DefaultScanner) Scan(
	ctx context.Context,
	path string,
	processResults func(diagnostics map[string][]lsp.Diagnostic, hovers []hover.DocumentHovers),
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
	preconditions.WaitUntilCLIAndAuthReady(ctx)
	if config.CurrentConfig().IsSnykIacEnabled() {
		go iac.ScanFile(ctx, sc.cli, uri.PathToUri(path), processResults)
	}
	if config.CurrentConfig().IsSnykOssEnabled() {
		go oss.ScanFile(ctx, sc.cli, uri.PathToUri(path), processResults)
	}
	if config.CurrentConfig().IsSnykCodeEnabled() {
		//todo can we make code receive a path like we do with oss & iac???
		go sc.snykCode.ScanWorkspace(ctx, naughtyHack2, naughtyHack1, processResults)
	}
}

type ScannerRecorder struct {
	Calls int
}

func NewScannerRecorder() *ScannerRecorder {
	return &ScannerRecorder{}
}

func (s *ScannerRecorder) Scan(ctx context.Context, path string, processResults func(diagnostics map[string][]lsp.Diagnostic, hovers []hover.DocumentHovers), naughtyHack1 string, naughtyHack2 []string) {
	s.Calls++
}
