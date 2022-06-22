package iac

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/di"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/snyk/issues"
	"github.com/snyk/snyk-ls/internal/cli"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/observability/ux"
	"github.com/snyk/snyk-ls/internal/preconditions"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/uri"
	lsp2 "github.com/snyk/snyk-ls/lsp"
)

func Test_ScanWorkspace(t *testing.T) {
	testutil.IntegTest(t)
	testutil.CreateDummyProgressListener(t)
	di.TestInit(t)
	ctx := context.Background()
	preconditions.EnsureReadyForAnalysisAndWait(ctx)
	config.CurrentConfig().SetFormat(config.FormatHtml)

	getwd, _ := os.Getwd()
	path := filepath.Clean(getwd + "/testdata")
	doc := uri.PathToUri(path)

	dChan := make(chan lsp2.DiagnosticResult, 1)
	hoverChan := make(chan hover.DocumentHovers, 1)

	wg := sync.WaitGroup{}
	wg.Add(1)
	snykCli := cli.SnykCli{}
	go ScanWorkspace(ctx, snykCli, doc, &wg, dChan, hoverChan)
	wg.Wait()

	diagnosticResult := <-dChan
	hoverResult := <-hoverChan

	assert.NotEqual(t, 0, len(diagnosticResult.Diagnostics))
	assert.NotEqual(t, 0, len(hoverResult.Hover))

	assert.True(t, strings.Contains(diagnosticResult.Diagnostics[0].Message, "<p>"))

	recorder := &di.Instrumentor().(*performance.TestInstrumentor).SpanRecorder
	spans := recorder.Spans()
	assert.Len(t, spans, 1)
	assert.Equal(t, "iac.doScan", spans[0].GetOperation())
	assert.Equal(t, "", spans[0].GetTxName())
}

func Test_ScanFile(t *testing.T) {
	testutil.IntegTest(t)
	di.TestInit(t)
	config.CurrentConfig().SetFormat(config.FormatHtml)
	ctx := context.Background()
	preconditions.EnsureReadyForAnalysisAndWait(ctx)

	workingDir, _ := os.Getwd()
	path, _ := filepath.Abs(workingDir + "/testdata/RBAC.yaml")

	doc := lsp.TextDocumentItem{
		URI:        uri.PathToUri(path),
		LanguageID: "yaml",
		Version:    0,
	}

	dChan := make(chan lsp2.DiagnosticResult, 1)
	hoverChan := make(chan hover.DocumentHovers, 1)

	wg := sync.WaitGroup{}
	wg.Add(1)
	snykCli := cli.SnykCli{}
	go ScanFile(ctx, snykCli, doc.URI, &wg, dChan, hoverChan)
	wg.Wait()

	diagnosticResult := <-dChan
	hoverResult := <-hoverChan

	assert.NotEqual(t, 0, len(hoverResult.Hover))
	assert.NotEqual(t, 0, len(diagnosticResult.Diagnostics))

	assert.True(t, strings.Contains(diagnosticResult.Diagnostics[0].Message, "<p>"))

	recorder := &di.Instrumentor().(*performance.TestInstrumentor).SpanRecorder
	spans := recorder.Spans()
	assert.Len(t, spans, 1)
	assert.Equal(t, "iac.doScan", spans[0].GetOperation())
	assert.Equal(t, "", spans[0].GetTxName())
}

func Test_Analytics(t *testing.T) {
	testutil.IntegTest(t)
	di.TestInit(t)
	config.CurrentConfig().SetFormat(config.FormatHtml)
	ctx := context.Background()
	preconditions.EnsureReadyForAnalysisAndWait(ctx)

	workingDir, _ := os.Getwd()
	path, _ := filepath.Abs(workingDir + "/testdata/RBAC.yaml")

	doc := lsp.TextDocumentItem{
		URI:        uri.PathToUri(path),
		LanguageID: "yaml",
		Version:    0,
	}

	dChan := make(chan lsp2.DiagnosticResult, 1)
	hoverChan := make(chan hover.DocumentHovers, 1)

	wg := sync.WaitGroup{}
	wg.Add(1)
	snykCli := cli.SnykCli{}
	go ScanFile(ctx, snykCli, doc.URI, &wg, dChan, hoverChan)
	wg.Wait()

	assert.GreaterOrEqual(t, len(di.Analytics().(*ux.AnalyticsRecorder).GetAnalytics()), 1)
	assert.Equal(t, ux.AnalysisIsReadyProperties{
		AnalysisType: ux.InfrastructureAsCode,
		Result:       ux.Success,
	}, di.Analytics().(*ux.AnalyticsRecorder).GetAnalytics()[0])
}

func Test_toHover_asHTML(t *testing.T) {
	testutil.UnitTest(t)
	config.CurrentConfig().SetFormat(config.FormatHtml)

	h := toHover(iacIssue{
		PublicID:      "PublicID",
		Title:         "Title",
		Severity:      "low",
		LineNumber:    3,
		Documentation: "4",
		IacDescription: iacDescription{
			Issue:   "Issue",
			Impact:  "Impact",
			Resolve: "Resolve",
		},
	})

	assert.Equal(
		t,
		hover.Hover[hover.Context]{
			Id: "PublicID",
			Range: lsp.Range{
				Start: lsp.Position{Line: 3, Character: 0},
				End:   lsp.Position{Line: 3, Character: 80},
			},
			Message: "\n### PublicID: <p>Title</p>\n\n\n**Issue:** <p>Issue</p>\n\n\n**Impact:** <p>Impact</p>\n\n\n**Resolve:** <p>Resolve</p>\n\n",
			Context: issues.Issue{ID: "PublicID", Severity: issues.Low, IssueType: issues.InfrastructureIssue},
		},
		h,
	)
}

func Test_toHover_asMD(t *testing.T) {
	testutil.UnitTest(t)
	config.CurrentConfig().SetFormat(config.FormatMd)

	h := toHover(iacIssue{
		PublicID:      "PublicID",
		Title:         "Title",
		Severity:      "high",
		LineNumber:    3,
		Documentation: "4",
		IacDescription: iacDescription{
			Issue:   "Issue",
			Impact:  "Impact",
			Resolve: "Resolve",
		},
	})

	assert.Equal(
		t,
		hover.Hover[hover.Context]{
			Id: "PublicID",
			Range: lsp.Range{
				Start: lsp.Position{Line: 3, Character: 0},
				End:   lsp.Position{Line: 3, Character: 80},
			},
			Message: "\n### PublicID: Title\n\n**Issue:** Issue\n\n**Impact:** Impact\n\n**Resolve:** Resolve\n",
			Context: issues.Issue{ID: "PublicID", Severity: issues.High, IssueType: issues.InfrastructureIssue},
		},
		h,
	)
}
