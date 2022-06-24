package iac

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/workspace/deleteme"
	"github.com/snyk/snyk-ls/domain/snyk/issues"
	"github.com/snyk/snyk-ls/internal/cli"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/observability/ux"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/uri"
)

//todo iac is undertested, at a very least we should make sure the CLI gets the right commands in

func Test_ScanWorkspace_IsInstrumented(t *testing.T) {
	testutil.UnitTest(t)
	instrumentor := performance.NewTestInstrumentor()
	scanner := New(instrumentor, error_reporting.NewTestErrorReporter(), ux.NewTestAnalytics(), cli.NewTestExecutor())
	getwd, _ := os.Getwd()

	scanner.ScanWorkspace(context.Background(), uri.PathToUri(filepath.Clean(getwd+"/testdata")), deleteme.NoopResultProcessor)

	spans := instrumentor.SpanRecorder.Spans()
	assert.Len(t, spans, 1)
	assert.Equal(t, "iac.doScan", spans[0].GetOperation())
	assert.Equal(t, "", spans[0].GetTxName())
}

func Test_ScanFile_IsInstrumented(t *testing.T) {
	testutil.UnitTest(t)
	instrumentor := performance.NewTestInstrumentor()
	scanner := New(instrumentor, error_reporting.NewTestErrorReporter(), ux.NewTestAnalytics(), cli.NewTestExecutor())

	scanner.ScanFile(context.Background(), uri.PathToUri("fake.yml"), deleteme.NoopResultProcessor)

	spans := instrumentor.SpanRecorder.Spans()
	assert.Len(t, spans, 1)
	assert.Equal(t, "iac.doScan", spans[0].GetOperation())
	assert.Equal(t, "", spans[0].GetTxName())
}

func Test_SuccessfulScanFile_TracksAnalytics(t *testing.T) {
	testutil.UnitTest(t)
	analytics := ux.NewTestAnalytics()
	scanner := New(performance.NewTestInstrumentor(), error_reporting.NewTestErrorReporter(), analytics, cli.NewTestExecutor())

	scanner.ScanFile(context.Background(), uri.PathToUri("fake.yml"), deleteme.NoopResultProcessor)

	assert.Len(t, analytics.GetAnalytics(), 1)
	assert.Equal(t, ux.AnalysisIsReadyProperties{
		AnalysisType: ux.InfrastructureAsCode,
		Result:       ux.Success,
	}, analytics.GetAnalytics()[0])
}

func Test_ErroredWorkspaceScan_TracksAnalytics(t *testing.T) {
	testutil.UnitTest(t)
	analytics := ux.NewTestAnalytics()
	executor := cli.NewTestExecutor()
	scanner := New(performance.NewTestInstrumentor(), error_reporting.NewTestErrorReporter(), analytics, executor)

	executor.ExecuteResponse = "invalid JSON"
	scanner.ScanWorkspace(context.Background(), uri.PathToUri("fake.yml"), deleteme.NoopResultProcessor)

	assert.Len(t, analytics.GetAnalytics(), 1)
	assert.Equal(t, ux.AnalysisIsReadyProperties{
		AnalysisType: ux.InfrastructureAsCode,
		Result:       ux.Error,
	}, analytics.GetAnalytics()[0])
}

func Test_toHover_asHTML(t *testing.T) {
	testutil.UnitTest(t)
	scanner := New(performance.NewTestInstrumentor(), error_reporting.NewTestErrorReporter(), ux.NewTestAnalytics(), cli.NewTestExecutor())
	config.CurrentConfig().SetFormat(config.FormatHtml)

	h := scanner.toHover(iacIssue{
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
	scanner := New(performance.NewTestInstrumentor(), error_reporting.NewTestErrorReporter(), ux.NewTestAnalytics(), cli.NewTestExecutor())
	config.CurrentConfig().SetFormat(config.FormatMd)

	h := scanner.toHover(iacIssue{
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
