package iac

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/observability/performance"
	ux2 "github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/internal/testutil"
)

//todo iac is undertested, at a very least we should make sure the CLI gets the right commands in

func Test_ScanWorkspace_IsInstrumented(t *testing.T) {
	testutil.UnitTest(t)
	instrumentor := performance.NewTestInstrumentor()
	scanner := New(instrumentor, error_reporting.NewTestErrorReporter(), ux2.NewTestAnalytics(), cli.NewTestExecutor())
	getwd, _ := os.Getwd()

	scanner.Scan(context.Background(), filepath.Clean(getwd+"/testdata.yml"), "", nil)

	spans := instrumentor.SpanRecorder.Spans()
	assert.Len(t, spans, 1)
	assert.Equal(t, "iac.doScan", spans[0].GetOperation())
	assert.Equal(t, "", spans[0].GetTxName())
}

func Test_ScanFile_IsInstrumented(t *testing.T) {
	testutil.UnitTest(t)
	instrumentor := performance.NewTestInstrumentor()
	scanner := New(instrumentor, error_reporting.NewTestErrorReporter(), ux2.NewTestAnalytics(), cli.NewTestExecutor())

	scanner.Scan(context.Background(), "fake.yml", "", nil)

	spans := instrumentor.SpanRecorder.Spans()
	assert.Len(t, spans, 1)
	assert.Equal(t, "iac.doScan", spans[0].GetOperation())
	assert.Equal(t, "", spans[0].GetTxName())
}

func Test_SuccessfulScanFile_TracksAnalytics(t *testing.T) {
	testutil.UnitTest(t)
	analytics := ux2.NewTestAnalytics()
	scanner := New(performance.NewTestInstrumentor(), error_reporting.NewTestErrorReporter(), analytics, cli.NewTestExecutor())

	scanner.Scan(context.Background(), "fake.yml", "", nil)

	assert.Len(t, analytics.GetAnalytics(), 1)
	assert.Equal(t, ux2.AnalysisIsReadyProperties{
		AnalysisType: ux2.InfrastructureAsCode,
		Result:       ux2.Success,
	}, analytics.GetAnalytics()[0])
}

func Test_ErroredWorkspaceScan_TracksAnalytics(t *testing.T) {
	testutil.UnitTest(t)
	analytics := ux2.NewTestAnalytics()
	executor := cli.NewTestExecutor()
	scanner := New(performance.NewTestInstrumentor(), error_reporting.NewTestErrorReporter(), analytics, executor)

	executor.ExecuteResponse = "invalid JSON"
	scanner.Scan(context.Background(), "fake.yml", "", nil)

	assert.Len(t, analytics.GetAnalytics(), 1)
	assert.Equal(t, ux2.AnalysisIsReadyProperties{
		AnalysisType: ux2.InfrastructureAsCode,
		Result:       ux2.Error,
	}, analytics.GetAnalytics()[0])
}

func Test_toHover_asHTML(t *testing.T) {
	testutil.UnitTest(t)
	scanner := New(performance.NewTestInstrumentor(), error_reporting.NewTestErrorReporter(), ux2.NewTestAnalytics(), cli.NewTestExecutor())
	config.CurrentConfig().SetFormat(config.FormatHtml)

	h := scanner.getExtendedMessage(sampleIssue())

	assert.Equal(
		t,
		"\n### PublicID: <p>Title</p>\n\n\n**Issue:** <p>Issue</p>\n\n\n**Impact:** <p>Impact</p>\n\n\n**Resolve:** <p>Resolve</p>\n\n",
		h,
	)
}

func Test_toHover_asMD(t *testing.T) {
	testutil.UnitTest(t)
	scanner := New(performance.NewTestInstrumentor(), error_reporting.NewTestErrorReporter(), ux2.NewTestAnalytics(), cli.NewTestExecutor())
	config.CurrentConfig().SetFormat(config.FormatMd)

	h := scanner.getExtendedMessage(sampleIssue())

	assert.Equal(
		t,
		"\n### PublicID: Title\n\n**Issue:** Issue\n\n**Impact:** Impact\n\n**Resolve:** Resolve\n",
		h,
	)
}

func sampleIssue() iacIssue {
	return iacIssue{
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
	}
}
