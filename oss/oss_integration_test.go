package oss_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/di"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/lsp"
)

func Test_ScanWorkspace(t *testing.T) {
	testutil.IntegTest(t)
	di.TestInit(t)
	testutil.CreateDummyProgressListener(t)
	ctx := context.Background()
	di.EnvironmentInitializer().WaitUntilCLIAndAuthReady(ctx)

	workingDir, _ := os.Getwd()
	path, _ := filepath.Abs(workingDir + "/testdata")
	doc := uri.PathToUri(path)

	var foundHovers []hover.DocumentHovers
	var diagnostics []lsp.Diagnostic

	output := func(issues []lsp.Diagnostic, hovers []hover.DocumentHovers) {
		diagnostics = issues
		foundHovers = hovers
	}

	di.OpenSourceScanner().ScanWorkspace(ctx, doc, output)

	assert.NotEqual(t, 0, len(diagnostics))
	assert.NotEqual(t, 0, len(foundHovers))
	recorder := &di.Instrumentor().(*performance.TestInstrumentor).SpanRecorder
	spans := (*recorder).Spans()
	assert.Len(t, spans, 1)
	assert.Equal(t, "oss.ScanWorkspace", spans[0].GetOperation())
}

func Test_ScanFile(t *testing.T) {
	testutil.IntegTest(t)
	config.CurrentConfig().SetFormat(config.FormatHtml)
	ctx := context.Background()
	di.EnvironmentInitializer().WaitUntilCLIAndAuthReady(ctx)
	di.TestInit(t)

	workingDir, _ := os.Getwd()
	path, _ := filepath.Abs(workingDir + "/testdata/package.json")

	var diagnostics []lsp.Diagnostic
	var foundHovers []hover.DocumentHovers
	output := func(issues []lsp.Diagnostic, hovers []hover.DocumentHovers) {
		diagnostics = issues
		foundHovers = hovers
	}

	di.OpenSourceScanner().ScanFile(ctx, uri.PathToUri(path), output)

	assert.NotEqual(t, 0, len(diagnostics))
	assert.NotEqual(t, 0, len(foundHovers))
	assert.True(t, strings.Contains(diagnostics[0].Message, "<p>"))
	recorder := &di.Instrumentor().(*performance.TestInstrumentor).SpanRecorder
	spans := (*recorder).Spans()
	assert.Equal(t, "oss.ScanFile", spans[0].GetOperation())
}
