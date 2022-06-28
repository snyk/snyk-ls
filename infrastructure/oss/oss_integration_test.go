package oss_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/observability/performance"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_Scan(t *testing.T) {
	testutil.IntegTest(t)
	config.CurrentConfig().SetFormat(config.FormatHtml)
	ctx := context.Background()
	di.TestInit(t)
	di.EnvironmentInitializer().WaitUntilCLIAndAuthReady(ctx)

	workingDir, _ := os.Getwd()
	path, _ := filepath.Abs(workingDir + "/testdata/package.json")

	var issues []snyk.Issue
	output := func(i []snyk.Issue) {
		issues = i
	}

	di.OpenSourceScanner().Scan(ctx, path, output, "", nil)

	assert.NotEqual(t, 0, len(issues))
	assert.True(t, strings.Contains(issues[0].Message, "<p>"))
	recorder := &di.Instrumentor().(*performance.TestInstrumentor).SpanRecorder
	spans := (*recorder).Spans()
	assert.Equal(t, "oss.ScanFile", spans[0].GetOperation())
}
