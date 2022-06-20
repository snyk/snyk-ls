package oss

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/di"
	"github.com/snyk/snyk-ls/internal/cli"
	"github.com/snyk/snyk-ls/internal/hover"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/observability/ux"
	"github.com/snyk/snyk-ls/internal/preconditions"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/lsp"
)

func Test_determineTargetFile(t *testing.T) {
	assert.Equal(t, "package.json", determineTargetFile("package-lock.json"))
	assert.Equal(t, "pom.xml", determineTargetFile("pom.xml"))
	assert.Equal(t, "asdf", determineTargetFile("asdf"))
}

func Test_ScanWorkspace(t *testing.T) {
	testutil.IntegTest(t)
	di.TestInit(t)
	testutil.CreateDummyProgressListener(t)
	config.CurrentConfig().SetFormat(config.FormatHtml)
	ctx := context.Background()
	preconditions.EnsureReadyForAnalysisAndWait(ctx)

	workingDir, _ := os.Getwd()
	path, _ := filepath.Abs(workingDir + "/testdata")
	doc := uri.PathToUri(path)

	dChan := make(chan lsp.DiagnosticResult)
	hoverChan := make(chan lsp.Hover)

	wg := sync.WaitGroup{}
	wg.Add(1)
	snykCli := &cli.SnykCli{}

	go ScanWorkspace(ctx, snykCli, doc, &wg, dChan, hoverChan)

	diagnosticResult := <-dChan
	hoverResult := <-hoverChan

	assert.NotEqual(t, 0, len(diagnosticResult.Diagnostics))
	assert.NotEqual(t, 0, len(hoverResult.Hover))
	assert.True(t, strings.Contains(diagnosticResult.Diagnostics[0].Message, "<p>"))
	recorder := &di.Instrumentor().(*performance.TestInstrumentor).SpanRecorder
	spans := recorder.Spans()
	assert.Len(t, spans, 1)
	assert.Equal(t, "oss.ScanWorkspace", spans[0].GetOperation())
}

func Test_ScanFile(t *testing.T) {
	hover.ClearAllHovers()
	testutil.IntegTest(t)
	config.CurrentConfig().SetFormat(config.FormatHtml)
	ctx := context.Background()
	preconditions.EnsureReadyForAnalysisAndWait(ctx)
	di.TestInit(t)

	workingDir, _ := os.Getwd()
	path, _ := filepath.Abs(workingDir + "/testdata/package.json")

	dChan := make(chan lsp.DiagnosticResult)
	hoverChan := make(chan lsp.Hover)
	wg := sync.WaitGroup{}
	wg.Add(1)

	snykCli := &cli.SnykCli{}
	go ScanFile(ctx, snykCli, uri.PathToUri(path), &wg, dChan, hoverChan)

	diagnosticResult := <-dChan
	hoverResult := <-hoverChan

	assert.NotEqual(t, 0, len(diagnosticResult.Diagnostics))
	assert.NotEqual(t, 0, len(hoverResult.Hover))
	assert.True(t, strings.Contains(diagnosticResult.Diagnostics[0].Message, "<p>"))
	recorder := &di.Instrumentor().(*performance.TestInstrumentor).SpanRecorder
	spans := recorder.Spans()
	assert.Equal(t, "oss.ScanFile", spans[0].GetOperation())
}

func Test_Analytics(t *testing.T) {
	hover.ClearAllHovers()
	testutil.IntegTest(t)
	config.CurrentConfig().SetFormat(config.FormatHtml)
	ctx := context.Background()
	preconditions.EnsureReadyForAnalysisAndWait(ctx)
	di.TestInit(t)

	workingDir, _ := os.Getwd()
	path, _ := filepath.Abs(workingDir + "/testdata/package.json")

	dChan := make(chan lsp.DiagnosticResult)
	hoverChan := make(chan lsp.Hover)
	wg := sync.WaitGroup{}
	wg.Add(1)

	snykCli := &cli.SnykCli{}
	go ScanFile(ctx, snykCli, uri.PathToUri(path), &wg, dChan, hoverChan)
	wg.Wait()

	assert.GreaterOrEqual(t, len(di.Analytics().(*ux.AnalyticsRecorder).GetAnalytics()), 1)
	assert.Equal(t, ux.AnalysisIsReadyProperties{
		AnalysisType: ux.OpenSource,
		Result:       ux.Success,
	}, di.Analytics().(*ux.AnalyticsRecorder).GetAnalytics()[0])
}

func Test_FindRange(t *testing.T) {
	issue := mavenTestIssue()
	content := "0\n1\n2\n  implementation 'a:test:4.17.4'"

	var documentUri = uri.PathToUri("build.gradle")
	foundRange := findRange(issue, documentUri, []byte(content))

	assert.Equal(t, 3, foundRange.Start.Line)
	assert.Equal(t, 20, foundRange.Start.Character)
	assert.Equal(t, 31, foundRange.End.Character)
}

func Test_introducingPackageAndVersion(t *testing.T) {
	var issue = ossIssue{
		Id:             "testIssue",
		Name:           "SNYK-TEST-ISSUE-1",
		Title:          "THOU SHALL NOT PASS",
		Severity:       "1",
		LineNumber:     0,
		Description:    "Getting into Moria is an issue!",
		References:     nil,
		Version:        "",
		PackageManager: "npm",
		From:           []string{"goof@1.0.1", "lodash@4.17.4"},
	}

	actualPackage, actualVersion := introducingPackageAndVersion(issue)
	assert.Equal(t, "4.17.4", actualVersion)
	assert.Equal(t, "lodash", actualPackage)
}

func Test_introducingPackageAndVersionJava(t *testing.T) {
	issue := mavenTestIssue()

	actualPackage, actualVersion := introducingPackageAndVersion(issue)
	assert.Equal(t, "4.17.4", actualVersion)
	assert.Equal(t, "test", actualPackage)
}

func mavenTestIssue() ossIssue {
	var issue = ossIssue{
		Id:             "testIssue",
		Name:           "SNYK-TEST-ISSUE-1",
		Title:          "THOU SHALL NOT PASS",
		Severity:       "1",
		LineNumber:     0,
		Description:    "Getting into Moria is an issue!",
		References:     nil,
		Version:        "",
		PackageManager: "maven",
		From:           []string{"goof@1.0.1", "a:test@4.17.4"},
	}

	return issue
}

func TestUnmarshalOssJsonSingle(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(t, "couldn't get working dir")
	}
	var path = filepath.Join(dir, "testdata", "oss-result.json")
	fileContent, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatal(t, "couldn't read test result file")
	}
	scanResults, done, err := unmarshallOssJson(fileContent)
	assert.NoError(t, err)
	assert.False(t, done)
	assert.Len(t, scanResults, 1)
}

func TestUnmarshalOssJsonArray(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(t, "couldn't get working dir")
	}
	var path = filepath.Join(dir, "testdata", "oss-result-array.json")
	fileContent, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatal(t, "couldn't read test result file")
	}
	scanResults, done, err := unmarshallOssJson(fileContent)
	assert.NoError(t, err)
	assert.False(t, done)
	assert.Len(t, scanResults, 3)
}

func TestUnmarshalOssErroneousJson(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(t, "couldn't get working dir")
	}
	var path = filepath.Join(dir, "testdata", "pom.xml")
	fileContent, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatal(t, "couldn't read test result file")
	}
	scanResults, done, err := unmarshallOssJson(fileContent)
	assert.Error(t, err)
	assert.True(t, done)
	assert.Nil(t, scanResults)
}
