package oss

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	lsp2 "github.com/sourcegraph/go-lsp"
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
	ctx := context.Background()
	preconditions.EnsureReadyForAnalysisAndWait(ctx)

	workingDir, _ := os.Getwd()
	path, _ := filepath.Abs(workingDir + "/testdata")
	doc := uri.PathToUri(path)

	snykCli := &cli.SnykCli{}

	diagnosticMap := map[string][]lsp.Diagnostic{}
	var foundHovers []hover.DocumentHovers
	output := func(issues map[string][]lsp.Diagnostic, hovers []hover.DocumentHovers) {
		diagnosticMap = issues
		foundHovers = hovers
	}

	ScanWorkspace(ctx, snykCli, doc, output)

	assert.NotEqual(t, 0, len(diagnosticMap))
	assert.NotEqual(t, 0, len(foundHovers))
	recorder := &di.Instrumentor().(*performance.TestInstrumentor).SpanRecorder
	spans := recorder.Spans()
	assert.Len(t, spans, 1)
	assert.Equal(t, "oss.ScanWorkspace", spans[0].GetOperation())
}

func Test_ScanFile(t *testing.T) {
	testutil.IntegTest(t)
	config.CurrentConfig().SetFormat(config.FormatHtml)
	ctx := context.Background()
	preconditions.EnsureReadyForAnalysisAndWait(ctx)
	di.TestInit(t)

	workingDir, _ := os.Getwd()
	path, _ := filepath.Abs(workingDir + "/testdata/package.json")

	snykCli := &cli.SnykCli{}

	diagnosticMap := map[string][]lsp.Diagnostic{}
	var foundHovers []hover.DocumentHovers
	output := func(issues map[string][]lsp.Diagnostic, hovers []hover.DocumentHovers) {
		diagnosticMap = issues
		foundHovers = hovers
	}

	ScanFile(ctx, snykCli, uri.PathToUri(path), output)

	assert.NotEqual(t, 0, len(diagnosticMap))
	assert.NotEqual(t, 0, len(foundHovers))
	assert.True(t, strings.Contains(diagnosticMap[path][0].Message, "<p>"))
	recorder := &di.Instrumentor().(*performance.TestInstrumentor).SpanRecorder
	spans := recorder.Spans()
	assert.Equal(t, "oss.ScanFile", spans[0].GetOperation())
}

func Test_Analytics(t *testing.T) {
	testutil.IntegTest(t)
	config.CurrentConfig().SetFormat(config.FormatHtml)
	ctx := context.Background()
	preconditions.EnsureReadyForAnalysisAndWait(ctx)
	di.TestInit(t)

	workingDir, _ := os.Getwd()
	path, _ := filepath.Abs(workingDir + "/testdata/package.json")

	snykCli := &cli.SnykCli{}
	ScanFile(ctx, snykCli, uri.PathToUri(path), testutil.NoopOutput)

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

func Test_toHover_asHTML(t *testing.T) {
	testutil.UnitTest(t)
	config.CurrentConfig().SetFormat(config.FormatHtml)

	content := "0\n1\n2\n  implementation 'a:test:4.17.4'"
	var documentUri = uri.PathToUri("build.gradle")

	var issue = ossIssue{
		Id:             "testIssue",
		Name:           "SNYK-TEST-ISSUE-1",
		Title:          "THOU SHALL NOT PASS",
		Severity:       "low",
		LineNumber:     0,
		Description:    "Getting into Moria is an issue!",
		References:     nil,
		Version:        "",
		PackageManager: "npm",
		From:           []string{"goof@1.0.1", "lodash@4.17.4"},
	}

	h := toHover(issue, findRange(issue, documentUri, []byte(content)))

	assert.Equal(
		t,
		hover.Hover[hover.Context]{
			Id:      "testIssue",
			Range:   lsp2.Range{Start: lsp2.Position{Line: 0, Character: 0}, End: lsp2.Position{Line: 0, Character: 0}},
			Message: "\n### testIssue: <p>THOU SHALL NOT PASS</p>\n affecting  package \n### Vulnerability   | [testIssue](https://snyk.io/vuln/testIssue) \n **Fixed in: Not Fixed | Exploit maturity: LOW** \n<p>Getting into Moria is an issue!</p>\n",
			Context: issues.Issue{
				ID:        "testIssue",
				Severity:  issues.Medium,
				IssueType: issues.DependencyVulnerability,
			},
		},
		h,
	)
}

func Test_toHover_asMarkdown(t *testing.T) {
	testutil.UnitTest(t)
	config.CurrentConfig().SetFormat(config.FormatMd)

	content := "0\n1\n2\n  implementation 'a:test:4.17.4'"
	var documentUri = uri.PathToUri("build.gradle")

	var issue = ossIssue{
		Id:             "testIssue",
		Name:           "SNYK-TEST-ISSUE-1",
		Title:          "THOU SHALL NOT PASS",
		Severity:       "high",
		LineNumber:     0,
		Description:    "Getting into Moria is an issue!",
		References:     nil,
		Version:        "",
		PackageManager: "npm",
		From:           []string{"goof@1.0.1", "lodash@4.17.4"},
	}

	h := toHover(issue, findRange(issue, documentUri, []byte(content)))

	assert.Equal(
		t,
		hover.Hover[hover.Context]{
			Id:      "testIssue",
			Range:   lsp2.Range{Start: lsp2.Position{Line: 0, Character: 0}, End: lsp2.Position{Line: 0, Character: 0}},
			Message: "\n### testIssue: THOU SHALL NOT PASS affecting  package \n### Vulnerability   | [testIssue](https://snyk.io/vuln/testIssue) \n **Fixed in: Not Fixed | Exploit maturity: HIGH** \nGetting into Moria is an issue!",
			Context: issues.Issue{
				ID:        "testIssue",
				Severity:  issues.High,
				IssueType: issues.DependencyVulnerability,
			},
		},
		h,
	)
}
