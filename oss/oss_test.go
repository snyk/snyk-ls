package oss

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	lsp2 "github.com/sourcegraph/go-lsp"
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

func Test_determineTargetFile(t *testing.T) {
	scanner := New(performance.NewTestInstrumentor(), error_reporting.NewTestErrorReporter(), ux.NewTestAnalytics(), cli.NewTestExecutor())
	assert.Equal(t, "package.json", scanner.determineTargetFile("package-lock.json"))
	assert.Equal(t, "pom.xml", scanner.determineTargetFile("pom.xml"))
	assert.Equal(t, "asdf", scanner.determineTargetFile("asdf"))
}

func Test_SuccessfulScanFile_TracksAnalytics(t *testing.T) {
	testutil.UnitTest(t)
	analytics := ux.NewTestAnalytics()
	workingDir, _ := os.Getwd()
	executor := cli.NewTestExecutor()
	fileContent, _ := ioutil.ReadFile(workingDir + "/testdata/oss-result.json")
	executor.ExecuteResponse = string(fileContent)
	filepath, _ := filepath.Abs(workingDir + "/testdata/package.json")

	scanner := New(performance.NewTestInstrumentor(), error_reporting.NewTestErrorReporter(), analytics, executor)
	scanner.ScanFile(context.Background(), uri.PathToUri(filepath), deleteme.NoopResultProcessor)

	assert.Len(t, analytics.GetAnalytics(), 1)
	assert.Equal(t, ux.AnalysisIsReadyProperties{
		AnalysisType: ux.OpenSource,
		Result:       ux.Success,
	}, analytics.GetAnalytics()[0])
}

func Test_FindRange(t *testing.T) {
	scanner := New(performance.NewTestInstrumentor(), error_reporting.NewTestErrorReporter(), ux.NewTestAnalytics(), cli.NewTestExecutor())
	issue := mavenTestIssue()
	content := "0\n1\n2\n  implementation 'a:test:4.17.4'"

	var documentUri = uri.PathToUri("build.gradle")
	foundRange := scanner.findRange(issue, documentUri, []byte(content))

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
	scanner := New(performance.NewTestInstrumentor(), error_reporting.NewTestErrorReporter(), ux.NewTestAnalytics(), cli.NewTestExecutor())

	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(t, "couldn't get working dir")
	}
	var path = filepath.Join(dir, "testdata", "oss-result.json")
	fileContent, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatal(t, "couldn't read test result file")
	}
	scanResults, done, err := scanner.unmarshallOssJson(fileContent)
	assert.NoError(t, err)
	assert.False(t, done)
	assert.Len(t, scanResults, 1)
}

func TestUnmarshalOssJsonArray(t *testing.T) {
	scanner := New(performance.NewTestInstrumentor(), error_reporting.NewTestErrorReporter(), ux.NewTestAnalytics(), cli.NewTestExecutor())

	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(t, "couldn't get working dir")
	}
	var path = filepath.Join(dir, "testdata", "oss-result-array.json")
	fileContent, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatal(t, "couldn't read test result file")
	}
	scanResults, done, err := scanner.unmarshallOssJson(fileContent)
	assert.NoError(t, err)
	assert.False(t, done)
	assert.Len(t, scanResults, 3)
}

func TestUnmarshalOssErroneousJson(t *testing.T) {
	scanner := New(performance.NewTestInstrumentor(), error_reporting.NewTestErrorReporter(), ux.NewTestAnalytics(), cli.NewTestExecutor())

	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(t, "couldn't get working dir")
	}
	var path = filepath.Join(dir, "testdata", "pom.xml")
	fileContent, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatal(t, "couldn't read test result file")
	}
	scanResults, done, err := scanner.unmarshallOssJson(fileContent)
	assert.Error(t, err)
	assert.True(t, done)
	assert.Nil(t, scanResults)
}

func Test_toHover_asHTML(t *testing.T) {
	scanner := New(performance.NewTestInstrumentor(), error_reporting.NewTestErrorReporter(), ux.NewTestAnalytics(), cli.NewTestExecutor())

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

	h := scanner.toHover(issue, scanner.findRange(issue, documentUri, []byte(content)))

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
	scanner := New(performance.NewTestInstrumentor(), error_reporting.NewTestErrorReporter(), ux.NewTestAnalytics(), cli.NewTestExecutor())

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

	h := scanner.toHover(issue, scanner.findRange(issue, documentUri, []byte(content)))

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
