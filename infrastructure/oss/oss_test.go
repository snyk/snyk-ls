/*
 * © 2022 Snyk Limited All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package oss

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/observability/performance"
	ux2 "github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/uri"
)

// todo test issue parsing & conversion

func Test_determineTargetFile(t *testing.T) {
	scanner := New(performance.NewTestInstrumentor(), error_reporting.NewTestErrorReporter(), ux2.NewTestAnalytics(), cli.NewTestExecutor())
	assert.Equal(t, "package.json", scanner.determineTargetFile("package-lock.json"))
	assert.Equal(t, "pom.xml", scanner.determineTargetFile("pom.xml"))
	assert.Equal(t, "asdf", scanner.determineTargetFile("asdf"))
}

func Test_SuccessfulScanFile_TracksAnalytics(t *testing.T) {
	testutil.UnitTest(t)
	analytics := ux2.NewTestAnalytics()
	workingDir, _ := os.Getwd()
	executor := cli.NewTestExecutor()
	fileContent, _ := os.ReadFile(workingDir + "/testdata/oss-result.json")
	executor.ExecuteResponse = fileContent
	path, _ := filepath.Abs(workingDir + "/testdata/package.json")

	scanner := New(performance.NewTestInstrumentor(), error_reporting.NewTestErrorReporter(), analytics, executor)
	_, _ = scanner.Scan(context.Background(), path, "")

	assert.Len(t, analytics.GetAnalytics(), 1)
	assert.Equal(t, ux2.AnalysisIsReadyProperties{
		AnalysisType: ux2.OpenSource,
		Result:       ux2.Success,
	}, analytics.GetAnalytics()[0])
}

func Test_FindRange(t *testing.T) {
	scanner := New(performance.NewTestInstrumentor(), error_reporting.NewTestErrorReporter(), ux2.NewTestAnalytics(), cli.NewTestExecutor())
	issue := mavenTestIssue()
	const content = "0\n1\n2\n  implementation 'a:test:4.17.4'"

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

func Test_ContextCanceled_Scan_DoesNotScan(t *testing.T) {
	cliMock := cli.NewTestExecutor()
	scanner := New(performance.NewTestInstrumentor(), error_reporting.NewTestErrorReporter(), ux2.NewTestAnalytics(), cliMock)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _ = scanner.Scan(ctx, "", "")

	assert.False(t, cliMock.WasExecuted())
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
	scanner := New(performance.NewTestInstrumentor(), error_reporting.NewTestErrorReporter(), ux2.NewTestAnalytics(), cli.NewTestExecutor())

	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(t, "couldn't get working dir")
	}
	var path = filepath.Join(dir, "testdata", "oss-result.json")
	fileContent, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(t, "couldn't read test result file")
	}
	scanResults, err := scanner.unmarshallOssJson(fileContent)
	assert.NoError(t, err)
	assert.Len(t, scanResults, 1)
}

func TestUnmarshalOssJsonArray(t *testing.T) {
	scanner := New(performance.NewTestInstrumentor(), error_reporting.NewTestErrorReporter(), ux2.NewTestAnalytics(), cli.NewTestExecutor())

	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(t, "couldn't get working dir")
	}
	var path = filepath.Join(dir, "testdata", "oss-result-array.json")
	fileContent, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(t, "couldn't read test result file")
	}
	scanResults, err := scanner.unmarshallOssJson(fileContent)
	assert.NoError(t, err)
	assert.Len(t, scanResults, 3)
}

func TestUnmarshalOssErroneousJson(t *testing.T) {
	scanner := New(performance.NewTestInstrumentor(), error_reporting.NewTestErrorReporter(), ux2.NewTestAnalytics(), cli.NewTestExecutor())

	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(t, "couldn't get working dir")
	}
	var path = filepath.Join(dir, "testdata", "pom.xml")
	fileContent, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(t, "couldn't read test result file")
	}
	scanResults, err := scanner.unmarshallOssJson(fileContent)
	assert.Error(t, err)
	assert.Nil(t, scanResults)
}

func Test_toHover_asHTML(t *testing.T) {
	testutil.UnitTest(t)
	config.CurrentConfig().SetFormat(config.FormatHtml)

	var issue = sampleIssue()
	h := issue.getExtendedMessage(issue)

	assert.Equal(
		t,
		"\n### testIssue: <p>THOU SHALL NOT PASS</p>\n affecting  package \n### Vulnerability   | [testIssue](https://snyk.io/vuln/testIssue) \n **Fixed in: Not Fixed | Exploit maturity: LOW** \n<p>Getting into Moria is an issue!</p>\n",
		h,
	)
}

func Test_toHover_asMarkdown(t *testing.T) {
	testutil.UnitTest(t)
	config.CurrentConfig().SetFormat(config.FormatMd)

	var issue = sampleIssue()
	h := issue.getExtendedMessage(issue)

	assert.Equal(
		t,
		"\n### testIssue: THOU SHALL NOT PASS affecting  package \n### Vulnerability   | [testIssue](https://snyk.io/vuln/testIssue) \n **Fixed in: Not Fixed | Exploit maturity: LOW** \nGetting into Moria is an issue!",
		h,
	)
}

func Test_SeveralScansOnSameFolder_DoNotRunAtOnce(t *testing.T) {
	// Arrange
	concurrentScanRequests := 10
	workingDir, _ := os.Getwd()
	folderPath := workingDir
	fakeCli := cli.NewTestExecutor()
	fakeCli.ExecuteDuration = time.Second
	scanner := New(performance.NewTestInstrumentor(), error_reporting.NewTestErrorReporter(), ux2.NewTestAnalytics(), fakeCli)
	wg := sync.WaitGroup{}
	path, _ := filepath.Abs(workingDir + "/testdata/package.json")

	// Act
	for i := 0; i < concurrentScanRequests; i++ {
		// Adding a short delay so the cancel listener will start before a new scan is sending the cancel signal
		time.Sleep(100 * time.Millisecond)

		wg.Add(1)
		go func() {
			_, _ = scanner.Scan(context.Background(), path, folderPath)
			wg.Done()
		}()
	}
	wg.Wait()

	// Assert
	assert.Equal(t, 1, fakeCli.GetFinishedScans())
}

func sampleIssue() ossIssue {
	return ossIssue{
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
}

func Test_prepareScanCommand_ExpandsAdditionalParameters(t *testing.T) {
	testutil.UnitTest(t)
	scanner := New(performance.NewTestInstrumentor(), error_reporting.NewTestErrorReporter(), ux2.NewTestAnalytics(), cli.NewTestExecutor())

	settings := config.CliSettings{
		AdditionalOssParameters: []string{"--all-projects", "-d"},
	}
	config.CurrentConfig().SetCliSettings(&settings)
	cmd := scanner.prepareScanCommand("a")
	assert.Contains(t, cmd, "--all-projects")
	assert.Contains(t, cmd, "-d")
}

func Test_Scan_SchedulesNewScan(t *testing.T) {
	testutil.UnitTest(t)
	// Arrange
	workingDir, _ := os.Getwd()
	fakeCli := cli.NewTestExecutorWithResponse(path.Join(workingDir, "testdata/oss-result.json"))
	fakeCli.ExecuteDuration = time.Millisecond
	scanner := New(performance.NewTestInstrumentor(), error_reporting.NewTestErrorReporter(), ux2.NewTestAnalytics(), fakeCli)
	scanner.scheduledScanDuration = 50 * time.Millisecond
	path, _ := filepath.Abs(workingDir + "/testdata/package.json")

	// Act
	_, _ = scanner.Scan(context.Background(), path, "")

	// Assert
	assert.Eventually(t, func() bool {
		return fakeCli.GetFinishedScans() == 2
	}, 3*time.Second, 50*time.Millisecond)
}

func Test_scheduleNewScan_CapturesAnalytics(t *testing.T) {
	testutil.UnitTest(t)
	// Arrange
	fakeCli := cli.NewTestExecutor()
	analytics := ux2.NewTestAnalytics()
	scanner := New(performance.NewTestInstrumentor(), error_reporting.NewTestErrorReporter(), analytics, fakeCli)
	scanner.scheduledScanDuration = 50 * time.Millisecond
	workingDir, _ := os.Getwd()
	path, _ := filepath.Abs(path.Join(workingDir, "/testdata/package.json"))

	// Act
	scanner.scheduleNewScan(path)

	// Assert
	assert.Eventually(t, func() bool {
		return fakeCli.GetFinishedScans() == 1
	}, 3*time.Second, 50*time.Millisecond)

	assert.Equal(t, ux2.AnalysisIsTriggeredProperties{
		AnalysisType:    []ux2.AnalysisType{ux2.OpenSource},
		TriggeredByUser: false,
	}, analytics.GetAnalytics()[0])
}

func Test_scheduleNewScanWithProductDisabled_NoScanRun(t *testing.T) {
	testutil.UnitTest(t)

	// Arrange
	config.CurrentConfig().SetSnykOssEnabled(false)
	fakeCli := cli.NewTestExecutor()
	fakeCli.ExecuteDuration = time.Millisecond
	analytics := ux2.NewTestAnalytics()
	scanner := New(performance.NewTestInstrumentor(), error_reporting.NewTestErrorReporter(), analytics, fakeCli)
	scanner.scheduledScanDuration = 50 * time.Millisecond
	workingDir, _ := os.Getwd()
	path, _ := filepath.Abs(path.Join(workingDir, "/testdata/package.json"))

	// Act
	scanner.scheduleNewScan(path)

	// Assert
	time.Sleep(scanner.scheduledScanDuration + fakeCli.ExecuteDuration + 10*time.Millisecond)
	assert.Equal(t, 0, fakeCli.GetFinishedScans())
	assert.Len(t, analytics.GetAnalytics(), 0)
}

func Test_scheduleNewScanTwice_RunsOnlyOnce(t *testing.T) {
	testutil.UnitTest(t)

	// Arrange
	fakeCli := cli.NewTestExecutor()
	fakeCli.ExecuteDuration = time.Millisecond
	analytics := ux2.NewTestAnalytics()
	scanner := New(performance.NewTestInstrumentor(), error_reporting.NewTestErrorReporter(), analytics, fakeCli)
	scanner.scheduledScanDuration = 50 * time.Millisecond
	workingDir, _ := os.Getwd()
	path, _ := filepath.Abs(path.Join(workingDir, "/testdata/package.json"))

	// Act
	scanner.scheduleNewScan(path)
	time.Sleep(fakeCli.ExecuteDuration + 5*time.Millisecond) // prevent from the first scan cancellation
	scanner.scheduleNewScan(path)

	// Assert
	time.Sleep(3*(scanner.scheduledScanDuration+fakeCli.ExecuteDuration) + 5*time.Millisecond)
	assert.Equal(t, 1, fakeCli.GetFinishedScans())
}
