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

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/infrastructure/learn/mock_learn"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/observability/ux"
	"github.com/snyk/snyk-ls/internal/testutil"
)

const testDataPackageJson = "/testdata/package.json"

// todo test issue parsing & conversion

func Test_toIssueSeverity(t *testing.T) {
	testutil.UnitTest(t)
	issue := ossIssue{Severity: "critical"}
	assert.Equal(t, snyk.Critical, issue.ToIssueSeverity())
	issue = ossIssue{Severity: "high"}
	assert.Equal(t, snyk.High, issue.ToIssueSeverity())
	issue = ossIssue{Severity: "medium"}
	assert.Equal(t, snyk.Medium, issue.ToIssueSeverity())
	issue = ossIssue{Severity: "info"}
	assert.Equal(t, snyk.Low, issue.ToIssueSeverity())
	issue = ossIssue{Severity: "asdf"}
	assert.Equal(t, snyk.Low, issue.ToIssueSeverity())
}

func Test_determineTargetFile(t *testing.T) {
	c := testutil.UnitTest(t)
	scanner := NewCLIScanner(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), ux.NewTestAnalytics(c), cli.NewTestExecutor(), getLearnMock(t), notification.NewNotifier()).(*CLIScanner)
	assert.Equal(t, "package.json", scanner.determineTargetFile("package-lock.json"))
	assert.Equal(t, "pom.xml", scanner.determineTargetFile("pom.xml"))
	assert.Equal(t, "asdf", scanner.determineTargetFile("asdf"))
	assert.Equal(t, "js/package.json", scanner.determineTargetFile("js/package-lock.json"))
}

func Test_SuccessfulScanFile_TracksAnalytics(t *testing.T) {
	c := testutil.UnitTest(t)
	analytics := ux.NewTestAnalytics(c)
	workingDir, _ := os.Getwd()
	executor := cli.NewTestExecutor()
	fileContent, _ := os.ReadFile(workingDir + "/testdata/oss-result.json")
	executor.ExecuteResponse = fileContent
	p, _ := filepath.Abs(workingDir + testDataPackageJson)

	scanner := NewCLIScanner(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), analytics, executor, getLearnMock(t), notification.NewNotifier())
	_, _ = scanner.Scan(context.Background(), p, "")

	assert.Len(t, analytics.GetAnalytics(), 1)
	assert.Equal(t, ux.AnalysisIsReadyProperties{
		AnalysisType: ux.OpenSource,
		Result:       ux.Success,
	}, analytics.GetAnalytics()[0])
}

func Test_FindRange(t *testing.T) {
	issue := mavenTestIssue()
	const content = "0\n1\n2\n  implementation 'a:test:4.17.4'"

	var p = "build.gradle"
	foundRange := findRange(issue, p, []byte(content))

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

func Test_toIssue_LearnParameterConversion(t *testing.T) {
	sampleOssIssue := sampleIssue()
	scanner := CLIScanner{
		learnService: getLearnMock(t),
	}

	issue := toIssue("testPath", sampleOssIssue, &scanResult{}, snyk.Range{}, scanner.learnService, scanner.errorReporter)

	assert.Equal(t, sampleOssIssue.Id, issue.ID)
	assert.Equal(t, sampleOssIssue.Identifiers.CWE, issue.CWEs)
	assert.Equal(t, sampleOssIssue.Identifiers.CVE, issue.CVEs)
	assert.Equal(t, sampleOssIssue.PackageManager, issue.Ecosystem)
	assert.Equal(t, "url", (issue.AdditionalData).(snyk.OssIssueData).Lesson)
}

//nolint:dupl // test cases differ by package name
func Test_toIssue_CodeActions_WithNPMFix(t *testing.T) {
	config.CurrentConfig().SetSnykOSSQuickFixCodeActionsEnabled(true)

	sampleOssIssue := sampleIssue()
	scanner := CLIScanner{
		learnService: getLearnMock(t),
	}
	sampleOssIssue.UpgradePath = []any{"false", "pkg@v2"}

	issue := toIssue("testPath", sampleOssIssue, &scanResult{}, snyk.Range{}, scanner.learnService, scanner.errorReporter)

	assert.Equal(t, sampleOssIssue.Id, issue.ID)
	assert.Equal(t, 3, len(issue.CodeActions))
	assert.Equal(t, "Upgrade to \"pkg\": \"v2\" (Snyk)", issue.CodeActions[0].Title)
	assert.Equal(t, "Open description of 'THOU SHALL NOT PASS affecting package pkg' in browser (Snyk)",
		issue.CodeActions[1].Title)
	assert.Equal(t, "Learn more about THOU SHALL NOT PASS (Snyk)", issue.CodeActions[2].Title)
	assert.Equal(t, 1, len(issue.CodelensCommands))
	assert.Equal(t, "⚡ Fix this issue: Upgrade to \"pkg\": \"v2\" (Snyk)", issue.CodelensCommands[0].Title)
}

//nolint:dupl // test cases differ by package name
func Test_toIssue_CodeActions_WithScopedNPMFix(t *testing.T) {
	config.CurrentConfig().SetSnykOSSQuickFixCodeActionsEnabled(true)

	sampleOssIssue := sampleIssue()
	scanner := CLIScanner{
		learnService: getLearnMock(t),
	}
	sampleOssIssue.UpgradePath = []any{"false", "@org/pkg@v2"}

	issue := toIssue("testPath", sampleOssIssue, &scanResult{}, snyk.Range{}, scanner.learnService, scanner.errorReporter)

	assert.Equal(t, sampleOssIssue.Id, issue.ID)
	assert.Equal(t, 3, len(issue.CodeActions))
	assert.Equal(t, "Upgrade to \"@org/pkg\": \"v2\" (Snyk)", issue.CodeActions[0].Title)
	assert.Equal(t, "Open description of 'THOU SHALL NOT PASS affecting package pkg' in browser (Snyk)",
		issue.CodeActions[1].Title)
	assert.Equal(t, "Learn more about THOU SHALL NOT PASS (Snyk)", issue.CodeActions[2].Title)
	assert.Equal(t, 1, len(issue.CodelensCommands))
	assert.Equal(t, "⚡ Fix this issue: Upgrade to \"@org/pkg\": \"v2\" (Snyk)", issue.CodelensCommands[0].Title)
}

func Test_toIssue_CodeActions_WithGomodFix(t *testing.T) {
	config.CurrentConfig().SetSnykOSSQuickFixCodeActionsEnabled(true)

	sampleOssIssue := sampleIssue()
	scanner := CLIScanner{
		learnService: getLearnMock(t),
	}
	sampleOssIssue.PackageManager = "gomodules"
	sampleOssIssue.UpgradePath = []any{"false", "pkg@v2"}

	issue := toIssue("testPath", sampleOssIssue, &scanResult{}, snyk.Range{}, scanner.learnService, scanner.errorReporter)

	assert.Equal(t, sampleOssIssue.Id, issue.ID)
	assert.Equal(t, 3, len(issue.CodeActions))
	assert.Equal(t, "Upgrade to vv2 (Snyk)", issue.CodeActions[0].Title)
	assert.Equal(t, 1, len(issue.CodelensCommands))
	assert.Equal(t, "⚡ Fix this issue: Upgrade to vv2 (Snyk)", issue.CodelensCommands[0].Title)
}

func Test_toIssue_CodeActions_WithMavenFix(t *testing.T) {
	config.CurrentConfig().SetSnykOSSQuickFixCodeActionsEnabled(true)

	sampleOssIssue := sampleIssue()
	scanner := CLIScanner{
		learnService: getLearnMock(t),
	}
	sampleOssIssue.PackageManager = "maven"
	sampleOssIssue.UpgradePath = []any{"false", "pkg@v2"}

	issue := toIssue("testPath", sampleOssIssue, &scanResult{}, snyk.Range{}, scanner.learnService, scanner.errorReporter)

	assert.Equal(t, sampleOssIssue.Id, issue.ID)
	assert.Equal(t, 3, len(issue.CodeActions))
	assert.Equal(t, "Upgrade to v2 (Snyk)", issue.CodeActions[0].Title)
	assert.Equal(t, 1, len(issue.CodelensCommands))
	assert.Equal(t, "⚡ Fix this issue: Upgrade to v2 (Snyk)", issue.CodelensCommands[0].Title)
}

func Test_toIssue_CodeActions_WithMavenFixForBuildGradle(t *testing.T) {
	config.CurrentConfig().SetSnykOSSQuickFixCodeActionsEnabled(true)

	sampleOssIssue := sampleIssue()
	scanner := CLIScanner{
		learnService: getLearnMock(t),
	}
	sampleOssIssue.PackageManager = "maven"
	sampleOssIssue.UpgradePath = []any{"false", "a:pkg@v2"}

	issue := toIssue("testPath", sampleOssIssue, &scanResult{}, snyk.Range{}, scanner.learnService, scanner.errorReporter)

	assert.Equal(t, sampleOssIssue.Id, issue.ID)
	assert.Equal(t, 3, len(issue.CodeActions))
	assert.Equal(t, "Upgrade to v2 (Snyk)", issue.CodeActions[0].Title)
	assert.Equal(t, 1, len(issue.CodelensCommands))
	assert.Equal(t, "⚡ Fix this issue: Upgrade to v2 (Snyk)", issue.CodelensCommands[0].Title)

	// TODO: remove once https://snyksec.atlassian.net/browse/OSM-1775 is fixed
	issue = toIssue("build.gradle", sampleOssIssue, &scanResult{}, snyk.Range{}, scanner.learnService, scanner.errorReporter)

	assert.Equal(t, sampleOssIssue.Id, issue.ID)
	assert.Equal(t, 3, len(issue.CodeActions))
	assert.Equal(t, "Upgrade to pkg:v2 (Snyk)", issue.CodeActions[0].Title)
	assert.Equal(t, 1, len(issue.CodelensCommands))
	assert.Equal(t, "⚡ Fix this issue: Upgrade to pkg:v2 (Snyk)", issue.CodelensCommands[0].Title)

	// TODO: remove once https://snyksec.atlassian.net/browse/OSM-1775 is fixed
	issue = toIssue("build.gradle.kts", sampleOssIssue, &scanResult{}, snyk.Range{}, scanner.learnService, scanner.errorReporter)

	assert.Equal(t, sampleOssIssue.Id, issue.ID)
	assert.Equal(t, 3, len(issue.CodeActions))
	assert.Equal(t, "Upgrade to pkg:v2 (Snyk)", issue.CodeActions[0].Title)
	assert.Equal(t, 1, len(issue.CodelensCommands))
	assert.Equal(t, "⚡ Fix this issue: Upgrade to pkg:v2 (Snyk)", issue.CodelensCommands[0].Title)
}

func Test_toIssue_CodeActions_WithGradleFix(t *testing.T) {
	config.CurrentConfig().SetSnykOSSQuickFixCodeActionsEnabled(true)

	sampleOssIssue := sampleIssue()
	scanner := CLIScanner{
		learnService: getLearnMock(t),
	}
	sampleOssIssue.PackageManager = "gradle"
	sampleOssIssue.UpgradePath = []any{"false", "a:pkg@v2"}

	issue := toIssue("testPath", sampleOssIssue, &scanResult{}, snyk.Range{}, scanner.learnService, scanner.errorReporter)

	assert.Equal(t, sampleOssIssue.Id, issue.ID)
	assert.Equal(t, 3, len(issue.CodeActions))
	assert.Equal(t, "Upgrade to pkg:v2 (Snyk)", issue.CodeActions[0].Title)
	assert.Equal(t, 1, len(issue.CodelensCommands))
	assert.Equal(t, "⚡ Fix this issue: Upgrade to pkg:v2 (Snyk)", issue.CodelensCommands[0].Title)
}

func Test_toIssue_CodeActions_WithoutFix(t *testing.T) {
	sampleOssIssue := sampleIssue()
	scanner := CLIScanner{
		learnService: getLearnMock(t),
	}
	sampleOssIssue.UpgradePath = []any{"*"}

	issue := toIssue("testPath", sampleOssIssue, &scanResult{}, snyk.Range{}, scanner.learnService, scanner.errorReporter)

	assert.Equal(t, sampleOssIssue.Id, issue.ID)
	assert.Equal(t, 2, len(issue.CodeActions))
	assert.Equal(t, "Open description of 'THOU SHALL NOT PASS affecting package pkg' in browser (Snyk)",
		issue.CodeActions[0].Title)
	assert.Equal(t, "Learn more about THOU SHALL NOT PASS (Snyk)", issue.CodeActions[1].Title)
	assert.Equal(t, 0, len(issue.CodelensCommands))
}

func Test_introducingPackageAndVersionJava(t *testing.T) {
	issue := mavenTestIssue()

	actualPackage, actualVersion := introducingPackageAndVersion(issue)
	assert.Equal(t, "4.17.4", actualVersion)
	assert.Equal(t, "test", actualPackage)
}

func Test_ContextCanceled_Scan_DoesNotScan(t *testing.T) {
	c := testutil.UnitTest(t)
	cliMock := cli.NewTestExecutor()
	scanner := NewCLIScanner(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), ux.NewTestAnalytics(c), cliMock, getLearnMock(t), notification.NewNotifier())
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
	c := testutil.UnitTest(t)
	scanner := NewCLIScanner(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), ux.NewTestAnalytics(c), cli.NewTestExecutor(), getLearnMock(t), notification.NewNotifier()).(*CLIScanner)

	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(t, "couldn't get working dir")
	}
	p := filepath.Join(dir, "testdata", "oss-result.json")
	fileContent, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(t, "couldn't read test result file")
	}
	scanResults, err := scanner.unmarshallOssJson(fileContent)
	assert.NoError(t, err)
	assert.Len(t, scanResults, 1)
}

func TestUnmarshalOssJsonArray(t *testing.T) {
	c := testutil.UnitTest(t)
	scanner := NewCLIScanner(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), ux.NewTestAnalytics(c), cli.NewTestExecutor(), getLearnMock(t), notification.NewNotifier()).(*CLIScanner)

	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(t, "couldn't get working dir")
	}
	var p = filepath.Join(dir, "testdata", "oss-result-array.json")
	fileContent, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(t, "couldn't read test result file")
	}
	scanResults, err := scanner.unmarshallOssJson(fileContent)
	assert.NoError(t, err)
	assert.Len(t, scanResults, 3)
}

func TestUnmarshalOssErroneousJson(t *testing.T) {
	c := testutil.UnitTest(t)
	scanner := NewCLIScanner(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), ux.NewTestAnalytics(c), cli.NewTestExecutor(), getLearnMock(t), notification.NewNotifier()).(*CLIScanner)

	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(t, "couldn't get working dir")
	}
	var p = filepath.Join(dir, "testdata", "pom.xml")
	fileContent, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(t, "couldn't read test result file")
	}
	scanResults, err := scanner.unmarshallOssJson(fileContent)
	assert.Error(t, err)
	assert.Nil(t, scanResults)
}

func Test_toHover_asHTML(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetFormat(config.FormatHtml)

	var issue = sampleIssue()
	h := issue.GetExtendedMessage(issue)

	assert.Equal(
		t,
		"\n### testIssue: <p>THOU SHALL NOT PASS</p>\n affecting pkg package \n### Vulnerability  | [CWE-123]("+
			"https://cwe.mitre.org/data/definitions/123.html) | [testIssue](https://snyk.io/vuln/testIssue) \n **Fixed in: Not Fixed | Exploit maturity: LOW** \n<p>Getting into Moria is an issue!</p>\n",
		h,
	)
}

func Test_toHover_asMarkdown(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetFormat(config.FormatMd)

	var issue = sampleIssue()
	h := issue.GetExtendedMessage(issue)

	assert.Equal(
		t,
		"\n### testIssue: THOU SHALL NOT PASS affecting pkg package \n### Vulnerability  | [CWE-123](https://cwe.mitre."+
			"org/data/definitions/123.html) | [testIssue](https://snyk.io/vuln/testIssue) \n **Fixed in: Not Fixed | Exploit maturity: LOW** \nGetting into Moria is an issue!",
		h,
	)
}

func Test_SeveralScansOnSameFolder_DoNotRunAtOnce(t *testing.T) {
	c := testutil.UnitTest(t)
	// Arrange
	concurrentScanRequests := 10
	workingDir, _ := os.Getwd()
	folderPath := workingDir
	fakeCli := cli.NewTestExecutor()
	fakeCli.ExecuteDuration = time.Second
	scanner := NewCLIScanner(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), ux.NewTestAnalytics(c), fakeCli, getLearnMock(t), notification.NewNotifier())
	wg := sync.WaitGroup{}
	p, _ := filepath.Abs(workingDir + testDataPackageJson)

	// Act
	for i := 0; i < concurrentScanRequests; i++ {
		// Adding a short delay so the cancel listener will start before a new scan is sending the cancel signal
		time.Sleep(100 * time.Millisecond)

		wg.Add(1)
		go func() {
			_, _ = scanner.Scan(context.Background(), p, folderPath)
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
		PackageName:    "pkg",
		PackageManager: "npm",
		From:           []string{"goof@1.0.1", "lodash@4.17.4"},
		Identifiers:    identifiers{CWE: []string{"CWE-123"}},
	}
}

func Test_prepareScanCommand(t *testing.T) {
	c := testutil.UnitTest(t)
	scanner := NewCLIScanner(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), ux.NewTestAnalytics(c), cli.NewTestExecutor(), getLearnMock(t), notification.NewNotifier()).(*CLIScanner)

	t.Run("Expands parameters", func(t *testing.T) {
		settings := config.CliSettings{
			AdditionalOssParameters: []string{"--all-projects", "-d"},
			C:                       c,
		}
		c.SetCliSettings(&settings)

		cmd := scanner.prepareScanCommand([]string{"a"}, map[string]bool{})

		assert.Contains(t, cmd, "--all-projects")
		assert.Contains(t, cmd, "-d")
	})

	t.Run("Uses --all-projects by default", func(t *testing.T) {
		settings := config.CliSettings{
			AdditionalOssParameters: []string{"-d"},
			C:                       c,
		}
		c.SetCliSettings(&settings)

		cmd := scanner.prepareScanCommand([]string{"a"}, map[string]bool{})

		assert.Contains(t, cmd, "--all-projects")
		assert.Len(t, cmd, 4)
	})
}

func Test_Scan_SchedulesNewScan(t *testing.T) {
	c := testutil.UnitTest(t)
	// Arrange
	workingDir, _ := os.Getwd()
	fakeCli := cli.NewTestExecutorWithResponseFromFile(path.Join(workingDir, "testdata/oss-result.json"), c.Logger())
	fakeCli.ExecuteDuration = time.Millisecond
	scanner := NewCLIScanner(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), ux.NewTestAnalytics(c), fakeCli, getLearnMock(t), notification.NewNotifier()).(*CLIScanner)

	scanner.refreshScanWaitDuration = 50 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())

	t.Cleanup(cancel)
	targetFile, _ := filepath.Abs(workingDir + testDataPackageJson)

	// Act
	_, _ = scanner.Scan(ctx, targetFile, "")

	// Assert
	assert.Eventually(t, func() bool {
		return fakeCli.GetFinishedScans() >= 2
	}, 3*time.Second, 50*time.Millisecond)
}

func Test_scheduleNewScan_CapturesAnalytics(t *testing.T) {
	c := testutil.UnitTest(t)
	// Arrange
	fakeCli := cli.NewTestExecutor()
	analytics := ux.NewTestAnalytics(c)
	scanner := NewCLIScanner(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), analytics, fakeCli, getLearnMock(t), notification.NewNotifier()).(*CLIScanner)

	scanner.refreshScanWaitDuration = 50 * time.Millisecond
	workingDir, _ := os.Getwd()
	p, _ := filepath.Abs(path.Join(workingDir, testDataPackageJson))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Act
	scanner.scheduleRefreshScan(ctx, p)

	// Assert
	assert.Eventually(t, func() bool {
		return fakeCli.GetFinishedScans() == 1
	}, 3*time.Second, 50*time.Millisecond)

	assert.Equal(t, ux.AnalysisIsTriggeredProperties{
		AnalysisType:    []ux.AnalysisType{ux.OpenSource},
		TriggeredByUser: false,
	}, analytics.GetAnalytics()[0])
}

func Test_scheduleNewScanWithProductDisabled_NoScanRun(t *testing.T) {
	c := testutil.UnitTest(t)

	// Arrange
	config.CurrentConfig().SetSnykOssEnabled(false)
	fakeCli := cli.NewTestExecutor()
	fakeCli.ExecuteDuration = time.Millisecond
	analytics := ux.NewTestAnalytics(c)
	scanner := NewCLIScanner(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), analytics, fakeCli, getLearnMock(t), notification.NewNotifier()).(*CLIScanner)

	scanner.refreshScanWaitDuration = 50 * time.Millisecond
	workingDir, _ := os.Getwd()
	p, _ := filepath.Abs(path.Join(workingDir, testDataPackageJson))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Act
	scanner.scheduleRefreshScan(ctx, p)

	// Assert
	time.Sleep(scanner.refreshScanWaitDuration + fakeCli.ExecuteDuration + 10*time.Millisecond)
	assert.Equal(t, 0, fakeCli.GetFinishedScans())
	assert.Len(t, analytics.GetAnalytics(), 0)
}

func Test_scheduleNewScanTwice_RunsOnlyOnce(t *testing.T) {
	c := testutil.UnitTest(t)

	// Arrange
	fakeCli := cli.NewTestExecutor()
	fakeCli.ExecuteDuration = time.Millisecond
	analytics := ux.NewTestAnalytics(c)
	scanner := NewCLIScanner(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), analytics, fakeCli, getLearnMock(t), notification.NewNotifier()).(*CLIScanner)

	scanner.refreshScanWaitDuration = 50 * time.Millisecond
	workingDir, _ := os.Getwd()
	targetPath, _ := filepath.Abs(path.Join(workingDir, testDataPackageJson))
	ctx1, cancel1 := context.WithCancel(context.Background())
	ctx2, cancel2 := context.WithCancel(context.Background())
	t.Cleanup(cancel1)
	t.Cleanup(cancel2)

	// Act
	scanner.scheduleRefreshScan(ctx1, targetPath)
	scanner.scheduleRefreshScan(ctx2, targetPath)

	// Assert
	time.Sleep(3*(scanner.refreshScanWaitDuration+fakeCli.ExecuteDuration) + 5*time.Millisecond)
	assert.Equal(t, 1, fakeCli.GetFinishedScans())
}

func Test_scheduleNewScan_ContextCancelledAfterScanScheduled_NoScanRun(t *testing.T) {
	c := testutil.UnitTest(t)

	// Arrange
	fakeCli := cli.NewTestExecutor()
	fakeCli.ExecuteDuration = time.Millisecond
	analytics := ux.NewTestAnalytics(c)
	scanner := NewCLIScanner(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), analytics, fakeCli, getLearnMock(t), notification.NewNotifier()).(*CLIScanner)

	scanner.refreshScanWaitDuration = 2 * time.Second
	workingDir, _ := os.Getwd()
	targetPath, _ := filepath.Abs(path.Join(workingDir, testDataPackageJson))
	ctx, cancel := context.WithCancel(context.Background())

	// Act
	scanner.scheduleRefreshScan(ctx, targetPath)
	cancel()

	// Assert
	scheduledScanDuration := scanner.refreshScanWaitDuration + fakeCli.ExecuteDuration
	time.Sleep(scheduledScanDuration * 2) // Ensure enough time has passed for a scheduled scan to complete
	assert.Equal(t, 0, fakeCli.GetFinishedScans())
	assert.Len(t, analytics.GetAnalytics(), 0)
}

func Test_Scan_missingDisplayTargetFileDoesNotBreakAnalysis(t *testing.T) {
	c := testutil.UnitTest(t)

	// Arrange
	workingDir, _ := os.Getwd()
	fakeCli := cli.NewTestExecutorWithResponseFromFile(path.Join(workingDir,
		"testdata/oss-result-without-targetFile.json"), c.Logger())
	fakeCli.ExecuteDuration = time.Millisecond
	scanner := NewCLIScanner(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), ux.NewTestAnalytics(c), fakeCli, getLearnMock(t), notification.NewNotifier())
	filePath, _ := filepath.Abs(workingDir + testDataPackageJson)

	// Act
	analysis, err := scanner.Scan(context.Background(), filePath, "")

	// Assert
	assert.NoError(t, err)
	assert.Len(t, analysis, 87)
}

func getLearnMock(t *testing.T) learn.Service {
	t.Helper()
	learnMock := mock_learn.NewMockService(gomock.NewController(t))
	learnMock.
		EXPECT().
		GetLesson(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&learn.Lesson{Url: "url"}, nil).AnyTimes()
	return learnMock
}
