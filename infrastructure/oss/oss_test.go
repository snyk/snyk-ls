/*
 * © 2022-2026 Snyk Limited
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
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/subosito/gotenv"

	"github.com/snyk/cli-extension-os-flows/pkg/flags"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/ast"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/infrastructure/learn/mock_learn"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

const testDataPackageJson = "/testdata/package.json"

// todo test issue parsing & conversion

func Test_toIssueSeverity(t *testing.T) {
	testutil.UnitTest(t)
	issue := ossIssue{Severity: "critical"}
	assert.Equal(t, types.Critical, issue.ToIssueSeverity())
	issue = ossIssue{Severity: "high"}
	assert.Equal(t, types.High, issue.ToIssueSeverity())
	issue = ossIssue{Severity: "medium"}
	assert.Equal(t, types.Medium, issue.ToIssueSeverity())
	issue = ossIssue{Severity: "info"}
	assert.Equal(t, types.Low, issue.ToIssueSeverity())
	issue = ossIssue{Severity: "asdf"}
	assert.Equal(t, types.Low, issue.ToIssueSeverity())
}

func Test_determineTargetFile(t *testing.T) {
	assert.Equal(t, "package.json", determineTargetFile("package-lock.json"))
	assert.Equal(t, "pom.xml", determineTargetFile("pom.xml"))
	assert.Equal(t, "asdf", determineTargetFile("asdf"))
	assert.Equal(t, "js/package.json", determineTargetFile("js/package-lock.json"))
}

func Test_FindRange(t *testing.T) {
	c := testutil.UnitTest(t)
	issue := mavenTestIssue()
	const content = "0\n1\n2\n  implementation 'a:test:4.17.4'"

	var p = "build.gradle"
	node := getDependencyNode(c.Logger(), types.FilePath(p), issue.PackageManager, issue.From, []byte(content))
	foundRange := getRangeFromNode(node)

	assert.Equal(t, 3, foundRange.Start.Line)
	assert.Equal(t, 20, foundRange.Start.Character)
	assert.Equal(t, 31, foundRange.End.Character)
}

func Test_introducingPackageAndVersion(t *testing.T) {
	actualPackage, actualVersion := introducingPackageAndVersion([]string{"goof@1.0.1", "lodash@4.17.4"}, "npm")
	assert.Equal(t, "4.17.4", actualVersion)
	assert.Equal(t, "lodash", actualPackage)
}

func Test_toIssue_LearnParameterConversion(t *testing.T) {
	c := testutil.UnitTest(t)
	sampleOssIssue := sampleIssue()
	scanner := CLIScanner{
		learnService: getLearnMock(t),
	}
	contentRoot := types.FilePath("/path/to/issue")
	issue := toIssue(c, contentRoot, "testPath", sampleOssIssue, &scanResult{}, nonEmptyNode(), scanner.learnService, scanner.errorReporter, c.Format())

	assert.Equal(t, sampleOssIssue.Id, issue.ID)
	assert.Equal(t, sampleOssIssue.Identifiers.CWE, issue.CWEs)
	assert.Equal(t, sampleOssIssue.Identifiers.CVE, issue.CVEs)
	assert.Equal(t, sampleOssIssue.PackageManager, issue.Ecosystem)
	assert.Equal(t, contentRoot, issue.ContentRoot)
	assert.Equal(t, "url", (issue.AdditionalData).(snyk.OssIssueData).Lesson)
}

func nonEmptyNode() *ast.Node {
	return &ast.Node{Line: 1}
}

func Test_toIssue_CodeActions(t *testing.T) {
	c := testutil.UnitTest(t)
	const flashy = "⚡️ "
	tests := []struct {
		name               string
		packageName        string
		packageManager     string
		expectedUpgrade    string
		openBrowserEnabled bool
	}{
		{"WithNPMFix", "pkg@v2", "npm", "Upgrade to \"pkg\": \"v2\"", false},
		{"WithScopedNPMFix", "@org/pkg@v2", "npm", "Upgrade to \"@org/pkg\": \"v2\"", true},
		{"WithGomodFix", "pkg@v2", "gomodules", "Upgrade to vv2", true},
		{"WithMavenFix", "pkg@v2", "maven", "Upgrade to v2", true},
		{"WithMavenFixForBuildGradle", "a:pkg@v2", "maven", "Upgrade to v2", true},
		{"WithGradleFix", "a:pkg@v2", "gradle", "Upgrade to pkg:v2", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c.SetSnykOSSQuickFixCodeActionsEnabled(true)
			c.SetSnykOpenBrowserActionsEnabled(test.openBrowserEnabled)

			sampleOssIssue := sampleIssue()
			scanner := CLIScanner{
				learnService: getLearnMock(t),
			}
			sampleOssIssue.PackageManager = test.packageManager
			sampleOssIssue.UpgradePath = []any{"false", test.packageName}
			contentRoot := types.FilePath("/path/to/issue")

			issue := toIssue(c, contentRoot, "testPath", sampleOssIssue, &scanResult{}, nonEmptyNode(), scanner.learnService, scanner.errorReporter, c.Format())

			assert.Equal(t, sampleOssIssue.Id, issue.ID)
			assert.Equal(t, flashy+test.expectedUpgrade, issue.CodeActions[0].GetTitle())
			assert.Equal(t, 1, len(issue.CodelensCommands))
			assert.Equal(t, contentRoot, issue.ContentRoot)
			assert.Equal(t, flashy+test.expectedUpgrade, issue.CodelensCommands[0].Title)

			if test.openBrowserEnabled {
				assert.Equal(t, 3, len(issue.CodeActions))
				assert.Equal(t, "Open description of 'THOU SHALL NOT PASS affecting package pkg' in browser (Snyk)", issue.CodeActions[1].GetTitle())
				assert.Equal(t, "Learn more about THOU SHALL NOT PASS (Snyk)", issue.CodeActions[2].GetTitle())
			} else {
				assert.Equal(t, 2, len(issue.CodeActions))
				assert.Equal(t, "Learn more about THOU SHALL NOT PASS (Snyk)", issue.CodeActions[1].GetTitle())
			}
		})
	}
}

func Test_toIssue_CodeActions_WithoutFix(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetSnykOpenBrowserActionsEnabled(true)

	sampleOssIssue := sampleIssue()
	scanner := CLIScanner{
		learnService: getLearnMock(t),
	}
	sampleOssIssue.UpgradePath = []any{"*"}
	contentRoot := types.FilePath("/path/to/issue")

	issue := toIssue(c, contentRoot, "testPath", sampleOssIssue, &scanResult{}, nonEmptyNode(), scanner.learnService, scanner.errorReporter, c.Format())

	assert.Equal(t, sampleOssIssue.Id, issue.ID)
	assert.Equal(t, 2, len(issue.CodeActions))
	assert.Equal(t, contentRoot, issue.ContentRoot)
	assert.Equal(t, "Open description of 'THOU SHALL NOT PASS affecting package pkg' in browser (Snyk)",
		issue.CodeActions[0].GetTitle())
	assert.Equal(t, "Learn more about THOU SHALL NOT PASS (Snyk)", issue.CodeActions[1].GetTitle())
	assert.Equal(t, 0, len(issue.CodelensCommands))
}

func Test_introducingPackageAndVersionJava(t *testing.T) {
	issue := mavenTestIssue()

	actualPackage, actualVersion := introducingPackageAndVersion(issue.From, issue.PackageManager)
	assert.Equal(t, "4.17.4", actualVersion)
	assert.Equal(t, "test", actualPackage)
}

func Test_ContextCanceled_Scan_DoesNotScan(t *testing.T) {
	c := testutil.UnitTest(t)
	cliMock := cli.NewTestExecutor(c)
	scanner := NewCLIScanner(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), cliMock, getLearnMock(t), notification.NewMockNotifier(), nil)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, _ = scanner.Scan(ctx, "", &types.FolderConfig{FolderPath: "."})

	assert.False(t, cliMock.WasExecuted())
}

func Test_Scan_FileScan_UsesFolderConfigOrganization(t *testing.T) {
	c := testutil.UnitTest(t)

	// Setup - use real temp dirs
	workspaceDir := t.TempDir()
	workspacePath := types.FilePath(workspaceDir)

	// Create a subfolder with a file
	subfolderPath := filepath.Join(workspaceDir, "src", "nested")
	require.NoError(t, os.MkdirAll(subfolderPath, 0755))
	filePath := filepath.Join(subfolderPath, "package.json")
	require.NoError(t, os.WriteFile(filePath, []byte(`{"name": "test"}`), 0644))

	expectedOrg := "test-org-for-file-scan"
	folderConfig := c.FolderConfig(workspacePath)
	folderConfig.PreferredOrg = expectedOrg
	folderConfig.OrgSetByUser = true
	require.NoError(t, storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), folderConfig, c.Logger()))

	cliMock := cli.NewTestExecutor(c)
	scanner := NewCLIScanner(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), cliMock, getLearnMock(t), notification.NewMockNotifier(), nil)

	// Act - scan a specific file within the workspace
	ctx := EnrichContextForTest(t, t.Context(), c, workspaceDir)
	_, _ = scanner.Scan(ctx, types.FilePath(filePath), folderConfig)

	// Assert - verify the CLI was executed with the correct org
	assert.True(t, cliMock.WasExecuted(), "CLI should be executed for file scan")
	assert.Contains(t, cliMock.GetCommand(), "--org="+expectedOrg, "CLI should be called with the org from folderConfig")
}

func Test_Scan_SubfolderScan_UsesFolderConfigOrganization(t *testing.T) {
	c := testutil.UnitTest(t)

	// Setup - use real temp dirs
	workspaceDir := t.TempDir()
	workspacePath := types.FilePath(workspaceDir)

	// Create a subfolder with a package.json
	subfolderPath := filepath.Join(workspaceDir, "packages", "subproject")
	require.NoError(t, os.MkdirAll(subfolderPath, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(subfolderPath, "package.json"), []byte(`{"name": "subproject"}`), 0644))

	expectedOrg := "test-org-for-subfolder-scan"
	folderConfig := c.FolderConfig(workspacePath)
	folderConfig.PreferredOrg = expectedOrg
	folderConfig.OrgSetByUser = true
	require.NoError(t, storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), folderConfig, c.Logger()))

	cliMock := cli.NewTestExecutor(c)
	scanner := NewCLIScanner(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), cliMock, getLearnMock(t), notification.NewMockNotifier(), nil)

	// Act - scan a subfolder (not the workspace root)
	ctx := EnrichContextForTest(t, t.Context(), c, workspaceDir)
	_, _ = scanner.Scan(ctx, types.FilePath(subfolderPath), folderConfig)

	// Assert - verify the CLI was executed with the correct org
	assert.True(t, cliMock.WasExecuted(), "CLI should be executed for subfolder scan")
	assert.Contains(t, cliMock.GetCommand(), "--org="+expectedOrg, "CLI should be called with the org from folderConfig")
}

func Test_Scan_WorkspaceFolderScan_UsesFolderConfigOrganization(t *testing.T) {
	c := testutil.UnitTest(t)

	// Setup - use real temp dirs
	workspaceDir := t.TempDir()
	workspacePath := types.FilePath(workspaceDir)

	// Create a package.json in the workspace root
	require.NoError(t, os.WriteFile(filepath.Join(workspaceDir, "package.json"), []byte(`{"name": "workspace"}`), 0644))

	expectedOrg := "test-org-for-workspace-scan"
	folderConfig := c.FolderConfig(workspacePath)
	folderConfig.PreferredOrg = expectedOrg
	folderConfig.OrgSetByUser = true
	require.NoError(t, storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), folderConfig, c.Logger()))

	cliMock := cli.NewTestExecutor(c)
	scanner := NewCLIScanner(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), cliMock, getLearnMock(t), notification.NewMockNotifier(), nil)

	// Act - scan the workspace folder itself
	ctx := EnrichContextForTest(t, t.Context(), c, workspaceDir)
	_, _ = scanner.Scan(ctx, workspacePath, folderConfig)

	// Assert - verify the CLI was executed with the correct org
	assert.True(t, cliMock.WasExecuted(), "CLI should be executed for workspace folder scan")
	assert.Contains(t, cliMock.GetCommand(), "--org="+expectedOrg, "CLI should be called with the org from folderConfig")
}

func Test_Scan_DeltaScan_BaseBranchUsesCorrectFolderConfig(t *testing.T) {
	c := testutil.UnitTest(t)

	// Setup - simulate delta scan scenario where:
	// - workspacePath is the original workspace
	// - baseFolderPath is a temp directory with the base branch checkout
	// - folderConfig.FolderPath points to baseFolderPath (as set by scanBaseBranch)
	// - folderConfig.PreferredOrg contains the org from the original workspace
	workspaceDir := t.TempDir()
	baseBranchDir := t.TempDir()
	baseFolderPath := types.FilePath(baseBranchDir)

	// Create a package.json in the base branch directory
	require.NoError(t, os.WriteFile(filepath.Join(baseBranchDir, "package.json"), []byte(`{"name": "base-branch"}`), 0644))

	// This simulates what scanBaseBranch does: create a copy of folderConfig with FolderPath = baseFolderPath
	expectedOrg := "org-from-workspace"
	baseScanConfig := &types.FolderConfig{
		FolderPath:   baseFolderPath, // Points to temp base branch dir
		PreferredOrg: expectedOrg,    // Org from original workspace
		OrgSetByUser: true,
	}

	// Store the folder config so it can be retrieved
	require.NoError(t, storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), baseScanConfig, c.Logger()))

	cliMock := cli.NewTestExecutor(c)
	scanner := NewCLIScanner(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), cliMock, getLearnMock(t), notification.NewMockNotifier(), nil)

	// Act - scan the base branch folder (as scanBaseBranch would do)
	ctx := EnrichContextForTest(t, t.Context(), c, workspaceDir)
	_, _ = scanner.Scan(ctx, baseFolderPath, baseScanConfig)

	// Assert - verify the CLI was executed with the correct org from the original workspace
	assert.True(t, cliMock.WasExecuted(), "CLI should be executed for delta scan base branch")
	assert.Contains(t, cliMock.GetCommand(), "--org="+expectedOrg, "CLI should be called with the org from the original workspace folderConfig")
}

// Test_Scan_UsesOrgFromFolderConfigNotFromPath verifies that the scanner uses the org from the
// passed FolderConfig parameter, not derived from the pathToScan path or global config.
// This is critical for delta scans where the scan path is a temp directory but the org
// should come from the original workspace's FolderConfig.
func Test_Scan_UsesOrgFromFolderConfigNotFromPath(t *testing.T) {
	c := testutil.UnitTest(t)

	// Setup three different orgs to ensure we're using the right one:
	// 1. Global default org - should NOT be used
	// 2. Org stored for the scan path - should NOT be used
	// 3. Org in the passed FolderConfig - SHOULD be used
	globalDefaultOrg := "global-default-org"
	orgStoredForPath := "org-stored-for-scan-path"
	expectedOrg := "org-from-passed-folderconfig"

	// Set global default org
	c.SetOrganization(globalDefaultOrg)

	// Create a directory that will be scanned
	scanDir := t.TempDir()
	scanPath := types.FilePath(scanDir)

	// Create a package.json file
	require.NoError(t, os.WriteFile(filepath.Join(scanDir, "package.json"), []byte(`{"name": "test"}`), 0644))

	// Store a different org for the scan path (simulating a workspace with its own org)
	pathFolderConfig := c.FolderConfig(scanPath)
	pathFolderConfig.PreferredOrg = orgStoredForPath
	pathFolderConfig.OrgSetByUser = true

	// Create the FolderConfig we'll pass to Scan() - with a DIFFERENT org
	// This simulates delta scan where we pass a config with the original workspace's org
	passedFolderConfig := &types.FolderConfig{
		FolderPath:   scanPath,
		PreferredOrg: expectedOrg,
		OrgSetByUser: true,
	}

	cliMock := cli.NewTestExecutor(c)
	scanner := NewCLIScanner(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), cliMock, getLearnMock(t), notification.NewMockNotifier(), nil)

	// Act
	ctx := EnrichContextForTest(t, t.Context(), c, scanDir)
	_, _ = scanner.Scan(ctx, scanPath, passedFolderConfig)

	// Assert - verify the CLI was called with the org from the PASSED FolderConfig,
	// not from the path's stored config or global default
	assert.True(t, cliMock.WasExecuted(), "CLI should be executed")
	cmd := cliMock.GetCommand()
	assert.Contains(t, cmd, "--org="+expectedOrg,
		"CLI should use org from passed FolderConfig, not from path lookup or global config")
	assert.NotContains(t, cmd, "--org="+orgStoredForPath,
		"CLI should NOT use org stored for the scan path")
	assert.NotContains(t, cmd, "--org="+globalDefaultOrg,
		"CLI should NOT use global default org")
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
	scanner := NewCLIScanner(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), cli.NewTestExecutor(c), getLearnMock(t), notification.NewMockNotifier(), nil).(*CLIScanner)

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
	scanner := NewCLIScanner(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), cli.NewTestExecutor(c), getLearnMock(t), notification.NewMockNotifier(), nil).(*CLIScanner)

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
	scanner := NewCLIScanner(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), cli.NewTestExecutor(c), getLearnMock(t), notification.NewMockNotifier(), nil).(*CLIScanner)

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
	h := GetExtendedMessage(
		issue.Id,
		issue.Title,
		issue.Description,
		issue.Severity,
		issue.PackageName,
		issue.Identifiers.CVE,
		issue.Identifiers.CWE,
		issue.FixedIn,
	)

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
	h := GetExtendedMessage(
		issue.Id,
		issue.Title,
		issue.Description,
		issue.Severity,
		issue.PackageName,
		issue.Identifiers.CVE,
		issue.Identifiers.CWE,
		issue.FixedIn,
	)

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
	fakeCli := cli.NewTestExecutor(c)
	fakeCli.ExecuteDuration = time.Second * 2
	scanner := NewCLIScanner(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), fakeCli, getLearnMock(t), notification.NewMockNotifier(), nil)
	wg := sync.WaitGroup{}
	p, _ := filepath.Abs(workingDir + testDataPackageJson)

	// Act
	for i := 0; i < concurrentScanRequests; i++ {
		wg.Add(1)
		go func() {
			// Adding a short delay so the cancel listener will start before a new scan is sending the cancel signal
			time.Sleep(200 * time.Millisecond)
			ctx := EnrichContextForTest(t, t.Context(), c, workingDir)
			folderConfig := c.FolderConfig(types.FilePath(folderPath))
			_, _ = scanner.Scan(ctx, types.FilePath(p), folderConfig)
			wg.Done()
		}()
	}
	wg.Wait()

	// Assert
	assert.Equal(t, 1, fakeCli.GetFinishedScans())
}

func EnrichContextForTest(t *testing.T, ctx context.Context, c *config.Config, folderPath string) context.Context {
	t.Helper()
	// add logger to context
	newCtx := ctx2.NewContextWithLogger(ctx, c.Logger())

	// add scanner dependencies to context
	folderConfig := c.FolderConfig(types.FilePath(folderPath))
	newCtx = ctx2.NewContextWithDependencies(newCtx, map[string]any{
		ctx2.DepFolderConfig: folderConfig,
	})
	return newCtx
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

func TestCLIScanner_ostestScan_AddsFlagSetAndAllowsUnknownFlags(t *testing.T) {
	c := testutil.UnitTest(t)

	// Mock engine so we can capture the config passed to InvokeWithConfig
	mockEngine, _ := testutil.SetUpEngineMock(t, c)

	// Pick a deterministic boolean flag from the OS test flagset.
	// We then assert that its value is reflected in the config passed to the workflow.
	fs := flags.OSTestFlagSet()
	var boolFlag *pflag.Flag
	fs.VisitAll(func(f *pflag.Flag) {
		if boolFlag != nil {
			return
		}
		if f == nil || f.Value == nil {
			return
		}
		if f.Value.Type() != "bool" {
			return
		}
		if f.Name == "help" {
			return
		}
		boolFlag = f
	})
	require.NotNil(t, boolFlag)

	var capturedConfigs []configuration.Configuration
	workflowID := workflow.NewWorkflowIdentifier("test")
	mockEngine.EXPECT().InvokeWithConfig(workflowID, gomock.Any()).
		Times(2).
		Do(func(_ workflow.Identifier, cfg configuration.Configuration) {
			capturedConfigs = append(capturedConfigs, cfg)
		}).
		Return([]workflow.Data{}, nil)

	cliScanner := &CLIScanner{
		config:        c,
		errorReporter: error_reporting.NewTestErrorReporter(),
	}

	workDir := types.FilePath(t.TempDir())
	folderConfig := &types.FolderConfig{FolderPath: workDir}
	path := types.FilePath(filepath.Join(string(workDir), "package.json"))

	cmdWithoutFlag := []string{"snyk", "test"}
	_, err := cliScanner.ostestScan(context.Background(), path, cmdWithoutFlag, folderConfig, gotenv.Env{})
	require.NoError(t, err)

	cmdWithFlag := []string{"snyk", "test", "--definitely-unknown-flag"}
	expectedWithout := boolFlag.DefValue == "true"
	expectedWith := !expectedWithout
	if expectedWithout {
		cmdWithFlag = append(cmdWithFlag, "--"+boolFlag.Name+"=false")
	} else {
		cmdWithFlag = append(cmdWithFlag, "--"+boolFlag.Name)
	}
	_, err = cliScanner.ostestScan(context.Background(), path, cmdWithFlag, folderConfig, gotenv.Env{})
	require.NoError(t, err)

	require.Len(t, capturedConfigs, 2)
	assert.Equal(t, cmdWithoutFlag[1:], capturedConfigs[0].GetStringSlice(configuration.RAW_CMD_ARGS))
	assert.Equal(t, cmdWithFlag[1:], capturedConfigs[1].GetStringSlice(configuration.RAW_CMD_ARGS))
	assert.Equal(t, expectedWithout, capturedConfigs[0].GetBool(boolFlag.Name))
	assert.Equal(t, expectedWith, capturedConfigs[1].GetBool(boolFlag.Name))
}

func TestCLIScanner_ostestScan_SetsSubprocessEnvironment(t *testing.T) {
	c := testutil.UnitTest(t)

	mockEngine, _ := testutil.SetUpEngineMock(t, c)

	var capturedConfig configuration.Configuration
	workflowID := workflow.NewWorkflowIdentifier("test")
	mockEngine.EXPECT().InvokeWithConfig(workflowID, gomock.Any()).
		Times(1).
		Do(func(_ workflow.Identifier, cfg configuration.Configuration) {
			capturedConfig = cfg
		}).
		Return([]workflow.Data{}, nil)

	cliScanner := &CLIScanner{
		config:        c,
		errorReporter: error_reporting.NewTestErrorReporter(),
	}

	workDir := types.FilePath(t.TempDir())
	folderConfig := &types.FolderConfig{FolderPath: workDir}
	targetPath := types.FilePath(filepath.Join(string(workDir), "package.json"))
	cmd := []string{"snyk", "test"}
	inputEnv := gotenv.Env{
		"SIMPLE": "x",
		"MULTI":  "line1\nline2",
	}

	_, err := cliScanner.ostestScan(context.Background(), targetPath, cmd, folderConfig, inputEnv)
	require.NoError(t, err)
	require.NotNil(t, capturedConfig)

	capturedEnv := capturedConfig.GetStringSlice(configuration.SUBPROCESS_ENVIRONMENT)
	assert.Contains(t, capturedEnv, "SIMPLE=x")
	assert.Contains(t, capturedEnv, "MULTI=line1\nline2")
}

func TestCLIScanner_ostestScan_PropagatesFeatureFlagsToGAFConfig(t *testing.T) {
	c := testutil.UnitTest(t)

	mockEngine, _ := testutil.SetUpEngineMock(t, c)

	var capturedConfig configuration.Configuration
	workflowID := workflow.NewWorkflowIdentifier("test")
	mockEngine.EXPECT().InvokeWithConfig(workflowID, gomock.Any()).
		Times(1).
		Do(func(_ workflow.Identifier, cfg configuration.Configuration) {
			capturedConfig = cfg
		}).
		Return([]workflow.Data{}, nil)

	cliScanner := &CLIScanner{
		config:        c,
		errorReporter: error_reporting.NewTestErrorReporter(),
	}

	workDir := types.FilePath(t.TempDir())
	folderConfig := &types.FolderConfig{
		FolderPath: workDir,
		FeatureFlags: map[string]bool{
			featureflag.UseExperimentalRiskScore:      true,
			featureflag.UseExperimentalRiskScoreInCLI: true,
			featureflag.UseOsTest:                     false,
		},
	}
	targetPath := types.FilePath(filepath.Join(string(workDir), "package.json"))
	cmd := []string{"snyk", "test"}

	_, err := cliScanner.ostestScan(context.Background(), targetPath, cmd, folderConfig, gotenv.Env{})
	require.NoError(t, err)
	require.NotNil(t, capturedConfig)

	assert.True(t, capturedConfig.GetBool("internal_snyk_cli_experimental_risk_score"),
		"expected UseExperimentalRiskScore to be propagated")
	assert.True(t, capturedConfig.GetBool("internal_snyk_cli_experimental_risk_score_in_cli"),
		"expected UseExperimentalRiskScoreInCLI to be propagated")
	assert.False(t, capturedConfig.GetBool("internal_snyk_cli_use_test_shim_for_os_cli_test"),
		"expected UseOsTest=false to be propagated")
}

func Test_processOsTestWorkFlowData_AggregatesIssues(t *testing.T) {
	c := testutil.UnitTest(t)
	ctx := ctx2.NewContextWithLogger(t.Context(), c.Logger())

	originalGet := getTestResultsFromWorkflowData
	originalConvert := convertTestResultToIssuesFn
	t.Cleanup(func() {
		getTestResultsFromWorkflowData = originalGet
		convertTestResultToIssuesFn = originalConvert
	})

	getTestResultsFromWorkflowData = func(_ workflow.Data) []testapi.TestResult {
		return []testapi.TestResult{nil, nil}
	}

	issue1 := testutil.NewMockIssue("id1", types.FilePath("path1"))
	issue2 := testutil.NewMockIssue("id2", types.FilePath("path2"))
	callCount := 0
	convertTestResultToIssuesFn = func(_ context.Context, _ testapi.TestResult, _ map[string][]types.Issue) ([]types.Issue, error) {
		callCount++
		if callCount == 1 {
			return []types.Issue{issue1}, nil
		}
		return []types.Issue{issue2}, nil
	}

	data := workflow.NewData(workflow.NewTypeIdentifier(workflow.NewWorkflowIdentifier("test"), "payload"), "application/json", []byte("{}"))
	issues, err := processOsTestWorkFlowData(ctx, []workflow.Data{data}, map[string][]types.Issue{})
	require.NoError(t, err)
	assert.ElementsMatch(t, []types.Issue{issue1, issue2}, issues)
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

func Test_prepareScanCommand(t *testing.T) {
	t.Run("Expands parameters", func(t *testing.T) {
		c := testutil.UnitTest(t)
		scanner := NewCLIScanner(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), cli.NewTestExecutor(c), getLearnMock(t), notification.NewMockNotifier(), nil).(*CLIScanner)

		settings := config.CliSettings{
			AdditionalOssParameters: []string{"--all-projects", "-d"},
			C:                       c,
		}
		c.SetCliSettings(&settings)
		workDir := types.FilePath(t.TempDir())
		folderConfig := c.FolderConfig(workDir)
		folderConfig.AdditionalParameters = []string{"--dev"}
		err := storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), folderConfig, c.Logger())
		require.NoError(t, err)

		cmd, _ := scanner.prepareScanCommand([]string{"a"}, map[string]bool{}, workDir, folderConfig)

		assert.Contains(t, cmd, "--dev")
		assert.Contains(t, cmd, "-d")
	})

	t.Run("does not use --all-projects if --file is given", func(t *testing.T) {
		c := testutil.UnitTest(t)
		scanner := NewCLIScanner(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), cli.NewTestExecutor(c), getLearnMock(t), notification.NewMockNotifier(), nil).(*CLIScanner)

		settings := config.CliSettings{
			AdditionalOssParameters: []string{"--file=asdf", "-d"},
			C:                       c,
		}
		c.SetCliSettings(&settings)
		folderConfig := &types.FolderConfig{}

		cmd, _ := scanner.prepareScanCommand([]string{"a"}, map[string]bool{}, "", folderConfig)

		assert.NotContains(t, cmd, "--all-projects")
		assert.Contains(t, cmd, "-d")
		assert.Contains(t, cmd, "--file=asdf")
	})

	t.Run("support `--`", func(t *testing.T) {
		c := testutil.UnitTest(t)
		scanner := NewCLIScanner(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), cli.NewTestExecutor(c), getLearnMock(t), notification.NewMockNotifier(), nil).(*CLIScanner)

		settings := config.CliSettings{
			AdditionalOssParameters: []string{"-d", "--", "-PappBuild=true", "-Prules=false", "-x"},
			C:                       c,
		}
		c.SetCliSettings(&settings)
		folderConfig := &types.FolderConfig{}

		cmd, _ := scanner.prepareScanCommand([]string{"a"}, map[string]bool{}, "", folderConfig)

		assert.Contains(t, cmd, "--")
		assert.Equal(t, "-x", cmd[len(cmd)-1])
	})

	t.Run("Uses --all-projects by default", func(t *testing.T) {
		c := testutil.UnitTest(t)
		// Clear the default org set by UnitTest to test command without --org parameter
		c.SetOrganization("")
		scanner := NewCLIScanner(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), cli.NewTestExecutor(c), getLearnMock(t), notification.NewMockNotifier(), nil).(*CLIScanner)

		settings := config.CliSettings{
			AdditionalOssParameters: []string{"-d"},
			C:                       c,
		}
		c.SetCliSettings(&settings)
		folderConfig := &types.FolderConfig{}

		cmd, _ := scanner.prepareScanCommand([]string{"a"}, map[string]bool{}, "", folderConfig)

		assert.Contains(t, cmd, "--all-projects")
		assert.Lenf(t, cmd, 6, "cmd: %v", cmd)
	})
}

func Test_Scan_SchedulesNewScan(t *testing.T) {
	c := testutil.UnitTest(t)
	// Arrange
	workingDir, _ := os.Getwd()
	fakeCli := cli.NewTestExecutorWithResponseFromFile(path.Join(workingDir, "testdata/oss-result.json"), c.Logger())
	fakeCli.ExecuteDuration = time.Millisecond
	scanner := NewCLIScanner(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), fakeCli, getLearnMock(t), notification.NewMockNotifier(), nil).(*CLIScanner)

	scanner.refreshScanWaitDuration = 50 * time.Millisecond
	ctx, cancel := context.WithCancel(t.Context())

	t.Cleanup(cancel)
	targetFile, _ := filepath.Abs(workingDir + testDataPackageJson)

	// Act
	ctx = EnrichContextForTest(t, ctx, c, workingDir)
	folderConfig := c.FolderConfig(types.FilePath(workingDir))
	_, _ = scanner.Scan(ctx, types.FilePath(targetFile), folderConfig)

	// Assert
	assert.Eventually(t, func() bool { return fakeCli.GetFinishedScans() >= 2 }, 10*time.Second, 50*time.Millisecond)
}

func Test_scheduleNewScanWithProductDisabled_NoScanRun(t *testing.T) {
	c := testutil.UnitTest(t)

	// Arrange
	c.SetSnykOssEnabled(false)
	fakeCli := cli.NewTestExecutor(c)
	fakeCli.ExecuteDuration = time.Millisecond
	scanner := NewCLIScanner(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), fakeCli, getLearnMock(t), notification.NewMockNotifier(), nil).(*CLIScanner)

	scanner.refreshScanWaitDuration = 50 * time.Millisecond
	workingDir, _ := os.Getwd()
	p, _ := filepath.Abs(path.Join(workingDir, testDataPackageJson))
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	folderConfig := c.FolderConfig(types.FilePath(workingDir))

	// Act
	scanner.scheduleRefreshScan(ctx, types.FilePath(p), folderConfig)

	// Assert
	time.Sleep(scanner.refreshScanWaitDuration + fakeCli.ExecuteDuration + 10*time.Millisecond)
	assert.Equal(t, 0, fakeCli.GetFinishedScans())
}

func Test_scheduleNewScanTwice_RunsOnlyOnce(t *testing.T) {
	c := testutil.UnitTest(t)

	// Arrange
	fakeCli := cli.NewTestExecutor(c)
	fakeCli.ExecuteDuration = time.Millisecond
	scanner := NewCLIScanner(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), fakeCli, getLearnMock(t), notification.NewMockNotifier(), nil).(*CLIScanner)

	scanner.refreshScanWaitDuration = 50 * time.Millisecond
	workingDir, _ := os.Getwd()
	targetPath, _ := filepath.Abs(path.Join(workingDir, testDataPackageJson))
	ctx1, cancel1 := context.WithCancel(t.Context())
	ctx2, cancel2 := context.WithCancel(t.Context())
	t.Cleanup(cancel1)
	t.Cleanup(cancel2)
	folderConfig := c.FolderConfig(types.FilePath(workingDir))

	// Act
	ctx1 = EnrichContextForTest(t, ctx1, c, workingDir)
	ctx2 = EnrichContextForTest(t, ctx2, c, workingDir)
	scanner.scheduleRefreshScan(ctx1, types.FilePath(targetPath), folderConfig)
	scanner.scheduleRefreshScan(ctx2, types.FilePath(targetPath), folderConfig)

	// Assert
	assert.Eventuallyf(t, func() bool {
		return fakeCli.GetFinishedScans() == 1
	}, time.Minute, time.Millisecond, "none of the scans finished in time or more than 1 scan ran")
}

func Test_scheduleNewScan_ContextCancelledAfterScanScheduled_NoScanRun(t *testing.T) {
	c := testutil.UnitTest(t)

	// Arrange
	fakeCli := cli.NewTestExecutor(c)
	fakeCli.ExecuteDuration = time.Millisecond
	scanner := NewCLIScanner(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), fakeCli, getLearnMock(t), notification.NewMockNotifier(), nil).(*CLIScanner)

	scanner.refreshScanWaitDuration = 2 * time.Second
	workingDir, _ := os.Getwd()
	targetPath, _ := filepath.Abs(path.Join(workingDir, testDataPackageJson))
	ctx, cancel := context.WithCancel(t.Context())
	folderConfig := c.FolderConfig(types.FilePath(workingDir))

	// Act
	scanner.scheduleRefreshScan(ctx, types.FilePath(targetPath), folderConfig)
	cancel()

	// Assert
	scheduledScanDuration := scanner.refreshScanWaitDuration + fakeCli.ExecuteDuration
	time.Sleep(scheduledScanDuration * 2) // Ensure enough time has passed for a scheduled scan to complete
	assert.Equal(t, 0, fakeCli.GetFinishedScans())
}

func Test_Scan_missingDisplayTargetFileDoesNotBreakAnalysis(t *testing.T) {
	c := testutil.UnitTest(t)

	// Arrange
	workingDir, _ := os.Getwd()
	fakeCli := cli.NewTestExecutorWithResponseFromFile(path.Join(workingDir,
		"testdata/oss-result-without-targetFile.json"), c.Logger())
	fakeCli.ExecuteDuration = time.Millisecond
	scanner := NewCLIScanner(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), fakeCli, getLearnMock(t), notification.NewMockNotifier(), nil)
	filePath, _ := filepath.Abs(workingDir + testDataPackageJson)

	// Act
	ctx := EnrichContextForTest(t, t.Context(), c, workingDir)
	folderConfig := c.FolderConfig(types.FilePath(workingDir))
	analysis, err := scanner.Scan(ctx, types.FilePath(filePath), folderConfig)

	// Assert
	assert.NoError(t, err)
	assert.Len(t, analysis, 87)
}
