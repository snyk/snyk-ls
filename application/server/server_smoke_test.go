/*
 * © 2024 Snyk Limited
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

package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/server"
	"github.com/go-git/go-git/v5"
	"github.com/rs/zerolog"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/internal/testsupport"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/cli/install"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

func Test_SmokeInstanceTest(t *testing.T) {
	c := testutil.SmokeTest(t, false)
	ossFile := "package.json"
	codeFile := "app.js"
	testutil.CreateDummyProgressListener(t)
	endpoint := os.Getenv("SNYK_API")
	if endpoint == "" {
		t.Setenv("SNYK_API", "https://api.snyk.io")
	}
	runSmokeTest(t, c, testsupport.NodejsGoof, "0336589", ossFile, codeFile, true, endpoint)
}

func Test_SmokeWorkspaceScan(t *testing.T) {
	ossFile := "package.json"
	iacFile := "main.tf"
	codeFile := "app.js"
	testutil.CreateDummyProgressListener(t)

	type test struct {
		name                 string
		repo                 string
		commit               string
		file1                string
		file2                string
		useConsistentIgnores bool
		hasVulns             bool
	}

	endpoint := os.Getenv("SNYK_API")
	if endpoint == "" {
		t.Setenv("SNYK_API", "https://api.snyk.io")
	}

	tests := []test{
		{
			name:                 "OSS_and_Code",
			repo:                 testsupport.NodejsGoof,
			commit:               "0336589",
			file1:                ossFile,
			file2:                codeFile,
			useConsistentIgnores: false,
			hasVulns:             true,
		},
		{
			name:                 "OSS_and_Code (PHP Goof)",
			repo:                 "https://github.com/snyk-labs/php-goof.git",
			commit:               "",
			file1:                "composer.json",
			file2:                "index.php",
			useConsistentIgnores: false,
			hasVulns:             true,
		},
		{
			name:                 "OSS_and_Code_with_consistent_ignores",
			repo:                 testsupport.NodejsGoof,
			commit:               "0336589",
			file1:                ossFile,
			file2:                codeFile,
			useConsistentIgnores: true,
			hasVulns:             true,
		},
		{
			name:                 "IaC_and_Code",
			repo:                 "https://github.com/deepcodeg/snykcon-goof.git",
			commit:               "eba8407",
			file1:                iacFile,
			file2:                codeFile,
			useConsistentIgnores: false,
			hasVulns:             true,
		},
		{
			name:                 "Code_without_vulns",
			repo:                 "https://github.com/imagec/simple-repo",
			commit:               "75bcc55",
			file1:                "",
			file2:                "providers.tf",
			useConsistentIgnores: false,
			hasVulns:             false,
		},
		{
			name:                 "IaC_and_Code_with_consistent_ignores",
			repo:                 "https://github.com/deepcodeg/snykcon-goof.git",
			commit:               "eba8407",
			file1:                iacFile,
			file2:                codeFile,
			useConsistentIgnores: true,
			hasVulns:             true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := testutil.SmokeTest(t, false)
			runSmokeTest(t, c, tc.repo, tc.commit, tc.file1, tc.file2, tc.hasVulns, "")
		})
	}
}

func Test_SmokePreScanCommand(t *testing.T) {
	t.Run("executes pre scan command if configured", func(t *testing.T) {
		testsupport.NotOnWindows(t, "we can enable windows if we have the correct error message")
		c := testutil.SmokeTest(t, false)
		loc, jsonRpcRecorder := setupServer(t, c)
		c.EnableSnykCodeSecurity(false)
		c.EnableSnykCodeQuality(false)
		c.SetSnykOssEnabled(true)
		c.SetSnykIacEnabled(false)
		di.Init()

		repo, err := storedconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), testsupport.PythonGoof, "", c.Logger())
		require.NoError(t, err)
		require.NotEmpty(t, repo)

		initParams := prepareInitParams(t, repo, c)
		folderConfig := types.FolderConfig{
			FolderPath:        repo,
			ScanCommandConfig: make(map[product.Product]types.ScanCommandConfig),
		}
		script := "/path/to/script"
		folderConfig.ScanCommandConfig[product.ProductOpenSource] = types.ScanCommandConfig{
			PreScanOnlyReferenceFolder: false,
			PreScanCommand:             script,
		}
		initParams.InitializationOptions.FolderConfigs = []types.FolderConfig{folderConfig}
		ensureInitialized(t, c, loc, initParams)

		assert.Eventuallyf(t, func() bool {
			notifications := jsonRpcRecorder.FindNotificationsByMethod("$/snyk.scan")
			if len(notifications) == 0 {
				return false
			}

			for _, n := range notifications {
				var scanParams types.SnykScanParams
				_ = n.UnmarshalParams(&scanParams)
				if scanParams.Product != product.ProductOpenSource.ToProductCodename() ||
					scanParams.FolderPath != repo || scanParams.Status != "error" {
					continue
				}
				// TODO: check right scan state and summary is sent
				return strings.Contains(scanParams.ErrorMessage, "fork/exec")
			}

			return false
		}, time.Minute, time.Second, "expected scan command to fail")
	})
}

func Test_SmokeIssueCaching(t *testing.T) {
	testsupport.NotOnWindows(t, "git clone does not work here. dunno why. ") // FIXME
	t.Run("adds issues to cache correctly", func(t *testing.T) {
		c := testutil.SmokeTest(t, false)
		loc, jsonRPCRecorder := setupServer(t, c)
		c.EnableSnykCodeSecurity(true)
		c.EnableSnykCodeQuality(false)
		c.SetSnykOssEnabled(true)
		c.SetSnykIacEnabled(false)
		di.Init()

		var cloneTargetDirGoof = setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", loc, c)
		cloneTargetDirGoofString := (string)(cloneTargetDirGoof)
		folderGoof := c.Workspace().GetFolderContaining(cloneTargetDirGoof)
		folderGoofIssueProvider, ok := folderGoof.(snyk.IssueProvider)
		require.Truef(t, ok, "Expected to find snyk issue provider")

		// wait till the whole workspace is scanned
		require.Eventually(t, func() bool {
			return folderGoof != nil && folderGoof.IsScanned()
		}, maxIntegTestDuration, time.Millisecond)

		ossIssuesForFile := folderGoofIssueProvider.IssuesForFile(types.FilePath(filepath.Join(cloneTargetDirGoofString, "package.json")))
		require.Greater(t, len(ossIssuesForFile), 1) // 108 is the number of issues in the package.json file as of now

		var codeIssuesForFile []types.Issue

		require.Eventually(t, func() bool {
			codeIssuesForFile = folderGoofIssueProvider.IssuesForFile(types.FilePath(filepath.Join(cloneTargetDirGoofString, "app.js")))
			return len(codeIssuesForFile) > 1
		}, time.Second*5, time.Second)

		checkDiagnosticPublishingForCachingSmokeTest(t, jsonRPCRecorder, 1, 1, c)

		jsonRPCRecorder.ClearNotifications()
		jsonRPCRecorder.ClearCallbacks()

		// now we add juice shop as second folder/repo
		if runtime.GOOS == "windows" {
			c.ConfigureLogging(nil)
			c.SetLogLevel(zerolog.TraceLevel.String())
		}

		folderJuice := addJuiceShopAsWorkspaceFolder(t, loc, c)

		// scan both created folders
		_, err := loc.Client.Call(context.Background(), "workspace/executeCommand", sglsp.ExecuteCommandParams{
			Command:   "snyk.workspaceFolder.scan",
			Arguments: []any{folderGoof.Path()},
		})

		require.NoError(t, err)

		_, err = loc.Client.Call(context.Background(), "workspace/executeCommand", sglsp.ExecuteCommandParams{
			Command:   "snyk.workspaceFolder.scan",
			Arguments: []any{folderJuice.Path()},
		})

		require.NoError(t, err)

		// wait till both folders are scanned
		assert.Eventually(t, func() bool {
			return folderGoof != nil && folderGoof.IsScanned() && folderJuice != nil && folderJuice.IsScanned()
		}, maxIntegTestDuration, time.Millisecond)

		ossIssuesForFileSecondScan := folderGoofIssueProvider.IssuesForFile(types.FilePath(filepath.Join(cloneTargetDirGoofString, "package.json")))
		require.Equal(t, len(ossIssuesForFile), len(ossIssuesForFileSecondScan))

		codeIssuesForFileSecondScan := folderGoofIssueProvider.IssuesForFile(types.FilePath(filepath.Join(cloneTargetDirGoofString, "app.js")))
		require.Equal(t, len(codeIssuesForFile), len(codeIssuesForFileSecondScan))

		// OSS: empty, package.json goof, package.json juice = 3
		// Code: app.js = 3
		checkDiagnosticPublishingForCachingSmokeTest(t, jsonRPCRecorder, 3, 3, c)
		checkScanResultsPublishingForCachingSmokeTest(t, jsonRPCRecorder, folderJuice, folderGoof, c)
		waitForDeltaScan(t, di.ScanStateAggregator())
	})

	t.Run("clears issues from cache correctly", func(t *testing.T) {
		c := testutil.SmokeTest(t, false)
		loc, jsonRPCRecorder := setupServer(t, c)
		c.EnableSnykCodeSecurity(true)
		c.EnableSnykCodeQuality(false)
		c.SetSnykOssEnabled(true)
		c.SetSnykIacEnabled(false)
		di.Init()

		var cloneTargetDirGoof = setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", loc, c)
		folderGoof := c.Workspace().GetFolderContaining(cloneTargetDirGoof)
		folderGoofIssueProvider, ok := folderGoof.(snyk.IssueProvider)
		require.Truef(t, ok, "Expected to find snyk issue provider")

		// wait till the whole workspace is scanned
		assert.Eventually(t, func() bool {
			return folderGoof != nil && folderGoof.IsScanned()
		}, maxIntegTestDuration, time.Millisecond)

		ossFilePath := "package.json"
		cloneTargetDirGoofString := (string)(cloneTargetDirGoof)
		ossIssuesForFile := folderGoofIssueProvider.IssuesForFile(types.FilePath(filepath.Join(cloneTargetDirGoofString, ossFilePath)))
		require.Greater(t, len(ossIssuesForFile), 1) // 108 is the number of issues in the package.json file as of now
		codeFilePath := "app.js"
		codeIssuesForFile := folderGoofIssueProvider.IssuesForFile(types.FilePath(filepath.Join(cloneTargetDirGoofString, codeFilePath)))
		require.Greater(t, len(codeIssuesForFile), 1) // 5 is the number of issues in the app.js file as of now
		checkDiagnosticPublishingForCachingSmokeTest(t, jsonRPCRecorder, 1, 1, c)
		require.Greater(t, len(folderGoofIssueProvider.Issues()), 0)
		jsonRPCRecorder.ClearNotifications()
		jsonRPCRecorder.ClearCallbacks()

		folderGoof.Clear()

		// empty file diagnostic
		require.Eventually(t, func() bool {
			notifications := jsonRPCRecorder.FindNotificationsByMethod("textDocument/publishDiagnostics")
			emptyOSSFound := false
			emptyCodeFound := false
			for _, notification := range notifications {
				var diagnostic types.PublishDiagnosticsParams
				require.NoError(t, json.Unmarshal([]byte(notification.ParamString()), &diagnostic))
				if filepath.Base(string(uri.PathFromUri(diagnostic.URI))) == ossFilePath && len(diagnostic.Diagnostics) == 0 {
					emptyOSSFound = true
				}
				if filepath.Base(string(uri.PathFromUri(diagnostic.URI))) == codeFilePath && len(diagnostic.Diagnostics) == 0 {
					emptyCodeFound = true
				}
			}
			return emptyOSSFound && emptyCodeFound
		}, time.Second*5, time.Second)

		// check issues deleted
		require.Empty(t, folderGoofIssueProvider.Issues())

		// check hovers deleted
		response, err := loc.Client.Call(context.Background(), "textDocument/hover", hover.Params{
			TextDocument: sglsp.TextDocumentIdentifier{URI: uri.PathToUri(types.FilePath(filepath.Join(string(folderGoof.Path()), ossFilePath)))},
			// at that file position, there should be a hover normally
			Position: sglsp.Position{Line: 27, Character: 20},
		})
		require.NoError(t, err)
		var emptyHover hover.Result
		require.NoError(t, response.UnmarshalResult(&emptyHover))
		require.Empty(t, emptyHover.Contents.Value)
		waitForDeltaScan(t, di.ScanStateAggregator())
	})
}

func Test_SmokeExecuteCLICommand(t *testing.T) {
	c := testutil.SmokeTest(t, false)
	loc, _ := setupServer(t, c)
	c.EnableSnykCodeSecurity(false)
	c.EnableSnykCodeQuality(false)
	c.SetSnykIacEnabled(false)
	c.SetSnykOssEnabled(true)
	di.Init()

	var cloneTargetDirGoof = setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", loc, c)
	folderGoof := c.Workspace().GetFolderContaining(cloneTargetDirGoof)

	// wait till the whole workspace is scanned
	assert.Eventually(t, func() bool {
		return folderGoof != nil && folderGoof.IsScanned()
	}, maxIntegTestDuration, time.Millisecond)

	// execute scan cli command
	response, err := loc.Client.Call(context.Background(), "workspace/executeCommand", sglsp.ExecuteCommandParams{
		Command:   types.ExecuteCLICommand,
		Arguments: []any{string(folderGoof.Path()), "test", "--json"},
	})
	require.NoError(t, err)

	var resp map[string]any
	err = response.UnmarshalResult(&resp)
	require.NoError(t, err)

	require.NotEmpty(t, resp)
	require.Equal(t, float64(1), resp["exitCode"])
	require.NotEmpty(t, resp["stdOut"])
}

func addJuiceShopAsWorkspaceFolder(t *testing.T, loc server.Local, c *config.Config) types.Folder {
	t.Helper()
	var cloneTargetDirJuice, err = storedconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), "https://github.com/juice-shop/juice-shop", "bc9cef127", c.Logger())
	require.NoError(t, err)

	juiceLspWorkspaceFolder := types.WorkspaceFolder{Uri: uri.PathToUri(cloneTargetDirJuice), Name: "juicy-mac-juice-face"}
	didChangeWorkspaceFoldersParams := types.DidChangeWorkspaceFoldersParams{
		Event: types.WorkspaceFoldersChangeEvent{Added: []types.WorkspaceFolder{juiceLspWorkspaceFolder}},
	}

	_, err = loc.Client.Call(context.Background(), "workspace/didChangeWorkspaceFolders", didChangeWorkspaceFoldersParams)
	require.NoError(t, err)

	folderJuice := c.Workspace().GetFolderContaining(cloneTargetDirJuice)
	require.NotNil(t, folderJuice)
	return folderJuice
}

// check that $/snyk.scan messages are sent
// check that they only contain issues that belong to the scanned folder
func checkScanResultsPublishingForCachingSmokeTest(t *testing.T, jsonRPCRecorder *testsupport.JsonRPCRecorder, folderJuice types.Folder, folderGoof types.Folder, c *config.Config) {
	t.Helper()

	require.Eventually(t, func() bool {
		notifications := jsonRPCRecorder.FindNotificationsByMethod("$/snyk.scan")
		scanResultCodeJuiceShopFound := false
		onlyIssuesForJuiceShop := false
		scanResultCodeGoofFound := false
		onlyIssuesForGoof := false

		for _, notification := range notifications {
			var scanResult types.SnykScanParams
			require.NoError(t, json.Unmarshal([]byte(notification.ParamString()), &scanResult))
			if scanResult.Status != types.Success {
				continue
			}
			if scanResult.Product == product.ProductCode.ToProductCodename() {
				switch scanResult.FolderPath {
				case folderGoof.Path():
					issueList := getIssueListFromPublishDiagnosticsNotification(t, jsonRPCRecorder, product.ProductCode, scanResult.FolderPath)
					scanResultCodeGoofFound = true
					onlyIssuesForGoof = true
					for _, issue := range issueList {
						issueContainedInGoof := folderGoof.Contains(issue.FilePath)
						onlyIssuesForGoof = onlyIssuesForGoof && issueContainedInGoof
					}
				case folderJuice.Path():
					issueList := getIssueListFromPublishDiagnosticsNotification(t, jsonRPCRecorder, product.ProductCode, scanResult.FolderPath)
					scanResultCodeJuiceShopFound = true
					onlyIssuesForJuiceShop = true
					for _, issue := range issueList {
						issueContainedInJuiceShop := folderJuice.Contains(issue.FilePath)
						onlyIssuesForJuiceShop = onlyIssuesForJuiceShop && issueContainedInJuiceShop
					}
				default:
					t.FailNow()
				}
			}
		}
		c.Logger().Debug().Bool("scanResultCodeGoofFound", scanResultCodeGoofFound).Send()
		c.Logger().Debug().Bool("scanResultCodeJuiceShopFound", scanResultCodeJuiceShopFound).Send()
		c.Logger().Debug().Bool("onlyIssuesForGoof", onlyIssuesForGoof).Send()
		c.Logger().Debug().Bool("onlyIssuesForJuiceShop", onlyIssuesForJuiceShop).Send()
		return scanResultCodeGoofFound &&
			scanResultCodeJuiceShopFound &&
			onlyIssuesForGoof &&
			onlyIssuesForJuiceShop
	}, time.Second*5, time.Second)
}

// check that notifications are sent
func checkDiagnosticPublishingForCachingSmokeTest(
	t *testing.T,
	jsonRPCRecorder *testsupport.JsonRPCRecorder,
	expectedCode, expectedOSS int,
	c *config.Config,
) {
	t.Helper()
	require.Eventually(t, func() bool {
		notifications := jsonRPCRecorder.FindNotificationsByMethod("textDocument/publishDiagnostics")
		appJsCount := 0
		packageJsonCount := 0

		for _, notification := range notifications {
			var param types.PublishDiagnosticsParams
			err := json.Unmarshal([]byte(notification.ParamString()), &param)
			require.NoError(t, err)
			if filepath.Base(string(uri.PathFromUri(param.URI))) == "package.json" {
				c.Logger().Debug().Any("notification", notification.ParamString()).Send()
				packageJsonCount++
			}

			if filepath.Base(string(uri.PathFromUri(param.URI))) == "app.js" {
				appJsCount++
			}
		}
		c.Logger().Debug().Int("appJsCount", appJsCount).Send()
		c.Logger().Debug().Int("packageJsonCount", packageJsonCount).Send()
		result := appJsCount == expectedCode &&
			packageJsonCount == expectedOSS

		return result
	}, time.Second*600, time.Second)
}

func runSmokeTest(t *testing.T, c *config.Config, repo string, commit string, file1 string, file2 string, hasVulns bool, endpoint string) {
	t.Helper()
	if endpoint != "" && endpoint != "/v1" {
		t.Setenv("SNYK_API", endpoint)
	}
	loc, jsonRPCRecorder := setupServer(t, c)
	c.SetSnykCodeEnabled(true)
	c.SetSnykIacEnabled(true)
	c.SetSnykOssEnabled(true)
	cleanupChannels()
	di.Init()

	cloneTargetDir := setupRepoAndInitialize(t, repo, commit, loc, c)
	cloneTargetDirString := (string)(cloneTargetDir)
	waitForScan(t, cloneTargetDirString, c)

	notifications := jsonRPCRecorder.FindNotificationsByMethod("$/snyk.folderConfigs")
	assert.Len(t, notifications, 1)
	var folderConfigsParam types.FolderConfigsParam
	err := notifications[0].UnmarshalParams(&folderConfigsParam)
	assert.NoError(t, err)
	assert.Len(t, folderConfigsParam.FolderConfigs, 1)
	assert.Equal(t, cloneTargetDir, folderConfigsParam.FolderConfigs[0].FolderPath)
	assert.NotEmpty(t, folderConfigsParam.FolderConfigs[0].BaseBranch)
	assert.NotEmpty(t, folderConfigsParam.FolderConfigs[0].LocalBranches)

	jsonRPCRecorder.ClearNotifications()
	var testPath types.FilePath
	if file1 != "" {
		testPath = types.FilePath(filepath.Join(cloneTargetDirString, file1))
		waitForNetwork(c)
		textDocumentDidSave(t, &loc, testPath)
		// serve diagnostics from file scan
		assert.Eventually(t, checkForPublishedDiagnostics(t, c, testPath, -1, jsonRPCRecorder), maxIntegTestDuration, 10*time.Millisecond)
	}

	jsonRPCRecorder.ClearNotifications()
	testPath = types.FilePath(filepath.Join(cloneTargetDirString, file2))
	waitForNetwork(c)
	textDocumentDidSave(t, &loc, testPath)
	assert.Eventually(t, checkForPublishedDiagnostics(t, c, testPath, -1, jsonRPCRecorder), maxIntegTestDuration, 10*time.Millisecond)

	// check for snyk code scan message
	checkForScanParams(t, jsonRPCRecorder, cloneTargetDirString, product.ProductCode)
	issueList := getIssueListFromPublishDiagnosticsNotification(t, jsonRPCRecorder, product.ProductCode, cloneTargetDir)

	// check for autofix diff on mt-us
	if hasVulns {
		checkAutofixDiffs(t, c, issueList, loc, cloneTargetDir)
	}

	checkFeatureFlagStatus(t, c, &loc)

	// check we only have one quickfix action in open source per line
	if c.IsSnykOssEnabled() {
		checkOnlyOneQuickFixCodeAction(t, jsonRPCRecorder, cloneTargetDirString, loc)
		checkOnlyOneCodeLens(t, jsonRPCRecorder, cloneTargetDirString, loc)
	}
	waitForDeltaScan(t, di.ScanStateAggregator())
}

func waitForNetwork(c *config.Config) {
	for c.Offline() {
		time.Sleep(5 * time.Second)
	}
}

func newFileInCurrentDir(t *testing.T, cloneTargetDir string, fileName string, content string) {
	t.Helper()

	testFile := filepath.Join(cloneTargetDir, fileName)
	err := os.WriteFile(testFile, []byte(content), 0600)
	assert.NoError(t, err)
}

func checkOnlyOneQuickFixCodeAction(t *testing.T, jsonRPCRecorder *testsupport.JsonRPCRecorder, cloneTargetDir string, loc server.Local) {
	t.Helper()
	if !strings.HasSuffix(t.Name(), "OSS_and_Code") {
		return
	}
	checkForScanParams(t, jsonRPCRecorder, cloneTargetDir, product.ProductOpenSource)
	issueList := getIssueListFromPublishDiagnosticsNotification(t, jsonRPCRecorder, product.ProductOpenSource, types.FilePath(cloneTargetDir))
	atLeastOneQuickfixActionFound := false
	for _, issue := range issueList {
		params := sglsp.CodeActionParams{
			TextDocument: sglsp.TextDocumentIdentifier{
				URI: uri.PathToUri(issue.FilePath),
			},
			Range: issue.Range,
		}
		response, err := loc.Client.Call(context.Background(), "textDocument/codeAction", params)
		assert.NoError(t, err)
		var actions []types.LSPCodeAction
		err = response.UnmarshalResult(&actions)
		assert.NoError(t, err)

		quickFixCount := 0
		for _, action := range actions {
			isQuickfixAction := strings.Contains(action.Title, "Upgrade to")
			if isQuickfixAction {
				quickFixCount++
				atLeastOneQuickfixActionFound = true
			}

			// "cfenv": "^1.0.4", 1 fixable issue
			if issue.Range.Start.Line == 19 && isQuickfixAction {
				assert.Contains(t, action.Title, "and fix 1 issue")
				assert.NotContains(t, action.Title, "and fix 1 issues")
			}

			// "tap": "^11.1.3", 12 fixable, 11 unfixable
			if issue.Range.Start.Line == 46 && isQuickfixAction {
				assert.Contains(t, action.Title, "and fix ")
				assert.Contains(t, action.Title, " issues")
			}
		}
		// no issues should have more than one quickfix
		if quickFixCount > 1 {
			t.FailNow()
		}

		// code action requests are debounced (50ms), so we need to wait
		time.Sleep(60 * time.Millisecond)
	}
	assert.Truef(t, atLeastOneQuickfixActionFound, "expected to find at least one code action")
}

func checkOnlyOneCodeLens(t *testing.T, jsonRPCRecorder *testsupport.JsonRPCRecorder, cloneTargetDir string, loc server.Local) {
	t.Helper()
	if !strings.HasSuffix(t.Name(), "OSS_and_Code") {
		return
	}
	checkForScanParams(t, jsonRPCRecorder, cloneTargetDir, product.ProductOpenSource)
	issueList := getIssueListFromPublishDiagnosticsNotification(t, jsonRPCRecorder, product.ProductOpenSource, types.FilePath(cloneTargetDir))

	atLeastOneOneIssueWithCodeLensFound := false
	for _, issue := range issueList {
		params := sglsp.CodeLensParams{
			TextDocument: sglsp.TextDocumentIdentifier{
				URI: uri.PathToUri(issue.FilePath),
			},
		}
		response, err := loc.Client.Call(context.Background(), "textDocument/codeLens", params)
		assert.NoError(t, err)
		var lenses []sglsp.CodeLens
		err = response.UnmarshalResult(&lenses)
		assert.NoError(t, err)

		lensCount := 0
		for _, lens := range lenses {
			if lensCount > 1 {
				t.FailNow()
			}
			if issue.Range.Start.Line == lens.Range.Start.Line {
				lensCount++
				atLeastOneOneIssueWithCodeLensFound = true
			}
			// "cfenv": "^1.0.4", 1 fixable issue
			if lens.Range.Start.Line == 19 {
				assert.Contains(t, lens.Command.Title, "and fix 1 issue")
				assert.NotContains(t, lens.Command.Title, "and fix 1 issues")
			}

			// "tap": "^11.1.3", 12 fixable, 11 unfixable
			if lens.Range.Start.Line == 46 {
				assert.Contains(t, lens.Command.Title, "and fix ")
				assert.Contains(t, lens.Command.Title, " issues")
			}
		}
	}
	assert.Truef(t, atLeastOneOneIssueWithCodeLensFound, "expected to find at least one code lens")
}

func waitForScan(t *testing.T, cloneTargetDir string, c *config.Config) {
	t.Helper()
	// wait till the whole workspace is scanned
	assert.Eventually(t, func() bool {
		f := c.Workspace().GetFolderContaining(types.FilePath(cloneTargetDir))
		return f != nil && f.IsScanned()
	}, maxIntegTestDuration, 2*time.Millisecond)
}

func waitForDeltaScan(t *testing.T, agg scanstates.Aggregator) {
	t.Helper()
	// wait till the whole workspace is scanned
	assert.Eventually(t, func() bool {
		return agg.StateSnapshot().AllScansFinishedWorkingDirectory && agg.StateSnapshot().AllScansFinishedReference
	}, maxIntegTestDuration, time.Second)
}

func checkForScanParams(t *testing.T, jsonRPCRecorder *testsupport.JsonRPCRecorder, cloneTargetDir string, p product.Product) {
	t.Helper()
	var notifications []jrpc2.Request
	assert.Eventually(t, func() bool {
		notifications = jsonRPCRecorder.FindNotificationsByMethod("$/snyk.scan")
		for _, n := range notifications {
			var scanParams types.SnykScanParams
			_ = n.UnmarshalParams(&scanParams)
			if scanParams.Product != p.ToProductCodename() ||
				scanParams.FolderPath != types.FilePath(cloneTargetDir) ||
				scanParams.Status != "success" {
				continue
			}
			return true
		}
		return false
	}, 5*time.Minute, 10*time.Millisecond)
}

func getIssueListFromPublishDiagnosticsNotification(t *testing.T, jsonRPCRecorder *testsupport.JsonRPCRecorder, p product.Product, folderPath types.FilePath) []types.ScanIssue {
	t.Helper()

	var issueList []types.ScanIssue
	notifications := jsonRPCRecorder.FindNotificationsByMethod("textDocument/publishDiagnostics")
	for _, n := range notifications {
		diagnosticsParams := types.PublishDiagnosticsParams{}
		_ = n.UnmarshalParams(&diagnosticsParams)
		for _, diagnostic := range diagnosticsParams.Diagnostics {
			diagnosticCode, ok := diagnostic.Code.(string)
			if ok && diagnosticCode == "Snyk Error" {
				continue
			}
			if diagnostic.Source != string(p) || !uri.FolderContains(folderPath, uri.PathFromUri(diagnosticsParams.URI)) {
				continue
			}

			issueList = append(issueList, diagnostic.Data)
		}
	}
	return issueList
}

func checkAutofixDiffs(t *testing.T, c *config.Config, issueList []types.ScanIssue, loc server.Local, folderPath types.FilePath) {
	t.Helper()
	if isNotStandardRegion(c) {
		return
	}
	assert.Greater(t, len(issueList), 0)
	for _, issue := range issueList {
		codeIssueData, ok := issue.AdditionalData.(map[string]interface{})
		if !ok || codeIssueData["hasAIFix"] == false || codeIssueData["rule"] != "WebCookieSecureDisabledByDefault" {
			continue
		}
		waitForNetwork(c)
		call, err := loc.Client.Call(ctx, "workspace/executeCommand", sglsp.ExecuteCommandParams{
			Command:   types.CodeFixDiffsCommand,
			Arguments: []any{uri.PathToUri(folderPath), uri.PathToUri(issue.FilePath), issue.Id},
		})
		assert.NoError(t, err)
		var unifiedDiffs []code.AutofixUnifiedDiffSuggestion
		err = call.UnmarshalResult(&unifiedDiffs)
		assert.NoError(t, err)
		assert.Greater(t, len(unifiedDiffs), 0)
		// don't check for all issues, just the first
		break
	}
}

func isNotStandardRegion(c *config.Config) bool {
	return c.SnykCodeApi() != "https://deeproxy.snyk.io"
}

func setupRepoAndInitialize(t *testing.T, repo string, commit string, loc server.Local, c *config.Config) types.FilePath {
	t.Helper()
	var cloneTargetDir, err = storedconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), repo, commit, c.Logger())
	if err != nil {
		t.Fatal(err, "Couldn't setup test repo")
	}

	initParams := prepareInitParams(t, cloneTargetDir, c)

	ensureInitialized(t, c, loc, initParams)
	return cloneTargetDir
}

func prepareInitParams(t *testing.T, cloneTargetDir types.FilePath, c *config.Config) types.InitializeParams {
	t.Helper()

	folder := types.WorkspaceFolder{
		Name: "Test Repo",
		Uri:  uri.PathToUri(cloneTargetDir),
	}

	setUniqueCliPath(t, c)

	clientParams := types.InitializeParams{
		WorkspaceFolders: []types.WorkspaceFolder{folder},
		InitializationOptions: types.Settings{
			Endpoint:                    os.Getenv("SNYK_API"),
			Token:                       os.Getenv("SNYK_TOKEN"),
			EnableTrustedFoldersFeature: "false",
			FilterSeverity:              types.DefaultSeverityFilter(),
			IssueViewOptions:            types.DefaultIssueViewOptions(),
			AuthenticationMethod:        types.TokenAuthentication,
			EnableDeltaFindings:         strconv.FormatBool(c.IsDeltaFindingsEnabled()),
			ActivateSnykCode:            strconv.FormatBool(c.IsSnykCodeEnabled()),
			ActivateSnykIac:             strconv.FormatBool(c.IsSnykIacEnabled()),
			ActivateSnykOpenSource:      strconv.FormatBool(c.IsSnykOssEnabled()),
			ActivateSnykCodeQuality:     strconv.FormatBool(c.IsSnykCodeQualityEnabled()),
			ActivateSnykCodeSecurity:    strconv.FormatBool(c.IsSnykCodeSecurityEnabled()),
			CliPath:                     c.CliSettings().Path(),
		},
	}
	return clientParams
}

func setUniqueCliPath(t *testing.T, c *config.Config) {
	t.Helper()
	discovery := install.Discovery{}
	c.CliSettings().SetPath(filepath.Join(t.TempDir(), discovery.ExecutableName(false)))
}

func checkFeatureFlagStatus(t *testing.T, c *config.Config, loc *server.Local) {
	t.Helper()
	// only check on mt-us
	if isNotStandardRegion(c) {
		return
	}
	waitForNetwork(c)
	call, err := loc.Client.Call(ctx, "workspace/executeCommand", sglsp.ExecuteCommandParams{
		Command:   types.GetFeatureFlagStatus,
		Arguments: []any{"bitbucketConnectApp"},
	})

	assert.NoError(t, err)

	if err := call.Error(); err != nil {
		c.Logger().Error().Err(err).Msg("FeatureFlagStatus Command failed")
	}

	c.Logger().Debug().Str("FeatureFlagStatus", call.ResultString()).Msg("Command result")

	var result map[string]any
	if err := json.Unmarshal([]byte(call.ResultString()), &result); err != nil {
		t.Fatal("Failed to parse the command result", err)
	}

	ok, _ := result["ok"].(bool)
	assert.Truef(t, ok, "expected feature flag bitbucketConnectApp to be enabled")
}

func Test_SmokeSnykCodeFileScan(t *testing.T) {
	c := testutil.SmokeTest(t, false)
	loc, jsonRPCRecorder := setupServer(t, c)
	c.SetSnykCodeEnabled(true)
	cleanupChannels()
	di.Init()

	var cloneTargetDir, err = storedconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), testsupport.NodejsGoof, "0336589", c.Logger())
	cloneTargetDirString := string(cloneTargetDir)
	if err != nil {
		t.Fatal(err, "Couldn't setup test repo")
	}

	folder := types.WorkspaceFolder{
		Name: "Test Repo",
		Uri:  uri.PathToUri(cloneTargetDir),
	}

	clientParams := types.InitializeParams{
		WorkspaceFolders: []types.WorkspaceFolder{folder},
		InitializationOptions: types.Settings{
			Endpoint:                    os.Getenv("SNYK_API"),
			Token:                       os.Getenv("SNYK_TOKEN"),
			EnableTrustedFoldersFeature: "false",
			FilterSeverity:              types.DefaultSeverityFilter(),
			IssueViewOptions:            types.DefaultIssueViewOptions(),
		},
	}

	_, _ = loc.Client.Call(ctx, "initialize", clientParams)

	testPath := types.FilePath(filepath.Join(cloneTargetDirString, "app.js"))

	w := c.Workspace()
	f := workspace.NewFolder(c, cloneTargetDir, "Test", di.Scanner(), di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister(), di.ScanStateAggregator())
	w.AddFolder(f)

	c.SetLSPInitialized(true)

	_ = textDocumentDidSave(t, &loc, testPath)

	assert.Eventually(t, checkForPublishedDiagnostics(t, c, testPath, -1, jsonRPCRecorder), 2*time.Minute, 10*time.Millisecond)
	waitForDeltaScan(t, di.ScanStateAggregator())
}

func Test_SmokeUncFilePath(t *testing.T) {
	c := testutil.IntegTest(t)
	testsupport.OnlyOnWindows(t, "testing windows UNC file paths")
	loc, jsonRPCRecorder := setupServer(t, c)
	c.SetSnykCodeEnabled(true)
	c.SetSnykOssEnabled(false)
	c.SetSnykIacEnabled(false)
	cleanupChannels()
	di.Init()

	var cloneTargetDir, err = storedconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), testsupport.NodejsGoof, "0336589", c.Logger())
	if err != nil {
		t.Fatal(err, "Couldn't setup test repo")
	}

	uncPath := "\\\\localhost\\" + strings.Replace(string(cloneTargetDir), ":", "$", 1)
	_, err = os.Stat(uncPath)
	assert.NoError(t, err)

	initializeParams := prepareInitParams(t, types.FilePath(uncPath), c)
	ensureInitialized(t, c, loc, initializeParams)
	waitForScan(t, uncPath, c)
	testPath := types.FilePath(filepath.Join(uncPath, "app.js"))

	assert.Eventually(t, checkForPublishedDiagnostics(t, c, testPath, -1, jsonRPCRecorder), maxIntegTestDuration, 10*time.Millisecond)
	waitForDeltaScan(t, di.ScanStateAggregator())
}

func Test_SmokeSnykCodeDelta_NewVulns(t *testing.T) {
	c := testutil.SmokeTest(t, false)
	loc, jsonRPCRecorder := setupServer(t, c)
	c.SetSnykCodeEnabled(true)
	c.SetSnykOssEnabled(false)
	c.SetSnykIacEnabled(false)
	c.SetDeltaFindingsEnabled(true)
	cleanupChannels()
	di.Init()
	scanAggregator := di.ScanStateAggregator()
	fileWithNewVulns := "vulns.js"
	var cloneTargetDir, err = storedconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), testsupport.NodejsGoof, "0336589", c.Logger())
	cloneTargetDirString := string(cloneTargetDir)
	assert.NoError(t, err)

	sourceContent, err := os.ReadFile(filepath.Join(cloneTargetDirString, "app.js"))
	require.NoError(t, err)

	newFileInCurrentDir(t, cloneTargetDirString, fileWithNewVulns, string(sourceContent))

	c.SetSnykOssEnabled(false)
	c.SetSnykIacEnabled(false)
	c.EnableSnykCodeQuality(false)
	c.SetManageBinariesAutomatically(false)
	initParams := prepareInitParams(t, cloneTargetDir, c)

	ensureInitialized(t, c, loc, initParams)

	waitForScan(t, cloneTargetDirString, c)

	waitForDeltaScan(t, scanAggregator)
	checkForScanParams(t, jsonRPCRecorder, cloneTargetDirString, product.ProductCode)
	var issueList []types.ScanIssue
	assert.Eventually(t, func() bool {
		issueList = getIssueListFromPublishDiagnosticsNotification(t, jsonRPCRecorder, product.ProductCode, cloneTargetDir)
		return len(issueList) > 0
	}, maxIntegTestDuration, 5*time.Second)

	assert.True(t, len(issueList) > 0)
	for _, issue := range issueList {
		issuePath := filepath.Clean(string(issue.FilePath))
		newVulnFilePath := filepath.Clean(filepath.Join(cloneTargetDirString, fileWithNewVulns))
		if issue.IsNew {
			assert.Equal(t, newVulnFilePath, issuePath, "should not be in delta list: %s", string(issue.FilePath))
		}
	}
}

func Test_SmokeSnykCodeDelta_NoNewIssuesFound(t *testing.T) {
	c := testutil.SmokeTest(t, false)
	loc, jsonRPCRecorder := setupServer(t, c)
	c.SetSnykCodeEnabled(true)
	c.SetDeltaFindingsEnabled(true)
	cleanupChannels()
	di.Init()
	scanAggregator := di.ScanStateAggregator()

	fileWithNewVulns := "vulns.js"
	var cloneTargetDir, err = storedconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), "https://github.com/snyk-labs/nodejs-goof", "0336589", c.Logger())
	assert.NoError(t, err)

	cloneTargetDirString := string(cloneTargetDir)

	newFileInCurrentDir(t, cloneTargetDirString, fileWithNewVulns, "// no problems")

	initParams := prepareInitParams(t, cloneTargetDir, c)

	ensureInitialized(t, c, loc, initParams)

	waitForScan(t, cloneTargetDirString, c)

	waitForDeltaScan(t, scanAggregator)
	checkForScanParams(t, jsonRPCRecorder, cloneTargetDirString, product.ProductCode)
	issueList := getIssueListFromPublishDiagnosticsNotification(t, jsonRPCRecorder, product.ProductCode, cloneTargetDir)

	assert.Equal(t, 0, len(issueList), "no issues expected, as delta and no new change")
}

func ensureInitialized(t *testing.T, c *config.Config, loc server.Local, initParams types.InitializeParams) {
	t.Helper()
	t.Setenv("SNYK_LOG_LEVEL", "info")
	c.SetLogLevel(zerolog.LevelInfoValue)
	c.ConfigureLogging(nil)
	c.Engine().GetConfiguration().Set(configuration.DEBUG, false)

	documentURI := initParams.WorkspaceFolders[0].Uri
	commitHash := getCurrentCommitHash(t, uri.PathFromUri(documentURI))
	config.Version = commitHash

	if initParams.ClientInfo.Name == "" {
		initParams.ClientInfo.Name = "snyk-ls_(" + t.Name() + ")"
		initParams.ClientInfo.Version = commitHash
	}

	if initParams.InitializationOptions.IntegrationName == "" {
		initParams.InitializationOptions.IntegrationName = "ls-smoke-tests(" + t.Name() + ")"
		initParams.InitializationOptions.IntegrationVersion = commitHash
	}

	_, err := loc.Client.Call(ctx, "initialize", initParams)
	assert.NoError(t, err)

	waitForNetwork(c)

	_, err = loc.Client.Call(ctx, "initialized", nil)
	assert.NoError(t, err)
}

func getCurrentCommitHash(t *testing.T, workDir types.FilePath) string {
	t.Helper()
	r, err := git.PlainOpen(string(workDir))
	if err != nil {
		t.Fatal(err)
	}

	// Get HEAD reference
	ref, err := r.Head()
	if err != nil {
		return ""
	}

	// Get the hash from the reference
	hash := ref.Hash().String()
	return hash
}

func textDocumentDidSave(t *testing.T, loc *server.Local, testPath types.FilePath) sglsp.DidSaveTextDocumentParams {
	t.Helper()
	didSaveParams := sglsp.DidSaveTextDocumentParams{
		TextDocument: sglsp.TextDocumentIdentifier{
			URI: uri.PathToUri(testPath),
		},
	}

	_, err := loc.Client.Call(ctx, "textDocument/didSave", didSaveParams)
	if err != nil {
		t.Fatal(err, "Call failed")
	}

	return didSaveParams
}
