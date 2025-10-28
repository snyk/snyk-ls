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
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/samber/lo"

	"github.com/snyk/snyk-ls/internal/util"

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
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
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
		ensureInitialized(t, c, loc, initParams, nil)

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
		c.SetSnykOssEnabled(true)
		c.SetSnykIacEnabled(false)
		di.Init()

		cloneTargetDirGoof := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", loc, c)
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
		_, err := loc.Client.Call(t.Context(), "workspace/executeCommand", sglsp.ExecuteCommandParams{
			Command:   "snyk.workspaceFolder.scan",
			Arguments: []any{folderGoof.Path()},
		})

		require.NoError(t, err)

		_, err = loc.Client.Call(t.Context(), "workspace/executeCommand", sglsp.ExecuteCommandParams{
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
		c.SetSnykOssEnabled(true)
		c.SetSnykIacEnabled(false)
		di.Init()

		cloneTargetDirGoof := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", loc, c)
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
		response, err := loc.Client.Call(t.Context(), "textDocument/hover", hover.Params{
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
	c.SetSnykIacEnabled(false)
	c.SetSnykOssEnabled(true)
	di.Init()

	cloneTargetDirGoof := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", loc, c)
	folderGoof := c.Workspace().GetFolderContaining(cloneTargetDirGoof)

	// wait till the whole workspace is scanned
	assert.Eventually(t, func() bool {
		return folderGoof != nil && folderGoof.IsScanned()
	}, maxIntegTestDuration, time.Millisecond)

	// execute scan cli command
	response, err := loc.Client.Call(t.Context(), "workspace/executeCommand", sglsp.ExecuteCommandParams{
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
	cloneTargetDirJuice, err := storedconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), "https://github.com/juice-shop/juice-shop", "bc9cef127", c.Logger())
	require.NoError(t, err)

	juiceLspWorkspaceFolder := types.WorkspaceFolder{Uri: uri.PathToUri(cloneTargetDirJuice), Name: "juicy-mac-juice-face"}
	addWorkSpaceFolder(t, loc, juiceLspWorkspaceFolder)

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
	assert.Greater(t, len(notifications), 0)

	foundFolderConfig := false
	for _, notification := range notifications {
		var folderConfigsParam types.FolderConfigsParam
		err := notification.UnmarshalParams(&folderConfigsParam)
		require.NoError(t, err)

		for _, folderConfig := range folderConfigsParam.FolderConfigs {
			assert.NotEmpty(t, folderConfigsParam.FolderConfigs[0].BaseBranch)
			assert.NotEmpty(t, folderConfigsParam.FolderConfigs[0].LocalBranches)

			// Normalize both paths for comparison since folder config paths are now normalized
			normalizedCloneTargetDir := util.PathKey(cloneTargetDir)
			if folderConfig.FolderPath == normalizedCloneTargetDir {
				foundFolderConfig = true
				break
			}
		}

		if foundFolderConfig {
			break
		}
	}
	assert.Truef(t, foundFolderConfig, "could not find folder config for %s", cloneTargetDirString)
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
		checkAutofixDiffs(t, c, issueList, loc, cloneTargetDir, jsonRPCRecorder)
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
	err := os.WriteFile(testFile, []byte(content), 0o600)
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
		response, err := loc.Client.Call(t.Context(), "textDocument/codeAction", params)
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
		response, err := loc.Client.Call(t.Context(), "textDocument/codeLens", params)
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

func checkAutofixDiffs(t *testing.T, c *config.Config, issueList []types.ScanIssue, loc server.Local, folderPath types.FilePath, recorder *testsupport.JsonRPCRecorder) {
	t.Helper()
	if isNotStandardRegion(c) {
		return
	}
	assert.Greater(t, len(issueList), 0)
	for _, issue := range issueList {
		codeIssueData, ok := issue.AdditionalData.(map[string]interface{})
		if !ok || codeIssueData["hasAIFix"] == false || codeIssueData["rule"] != "UseCsurfForExpress" {
			continue
		}
		waitForNetwork(c)
		_, err := loc.Client.Call(ctx, "workspace/executeCommand", sglsp.ExecuteCommandParams{
			Command:   types.CodeFixDiffsCommand,
			Arguments: []any{issue.Id},
		})
		assert.NoError(t, err)
		// don't check for all issues, just the first
		assert.Eventuallyf(t, func() bool {
			notifications := recorder.FindCallbacksByMethod("window/showDocument")
			for _, notification := range notifications {
				if strings.Contains(notification.ParamString(), "snyk://") {
					return true
				}
			}
			return false
		}, 30*time.Second, 10*time.Millisecond, "failed to get autofix diffs")
		break
	}
}

func isNotStandardRegion(c *config.Config) bool {
	return c.SnykCodeApi() != "https://deeproxy.snyk.io"
}

func setupRepoAndInitialize(t *testing.T, repo string, commit string, loc server.Local, c *config.Config) types.FilePath {
	t.Helper()
	cloneTargetDir, err := storedconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), repo, commit, c.Logger())
	if err != nil {
		t.Fatal(err, "Couldn't setup test repo")
	}

	initParams := prepareInitParams(t, cloneTargetDir, c)
	ensureInitialized(t, c, loc, initParams, nil)
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
			Token:                       c.Token(),
			EnableTrustedFoldersFeature: "false",
			FilterSeverity:              util.Ptr(types.DefaultSeverityFilter()),
			IssueViewOptions:            util.Ptr(types.DefaultIssueViewOptions()),
			AuthenticationMethod:        types.TokenAuthentication,
			EnableDeltaFindings:         strconv.FormatBool(c.IsDeltaFindingsEnabled()),
			ActivateSnykCode:            strconv.FormatBool(c.IsSnykCodeEnabled()),
			ActivateSnykIac:             strconv.FormatBool(c.IsSnykIacEnabled()),
			ActivateSnykOpenSource:      strconv.FormatBool(c.IsSnykOssEnabled()),
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

	cloneTargetDir, err := storedconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), testsupport.NodejsGoof, "0336589", c.Logger())
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
			FilterSeverity:              util.Ptr(types.DefaultSeverityFilter()),
			IssueViewOptions:            util.Ptr(types.DefaultIssueViewOptions()),
		},
	}

	_, _ = loc.Client.Call(ctx, "initialize", clientParams)

	testPath := types.FilePath(filepath.Join(cloneTargetDirString, "app.js"))

	w := c.Workspace()
	f := workspace.NewFolder(c, cloneTargetDir, "Test", di.Scanner(), di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister(), di.ScanStateAggregator(), featureflag.NewFakeService())
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

	cloneTargetDir, err := storedconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), testsupport.NodejsGoof, "0336589", c.Logger())
	if err != nil {
		t.Fatal(err, "Couldn't setup test repo")
	}

	uncPath := "\\\\localhost\\" + strings.Replace(string(cloneTargetDir), ":", "$", 1)
	_, err = os.Stat(uncPath)
	assert.NoError(t, err)

	initializeParams := prepareInitParams(t, types.FilePath(uncPath), c)
	ensureInitialized(t, c, loc, initializeParams, nil)
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
	cloneTargetDir, err := storedconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), testsupport.NodejsGoof, "0336589", c.Logger())
	cloneTargetDirString := string(cloneTargetDir)
	assert.NoError(t, err)

	sourceContent, err := os.ReadFile(filepath.Join(cloneTargetDirString, "app.js"))
	require.NoError(t, err)

	newFileInCurrentDir(t, cloneTargetDirString, fileWithNewVulns, string(sourceContent))

	c.SetSnykOssEnabled(false)
	c.SetSnykIacEnabled(false)
	c.SetManageBinariesAutomatically(false)
	initParams := prepareInitParams(t, cloneTargetDir, c)

	ensureInitialized(t, c, loc, initParams, nil)

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
	cloneTargetDir, err := storedconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), "https://github.com/snyk-labs/nodejs-goof", "0336589", c.Logger())
	assert.NoError(t, err)

	cloneTargetDirString := string(cloneTargetDir)

	newFileInCurrentDir(t, cloneTargetDirString, fileWithNewVulns, "// no problems")

	initParams := prepareInitParams(t, cloneTargetDir, c)

	ensureInitialized(t, c, loc, initParams, nil)

	waitForScan(t, cloneTargetDirString, c)

	waitForDeltaScan(t, scanAggregator)
	checkForScanParams(t, jsonRPCRecorder, cloneTargetDirString, product.ProductCode)
	issueList := getIssueListFromPublishDiagnosticsNotification(t, jsonRPCRecorder, product.ProductCode, cloneTargetDir)

	assert.Equal(t, 0, len(issueList), "no issues expected, as delta and no new change")
}

func Test_SmokeSnykCodeDelta_NoNewIssuesFound_JavaGoof(t *testing.T) {
	c := testutil.SmokeTest(t, false)
	loc, jsonRPCRecorder := setupServer(t, c)
	c.SetSnykCodeEnabled(true)
	c.SetDeltaFindingsEnabled(true)
	cleanupChannels()
	di.Init()
	scanAggregator := di.ScanStateAggregator()

	cloneTargetDir, err := storedconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), "https://github.com/snyk-labs/java-goof", "f5719ae", c.Logger())
	assert.NoError(t, err)

	cloneTargetDirString := string(cloneTargetDir)

	initParams := prepareInitParams(t, cloneTargetDir, c)

	ensureInitialized(t, c, loc, initParams, nil)

	waitForScan(t, cloneTargetDirString, c)

	waitForDeltaScan(t, scanAggregator)
	checkForScanParams(t, jsonRPCRecorder, cloneTargetDirString, product.ProductCode)
	issueList := getIssueListFromPublishDiagnosticsNotification(t, jsonRPCRecorder, product.ProductCode, cloneTargetDir)

	assert.Equal(t, 0, len(issueList), "no issues expected, as delta and no new change")
}

func Test_SmokeScanUnmanaged(t *testing.T) {
	testsupport.NotOnWindows(t, "git clone does not work here. dunno why. ") // FIXME
	c := testutil.SmokeTest(t, false)
	loc, jsonRPCRecorder := setupServer(t, c)
	c.SetSnykIacEnabled(false)
	cleanupChannels()
	di.Init()

	cloneTargetDir, err := storedconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), testsupport.CppGoof, "259ea516a4ec", c.Logger())
	cloneTargetDirString := string(cloneTargetDir)
	if err != nil {
		t.Fatal(err, "Couldn't setup test repo")
	}

	initParams := prepareInitParams(t, cloneTargetDir, c)
	folderConfig := c.FolderConfig(cloneTargetDir)
	folderConfig.AdditionalParameters = []string{"--unmanaged"}
	initParams.InitializationOptions.FolderConfigs = []types.FolderConfig{*folderConfig}

	ensureInitialized(t, c, loc, initParams, nil)

	waitForScan(t, cloneTargetDirString, c)

	issueList := getIssueListFromPublishDiagnosticsNotification(t, jsonRPCRecorder, product.ProductOpenSource, cloneTargetDir)

	assert.Greater(t, len(issueList), 100, "More than 100 unmanaged issues expected")
}

// requireFolderConfigNotification is a helper to check folder config notifications
// validators is a map of folder path to validation function, call require/assert inside of them
func requireFolderConfigNotification(t *testing.T, jsonRpcRecorder *testsupport.JsonRPCRecorder, validators map[types.FilePath]func(types.FolderConfig)) {
	t.Helper()

	var notifications []jrpc2.Request
	require.Eventuallyf(t, func() bool {
		notifications = jsonRpcRecorder.FindNotificationsByMethod("$/snyk.folderConfigs")
		return len(notifications) != 0
	}, 10*time.Second, 5*time.Millisecond, "No $/snyk.folderConfigs notifications")
	require.Equal(t, 1, len(notifications), "Expected exactly one $/snyk.folderConfigs notification")

	var param types.FolderConfigsParam
	require.NoError(t, notifications[0].UnmarshalParams(&param))

	validationsCount := 0

	for _, folderConfig := range param.FolderConfigs {
		validator, ok := validators[folderConfig.FolderPath]
		// allowing empty validator for cases when we just care about folderconfig being present
		if ok {
			validationsCount = validationsCount + 1
		}
		if validator != nil {
			validator(folderConfig)
		}
	}

	require.Equal(t, len(param.FolderConfigs), validationsCount, "Not all folder configs were validated")

	jsonRpcRecorder.ClearNotifications()
}

func Test_SmokeOrgSelection(t *testing.T) {
	setupOrgSelectionTest := func(t *testing.T) (*config.Config, server.Local, *testsupport.JsonRPCRecorder, types.FilePath, types.InitializeParams) {
		t.Helper()
		c := testutil.SmokeTest(t, false)
		loc, jsonRpcRecorder := setupServer(t, c)
		c.EnableSnykCodeSecurity(false)
		c.SetSnykOssEnabled(true)
		c.SetSnykIacEnabled(false)
		di.Init()

		repo, err := storedconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), testsupport.PythonGoof, "", c.Logger())
		require.NoError(t, err)
		require.NotEmpty(t, repo)
		require.NoError(t, err)

		initParams := prepareInitParams(t, repo, c)
		initParams.InitializationOptions.ManageBinariesAutomatically = "false"
		initParams.InitializationOptions.CliPath = "/some/invalid/path/that/does/not/matter/but/cannot/be/blank"
		initParams.InitializationOptions.AuthenticationMethod = types.TokenAuthentication
		initParams.InitializationOptions.AutomaticAuthentication = "false"
		initParams.InitializationOptions.ScanningMode = "manual"
		return c, loc, jsonRpcRecorder, repo, initParams
	}

	t.Run("authenticated - takes given non-default org, sends folder config after init", func(t *testing.T) {
		c, loc, jsonRpcRecorder, repo, initParams := setupOrgSelectionTest(t)
		preferredOrg := "non-default"

		folderConfig := types.FolderConfig{
			FolderPath:                  repo,
			PreferredOrg:                preferredOrg,
			OrgSetByUser:                true,
			OrgMigratedFromGlobalConfig: true,
		}

		initParams.InitializationOptions.FolderConfigs = []types.FolderConfig{folderConfig}

		ensureInitialized(t, c, loc, initParams, nil)

		requireFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.FolderConfig){
			repo: func(fc types.FolderConfig) {
				require.Equal(t, preferredOrg, fc.PreferredOrg)
				require.True(t, fc.OrgSetByUser)
				require.NotEmpty(t, fc.AutoDeterminedOrg, "Should be set by auto-org resolution on initialized")
				require.True(t, fc.OrgMigratedFromGlobalConfig)

				// Check for required feature flag keys
				for _, key := range featureflag.Flags {
					require.Contains(t, fc.FeatureFlags, key, "FeatureFlag map should contain %s key", key)
				}
			},
		})
	})

	t.Run("authenticated - determines org when nothing is given", func(t *testing.T) {
		c, loc, jsonRpcRecorder, repo, initParams := setupOrgSelectionTest(t)
		folderConfig := types.FolderConfig{
			FolderPath: repo,
		}

		initParams.InitializationOptions.FolderConfigs = []types.FolderConfig{folderConfig}

		ensureInitialized(t, c, loc, initParams, nil)

		requireFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.FolderConfig){
			repo: func(fc types.FolderConfig) {
				require.False(t, fc.OrgSetByUser)
				require.Empty(t, fc.PreferredOrg)
				require.NotEmpty(t, fc.AutoDeterminedOrg)
				require.True(t, fc.OrgMigratedFromGlobalConfig)
			},
		})
	})

	t.Run("authenticated - determines org when global default org is given (migration)", func(t *testing.T) {
		// TODO - Should this even be a smoke test? Why not just make it a unit / integration test with mocking?
		t.Skip(t, "TODO: Everyone would have to be in an org which takes priority for Python-goof"+
			"as this test expects a non-default org to be returned.")

		c, loc, jsonRpcRecorder, repo, initParams := setupOrgSelectionTest(t)
		folderConfig := types.FolderConfig{
			FolderPath: repo,
		}

		// Pre-populate storage with a folder config so it gets migrated on init.
		setupFunc := func(c *config.Config) {
			err := storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), &folderConfig, c.Logger())
			require.NoError(t, err)
		}

		ensureInitialized(t, c, loc, initParams, setupFunc)

		// We should be using the default org. We derive this at runtime as it will depend on the SNYK_TOKEN
		// environment variable used to run the test.
		defaultOrg := c.Engine().GetConfiguration().GetString(configuration.ORGANIZATION)
		requireFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.FolderConfig){
			repo: func(fc types.FolderConfig) {
				require.False(t, fc.OrgSetByUser)
				require.Empty(t, fc.PreferredOrg)
				require.NotEqual(t, defaultOrg, fc.AutoDeterminedOrg)
				require.NotEmpty(t, fc.AutoDeterminedOrg)
				require.True(t, fc.OrgMigratedFromGlobalConfig)
			},
		})
	})

	t.Run("authenticated - migration uses global non-default org", func(t *testing.T) {
		c, loc, jsonRpcRecorder, repo, initParams := setupOrgSelectionTest(t)
		folderConfig := types.FolderConfig{
			FolderPath: repo,
		}

		expectedOrg := uuid.NewString()

		// Pre-populate storage with a folder config to simulate migration
		setupFunc := func(c *config.Config) {
			c.SetOrganization(expectedOrg)
			err := storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), &folderConfig, c.Logger())
			require.NoError(t, err)
		}

		ensureInitialized(t, c, loc, initParams, setupFunc)

		requireFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.FolderConfig){
			repo: func(fc types.FolderConfig) {
				require.True(t, fc.OrgSetByUser)
				require.Equal(t, expectedOrg, fc.PreferredOrg)
				require.NotEmpty(t, fc.AutoDeterminedOrg)
				require.True(t, fc.OrgMigratedFromGlobalConfig)
			},
		})
	})

	t.Run("authenticated - adding folder with existing stored config. Making sure PreferredOrg is preserved", func(t *testing.T) {
		c, loc, jsonRpcRecorder, repo, initParams := setupOrgSelectionTest(t)

		ensureInitialized(t, c, loc, initParams, nil)
		repoValidator := func(fc types.FolderConfig) {
			require.False(t, fc.OrgSetByUser)
			require.Empty(t, fc.PreferredOrg)
			require.NotEmpty(t, fc.AutoDeterminedOrg)
			require.True(t, fc.OrgMigratedFromGlobalConfig)
		}

		requireFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.FolderConfig){
			repo: repoValidator,
		})

		// add folder (LS has not seen before)
		fakeDirFolder, fakeDirFolderPath := addFakeDirAsWorkspaceFolder(t, loc)

		requireFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.FolderConfig){
			repo: repoValidator,
			fakeDirFolderPath: func(fc types.FolderConfig) {
				require.False(t, fc.OrgSetByUser, "OrgSetByUser should be false for new folder in auto mode")
				require.Empty(t, fc.PreferredOrg, "PreferredOrg should be empty for new folder in auto mode")
				require.NotEmpty(t, fc.AutoDeterminedOrg, "AutoDeterminedOrg should be set from LDX-Sync")
				require.True(t, fc.OrgMigratedFromGlobalConfig, "OrgMigratedFromGlobalConfig should be true")
			},
		})

		// remove folder
		removeWorkSpaceFolder(t, loc, fakeDirFolder)
		requireFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.FolderConfig){
			repo: repoValidator,
		})

		err := storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), &types.FolderConfig{
			FolderPath:                  fakeDirFolderPath,
			AutoDeterminedOrg:           "any",
			PreferredOrg:                "any",
			OrgMigratedFromGlobalConfig: true,
			OrgSetByUser:                false,
		}, c.Logger())
		require.NoError(t, err)

		// re-add folder
		addWorkSpaceFolder(t, loc, fakeDirFolder)

		requireFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.FolderConfig){
			repo: repoValidator,
			fakeDirFolderPath: func(fc types.FolderConfig) {
				require.False(t, fc.OrgSetByUser, "OrgSetByUser must be preserved")
				require.Equal(t, "any", fc.PreferredOrg, "PreferredOrg must be preserved")
				require.NotEmpty(t, fc.AutoDeterminedOrg, "AutoDeterminedOrg must override 'any'")
				require.NotEqual(t, "any", fc.AutoDeterminedOrg, "AutoDeterminedOrg must override 'any'")
				require.True(t, fc.OrgMigratedFromGlobalConfig, "OrgMigratedFromGlobalConfig should be true")
			},
		})
	})

	t.Run("authenticated - user blanks folder-level org, so LS uses global org", func(t *testing.T) {
		c, loc, jsonRpcRecorder, repo, initParams := setupOrgSelectionTest(t)
		t.Cleanup(func() {
			s, _ := storedconfig.ConfigFile(c.IdeName())
			_ = os.Remove(s)
		})

		initialOrg := "user-chosen-org"
		globalOrg := "00000000-0000-0000-0000-000000000002" // Must be UUID to prevent resolution

		setupFunc := func(c *config.Config) {
			c.SetOrganization(globalOrg)
			err := storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), &types.FolderConfig{
				FolderPath:                  repo,
				PreferredOrg:                initialOrg,
				OrgSetByUser:                true,
				OrgMigratedFromGlobalConfig: true,
			}, c.Logger())
			require.NoError(t, err)
		}

		ensureInitialized(t, c, loc, initParams, setupFunc)

		// Verify initial state
		requireFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.FolderConfig){
			repo: func(fc types.FolderConfig) {
				require.True(t, fc.OrgSetByUser)
				require.Equal(t, initialOrg, fc.PreferredOrg)
				require.NotEmpty(t, fc.AutoDeterminedOrg, "AutoDeterminedOrg should be set from LDX-Sync")
			},
		})

		// Verify that the global org is still what we set it to
		require.Equal(t, globalOrg, c.Organization(), "Global org should remain unchanged")

		// Verify that the folder's effective organization equals the preferred org
		require.Equal(t, initialOrg, c.FolderOrganization(repo), "Folder should use PreferredOrg when not blank and OrgSetByUser is true")

		// User blanks the folder-level org via configuration change
		sendModifiedFolderConfiguration(t, c, loc, func(folderConfigs map[types.FilePath]*types.FolderConfig) {
			require.Len(t, folderConfigs, 1, "should only have one folder config")
			folderConfigs[repo].PreferredOrg = ""
		})

		// Verify PreferredOrg is now empty and OrgSetByUser is true
		requireFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.FolderConfig){
			repo: func(fc types.FolderConfig) {
				require.True(t, fc.OrgSetByUser, "OrgSetByUser should remain true after user blanks org")
				require.Empty(t, fc.PreferredOrg, "PreferredOrg should be empty after user blanks it")
				require.NotEmpty(t, fc.AutoDeterminedOrg, "AutoDeterminedOrg should still be set from LDX-Sync")
				require.True(t, fc.OrgMigratedFromGlobalConfig, "OrgMigratedFromGlobalConfig should remain true")
			},
		})

		// Verify that the global org is still what we set it to
		assert.Equal(t, globalOrg, c.Organization(), "Global org should remain unchanged")

		// Verify that the folder's effective organization equals the global org
		assert.Equal(t, globalOrg, c.FolderOrganization(repo), "Folder should use global org when PreferredOrg is blank and OrgSetByUser is true")
	})

	t.Run("unauthenticated - re-adding folder with changing the config through workspace/didChangeConfiguration", func(t *testing.T) {
		c, loc, jsonRpcRecorder, repo, initParams := setupOrgSelectionTest(t)
		t.Cleanup(func() {
			s, _ := storedconfig.ConfigFile(c.IdeName())
			_ = os.Remove(s)
		})
		t.Setenv("SNYK_TOKEN", "")

		ensureInitialized(t, c, loc, initParams, nil)

		repoValidator := func(fc types.FolderConfig) {
			require.False(t, fc.OrgSetByUser)
			require.Empty(t, fc.PreferredOrg)
			require.Empty(t, fc.AutoDeterminedOrg)
			require.True(t, fc.OrgMigratedFromGlobalConfig)
		}
		requireFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.FolderConfig){
			repo: repoValidator,
		})

		// add folder
		fakeDirFolder, fakeDirFolderPath := addFakeDirAsWorkspaceFolder(t, loc)
		fakeDirFolderInitialValidator := func(fc types.FolderConfig) {
			require.False(t, fc.OrgSetByUser)
			require.Empty(t, fc.PreferredOrg)
			require.Empty(t, fc.AutoDeterminedOrg)
			require.True(t, fc.OrgMigratedFromGlobalConfig)
		}

		requireFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.FolderConfig){
			repo:              repoValidator,
			fakeDirFolderPath: fakeDirFolderInitialValidator,
		})

		// remove folder
		removeWorkSpaceFolder(t, loc, fakeDirFolder)

		requireFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.FolderConfig){
			repo: repoValidator,
		})

		// re-add folder
		addWorkSpaceFolder(t, loc, fakeDirFolder)

		requireFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.FolderConfig){
			repo:              repoValidator,
			fakeDirFolderPath: fakeDirFolderInitialValidator,
		})

		// simulate settings change from the IDE
		sendModifiedFolderConfiguration(t, c, loc, func(folderConfigs map[types.FilePath]*types.FolderConfig) {
			folderConfigs[fakeDirFolderPath].PreferredOrg = "any"
		})

		requireFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.FolderConfig){
			repo: repoValidator,
			fakeDirFolderPath: func(fc types.FolderConfig) {
				require.True(t, fc.OrgSetByUser)
				require.Equal(t, "any", fc.PreferredOrg)
				require.Empty(t, fc.AutoDeterminedOrg)
				require.True(t, fc.OrgMigratedFromGlobalConfig)
			},
		})
	})

	t.Run("authenticated - user opts in to automatic org selection", func(t *testing.T) {
		c, loc, jsonRpcRecorder, repo, initParams := setupOrgSelectionTest(t)
		t.Cleanup(func() {
			s, _ := storedconfig.ConfigFile(c.IdeName())
			_ = os.Remove(s)
		})

		initialOrg := "user-chosen-org"
		globalOrg := "00000000-0000-0000-0000-000000000002" // Must be UUID to prevent resolution

		setupFunc := func(c *config.Config) {
			c.SetOrganization(globalOrg)
			err := storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), &types.FolderConfig{
				FolderPath:                  repo,
				PreferredOrg:                initialOrg,
				OrgSetByUser:                true,
				OrgMigratedFromGlobalConfig: true,
			}, c.Logger())
			require.NoError(t, err)
		}

		ensureInitialized(t, c, loc, initParams, setupFunc)

		// Verify initial state
		var autoDeterminedOrg string
		requireFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.FolderConfig){
			repo: func(fc types.FolderConfig) {
				require.True(t, fc.OrgSetByUser)
				require.Equal(t, initialOrg, fc.PreferredOrg)
				require.NotEmpty(t, fc.AutoDeterminedOrg, "AutoDeterminedOrg should be set from LDX-Sync")
				autoDeterminedOrg = fc.AutoDeterminedOrg
			},
		})
		require.Equal(t, initialOrg, c.FolderOrganization(repo), "Folder should use PreferredOrg when not blank and OrgSetByUser is true")

		// User opts-in to automatic org selection for the folder
		sendModifiedFolderConfiguration(t, c, loc, func(folderConfigs map[types.FilePath]*types.FolderConfig) {
			require.Len(t, folderConfigs, 1, "should only have one folder config")
			folderConfigs[repo].OrgSetByUser = false
		})

		// Verify that OrgSetByUser is false, PreferredOrg is empty, and the folder's effective org is the auto-determined one
		requireFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.FolderConfig){
			repo: func(fc types.FolderConfig) {
				require.False(t, fc.OrgSetByUser, "OrgSetByUser should be false after user opts-in to auto org selection")
				require.Empty(t, fc.PreferredOrg, "PreferredOrg should be empty after user opts-in to auto org selection")
				require.Equal(t, autoDeterminedOrg, fc.AutoDeterminedOrg, "AutoDeterminedOrg should remain the same")
				require.True(t, fc.OrgMigratedFromGlobalConfig, "OrgMigratedFromGlobalConfig should remain true")
			},
		})
		assert.Equal(t, autoDeterminedOrg, c.FolderOrganization(repo), "Folder should use auto-determined org when OrgSetByUser is false")
	})

	t.Run("authenticated - user opts out of automatic org selection", func(t *testing.T) {
		c, loc, jsonRpcRecorder, repo, initParams := setupOrgSelectionTest(t)
		t.Cleanup(func() {
			s, _ := storedconfig.ConfigFile(c.IdeName())
			_ = os.Remove(s)
		})

		globalOrg := "00000000-0000-0000-0000-000000000002" // Must be UUID to prevent resolution

		setupFunc := func(c *config.Config) {
			c.SetOrganization(globalOrg)
			err := storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), &types.FolderConfig{
				FolderPath:                  repo,
				OrgSetByUser:                false, // auto-selection enabled
				OrgMigratedFromGlobalConfig: true,
			}, c.Logger())
			require.NoError(t, err)
		}

		ensureInitialized(t, c, loc, initParams, setupFunc)

		// Verify initial state
		var autoDeterminedOrg string
		requireFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.FolderConfig){
			repo: func(fc types.FolderConfig) {
				require.False(t, fc.OrgSetByUser)
				require.Empty(t, fc.PreferredOrg)
				require.NotEmpty(t, fc.AutoDeterminedOrg, "AutoDeterminedOrg should be set from LDX-Sync")
				autoDeterminedOrg = fc.AutoDeterminedOrg
			},
		})
		require.Equal(t, autoDeterminedOrg, c.FolderOrganization(repo), "Folder should use auto-determined org when OrgSetByUser is false")

		// User opts-out of automatic org selection for the folder
		sendModifiedFolderConfiguration(t, c, loc, func(folderConfigs map[types.FilePath]*types.FolderConfig) {
			require.Len(t, folderConfigs, 1, "should only have one folder config")
			folderConfigs[repo].OrgSetByUser = true
		})

		// Verify that OrgSetByUser is true, and the folder's effective org is the global one
		requireFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.FolderConfig){
			repo: func(fc types.FolderConfig) {
				require.True(t, fc.OrgSetByUser, "OrgSetByUser should be true after user opts-out of auto org selection")
				require.Empty(t, fc.PreferredOrg, "PreferredOrg should be empty")
				require.Equal(t, autoDeterminedOrg, fc.AutoDeterminedOrg, "AutoDeterminedOrg should remain the same")
				require.True(t, fc.OrgMigratedFromGlobalConfig, "OrgMigratedFromGlobalConfig should remain true")
			},
		})
		assert.Equal(t, globalOrg, c.FolderOrganization(repo), "Folder should use global org when OrgSetByUser is true and PreferredOrg is empty")
	})
}

func ensureInitialized(t *testing.T, c *config.Config, loc server.Local, initParams types.InitializeParams, preInitSetupFunc func(*config.Config)) {
	t.Helper()
	t.Setenv("SNYK_LOG_LEVEL", "debug")
	c.SetLogLevel(zerolog.LevelDebugValue)
	c.ConfigureLogging(nil)
	gafConfig := c.Engine().GetConfiguration()
	gafConfig.Set(configuration.DEBUG, false)

	documentURI := initParams.WorkspaceFolders[0].Uri
	commitHash := getCurrentCommitHash(t, uri.PathFromUri(documentURI))
	config.Version = commitHash

	// Sanitize test name to make it safe for file system paths
	sanitizedTestName := testsupport.PathSafeTestName(t)

	if initParams.ClientInfo.Name == "" {
		initParams.ClientInfo.Name = "snyk-ls_(" + sanitizedTestName + ")"
		initParams.ClientInfo.Version = commitHash
	}

	if initParams.InitializationOptions.IntegrationName == "" {
		initParams.InitializationOptions.IntegrationName = "ls-smoke-tests(" + sanitizedTestName + ")"
		initParams.InitializationOptions.IntegrationVersion = commitHash
	}

	_, err := loc.Client.Call(ctx, "initialize", initParams)
	assert.NoError(t, err)

	// Filter out old stored folder configs and only keep the ones from initParams
	storedConfig, getSCErr := storedconfig.GetStoredConfig(c.Engine().GetConfiguration(), c.Logger())
	if getSCErr == nil {
		filteredConfigs := make(map[types.FilePath]*types.FolderConfig)
		for _, fc := range initParams.InitializationOptions.FolderConfigs {
			if storedFc, exists := storedConfig.FolderConfigs[fc.FolderPath]; exists {
				filteredConfigs[fc.FolderPath] = storedFc
			}
		}

		storedConfig.FolderConfigs = filteredConfigs
		saveErr := storedconfig.Save(c.Engine().GetConfiguration(), storedConfig)
		assert.NoError(t, saveErr)
	}

	waitForNetwork(c)

	// Run optional setup function after initialization but before call to initialized.
	// This allows tests to, for example, pre-populate storage to be read by the initialized call.
	if preInitSetupFunc != nil {
		preInitSetupFunc(c)
	}

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

func addFakeDirAsWorkspaceFolder(t *testing.T, loc server.Local) (types.WorkspaceFolder, types.FilePath) {
	t.Helper()
	fakeDirFolderPath := types.FilePath(t.TempDir())
	fakeDirFolder := types.WorkspaceFolder{Uri: uri.PathToUri(fakeDirFolderPath), Name: "fake-dir"}

	addWorkSpaceFolder(t, loc, fakeDirFolder)

	return fakeDirFolder, fakeDirFolderPath
}

func sendModifiedFolderConfiguration(
	t *testing.T,
	c *config.Config,
	loc server.Local,
	modification func(folderConfigs map[types.FilePath]*types.FolderConfig),
) {
	t.Helper()
	storedConfig, err := storedconfig.GetStoredConfig(c.Engine().GetConfiguration(), c.Logger())
	require.NoError(t, err)
	modification(storedConfig.FolderConfigs)
	sendConfigurationDidChange(t, loc, types.Settings{
		FolderConfigs: lo.Values(lo.MapValues(storedConfig.FolderConfigs, func(v *types.FolderConfig, k types.FilePath) types.FolderConfig { return *v })),
	})
}

func sendConfigurationDidChange(t *testing.T, loc server.Local, s types.Settings) {
	t.Helper()
	params := types.DidChangeConfigurationParams{
		Settings: s,
	}
	_, err := loc.Client.Call(t.Context(), "workspace/didChangeConfiguration", params)
	require.NoError(t, err)
}

func addWorkSpaceFolder(t *testing.T, loc server.Local, f types.WorkspaceFolder) {
	t.Helper()
	_, err := loc.Client.Call(t.Context(), "workspace/didChangeWorkspaceFolders", types.DidChangeWorkspaceFoldersParams{
		Event: types.WorkspaceFoldersChangeEvent{Added: []types.WorkspaceFolder{f}},
	})
	require.NoError(t, err)
}

func removeWorkSpaceFolder(t *testing.T, loc server.Local, f types.WorkspaceFolder) {
	t.Helper()
	_, err := loc.Client.Call(t.Context(), "workspace/didChangeWorkspaceFolders", types.DidChangeWorkspaceFoldersParams{
		Event: types.WorkspaceFoldersChangeEvent{Removed: []types.WorkspaceFolder{f}},
	})
	require.NoError(t, err)
}
