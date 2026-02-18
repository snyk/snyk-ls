/*
 * © 2024-2026 Snyk Limited
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
	"os/exec"
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
	"github.com/snyk/go-application-framework/pkg/workflow"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/cli/install"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/internal/util"
)

func Test_SmokeInstanceTest(t *testing.T) {
	c := testutil.SmokeTest(t, "")
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
			tokenSecretName := ""
			if tc.useConsistentIgnores {
				tokenSecretName = "SNYK_TOKEN_CONSISTENT_IGNORES"
			}

			c := testutil.SmokeTest(t, tokenSecretName)
			runSmokeTest(t, c, tc.repo, tc.commit, tc.file1, tc.file2, tc.hasVulns, "")
		})
	}
}

func Test_SmokePreScanCommand(t *testing.T) {
	t.Run("executes pre scan command if configured", func(t *testing.T) {
		testsupport.NotOnWindows(t, "we can enable windows if we have the correct error message")
		c := testutil.SmokeTest(t, "")
		loc, jsonRpcRecorder := setupServer(t, c)
		c.SetSnykCodeEnabled(false)
		c.SetSnykOssEnabled(true)
		c.SetSnykIacEnabled(false)
		di.Init()

		repo, err := storedconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), testsupport.PythonGoof, "", c.Logger(), false)
		require.NoError(t, err)
		require.NotEmpty(t, repo)

		initParams := prepareInitParams(t, repo, c)

		// Pass ScanCommandConfig via LspFolderConfig in initParams
		script := "/path/to/script"
		initParams.InitializationOptions.FolderConfigs = []types.LspFolderConfig{
			{
				FolderPath:                  repo,
				OrgMigratedFromGlobalConfig: util.Ptr(true),
				SnykOssEnabled:              types.NullableField[bool]{Value: true, Present: true},
				ScanCommandConfig: map[product.Product]types.ScanCommandConfig{
					product.ProductOpenSource: {
						PreScanOnlyReferenceFolder: false,
						PreScanCommand:             script,
					},
				},
			},
		}

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
				return strings.Contains(scanParams.PresentableError.ErrorMessage, "fork/exec")
			}

			return false
		}, time.Minute, time.Second, "expected scan command to fail")
	})
}

func Test_SmokeIssueCaching(t *testing.T) {
	testsupport.NotOnWindows(t, "git clone does not work here. dunno why. ") // FIXME
	t.Run("adds issues to cache correctly", func(t *testing.T) {
		c := testutil.SmokeTest(t, "")
		loc, jsonRPCRecorder := setupServer(t, c)
		c.SetSnykCodeEnabled(true)
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
		c := testutil.SmokeTest(t, "")
		loc, jsonRPCRecorder := setupServer(t, c)
		c.SetSnykCodeEnabled(true)
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
	c := testutil.SmokeTest(t, "")
	repoTempDir := types.FilePath(testutil.TempDirWithRetry(t))
	loc, _ := setupServer(t, c)
	c.SetSnykCodeEnabled(false)
	c.SetSnykIacEnabled(false)
	c.SetSnykOssEnabled(true)
	di.Init()

	cloneTargetDirGoof := setupRepoAndInitializeInDir(t, repoTempDir, testsupport.NodejsGoof, "0336589", loc, c)
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

func Test_SmokeLegacyRoutingUnmanagedWithRiskScore(t *testing.T) {
	c := testutil.SmokeTest(t, tokenSecretNameForRiskScore)
	loc, jsonRpcRecorder := setupServer(t, c)
	c.SetSnykCodeEnabled(false)
	c.SetSnykOssEnabled(true)
	c.SetSnykIacEnabled(false)
	di.Init()

	repo, err := storedconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), testsupport.CGoof, "", c.Logger(), false)
	require.NoError(t, err)
	require.NotEmpty(t, repo)

	initParams := prepareInitParams(t, repo, c)

	initParams.InitializationOptions.FolderConfigs = []types.LspFolderConfig{
		{
			FolderPath:                  repo,
			OrgMigratedFromGlobalConfig: util.Ptr(true),
			AdditionalParameters:        []string{"--unmanaged"},
		},
	}

	ensureInitialized(t, c, loc, initParams, func(c *config.Config) {
		fc := &types.FolderConfig{
			FolderPath:           repo,
			AdditionalParameters: []string{"--unmanaged"},
			FeatureFlags: map[string]bool{
				featureflag.UseExperimentalRiskScoreInCLI: true, // The one we actually use.
				// featureflag.UseExperimentalRiskScore: true, // Not used in the prod filtering logic.
			},
		}
		_ = storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), fc, c.Logger())
	})

	assert.Eventuallyf(t, func() bool {
		notifications := jsonRpcRecorder.FindNotificationsByMethod("$/snyk.scan")
		for _, n := range notifications {
			var scanParams types.SnykScanParams
			_ = n.UnmarshalParams(&scanParams)
			if scanParams.Product == product.ProductOpenSource.ToProductCodename() &&
				scanParams.FolderPath == repo &&
				scanParams.Status == types.Success {
				return true
			}
		}
		return false
	}, maxIntegTestDuration, time.Second, "expected OSS scan to succeed via legacy routing with --unmanaged despite risk score FF")
}

func addJuiceShopAsWorkspaceFolder(t *testing.T, loc server.Local, c *config.Config) types.Folder {
	t.Helper()
	cloneTargetDirJuice, err := storedconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), "https://github.com/juice-shop/juice-shop", "bc9cef127", c.Logger(), false)
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
	// Allocate temp dir BEFORE setupServer so t.Cleanup LIFO order ensures
	// the server shuts down before the temp dir is removed (fixes Windows file locking).
	// TempDirWithRetry adds retry logic for os.RemoveAll to handle lingering file locks.
	repoTempDir := types.FilePath(testutil.TempDirWithRetry(t))
	loc, jsonRPCRecorder := setupServer(t, c)
	c.SetSnykCodeEnabled(true)
	c.SetSnykIacEnabled(true)
	c.SetSnykOssEnabled(true)
	cleanupChannels()
	di.Init()

	cloneTargetDir := setupRepoAndInitializeInDir(t, repoTempDir, repo, commit, loc, c)
	cloneTargetDirString := (string)(cloneTargetDir)

	waitForScan(t, cloneTargetDirString, c)

	notifications := jsonRPCRecorder.FindNotificationsByMethod("$/snyk.folderConfigs")
	assert.Greater(t, len(notifications), 0)

	assert.Eventuallyf(t, func() bool {
		return receivedFolderConfigNotification(t, notifications, cloneTargetDir)
	}, time.Second*5, time.Second, "did not receive folder configs")

	var testPath types.FilePath

	// ------------------------------------------------------
	// check snyk open source diagnostics (file1)
	// ------------------------------------------------------
	if file1 != "" {
		testPath = types.FilePath(filepath.Join(cloneTargetDirString, file1))
		waitForNetwork(c)
		textDocumentDidSave(t, &loc, testPath)
		// serve diagnostics from file scan
		require.Eventually(t, checkForPublishedDiagnostics(t, c, testPath, -1, jsonRPCRecorder), maxIntegTestDuration, 10*time.Millisecond,
			"Diagnostics not published for file %s", file1)
	}

	jsonRPCRecorder.ClearNotifications()

	// ------------------------------------------------------
	// check snyk code diagnostics (file2)
	// ------------------------------------------------------
	testPath = types.FilePath(filepath.Join(cloneTargetDirString, file2))
	waitForNetwork(c)
	textDocumentDidSave(t, &loc, testPath)
	// Check scan completed successfully
	checkForScanParams(t, jsonRPCRecorder, cloneTargetDirString, product.ProductCode)
	require.Eventually(t, checkForPublishedDiagnostics(t, c, testPath, -1, jsonRPCRecorder), maxIntegTestDuration, 10*time.Millisecond,
		"Diagnostics not published for file %s", file2)
	issueList := getIssueListFromPublishDiagnosticsNotification(t, jsonRPCRecorder, product.ProductCode, cloneTargetDir)

	// check for autofix diff on mt-us
	if hasVulns {
		checkAutofixDiffs(t, c, issueList, loc, jsonRPCRecorder)
	}

	checkFeatureFlagStatus(t, c, &loc)

	// check we only have one quickfix action in open source per line
	if c.IsSnykOssEnabled() {
		checkOnlyOneQuickFixCodeAction(t, jsonRPCRecorder, cloneTargetDirString, loc)
		checkOnlyOneCodeLens(t, jsonRPCRecorder, cloneTargetDirString, loc)
	}
	waitForDeltaScan(t, di.ScanStateAggregator())
}

func receivedFolderConfigNotification(t *testing.T, notifications []jrpc2.Request, cloneTargetDir types.FilePath) bool {
	t.Helper()
	foundFolderConfig := false
	for _, notification := range notifications {
		var folderConfigsParam types.LspFolderConfigsParam
		err := notification.UnmarshalParams(&folderConfigsParam)
		require.NoError(t, err)

		for _, folderConfig := range folderConfigsParam.FolderConfigs {
			assert.NotEmpty(t, folderConfig.BaseBranch)
			assert.NotEmpty(t, folderConfig.LocalBranches)

			// Normalize both paths for comparison since folder config paths are now normalized
			normalizedCloneTargetDir := types.PathKey(cloneTargetDir)
			if folderConfig.FolderPath == normalizedCloneTargetDir {
				foundFolderConfig = true
				break
			}
		}

		if foundFolderConfig {
			break
		}
	}
	return foundFolderConfig
}

var (
	// now register it with the engine
	depGraphWorkFlowID = workflow.NewWorkflowIdentifier("depgraph")
	depGraphDataID     = workflow.NewTypeIdentifier(depGraphWorkFlowID, "depgraph")
)

// substituteDepGraphFlow generate depgraph. necessary, as depgraph workflow needs legacycli workflow which
// does not work without the TypeScript CLI
func substituteDepGraphFlow(t *testing.T, c *config.Config, cloneTargetDirString, displayTargetFile string) {
	t.Helper()

	flagset := workflow.ConfigurationOptionsFromFlagset(pflag.NewFlagSet("", pflag.ContinueOnError))
	callback := func(invocation workflow.InvocationContext, workflowInputData []workflow.Data) ([]workflow.Data, error) {
		cmd := exec.CommandContext(t.Context(), c.CliSettings().Path(), "depgraph")
		cmd.Dir = cloneTargetDirString
		cmd.Env = os.Environ()
		depGraphJson, err := cmd.Output()
		if err != nil {
			t.Fatalf("couldn't retrieve the depgraph %s: ", err.Error())
		}
		depGraphData := workflow.NewData(depGraphDataID, "application/json", depGraphJson)
		normalisedTargetFile := strings.TrimSpace(displayTargetFile)
		depGraphData.SetMetaData("Content-Location", normalisedTargetFile)
		depGraphData.SetMetaData("normalisedTargetFile", normalisedTargetFile) // Required for cli-extension-os-flow

		return []workflow.Data{depGraphData}, nil
	}

	_, err := c.Engine().Register(depGraphWorkFlowID, flagset, callback)
	require.NoError(t, err)
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
	errorhandlerCheckHit := false
	tapCheckHit := false
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

			// "errorhandler": "^1.2.0" on line 25 - test singular "1 issue" vs plural "1 issues"
			if issue.Range.Start.Line == 25 && isQuickfixAction {
				assert.Contains(t, action.Title, "and fix 1 issue")
				assert.NotContains(t, action.Title, "and fix 1 issues")
				errorhandlerCheckHit = true
			}

			// "tap": "^11.1.3", 12 fixable, 11 unfixable
			if issue.Range.Start.Line == 46 && isQuickfixAction {
				assert.Contains(t, action.Title, "and fix ")
				assert.Contains(t, action.Title, " issues")
				tapCheckHit = true
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
	assert.Truef(t, errorhandlerCheckHit, "expected to hit errorhandler singular check")
	assert.Truef(t, tapCheckHit, "expected to hit tap plural check")
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
				assert.Contains(t, lens.Command.Title, "and fix ")
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
	var finalScanParams *types.SnykScanParams

	// Wait for scan to complete (success or error)
	require.Eventually(t, func() bool {
		notifications = jsonRPCRecorder.FindNotificationsByMethod("$/snyk.scan")
		for _, n := range notifications {
			var scanParams types.SnykScanParams
			_ = n.UnmarshalParams(&scanParams)
			if scanParams.Product != p.ToProductCodename() ||
				scanParams.FolderPath != types.FilePath(cloneTargetDir) ||
				scanParams.Status == types.InProgress {
				continue
			}
			finalScanParams = &scanParams
			return true
		}
		return false
	}, 5*time.Minute, 10*time.Millisecond,
		"Scan did not complete for product %s in folder %s", p.ToProductCodename(), cloneTargetDir)

	require.NotNil(t, finalScanParams, "No scan notification received for product %s in folder %s", p.ToProductCodename(), cloneTargetDir)
	require.NotEqual(t, types.ErrorStatus, finalScanParams.Status,
		"Scan failed - Product: %s, Folder: %s, Error: %w",
		finalScanParams.Product, finalScanParams.FolderPath, finalScanParams.PresentableError)
	require.Equal(t, types.Success, finalScanParams.Status,
		"Unexpected scan status: %s", finalScanParams.Status)
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

// assertDeltaNewIssuesInFile waits for delta issues to be published and asserts that
// new issues are only reported for the expected file path.
func assertDeltaNewIssuesInFile(t *testing.T, jsonRPCRecorder *testsupport.JsonRPCRecorder, folderPath types.FilePath, expectedNewIssuePath string) {
	t.Helper()
	var issueList []types.ScanIssue
	assert.Eventually(t, func() bool {
		issueList = getIssueListFromPublishDiagnosticsNotification(t, jsonRPCRecorder, product.ProductCode, folderPath)
		return len(issueList) > 0
	}, maxIntegTestDuration, 5*time.Second)

	for _, issue := range issueList {
		if issue.IsNew {
			issuePath := filepath.Clean(string(issue.FilePath))
			assert.Equal(t, expectedNewIssuePath, issuePath, "new issue should only be from the expected file: %s", string(issue.FilePath))
		}
	}
}

func checkAutofixDiffs(t *testing.T, c *config.Config, issueList []types.ScanIssue, loc server.Local, recorder *testsupport.JsonRPCRecorder) {
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
	return c.Endpoint() != "https://api.snyk.io" && c.Endpoint() != ""
}

func setupRepoAndInitialize(t *testing.T, repo string, commit string, loc server.Local, c *config.Config) types.FilePath {
	t.Helper()
	return setupRepoAndInitializeInDir(t, types.FilePath(testutil.TempDirWithRetry(t)), repo, commit, loc, c)
}

// setupRepoAndInitializeInDir clones a repo into the given rootDir and initializes the server with it.
// Use this variant when the temp dir must be allocated before setupServer to ensure correct t.Cleanup
// LIFO ordering on Windows (server closes before temp dir removal).
func setupRepoAndInitializeInDir(t *testing.T, rootDir types.FilePath, repo string, commit string, loc server.Local, c *config.Config) types.FilePath {
	t.Helper()

	// Wait for scans to complete before temp dir removal (LIFO order).
	// This prevents Windows file locking issues where HTTP requests are still in flight during cleanup.
	t.Cleanup(func() {
		waitForAllScansToComplete(t, di.ScanStateAggregator())
	})

	cloneTargetDir, err := storedconfig.SetupCustomTestRepo(t, rootDir, repo, commit, c.Logger(), false)
	if err != nil {
		t.Fatal(err, "Couldn't setup test repo")
	}

	initParams := prepareInitParams(t, cloneTargetDir, c)
	ensureInitialized(t, c, loc, initParams, nil)
	return cloneTargetDir
}

// buildSmokeTestSettings creates a complete settings object from config
// This ensures all critical fields (token, endpoint, etc.) are preserved
func buildSmokeTestSettings(c *config.Config) types.Settings {
	return types.Settings{
		Endpoint:                    c.Endpoint(),
		Token:                       c.Token(),
		Organization:                c.Organization(),
		EnableTrustedFoldersFeature: "false",
		FilterSeverity:              util.Ptr(types.DefaultSeverityFilter()),
		IssueViewOptions:            util.Ptr(types.DefaultIssueViewOptions()),
		AuthenticationMethod:        c.AuthenticationMethod(),
		AutomaticAuthentication:     "false",
		EnableDeltaFindings:         strconv.FormatBool(c.IsDeltaFindingsEnabled()),
		ActivateSnykCode:            strconv.FormatBool(c.IsSnykCodeEnabled()),
		ActivateSnykIac:             strconv.FormatBool(c.IsSnykIacEnabled()),
		ActivateSnykOpenSource:      strconv.FormatBool(c.IsSnykOssEnabled()),
		ActivateSnykCodeSecurity:    strconv.FormatBool(c.IsSnykCodeEnabled()),
		CliPath:                     c.CliSettings().Path(),
	}
}

// waitForAllScansToComplete waits for all in-progress scans to finish.
// This is used in cleanup to ensure file handles are released before temp directory removal.
func waitForAllScansToComplete(t *testing.T, agg scanstates.Aggregator) {
	t.Helper()
	// Wait for both working directory and reference scans to complete
	_ = assert.Eventually(t, func() bool {
		snapshot := agg.StateSnapshot()
		return snapshot.AllScansFinishedWorkingDirectory && snapshot.AllScansFinishedReference
	}, 30*time.Second, 100*time.Millisecond)
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
			Organization:                c.Organization(),
			EnableTrustedFoldersFeature: "false",
			FilterSeverity:              util.Ptr(types.DefaultSeverityFilter()),
			IssueViewOptions:            util.Ptr(types.DefaultIssueViewOptions()),
			AuthenticationMethod:        types.TokenAuthentication,
			AutomaticAuthentication:     "false",
			EnableDeltaFindings:         strconv.FormatBool(c.IsDeltaFindingsEnabled()),
			ActivateSnykCode:            strconv.FormatBool(c.IsSnykCodeEnabled()),
			ActivateSnykIac:             strconv.FormatBool(c.IsSnykIacEnabled()),
			ActivateSnykOpenSource:      strconv.FormatBool(c.IsSnykOssEnabled()),
			ActivateSnykCodeSecurity:    strconv.FormatBool(c.IsSnykCodeEnabled()),
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
	c := testutil.SmokeTest(t, "")
	repoTempDir := types.FilePath(testutil.TempDirWithRetry(t))
	loc, jsonRPCRecorder := setupServer(t, c)
	c.SetSnykCodeEnabled(true)
	cleanupChannels()
	di.Init()

	cloneTargetDir := setupRepoAndInitializeInDir(t, repoTempDir, testsupport.NodejsGoof, "0336589", loc, c)
	cloneTargetDirString := string(cloneTargetDir)

	testPath := types.FilePath(filepath.Join(cloneTargetDirString, "app.js"))

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
	testutil.EnableSastAndAutoFix(c)
	cleanupChannels()
	di.Init()

	cloneTargetDir, err := storedconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), testsupport.NodejsGoof, "0336589", c.Logger(), false)
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
	c := testutil.SmokeTest(t, "")
	loc, jsonRPCRecorder := setupServer(t, c)
	c.SetSnykCodeEnabled(true)
	c.SetDeltaFindingsEnabled(true)
	testutil.EnableSastAndAutoFix(c)
	cleanupChannels()
	di.Init()
	scanAggregator := di.ScanStateAggregator()
	fileWithNewVulns := "vulns.js"
	cloneTargetDir, err := storedconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), testsupport.NodejsGoof, "0336589", c.Logger(), false)
	cloneTargetDirString := string(cloneTargetDir)
	assert.NoError(t, err)

	sourceContent, err := os.ReadFile(filepath.Join(cloneTargetDirString, "app.js"))
	require.NoError(t, err)

	newFileInCurrentDir(t, cloneTargetDirString, fileWithNewVulns, string(sourceContent))

	initParams := prepareInitParams(t, cloneTargetDir, c)

	ensureInitialized(t, c, loc, initParams, nil)

	waitForScan(t, cloneTargetDirString, c)

	waitForDeltaScan(t, scanAggregator)
	checkForScanParams(t, jsonRPCRecorder, cloneTargetDirString, product.ProductCode)
	newVulnFilePath := filepath.Clean(filepath.Join(cloneTargetDirString, fileWithNewVulns))
	assertDeltaNewIssuesInFile(t, jsonRPCRecorder, cloneTargetDir, newVulnFilePath)
}

func Test_SmokeSnykCodeDelta_NoNewIssuesFound(t *testing.T) {
	c := testutil.SmokeTest(t, "")
	loc, jsonRPCRecorder := setupServer(t, c)
	c.SetSnykCodeEnabled(true)
	c.SetDeltaFindingsEnabled(true)
	cleanupChannels()
	di.Init()
	scanAggregator := di.ScanStateAggregator()

	fileWithNewVulns := "vulns.js"
	cloneTargetDir, err := storedconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), "https://github.com/snyk-labs/nodejs-goof", "0336589", c.Logger(), false)
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
	c := testutil.SmokeTest(t, "")
	loc, jsonRPCRecorder := setupServer(t, c)
	c.SetSnykCodeEnabled(true)
	c.SetDeltaFindingsEnabled(true)
	cleanupChannels()
	di.Init()
	scanAggregator := di.ScanStateAggregator()

	cloneTargetDir, err := storedconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), "https://github.com/snyk-labs/java-goof", "f5719ae", c.Logger(), false)
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

// Test_SmokeSnykCodeDelta_SubfolderWorkspace verifies that delta findings work correctly
// when the workspace folder is a subfolder of the git repository root.
// This reproduces the bug where git.PlainOpen fails for subfolders because it doesn't
// walk up parent directories to find .git. The fix uses PlainOpenWithOptions with DetectDotGit.
func Test_SmokeSnykCodeDelta_SubfolderWorkspace(t *testing.T) {
	c := testutil.SmokeTest(t, "")
	loc, jsonRPCRecorder := setupServer(t, c)
	testutil.OnlyEnableCode(t, c)
	testutil.EnableSastAndAutoFix(c)
	c.SetDeltaFindingsEnabled(true)
	cleanupChannels()
	di.Init()
	scanAggregator := di.ScanStateAggregator()

	// Clone a repo — this is the git root
	gitRoot, err := storedconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), testsupport.NodejsGoof, "0336589", c.Logger(), false)
	require.NoError(t, err)
	gitRootString := string(gitRoot)

	// Create a subfolder inside the git repo — this will be our workspace folder,
	// simulating how IntelliJ sends a content root that is a subdirectory of the git repo
	subfolder := filepath.Join(gitRootString, "subproject")
	require.NoError(t, os.MkdirAll(subfolder, 0o755))

	// Create a file with unique vulnerable content to ensure delta identifies it as new.
	// Using unique content avoids false negatives from fingerprint matching with baseline files.
	newFileInCurrentDir(t, subfolder, "vulns.js", `
var express = require('express');
var app = express();
app.get('/unique_subfolder_test', function(req, res) {
   var input = req.query.userInput;
   res.send(input);
});
`)

	// Use the SUBFOLDER as the workspace folder (not the git root)
	subfolderPath := types.FilePath(subfolder)
	initParams := prepareInitParams(t, subfolderPath, c)

	ensureInitialized(t, c, loc, initParams, nil)

	waitForScan(t, subfolder, c)
	waitForDeltaScan(t, scanAggregator)

	// Verify scan completed successfully — before the fix, this would fail with
	// "repository not found" or "must specify reference for delta scans"
	checkForScanParams(t, jsonRPCRecorder, subfolder, product.ProductCode)

	newVulnFilePath := filepath.Clean(filepath.Join(subfolder, "vulns.js"))
	assertDeltaNewIssuesInFile(t, jsonRPCRecorder, subfolderPath, newVulnFilePath)
}

func Test_SmokeScanUnmanaged(t *testing.T) {
	testsupport.NotOnWindows(t, "git clone does not work here. dunno why. ") // FIXME
	c := testutil.SmokeTest(t, "")
	loc, jsonRPCRecorder := setupServer(t, c)
	c.SetSnykIacEnabled(false)
	cleanupChannels()
	di.Init()

	cloneTargetDir, err := storedconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), testsupport.CppGoof, "259ea516a4ec", c.Logger(), false)
	cloneTargetDirString := string(cloneTargetDir)
	if err != nil {
		t.Fatal(err, "Couldn't setup test repo")
	}

	initParams := prepareInitParams(t, cloneTargetDir, c)

	// AdditionalParameters is internal-only (not transmitted via LSP), so we must persist it
	// directly to storage before initialization triggers the scan.
	folderConfig := c.FolderConfig(cloneTargetDir)
	folderConfig.AdditionalParameters = []string{"--unmanaged"}
	err = storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), folderConfig, c.Logger())
	require.NoError(t, err)

	ensureInitialized(t, c, loc, initParams, nil)

	waitForScan(t, cloneTargetDirString, c)

	issueList := getIssueListFromPublishDiagnosticsNotification(t, jsonRPCRecorder, product.ProductOpenSource, cloneTargetDir)

	assert.Greater(t, len(issueList), 100, "More than 100 unmanaged issues expected")
}

// requireLspFolderConfigNotification is a helper to check folder config notifications
// validators is a map of folder path to validation function, call require/assert inside of them
// clearNotifications controls whether to clear notifications after validation (default: true)
func requireLspFolderConfigNotification(t *testing.T, jsonRpcRecorder *testsupport.JsonRPCRecorder, validators map[types.FilePath]func(types.LspFolderConfig), clearNotifications ...bool) {
	t.Helper()

	var notifications []jrpc2.Request
	require.Eventuallyf(t, func() bool {
		notifications = jsonRpcRecorder.FindNotificationsByMethod("$/snyk.folderConfigs")
		return len(notifications) != 0
	}, 10*time.Second, 5*time.Millisecond, "No $/snyk.folderConfigs notifications")
	require.Equal(t, 1, len(notifications), "Expected exactly one $/snyk.folderConfigs notification")

	var param types.LspFolderConfigsParam
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

	// Clear notifications by default unless explicitly disabled
	shouldClear := true
	if len(clearNotifications) > 0 {
		shouldClear = clearNotifications[0]
	}
	if shouldClear {
		jsonRpcRecorder.ClearNotifications()
	}
}

func Test_SmokeOrgSelection(t *testing.T) {
	setupOrgSelectionTest := func(t *testing.T) (*config.Config, server.Local, *testsupport.JsonRPCRecorder, types.FilePath, types.InitializeParams) {
		t.Helper()
		c := testutil.SmokeTest(t, "")
		loc, jsonRpcRecorder := setupServer(t, c)
		c.SetSnykCodeEnabled(false)
		c.SetSnykOssEnabled(true)
		c.SetSnykIacEnabled(false)
		di.Init()

		repo, err := storedconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), testsupport.PythonGoof, "", c.Logger(), false)
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

		// Use LspFolderConfig to transmit folder configuration via LSP
		initParams.InitializationOptions.FolderConfigs = []types.LspFolderConfig{
			{
				FolderPath:   repo,
				PreferredOrg: &preferredOrg,
			},
		}

		ensureInitialized(t, c, loc, initParams, nil)

		requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.LspFolderConfig){
			repo: func(fc types.LspFolderConfig) {
				require.NotNil(t, fc.PreferredOrg)
				require.Equal(t, preferredOrg, *fc.PreferredOrg)
				require.NotNil(t, fc.OrgSetByUser)
				require.True(t, *fc.OrgSetByUser)
				require.NotNil(t, fc.OrgMigratedFromGlobalConfig)
				require.True(t, *fc.OrgMigratedFromGlobalConfig)
			},
		})
	})

	t.Run("authenticated - determines org when nothing is given", func(t *testing.T) {
		c, loc, jsonRpcRecorder, repo, initParams := setupOrgSelectionTest(t)

		// No folder config needed - LS will auto-determine org
		ensureInitialized(t, c, loc, initParams, nil)

		requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.LspFolderConfig){
			repo: func(fc types.LspFolderConfig) {
				require.NotNil(t, fc.OrgSetByUser)
				require.False(t, *fc.OrgSetByUser)
				require.Nil(t, fc.PreferredOrg)
				require.NotNil(t, fc.OrgMigratedFromGlobalConfig)
				require.True(t, *fc.OrgMigratedFromGlobalConfig)
			},
		})
	})

	t.Run("authenticated - migration with global default org results in auto mode", func(t *testing.T) {
		c, loc, jsonRpcRecorder, repo, initParams := setupOrgSelectionTest(t)

		// Pass folder config via initParams - simulating IDE sending config that needs migration
		initParams.InitializationOptions.FolderConfigs = []types.LspFolderConfig{
			{
				FolderPath:                  repo,
				OrgMigratedFromGlobalConfig: util.Ptr(false), // needs migration
			},
		}

		ensureInitialized(t, c, loc, initParams, nil)

		// When migrating with the default org, the folder should be in auto mode (OrgSetByUser=false)
		requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.LspFolderConfig){
			repo: func(fc types.LspFolderConfig) {
				require.NotNil(t, fc.OrgSetByUser)
				require.False(t, *fc.OrgSetByUser, "Migration with default org should result in auto mode")
				require.Nil(t, fc.PreferredOrg, "PreferredOrg should be nil in auto mode")
				require.NotNil(t, fc.OrgMigratedFromGlobalConfig)
				require.True(t, *fc.OrgMigratedFromGlobalConfig, "Config should be marked as migrated")
			},
		})
	})

	t.Run("authenticated - migration uses global non-default org", func(t *testing.T) {
		c, loc, jsonRpcRecorder, repo, initParams := setupOrgSelectionTest(t)

		expectedOrg := "00000000-0000-0000-0000-000000000001"

		// Pre-populate storage with a folder config to simulate migration
		setupFunc := func(c *config.Config) {
			c.SetOrganization(expectedOrg)
			folderConfig := &types.FolderConfig{
				FolderPath: repo,
			}
			err := storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), folderConfig, c.Logger())
			require.NoError(t, err)
		}

		ensureInitialized(t, c, loc, initParams, setupFunc)

		requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.LspFolderConfig){
			repo: func(fc types.LspFolderConfig) {
				require.NotNil(t, fc.OrgSetByUser)
				require.True(t, *fc.OrgSetByUser, "OrgSetByUser should be true for non-default org")
				require.NotNil(t, fc.PreferredOrg)
				require.Equal(t, expectedOrg, *fc.PreferredOrg)
				require.NotNil(t, fc.OrgMigratedFromGlobalConfig)
				require.True(t, *fc.OrgMigratedFromGlobalConfig)
			},
		})
	})

	t.Run("authenticated - adding folder with existing stored config. Making sure PreferredOrg is preserved", func(t *testing.T) {
		c, loc, jsonRpcRecorder, repo, initParams := setupOrgSelectionTest(t)

		ensureInitialized(t, c, loc, initParams, nil)
		repoValidator := func(fc types.LspFolderConfig) {
			require.NotNil(t, fc.OrgSetByUser)
			require.False(t, *fc.OrgSetByUser)
			require.Nil(t, fc.PreferredOrg)
			require.NotNil(t, fc.OrgMigratedFromGlobalConfig)
			require.True(t, *fc.OrgMigratedFromGlobalConfig)
		}

		requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.LspFolderConfig){
			repo: repoValidator,
		})

		// add folder (LS has not seen before)
		fakeDirFolder, fakeDirFolderPath := addFakeDirAsWorkspaceFolder(t, loc)

		requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.LspFolderConfig){
			repo: repoValidator,
			fakeDirFolderPath: func(fc types.LspFolderConfig) {
				require.NotNil(t, fc.OrgSetByUser)
				require.False(t, *fc.OrgSetByUser, "OrgSetByUser should be false for new folder in auto mode")
				require.Nil(t, fc.PreferredOrg, "PreferredOrg should be nil for new folder in auto mode")
				require.NotNil(t, fc.OrgMigratedFromGlobalConfig)
				require.True(t, *fc.OrgMigratedFromGlobalConfig, "OrgMigratedFromGlobalConfig should be true")
			},
		})

		// remove folder
		removeWorkSpaceFolder(t, loc, fakeDirFolder)
		requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.LspFolderConfig){
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

		requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.LspFolderConfig){
			repo: repoValidator,
			fakeDirFolderPath: func(fc types.LspFolderConfig) {
				require.NotNil(t, fc.OrgSetByUser)
				require.False(t, *fc.OrgSetByUser, "OrgSetByUser must be preserved")
				require.NotNil(t, fc.PreferredOrg, "PreferredOrg must be preserved")
				require.Equal(t, "any", *fc.PreferredOrg, "PreferredOrg must be preserved")
				require.NotNil(t, fc.OrgMigratedFromGlobalConfig)
				require.True(t, *fc.OrgMigratedFromGlobalConfig, "OrgMigratedFromGlobalConfig should be true")
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

		// Use LspFolderConfig to transmit folder configuration via LSP
		initParams.InitializationOptions.Organization = globalOrg
		initParams.InitializationOptions.FolderConfigs = []types.LspFolderConfig{
			{
				FolderPath:   repo,
				PreferredOrg: &initialOrg,
			},
		}

		ensureInitialized(t, c, loc, initParams, nil)

		// Verify initial state
		requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.LspFolderConfig){
			repo: func(fc types.LspFolderConfig) {
				require.NotNil(t, fc.OrgSetByUser)
				require.True(t, *fc.OrgSetByUser)
				require.NotNil(t, fc.PreferredOrg)
				require.Equal(t, initialOrg, *fc.PreferredOrg)
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
		requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.LspFolderConfig){
			repo: func(fc types.LspFolderConfig) {
				require.NotNil(t, fc.OrgSetByUser)
				require.True(t, *fc.OrgSetByUser, "OrgSetByUser should remain true after user blanks org")
				require.Nil(t, fc.PreferredOrg, "PreferredOrg should be nil after user blanks it")
				require.NotNil(t, fc.OrgMigratedFromGlobalConfig)
				require.True(t, *fc.OrgMigratedFromGlobalConfig, "OrgMigratedFromGlobalConfig should remain true")
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

		repoValidator := func(fc types.LspFolderConfig) {
			require.NotNil(t, fc.OrgSetByUser)
			require.False(t, *fc.OrgSetByUser)
			require.Nil(t, fc.PreferredOrg)
			require.Nil(t, fc.AutoDeterminedOrg)
			require.NotNil(t, fc.OrgMigratedFromGlobalConfig)
			require.True(t, *fc.OrgMigratedFromGlobalConfig)
		}
		requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.LspFolderConfig){
			repo: repoValidator,
		})

		// add folder
		fakeDirFolder, fakeDirFolderPath := addFakeDirAsWorkspaceFolder(t, loc)
		fakeDirFolderInitialValidator := func(fc types.LspFolderConfig) {
			require.NotNil(t, fc.OrgSetByUser)
			require.False(t, *fc.OrgSetByUser)
			require.Nil(t, fc.PreferredOrg)
			require.Nil(t, fc.AutoDeterminedOrg)
			require.NotNil(t, fc.OrgMigratedFromGlobalConfig)
			require.True(t, *fc.OrgMigratedFromGlobalConfig)
		}

		requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.LspFolderConfig){
			repo:              repoValidator,
			fakeDirFolderPath: fakeDirFolderInitialValidator,
		})

		// remove folder
		removeWorkSpaceFolder(t, loc, fakeDirFolder)

		requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.LspFolderConfig){
			repo: repoValidator,
		})

		// re-add folder
		addWorkSpaceFolder(t, loc, fakeDirFolder)

		requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.LspFolderConfig){
			repo:              repoValidator,
			fakeDirFolderPath: fakeDirFolderInitialValidator,
		})

		// simulate settings change from the IDE
		sendModifiedFolderConfiguration(t, c, loc, func(folderConfigs map[types.FilePath]*types.FolderConfig) {
			folderConfigs[fakeDirFolderPath].PreferredOrg = "any"
		})

		requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.LspFolderConfig){
			repo: repoValidator,
			fakeDirFolderPath: func(fc types.LspFolderConfig) {
				require.NotNil(t, fc.OrgSetByUser)
				require.True(t, *fc.OrgSetByUser)
				require.NotNil(t, fc.PreferredOrg)
				require.Equal(t, "any", *fc.PreferredOrg)
				require.Nil(t, fc.AutoDeterminedOrg)
				require.NotNil(t, fc.OrgMigratedFromGlobalConfig)
				require.True(t, *fc.OrgMigratedFromGlobalConfig)
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

		// Use LspFolderConfig to transmit folder configuration via LSP
		initParams.InitializationOptions.Organization = globalOrg
		initParams.InitializationOptions.FolderConfigs = []types.LspFolderConfig{
			{
				FolderPath:   repo,
				PreferredOrg: &initialOrg,
			},
		}

		ensureInitialized(t, c, loc, initParams, nil)

		// Verify initial state - when OrgSetByUser=true, PreferredOrg is used
		requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.LspFolderConfig){
			repo: func(fc types.LspFolderConfig) {
				require.NotNil(t, fc.OrgSetByUser)
				require.True(t, *fc.OrgSetByUser)
				require.NotNil(t, fc.PreferredOrg)
				require.Equal(t, initialOrg, *fc.PreferredOrg)
			},
		})
		require.Equal(t, initialOrg, c.FolderOrganization(repo), "Folder should use PreferredOrg when not blank and OrgSetByUser is true")

		// User opts-in to automatic org selection for the folder
		sendModifiedFolderConfiguration(t, c, loc, func(folderConfigs map[types.FilePath]*types.FolderConfig) {
			require.Len(t, folderConfigs, 1, "should only have one folder config")
			folderConfigs[repo].OrgSetByUser = false
		})

		// Verify that OrgSetByUser is false, PreferredOrg is nil
		requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.LspFolderConfig){
			repo: func(fc types.LspFolderConfig) {
				require.NotNil(t, fc.OrgSetByUser)
				require.False(t, *fc.OrgSetByUser, "OrgSetByUser should be false after user opts-in to auto org selection")
				require.Nil(t, fc.PreferredOrg, "PreferredOrg should be nil after user opts-in to auto org selection")
				require.NotNil(t, fc.OrgMigratedFromGlobalConfig)
				require.True(t, *fc.OrgMigratedFromGlobalConfig, "OrgMigratedFromGlobalConfig should remain true")
			},
		})
		// When OrgSetByUser is false, effective org is AutoDeterminedOrg (if LDX-Sync succeeded) or global org (fallback)
		// Either way, it should NOT be the user's initialOrg anymore
		effectiveOrg := c.FolderOrganization(repo)
		assert.NotEqual(t, initialOrg, effectiveOrg, "Folder should no longer use user's preferred org after opting in to auto selection")
		assert.NotEmpty(t, effectiveOrg, "Folder should have an effective org (either auto-determined or global fallback)")
	})

	t.Run("authenticated - user opts out of automatic org selection", func(t *testing.T) {
		c, loc, jsonRpcRecorder, repo, initParams := setupOrgSelectionTest(t)
		t.Cleanup(func() {
			s, _ := storedconfig.ConfigFile(c.IdeName())
			_ = os.Remove(s)
		})

		globalOrg := "00000000-0000-0000-0000-000000000002" // Must be UUID to prevent resolution

		// Start with auto-selection enabled (no PreferredOrg set)
		initParams.InitializationOptions.Organization = globalOrg

		ensureInitialized(t, c, loc, initParams, nil)

		// Verify initial state - when OrgSetByUser=false, effective org is AutoDeterminedOrg or global fallback
		requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.LspFolderConfig){
			repo: func(fc types.LspFolderConfig) {
				require.NotNil(t, fc.OrgSetByUser)
				require.False(t, *fc.OrgSetByUser)
				require.Nil(t, fc.PreferredOrg)
			},
		})
		// Effective org should be non-empty (either AutoDeterminedOrg or global fallback)
		require.NotEmpty(t, c.FolderOrganization(repo), "Folder should have an effective org when OrgSetByUser is false")

		// User opts-out of automatic org selection for the folder
		sendModifiedFolderConfiguration(t, c, loc, func(folderConfigs map[types.FilePath]*types.FolderConfig) {
			require.Len(t, folderConfigs, 1, "should only have one folder config")
			folderConfigs[repo].OrgSetByUser = true
		})

		// Verify that OrgSetByUser is true, and the folder's effective org is the global one
		requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.LspFolderConfig){
			repo: func(fc types.LspFolderConfig) {
				require.NotNil(t, fc.OrgSetByUser)
				require.True(t, *fc.OrgSetByUser, "OrgSetByUser should be true after user opts-out of auto org selection")
				require.Nil(t, fc.PreferredOrg, "PreferredOrg should be nil")
				require.NotNil(t, fc.OrgMigratedFromGlobalConfig)
				require.True(t, *fc.OrgMigratedFromGlobalConfig, "OrgMigratedFromGlobalConfig should remain true")
			},
		})
		// When OrgSetByUser=true and PreferredOrg is empty, effective org is global org
		assert.Equal(t, globalOrg, c.FolderOrganization(repo), "Folder should use global org when OrgSetByUser is true and PreferredOrg is empty")
	})
}

func ensureInitialized(t *testing.T, c *config.Config, loc server.Local, initParams types.InitializeParams, preInitSetupFunc func(*config.Config)) {
	t.Helper()
	t.Setenv("SNYK_LOG_LEVEL", "info")
	c.SetLogLevel(zerolog.LevelInfoValue)
	c.ConfigureLogging(nil) // we don't need to send logs to the client
	gafConfig := c.Engine().GetConfiguration()
	gafConfig.Set(configuration.DEBUG, c.Logger().GetLevel() == zerolog.DebugLevel)

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
	r, err := git.PlainOpenWithOptions(string(workDir), &git.PlainOpenOptions{DetectDotGit: true})
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
	storedConfig, err := storedconfig.GetStoredConfig(c.Engine().GetConfiguration(), c.Logger(), true)
	require.NoError(t, err)
	modification(storedConfig.FolderConfigs)

	// Convert FolderConfigs to LspFolderConfigs for transmission via JSON-RPC
	// FolderConfigs has json:"-" so it won't be serialized
	// We need to explicitly include all fields (even empty ones) to ensure PATCH semantics work correctly
	var lspConfigs []types.LspFolderConfig
	for _, sfc := range storedConfig.FolderConfigs {
		lspConfig := sfc.ToLspFolderConfig(nil)
		if lspConfig != nil {
			// Explicitly set PreferredOrg even if empty (to support blanking)
			lspConfig.PreferredOrg = &sfc.PreferredOrg
			lspConfigs = append(lspConfigs, *lspConfig)
		}
	}
	settings := buildSmokeTestSettings(c)
	settings.FolderConfigs = lspConfigs
	sendConfigurationDidChange(t, loc, settings)
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
