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
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/server"
	"github.com/go-git/go-git/v5"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/benchmark"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/cli/install"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/folderconfig"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

func Test_SmokeInstanceTest(t *testing.T) {
	engine, tokenService := testutil.SmokeTestWithEngine(t, "")
	ossFile := "package.json"
	codeFile := "app.js"
	testutil.CreateDummyProgressListener(t)
	endpoint := os.Getenv("SNYK_API")
	if endpoint == "" {
		t.Setenv("SNYK_API", "https://api.snyk.io")
	}
	runSmokeTest(t, engine, tokenService, testsupport.NodejsGoof, "0336589", ossFile, codeFile, true, endpoint)
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

			engine, tokenService := testutil.SmokeTestWithEngine(t, tokenSecretName)
			runSmokeTest(t, engine, tokenService, tc.repo, tc.commit, tc.file1, tc.file2, tc.hasVulns, "")
		})
	}
}

func Test_SmokePreScanCommand(t *testing.T) {
	t.Run("executes pre scan command if configured", func(t *testing.T) {
		testsupport.NotOnWindows(t, "we can enable windows if we have the correct error message")
		engine, tokenService := testutil.SmokeTestWithEngine(t, "")
		loc, jsonRpcRecorder := setupServer(t, engine, tokenService)
		engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), false)
		engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), true)
		engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), false)
		di.Init(engine, tokenService)

		repo, err := folderconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), testsupport.PythonGoof, "", engine.GetLogger(), false)
		require.NoError(t, err)
		require.NotEmpty(t, repo)

		initParams := prepareInitParams(t, repo, engine)

		// Pass ScanCommandConfig via LspFolderConfig in initParams
		script := "/path/to/script"
		initParams.InitializationOptions.FolderConfigs = []types.LspFolderConfig{
			{
				FolderPath: repo,
				Settings: map[string]*types.ConfigSetting{
					types.SettingSnykOssEnabled: {Value: true, Changed: true},
					types.SettingScanCommandConfig: {Value: map[product.Product]types.ScanCommandConfig{
						product.ProductOpenSource: {
							PreScanOnlyReferenceFolder: false,
							PreScanCommand:             script,
						},
					}},
				},
			},
		}

		ensureInitialized(t, engine, tokenService, loc, initParams, nil)

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
		}, time.Minute, time.Millisecond, "expected scan command to fail")
	})
}

func Test_SmokeIssueCaching(t *testing.T) {
	testsupport.NotOnWindows(t, "git clone does not work here. dunno why. ") // FIXME
	t.Run("adds issues to cache correctly", func(t *testing.T) {
		engine, tokenService := testutil.SmokeTestWithEngine(t, "")
		loc, jsonRPCRecorder := setupServer(t, engine, tokenService)
		engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
		engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), true)
		engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), false)
		di.Init(engine, tokenService)

		cloneTargetDirGoof := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", "package.json", loc, engine, tokenService)
		cloneTargetDirGoofString := (string)(cloneTargetDirGoof)
		folderGoof := config.GetWorkspace(engine.GetConfiguration()).GetFolderContaining(cloneTargetDirGoof)
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
		}, maxIntegTestDuration, time.Millisecond)

		checkDiagnosticPublishingForCachingSmokeTest(t, jsonRPCRecorder, 1, 1, engine)

		jsonRPCRecorder.ClearNotifications()
		jsonRPCRecorder.ClearCallbacks()

		// now we add juice shop as second folder/repo
		if runtime.GOOS == "windows" {
			config.SetupLogging(engine, tokenService, nil)
			config.SetLogLevel(zerolog.TraceLevel.String())
		}

		folderJuice := addJuiceShopAsWorkspaceFolder(t, loc, engine)

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
		require.Eventually(t, func() bool {
			return folderGoof != nil && folderGoof.IsScanned() && folderJuice != nil && folderJuice.IsScanned()
		}, maxIntegTestDuration, time.Millisecond, "both folders should complete scanning")

		ossIssuesForFileSecondScan := folderGoofIssueProvider.IssuesForFile(types.FilePath(filepath.Join(cloneTargetDirGoofString, "package.json")))
		require.Equal(t, len(ossIssuesForFile), len(ossIssuesForFileSecondScan))

		codeIssuesForFileSecondScan := folderGoofIssueProvider.IssuesForFile(types.FilePath(filepath.Join(cloneTargetDirGoofString, "app.js")))
		require.Equal(t, len(codeIssuesForFile), len(codeIssuesForFileSecondScan))

		// OSS: empty, package.json goof, package.json juice = 2
		// Code: app.js = 2
		checkDiagnosticPublishingForCachingSmokeTest(t, jsonRPCRecorder, 2, 2, engine)
		checkScanResultsPublishingForCachingSmokeTest(t, jsonRPCRecorder, folderJuice, folderGoof, engine)
		waitForDeltaScan(t, di.ScanStateAggregator())
	})

	t.Run("clears issues from cache correctly", func(t *testing.T) {
		engine, tokenService := testutil.SmokeTestWithEngine(t, "")
		loc, jsonRPCRecorder := setupServer(t, engine, tokenService)
		engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
		engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), true)
		engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), false)
		di.Init(engine, tokenService)

		cloneTargetDirGoof := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", "package.json", loc, engine, tokenService)
		folderGoof := config.GetWorkspace(engine.GetConfiguration()).GetFolderContaining(cloneTargetDirGoof)
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
		checkDiagnosticPublishingForCachingSmokeTest(t, jsonRPCRecorder, 1, 1, engine)
		require.Greater(t, len(folderGoofIssueProvider.Issues()), 0)
		jsonRPCRecorder.ClearNotifications()
		jsonRPCRecorder.ClearCallbacks()

		folderGoof.Clear()

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
	engine, tokenService := testutil.SmokeTestWithEngine(t, "")
	repoTempDir := types.FilePath(testutil.TempDirWithRetry(t))
	loc, _ := setupServer(t, engine, tokenService)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), false)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), false)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), true)
	di.Init(engine, tokenService)

	cloneTargetDirGoof := setupRepoAndInitializeInDir(t, repoTempDir, testsupport.NodejsGoof, "0336589", "package.json", loc, engine, tokenService)
	folderGoof := config.GetWorkspace(engine.GetConfiguration()).GetFolderContaining(cloneTargetDirGoof)

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
	engine, tokenService := testutil.SmokeTestWithEngine(t, tokenSecretNameForRiskScore)
	loc, jsonRpcRecorder := setupServer(t, engine, tokenService)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), false)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), true)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), false)
	di.Init(engine, tokenService)

	repo, err := folderconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), testsupport.CGoof, "", engine.GetLogger(), false)
	require.NoError(t, err)
	require.NotEmpty(t, repo)

	initParams := prepareInitParams(t, repo, engine)

	initParams.InitializationOptions.FolderConfigs = []types.LspFolderConfig{
		{
			FolderPath: repo,
			Settings: map[string]*types.ConfigSetting{
				types.SettingAdditionalParameters: {Value: []string{"--unmanaged"}},
			},
		},
	}

	ensureInitialized(t, engine, tokenService, loc, initParams, func(eng workflow.Engine) {
		fc := &types.FolderConfig{
			FolderPath:     repo,
			ConfigResolver: testutil.DefaultConfigResolver(eng),
		}
		fc.ConfigResolver = types.NewMinimalConfigResolver(eng.GetConfiguration())
		engineConfig := eng.GetConfiguration()
		fp := string(types.PathKey(repo))
		engineConfig.Set(configresolver.UserFolderKey(fp, types.SettingAdditionalParameters), &configresolver.LocalConfigField{Value: []string{"--unmanaged"}, Changed: true})
		fc.SetFeatureFlag(featureflag.UseExperimentalRiskScoreInCLI, true) // The one we actually use.
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
	}, maxIntegTestDuration, time.Millisecond, "expected OSS scan to succeed via legacy routing with --unmanaged despite risk score FF")
}

func addJuiceShopAsWorkspaceFolder(t *testing.T, loc server.Local, engine workflow.Engine) types.Folder {
	t.Helper()
	cloneTargetDirJuice, err := folderconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), "https://github.com/juice-shop/juice-shop", "bc9cef127", engine.GetLogger(), false)
	require.NoError(t, err)

	juiceLspWorkspaceFolder := types.WorkspaceFolder{Uri: uri.PathToUri(cloneTargetDirJuice), Name: "juicy-mac-juice-face"}
	addWorkSpaceFolder(t, loc, juiceLspWorkspaceFolder)

	folderJuice := config.GetWorkspace(engine.GetConfiguration()).GetFolderContaining(cloneTargetDirJuice)
	require.NotNil(t, folderJuice)
	return folderJuice
}

// check that $/snyk.scan messages are sent
// check that they only contain issues that belong to the scanned folder
func checkScanResultsPublishingForCachingSmokeTest(t *testing.T, jsonRPCRecorder *testsupport.JsonRPCRecorder, folderJuice types.Folder, folderGoof types.Folder, engine workflow.Engine) {
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
		engine.GetLogger().Debug().Bool("scanResultCodeGoofFound", scanResultCodeGoofFound).Send()
		engine.GetLogger().Debug().Bool("scanResultCodeJuiceShopFound", scanResultCodeJuiceShopFound).Send()
		engine.GetLogger().Debug().Bool("onlyIssuesForGoof", onlyIssuesForGoof).Send()
		engine.GetLogger().Debug().Bool("onlyIssuesForJuiceShop", onlyIssuesForJuiceShop).Send()
		return scanResultCodeGoofFound &&
			scanResultCodeJuiceShopFound &&
			onlyIssuesForGoof &&
			onlyIssuesForJuiceShop
	}, time.Second*5, time.Millisecond)
}

// check that notifications are sent
func checkDiagnosticPublishingForCachingSmokeTest(
	t *testing.T,
	jsonRPCRecorder *testsupport.JsonRPCRecorder,
	expectedCode, expectedOSS int,
	engine workflow.Engine,
) {
	t.Helper()
	require.Eventually(t, func() bool {
		notifications := jsonRPCRecorder.FindNotificationsByMethod("textDocument/publishDiagnostics")
		appJsCount := 0
		packageJsonCount := 0

		for _, notification := range notifications {
			var param types.PublishDiagnosticsParams
			err := json.Unmarshal([]byte(notification.ParamString()), &param)
			if err != nil {
				engine.GetLogger().Warn().Err(err).Msg("failed to unmarshal publishDiagnostics notification")
				continue
			}
			if filepath.Base(string(uri.PathFromUri(param.URI))) == "package.json" {
				packageJsonCount++
			}
			if filepath.Base(string(uri.PathFromUri(param.URI))) == "app.js" {
				appJsCount++
			}
		}
		engine.GetLogger().Debug().Int("appJsCount", appJsCount).Send()
		engine.GetLogger().Debug().Int("packageJsonCount", packageJsonCount).Send()
		result := appJsCount >= expectedCode &&
			packageJsonCount >= expectedOSS

		return result
	}, time.Second*600, time.Millisecond)
}

func runSmokeTest(t *testing.T, engine workflow.Engine, tokenService *config.TokenServiceImpl, repo string, commit string, file1 string, file2 string, hasVulns bool, endpoint string) {
	t.Helper()
	if endpoint != "" && endpoint != "/v1" {
		t.Setenv("SNYK_API", endpoint)
	}
	// Allocate temp dir BEFORE setupServer so t.Cleanup LIFO order ensures
	// the server shuts down before the temp dir is removed (fixes Windows file locking).
	// TempDirWithRetry adds retry logic for os.RemoveAll to handle lingering file locks.
	repoTempDir := types.FilePath(testutil.TempDirWithRetry(t))
	loc, jsonRPCRecorder := setupServer(t, engine, tokenService)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), true)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), true)
	cleanupChannels()
	di.Init(engine, tokenService)

	cloneTargetDir := setupRepoAndInitializeInDir(t, repoTempDir, repo, commit, file1, loc, engine, tokenService)
	cloneTargetDirString := (string)(cloneTargetDir)

	waitForScan(t, cloneTargetDirString, engine)

	assert.Eventuallyf(t, func() bool {
		notifications := jsonRPCRecorder.FindNotificationsByMethod("$/snyk.configuration")
		return receivedFolderConfigNotification(t, notifications, cloneTargetDir)
	}, time.Second*5, time.Millisecond, "did not receive folder configs in $/snyk.configuration")

	var testPath types.FilePath

	// ------------------------------------------------------
	// check snyk open source diagnostics (file1)
	// ------------------------------------------------------
	if file1 != "" {
		testPath = types.FilePath(filepath.Join(cloneTargetDirString, file1))
		waitForNetwork(engine)
		textDocumentDidSave(t, &loc, testPath)
		// serve diagnostics from file scan
		require.Eventually(t, checkForPublishedDiagnostics(t, engine, testPath, -1, jsonRPCRecorder), maxIntegTestDuration, time.Millisecond,
			"Diagnostics not published for file %s", file1)
	}

	jsonRPCRecorder.ClearNotifications()

	// ------------------------------------------------------
	// check snyk code diagnostics (file2)
	// ------------------------------------------------------
	testPath = types.FilePath(filepath.Join(cloneTargetDirString, file2))
	waitForNetwork(engine)
	textDocumentDidSave(t, &loc, testPath)
	// Check scan completed successfully
	checkForScanParams(t, jsonRPCRecorder, cloneTargetDirString, product.ProductCode)
	require.Eventually(t, checkForPublishedDiagnostics(t, engine, testPath, -1, jsonRPCRecorder), maxIntegTestDuration, time.Millisecond,
		"Diagnostics not published for file %s", file2)
	issueList := getIssueListFromPublishDiagnosticsNotification(t, jsonRPCRecorder, product.ProductCode, cloneTargetDir)

	// check for autofix diff on mt-us
	if hasVulns {
		checkAutofixDiffs(t, engine, issueList, loc, jsonRPCRecorder)
	}

	checkFeatureFlagStatus(t, engine, &loc)

	// check we only have one quickfix action in open source per line
	if types.GetGlobalBool(engine.GetConfiguration(), types.SettingSnykOssEnabled) {
		checkOnlyOneQuickFixCodeAction(t, jsonRPCRecorder, cloneTargetDirString, loc)
		checkOnlyOneCodeLens(t, jsonRPCRecorder, cloneTargetDirString, loc)
	}
	waitForDeltaScan(t, di.ScanStateAggregator())
}

func receivedFolderConfigNotification(t *testing.T, notifications []jrpc2.Request, cloneTargetDir types.FilePath) bool {
	t.Helper()
	for _, notification := range notifications {
		var configParam types.LspConfigurationParam
		err := notification.UnmarshalParams(&configParam)
		require.NoError(t, err)

		for _, folderConfig := range configParam.FolderConfigs {
			if folderConfig.Settings[types.SettingBaseBranch] == nil ||
				folderConfig.Settings[types.SettingLocalBranches] == nil {
				return false
			}
			assert.NotEmpty(t, folderConfig.Settings[types.SettingBaseBranch].Value)
			assert.NotEmpty(t, folderConfig.Settings[types.SettingLocalBranches].Value)

			normalizedCloneTargetDir := types.PathKey(cloneTargetDir)
			if folderConfig.FolderPath == normalizedCloneTargetDir {
				return true
			}
		}
	}
	return false
}

var (
	// now register it with the engine
	depGraphWorkFlowID = workflow.NewWorkflowIdentifier("depgraph")
	depGraphDataID     = workflow.NewTypeIdentifier(depGraphWorkFlowID, "depgraph")
)

// substituteDepGraphFlow generate depgraph. necessary, as depgraph workflow needs legacycli workflow which
// does not work without the TypeScript CLI
func substituteDepGraphFlow(t *testing.T, engine workflow.Engine, cloneTargetDirString, displayTargetFile string) {
	t.Helper()

	flagset := workflow.ConfigurationOptionsFromFlagset(pflag.NewFlagSet("", pflag.ContinueOnError))
	callback := func(invocation workflow.InvocationContext, workflowInputData []workflow.Data) ([]workflow.Data, error) {
		cmd := exec.CommandContext(t.Context(), types.GetGlobalString(engine.GetConfiguration(), types.SettingCliPath), "depgraph")
		cmd.Dir = cloneTargetDirString
		cmd.Env = os.Environ()
		depGraphJson, err := cmd.Output()
		if err != nil {
			// Return error instead of t.Fatalf: this callback runs in a background scanner goroutine
			// that can outlive the test. Since Go 1.24, calling t.Fatal from such a goroutine panics
			// the entire test binary with "Fail in goroutine after TestX has completed".
			return nil, fmt.Errorf("couldn't retrieve the depgraph: %w", err)
		}
		depGraphData := workflow.NewData(depGraphDataID, "application/json", depGraphJson)
		normalisedTargetFile := strings.TrimSpace(displayTargetFile)
		depGraphData.SetMetaData("Content-Location", normalisedTargetFile)
		depGraphData.SetMetaData("normalisedTargetFile", normalisedTargetFile) // Required for cli-extension-os-flow

		return []workflow.Data{depGraphData}, nil
	}

	_, err := engine.Register(depGraphWorkFlowID, flagset, callback)
	require.NoError(t, err)
}

func waitForNetwork(engine workflow.Engine) {
	for engine.GetConfiguration().GetBool(types.SettingOffline) {
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

	assert.Eventually(t, func() bool {
		issueList := getIssueListFromPublishDiagnosticsNotification(t, jsonRPCRecorder, product.ProductOpenSource, types.FilePath(cloneTargetDir))
		return verifyQuickFixActions(t, issueList, loc)
	}, 2*time.Minute, time.Millisecond, "expected quickfix code actions with correct singular/plural issue counts")
}

func verifyQuickFixActions(t *testing.T, issueList []types.ScanIssue, loc server.Local) bool {
	t.Helper()
	found, errorhandler, tap := false, false, false
	for _, issue := range issueList {
		violated, ef, tf := verifyQuickFixForIssue(t, issue, loc)
		if violated {
			// A correctness rule was violated (e.g. wrong title format or >1 upgrade action).
			return false
		}
		found = found || ef || tf
		errorhandler = errorhandler || ef
		tap = tap || tf
	}
	return found && errorhandler && tap
}

// verifyQuickFixForIssue checks code actions for a single issue.
// violated=true means a correctness rule was broken and the test should fail.
// Transient errors (network, unmarshal) are treated as a soft skip (violated=false, no hits).
func verifyQuickFixForIssue(t *testing.T, issue types.ScanIssue, loc server.Local) (violated, errorhandlerHit, tapHit bool) {
	t.Helper()
	params := sglsp.CodeActionParams{
		TextDocument: sglsp.TextDocumentIdentifier{URI: uri.PathToUri(issue.FilePath)},
		Range:        issue.Range,
	}
	response, err := loc.Client.Call(t.Context(), "textDocument/codeAction", params)
	if err != nil {
		// Transient: skip this issue without failing.
		return false, false, false
	}
	var actions []types.LSPCodeAction
	if err = response.UnmarshalResult(&actions); err != nil {
		// Transient: skip this issue without failing.
		return false, false, false
	}

	quickFixCount := 0
	for _, action := range actions {
		if !strings.Contains(action.Title, "Upgrade to") {
			continue
		}
		quickFixCount++
		if issue.Range.Start.Line == 25 {
			if !strings.Contains(action.Title, "and fix 1 issue") || strings.Contains(action.Title, "and fix 1 issues") {
				return true, false, false
			}
			errorhandlerHit = true
		}
		if issue.Range.Start.Line == 46 {
			if !strings.Contains(action.Title, "and fix ") || !strings.Contains(action.Title, " issues") {
				return true, false, false
			}
			tapHit = true
		}
	}
	if quickFixCount > 1 {
		// Correctness violation: more than one "Upgrade to" action for a single issue.
		return true, false, false
	}
	return false, errorhandlerHit, tapHit
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

func waitForScan(t *testing.T, cloneTargetDir string, engine workflow.Engine) {
	t.Helper()
	waitUntilWorkspaceFolderScanned(t, cloneTargetDir, engine, maxIntegTestDuration, false)
}

// waitUntilWorkspaceFolderScanned waits until the workspace folder for cloneTargetDir is scanned.
// If hardFail is true, uses require.Eventually (stops the test); otherwise assert.Eventually (legacy smoke behavior).
func waitUntilWorkspaceFolderScanned(t *testing.T, cloneTargetDir string, engine workflow.Engine, maxWait time.Duration, hardFail bool) {
	t.Helper()
	cond := func() bool {
		f := config.GetWorkspace(engine.GetConfiguration()).GetFolderContaining(types.FilePath(cloneTargetDir))
		return f != nil && f.IsScanned()
	}
	if hardFail {
		require.Eventually(t, cond, maxWait, time.Millisecond,
			"workspace folder did not reach scanned state within %s", maxWait)
	} else {
		assert.Eventually(t, cond, maxWait, time.Millisecond)
	}
}

func waitForDeltaScan(t *testing.T, agg scanstates.Aggregator) {
	t.Helper()
	waitUntilDeltaScanComplete(t, agg, maxIntegTestDuration, false)
}

func waitUntilDeltaScanComplete(t *testing.T, agg scanstates.Aggregator, maxWait time.Duration, hardFail bool) {
	t.Helper()
	cond := func() bool {
		return agg.StateSnapshot().AllScansFinishedWorkingDirectory && agg.StateSnapshot().AllScansFinishedReference
	}
	if hardFail {
		require.Eventually(t, cond, maxWait, time.Millisecond,
			"delta/reference scans did not finish within %s", maxWait)
	} else {
		assert.Eventually(t, cond, maxWait, time.Millisecond)
	}
}

func checkForScanParams(t *testing.T, jsonRPCRecorder *testsupport.JsonRPCRecorder, cloneTargetDir string, p product.Product) {
	t.Helper()
	checkForScanParamsWithMaxWait(t, jsonRPCRecorder, cloneTargetDir, p, 5*time.Minute)
}

func checkForScanParamsWithMaxWait(t *testing.T, jsonRPCRecorder *testsupport.JsonRPCRecorder, cloneTargetDir string, p product.Product, maxWait time.Duration) {
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
	}, maxWait, time.Millisecond,
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
	}, maxIntegTestDuration, time.Millisecond)

	for _, issue := range issueList {
		if issue.IsNew {
			issuePath := filepath.Clean(string(issue.FilePath))
			assert.Equal(t, expectedNewIssuePath, issuePath, "new issue should only be from the expected file: %s", string(issue.FilePath))
		}
	}
}

func checkAutofixDiffs(t *testing.T, engine workflow.Engine, issueList []types.ScanIssue, loc server.Local, recorder *testsupport.JsonRPCRecorder) {
	t.Helper()
	if isNotStandardRegion(engine) {
		return
	}
	assert.Greater(t, len(issueList), 0)
	for _, issue := range issueList {
		codeIssueData, ok := issue.AdditionalData.(map[string]interface{})
		if !ok || codeIssueData["hasAIFix"] == false || codeIssueData["rule"] != "UseCsurfForExpress" {
			continue
		}
		waitForNetwork(engine)
		_, err := loc.Client.Call(t.Context(), "workspace/executeCommand", sglsp.ExecuteCommandParams{
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
		}, 30*time.Second, time.Millisecond, "failed to get autofix diffs")
		break
	}
}

func isNotStandardRegion(engine workflow.Engine) bool {
	ep := types.GetGlobalString(engine.GetConfiguration(), types.SettingApiEndpoint)
	return ep != "https://api.snyk.io" && ep != ""
}

func setupRepoAndInitialize(t *testing.T, repo string, commit string, manifestFile string, loc server.Local, engine workflow.Engine, tokenService *config.TokenServiceImpl) types.FilePath {
	t.Helper()
	return setupRepoAndInitializeInDir(t, types.FilePath(testutil.TempDirWithRetry(t)), repo, commit, manifestFile, loc, engine, tokenService)
}

// setupRepoAndInitializeInDir clones a repo into the given rootDir and initializes the server with it.
// Use this variant when the temp dir must be allocated before setupServer to ensure correct t.Cleanup
// LIFO ordering on Windows (server closes before temp dir removal).
func setupRepoAndInitializeInDir(t *testing.T, rootDir types.FilePath, repo string, commit string, manifestFile string, loc server.Local, engine workflow.Engine, tokenService *config.TokenServiceImpl) types.FilePath {
	t.Helper()

	// Wait for scans to complete before temp dir removal (LIFO order).
	// This prevents Windows file locking issues where HTTP requests are still in flight during cleanup.
	t.Cleanup(func() {
		waitForAllScansToComplete(t, di.ScanStateAggregator())
	})

	cloneTargetDir, err := folderconfig.SetupCustomTestRepo(t, rootDir, repo, commit, engine.GetLogger(), false)
	if err != nil {
		t.Fatal(err, "Couldn't setup test repo")
	}

	initParams := prepareInitParams(t, cloneTargetDir, engine)
	ensureInitialized(t, engine, tokenService, loc, initParams, nil)
	return cloneTargetDir
}

// buildSmokeTestSettings creates a complete DidChangeConfigurationParams from config.
// This ensures all critical fields (token, endpoint, etc.) are preserved.
func buildSmokeTestSettings(engine workflow.Engine) types.DidChangeConfigurationParams {
	cfg := engine.GetConfiguration()
	return types.DidChangeConfigurationParams{
		Settings: types.LspConfigurationParam{
			Settings: map[string]*types.ConfigSetting{
				types.SettingApiEndpoint:                  {Value: types.GetGlobalString(cfg, types.SettingApiEndpoint), Changed: true},
				types.SettingToken:                        {Value: config.GetToken(cfg), Changed: true},
				types.SettingOrganization:                 {Value: cfg.GetString(configuration.ORGANIZATION), Changed: true},
				types.SettingTrustEnabled:                 {Value: false, Changed: true},
				types.SettingSeverityFilterCritical:       {Value: true, Changed: true},
				types.SettingSeverityFilterHigh:           {Value: true, Changed: true},
				types.SettingSeverityFilterMedium:         {Value: true, Changed: true},
				types.SettingSeverityFilterLow:            {Value: true, Changed: true},
				types.SettingAuthenticationMethod:         {Value: string(config.GetAuthenticationMethodFromConfig(cfg)), Changed: true},
				types.SettingAutomaticAuthentication:      {Value: false, Changed: true},
				types.SettingScanNetNew:                   {Value: types.GetGlobalBool(cfg, types.SettingScanNetNew), Changed: true},
				types.SettingSnykCodeEnabled:              {Value: types.GetGlobalBool(cfg, types.SettingSnykCodeEnabled), Changed: true},
				types.SettingSnykIacEnabled:               {Value: types.GetGlobalBool(cfg, types.SettingSnykIacEnabled), Changed: true},
				types.SettingSnykOssEnabled:               {Value: types.GetGlobalBool(cfg, types.SettingSnykOssEnabled), Changed: true},
				types.SettingCliPath:                      {Value: types.GetGlobalString(cfg, types.SettingCliPath), Changed: true},
				types.SettingEnableSnykOssQuickFixActions: {Value: true, Changed: true},
				types.SettingEnableSnykLearnCodeActions:   {Value: true, Changed: true},
			},
		},
	}
}

// waitForAllScansToComplete waits for all in-progress scans to finish.
// This is used in cleanup to ensure file handles are released before temp directory removal.
func waitForAllScansToComplete(t *testing.T, agg scanstates.Aggregator) {
	t.Helper()
	// Wait for both working directory and reference scans to complete.
	// Uses maxIntegTestDuration to handle tests with many concurrent folders (e.g. Test_Concurrent_CLI_Runs)
	// where reference scans may still be running after working directory scans finish.
	// Polls every second to reduce lock contention on the ScanStateAggregator mutex during
	// long-running concurrent scan scenarios.
	_ = assert.Eventually(t, func() bool {
		snapshot := agg.StateSnapshot()
		return snapshot.AllScansFinishedWorkingDirectory && snapshot.AllScansFinishedReference
	}, maxIntegTestDuration, time.Second)
}

func prepareInitParams(t *testing.T, cloneTargetDir types.FilePath, engine workflow.Engine) types.InitializeParams {
	t.Helper()

	folder := types.WorkspaceFolder{
		Name: "Test Repo",
		Uri:  uri.PathToUri(cloneTargetDir),
	}

	setUniqueCliPath(t, engine)

	cfg := engine.GetConfiguration()
	clientParams := types.InitializeParams{
		WorkspaceFolders: []types.WorkspaceFolder{folder},
		InitializationOptions: types.InitializationOptions{
			Settings: map[string]*types.ConfigSetting{
				types.SettingApiEndpoint:                  {Value: os.Getenv("SNYK_API"), Changed: true},
				types.SettingToken:                        {Value: config.GetToken(cfg), Changed: true},
				types.SettingOrganization:                 {Value: cfg.GetString(configuration.ORGANIZATION), Changed: true},
				types.SettingTrustEnabled:                 {Value: false, Changed: true},
				types.SettingSeverityFilterCritical:       {Value: true, Changed: true},
				types.SettingSeverityFilterHigh:           {Value: true, Changed: true},
				types.SettingSeverityFilterMedium:         {Value: true, Changed: true},
				types.SettingSeverityFilterLow:            {Value: true, Changed: true},
				types.SettingAuthenticationMethod:         {Value: string(types.TokenAuthentication), Changed: true},
				types.SettingAutomaticAuthentication:      {Value: false, Changed: true},
				types.SettingScanNetNew:                   {Value: types.GetGlobalBool(cfg, types.SettingScanNetNew), Changed: true},
				types.SettingSnykCodeEnabled:              {Value: types.GetGlobalBool(cfg, types.SettingSnykCodeEnabled), Changed: true},
				types.SettingSnykIacEnabled:               {Value: types.GetGlobalBool(cfg, types.SettingSnykIacEnabled), Changed: true},
				types.SettingSnykOssEnabled:               {Value: types.GetGlobalBool(cfg, types.SettingSnykOssEnabled), Changed: true},
				types.SettingCliPath:                      {Value: types.GetGlobalString(cfg, types.SettingCliPath), Changed: true},
				types.SettingEnableSnykOssQuickFixActions: {Value: true, Changed: true},
				types.SettingEnableSnykLearnCodeActions:   {Value: true, Changed: true},
			},
		},
	}
	return clientParams
}

func setUniqueCliPath(t *testing.T, engine workflow.Engine) {
	t.Helper()
	discovery := install.Discovery{}
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingCliPath), filepath.Join(t.TempDir(), discovery.ExecutableName(false)))
}

func checkFeatureFlagStatus(t *testing.T, engine workflow.Engine, loc *server.Local) {
	t.Helper()
	// only check on mt-us
	if isNotStandardRegion(engine) {
		return
	}
	waitForNetwork(engine)
	call, err := loc.Client.Call(t.Context(), "workspace/executeCommand", sglsp.ExecuteCommandParams{
		Command:   types.GetFeatureFlagStatus,
		Arguments: []any{"bitbucketConnectApp"},
	})

	assert.NoError(t, err)

	if err := call.Error(); err != nil {
		engine.GetLogger().Error().Err(err).Msg("FeatureFlagStatus Command failed")
	}

	engine.GetLogger().Debug().Str("FeatureFlagStatus", call.ResultString()).Msg("Command result")

	var result map[string]any
	if err := json.Unmarshal([]byte(call.ResultString()), &result); err != nil {
		t.Fatal("Failed to parse the command result", err)
	}

	ok, _ := result["ok"].(bool)
	assert.Truef(t, ok, "expected feature flag bitbucketConnectApp to be enabled")
}

func Test_SmokeSnykCodeFileScan(t *testing.T) {
	engine, tokenService := testutil.SmokeTestWithEngine(t, "")
	repoTempDir := types.FilePath(testutil.TempDirWithRetry(t))
	loc, jsonRPCRecorder := setupServer(t, engine, tokenService)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	cleanupChannels()
	di.Init(engine, tokenService)

	cloneTargetDir := setupRepoAndInitializeInDir(t, repoTempDir, testsupport.NodejsGoof, "0336589", "package.json", loc, engine, tokenService)
	cloneTargetDirString := string(cloneTargetDir)

	testPath := types.FilePath(filepath.Join(cloneTargetDirString, "app.js"))

	_ = textDocumentDidSave(t, &loc, testPath)

	assert.Eventually(t, checkForPublishedDiagnostics(t, engine, testPath, -1, jsonRPCRecorder), 2*time.Minute, time.Millisecond)
	waitForDeltaScan(t, di.ScanStateAggregator())
}

func Test_SmokeUncFilePath(t *testing.T) {
	engine, tokenService := testutil.IntegTestWithEngine(t)
	testsupport.OnlyOnWindows(t, "testing windows UNC file paths")
	loc, jsonRPCRecorder := setupServer(t, engine, tokenService)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), false)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), false)
	testutil.EnableSastAndAutoFix(engine)
	cleanupChannels()
	di.Init(engine, tokenService)

	cloneTargetDir, err := folderconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), testsupport.NodejsGoof, "0336589", engine.GetLogger(), false)
	if err != nil {
		t.Fatal(err, "Couldn't setup test repo")
	}

	uncPath := "\\\\localhost\\" + strings.Replace(string(cloneTargetDir), ":", "$", 1)
	_, err = os.Stat(uncPath)
	assert.NoError(t, err)

	initializeParams := prepareInitParams(t, types.FilePath(uncPath), engine)
	ensureInitialized(t, engine, tokenService, loc, initializeParams, nil)
	waitForScan(t, uncPath, engine)
	testPath := types.FilePath(filepath.Join(uncPath, "app.js"))

	assert.Eventually(t, checkForPublishedDiagnostics(t, engine, testPath, -1, jsonRPCRecorder), maxIntegTestDuration, time.Millisecond)
	waitForDeltaScan(t, di.ScanStateAggregator())
}

func Test_SmokeSnykCodeDelta_NewVulns(t *testing.T) {
	engine, tokenService := testutil.SmokeTestWithEngine(t, "")
	loc, jsonRPCRecorder := setupServer(t, engine, tokenService)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingScanNetNew), true)
	testutil.EnableSastAndAutoFix(engine)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), false)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), false)
	cleanupChannels()
	di.Init(engine, tokenService)
	scanAggregator := di.ScanStateAggregator()
	fileWithNewVulns := "vulns.js"
	cloneTargetDir, err := folderconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), testsupport.NodejsGoof, "0336589", engine.GetLogger(), false)
	cloneTargetDirString := string(cloneTargetDir)
	assert.NoError(t, err)

	sourceContent, err := os.ReadFile(filepath.Join(cloneTargetDirString, "app.js"))
	require.NoError(t, err)

	newFileInCurrentDir(t, cloneTargetDirString, fileWithNewVulns, string(sourceContent))

	initParams := prepareInitParams(t, cloneTargetDir, engine)

	ensureInitialized(t, engine, tokenService, loc, initParams, nil)

	waitForScan(t, cloneTargetDirString, engine)

	waitForDeltaScan(t, scanAggregator)
	checkForScanParams(t, jsonRPCRecorder, cloneTargetDirString, product.ProductCode)
	newVulnFilePath := filepath.Clean(filepath.Join(cloneTargetDirString, fileWithNewVulns))
	assertDeltaNewIssuesInFile(t, jsonRPCRecorder, cloneTargetDir, newVulnFilePath)
}

func Test_SmokeSnykCodeDelta_NoNewIssuesFound(t *testing.T) {
	engine, tokenService := testutil.SmokeTestWithEngine(t, "")
	loc, jsonRPCRecorder := setupServer(t, engine, tokenService)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingScanNetNew), true)
	cleanupChannels()
	di.Init(engine, tokenService)
	scanAggregator := di.ScanStateAggregator()

	fileWithNewVulns := "vulns.js"
	cloneTargetDir, err := folderconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), "https://github.com/snyk-labs/nodejs-goof", "0336589", engine.GetLogger(), false)
	assert.NoError(t, err)

	cloneTargetDirString := string(cloneTargetDir)

	newFileInCurrentDir(t, cloneTargetDirString, fileWithNewVulns, "// no problems")

	initParams := prepareInitParams(t, cloneTargetDir, engine)

	ensureInitialized(t, engine, tokenService, loc, initParams, nil)

	waitForScan(t, cloneTargetDirString, engine)

	waitForDeltaScan(t, scanAggregator)
	checkForScanParams(t, jsonRPCRecorder, cloneTargetDirString, product.ProductCode)
	issueList := getIssueListFromPublishDiagnosticsNotification(t, jsonRPCRecorder, product.ProductCode, cloneTargetDir)

	assert.Equal(t, 0, len(issueList), "no issues expected, as delta and no new change")
}

func Test_SmokeSnykCodeDelta_NoNewIssuesFound_JavaGoof(t *testing.T) {
	engine, tokenService := testutil.SmokeTestWithEngine(t, "")
	loc, jsonRPCRecorder := setupServer(t, engine, tokenService)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingScanNetNew), true)
	cleanupChannels()
	di.Init(engine, tokenService)
	scanAggregator := di.ScanStateAggregator()

	cloneTargetDir, err := folderconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), "https://github.com/snyk-labs/java-goof", "f5719ae", engine.GetLogger(), false)
	assert.NoError(t, err)

	cloneTargetDirString := string(cloneTargetDir)

	initParams := prepareInitParams(t, cloneTargetDir, engine)

	ensureInitialized(t, engine, tokenService, loc, initParams, nil)

	waitForScan(t, cloneTargetDirString, engine)

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
	engine, tokenService := testutil.SmokeTestWithEngine(t, "")
	loc, jsonRPCRecorder := setupServer(t, engine, tokenService)
	testutil.OnlyEnableCode(t, engine)
	testutil.EnableSastAndAutoFix(engine)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingScanNetNew), true)
	cleanupChannels()
	di.Init(engine, tokenService)
	scanAggregator := di.ScanStateAggregator()

	// Clone a repo — this is the git root
	gitRoot, err := folderconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), testsupport.NodejsGoof, "0336589", engine.GetLogger(), false)
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
	initParams := prepareInitParams(t, subfolderPath, engine)

	ensureInitialized(t, engine, tokenService, loc, initParams, nil)

	waitForScan(t, subfolder, engine)
	waitForDeltaScan(t, scanAggregator)

	// Verify scan completed successfully — before the fix, this would fail with
	// "repository not found" or "must specify reference for delta scans"
	checkForScanParams(t, jsonRPCRecorder, subfolder, product.ProductCode)

	newVulnFilePath := filepath.Clean(filepath.Join(subfolder, "vulns.js"))
	assertDeltaNewIssuesInFile(t, jsonRPCRecorder, subfolderPath, newVulnFilePath)
}

func Test_SmokeScanUnmanaged(t *testing.T) {
	testsupport.NotOnWindows(t, "git clone does not work here. dunno why. ") // FIXME
	engine, tokenService := testutil.SmokeTestWithEngine(t, "")
	loc, jsonRPCRecorder := setupServer(t, engine, tokenService)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), false)
	cleanupChannels()
	di.Init(engine, tokenService)

	cloneTargetDir, err := folderconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), testsupport.CppGoof, "259ea516a4ec", engine.GetLogger(), false)
	cloneTargetDirString := string(cloneTargetDir)
	if err != nil {
		t.Fatal(err, "Couldn't setup test repo")
	}

	initParams := prepareInitParams(t, cloneTargetDir, engine)

	// AdditionalParameters is internal-only (not transmitted via LSP), so we must persist it
	// directly to storage before initialization triggers the scan.
	engineConfig := engine.GetConfiguration()
	fp := string(types.PathKey(cloneTargetDir))
	engineConfig.Set(configresolver.UserFolderKey(fp, types.SettingAdditionalParameters), &configresolver.LocalConfigField{Value: []string{"--unmanaged"}, Changed: true})

	ensureInitialized(t, engine, tokenService, loc, initParams, nil)

	waitForScan(t, cloneTargetDirString, engine)
	checkForScanParams(t, jsonRPCRecorder, cloneTargetDirString, product.ProductOpenSource)

	issueList := getIssueListFromPublishDiagnosticsNotification(t, jsonRPCRecorder, product.ProductOpenSource, cloneTargetDir)

	assert.Greater(t, len(issueList), 10, "More than 10 unmanaged issues expected")
}

// requireLspFolderConfigNotification checks that a $/snyk.configuration notification
// contains the expected folder configs. validators is a map of folder path to validation function.
// clearNotifications controls whether to clear notifications after validation (default: true).
func requireLspFolderConfigNotification(t *testing.T, jsonRpcRecorder *testsupport.JsonRPCRecorder, validators map[types.FilePath]func(types.LspFolderConfig), clearNotifications ...bool) {
	t.Helper()

	var notifications []jrpc2.Request
	var lastConfigParam types.LspConfigurationParam
	require.Eventuallyf(t, func() bool {
		notifications = jsonRpcRecorder.FindNotificationsByMethod("$/snyk.configuration")
		for i := len(notifications) - 1; i >= 0; i-- {
			var param types.LspConfigurationParam
			if err := notifications[i].UnmarshalParams(&param); err == nil && len(param.FolderConfigs) > 0 {
				lastConfigParam = param
				return true
			}
		}
		return false
	}, 10*time.Second, time.Millisecond, "No $/snyk.configuration notification with folder configs")

	validationsCount := 0
	for _, folderConfig := range lastConfigParam.FolderConfigs {
		validator, ok := validators[folderConfig.FolderPath]
		if ok {
			validationsCount++
		}
		if validator != nil {
			validator(folderConfig)
		}
	}

	require.Equal(t, len(lastConfigParam.FolderConfigs), validationsCount, "Not all folder configs were validated")

	shouldClear := true
	if len(clearNotifications) > 0 {
		shouldClear = clearNotifications[0]
	}
	if shouldClear {
		jsonRpcRecorder.ClearNotifications()
	}
}

func Test_SmokeOrgSelection(t *testing.T) {
	setupOrgSelectionTest := func(t *testing.T) (workflow.Engine, *config.TokenServiceImpl, server.Local, *testsupport.JsonRPCRecorder, types.FilePath, types.InitializeParams) {
		t.Helper()
		engine, tokenService := testutil.SmokeTestWithEngine(t, "")
		loc, jsonRpcRecorder := setupServer(t, engine, tokenService)
		engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), false)
		engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), true)
		engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), false)
		di.Init(engine, tokenService)

		repo, err := folderconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), testsupport.PythonGoof, "", engine.GetLogger(), false)
		require.NoError(t, err)
		require.NotEmpty(t, repo)
		require.NoError(t, err)

		initParams := prepareInitParams(t, repo, engine)
		if initParams.InitializationOptions.Settings == nil {
			initParams.InitializationOptions.Settings = make(map[string]*types.ConfigSetting)
		}
		initParams.InitializationOptions.Settings[types.SettingAutomaticDownload] = &types.ConfigSetting{Value: false, Changed: true}
		initParams.InitializationOptions.Settings[types.SettingCliPath] = &types.ConfigSetting{Value: "/some/invalid/path/that/does/not/matter/but/cannot/be/blank", Changed: true}
		initParams.InitializationOptions.Settings[types.SettingAuthenticationMethod] = &types.ConfigSetting{Value: string(types.TokenAuthentication), Changed: true}
		initParams.InitializationOptions.Settings[types.SettingAutomaticAuthentication] = &types.ConfigSetting{Value: false, Changed: true}
		initParams.InitializationOptions.Settings[types.SettingScanAutomatic] = &types.ConfigSetting{Value: "manual", Changed: true}
		return engine, tokenService, loc, jsonRpcRecorder, repo, initParams
	}

	t.Run("authenticated - takes given non-default org, sends folder config after init", func(t *testing.T) {
		engine, tokenService, loc, jsonRpcRecorder, repo, initParams := setupOrgSelectionTest(t)
		preferredOrg := "non-default"

		// Use LspFolderConfig to transmit folder configuration via LSP
		initParams.InitializationOptions.FolderConfigs = []types.LspFolderConfig{
			{
				FolderPath: repo,
				Settings: map[string]*types.ConfigSetting{
					types.SettingPreferredOrg: {Value: preferredOrg},
				},
			},
		}

		ensureInitialized(t, engine, tokenService, loc, initParams, nil)

		requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.LspFolderConfig){
			repo: func(fc types.LspFolderConfig) {
				require.NotNil(t, fc.Settings[types.SettingPreferredOrg])
				require.Equal(t, preferredOrg, fc.Settings[types.SettingPreferredOrg].Value)
				require.NotNil(t, fc.Settings[types.SettingOrgSetByUser])
				require.True(t, fc.Settings[types.SettingOrgSetByUser].Value.(bool))
			},
		})
	})

	t.Run("authenticated - determines org when nothing is given", func(t *testing.T) {
		engine, tokenService, loc, jsonRpcRecorder, repo, initParams := setupOrgSelectionTest(t)

		// No folder config needed - LS will auto-determine org
		ensureInitialized(t, engine, tokenService, loc, initParams, nil)

		requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.LspFolderConfig){
			repo: func(fc types.LspFolderConfig) {
				require.NotNil(t, fc.Settings[types.SettingOrgSetByUser])
				require.False(t, fc.Settings[types.SettingOrgSetByUser].Value.(bool))
				// LDX-Sync auto-determines the default org from the API, so preferredOrg may be set
				if fc.Settings[types.SettingPreferredOrg] != nil {
					require.NotEmpty(t, fc.Settings[types.SettingPreferredOrg].Value)
				}
			},
		})
	})

	t.Run("authenticated - global default org results in auto mode", func(t *testing.T) {
		engine, tokenService, loc, jsonRpcRecorder, repo, initParams := setupOrgSelectionTest(t)

		initParams.InitializationOptions.FolderConfigs = []types.LspFolderConfig{
			{FolderPath: repo, Settings: map[string]*types.ConfigSetting{}},
		}

		ensureInitialized(t, engine, tokenService, loc, initParams, nil)

		requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.LspFolderConfig){
			repo: func(fc types.LspFolderConfig) {
				require.NotNil(t, fc.Settings[types.SettingOrgSetByUser])
				require.False(t, fc.Settings[types.SettingOrgSetByUser].Value.(bool), "Default org should result in auto mode")
				// In auto mode, PreferredOrg may be inherited from the global org
				if fc.Settings[types.SettingPreferredOrg] != nil {
					require.NotEmpty(t, fc.Settings[types.SettingPreferredOrg].Value)
				}
			},
		})
	})

	t.Run("authenticated - global non-default org is preserved", func(t *testing.T) {
		engine, tokenService, loc, jsonRpcRecorder, repo, initParams := setupOrgSelectionTest(t)

		expectedOrg := "00000000-0000-0000-0000-000000000001"

		setupFunc := func(eng workflow.Engine) {
			config.SetOrganization(eng.GetConfiguration(), expectedOrg)
			types.SetPreferredOrgAndOrgSetByUser(eng.GetConfiguration(), repo, expectedOrg, true)
		}

		ensureInitialized(t, engine, tokenService, loc, initParams, setupFunc)

		requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.LspFolderConfig){
			repo: func(fc types.LspFolderConfig) {
				require.NotNil(t, fc.Settings[types.SettingOrgSetByUser])
				require.True(t, fc.Settings[types.SettingOrgSetByUser].Value.(bool), "OrgSetByUser should be true for non-default org")
				require.NotNil(t, fc.Settings[types.SettingPreferredOrg])
				require.Equal(t, expectedOrg, fc.Settings[types.SettingPreferredOrg].Value)
			},
		})
	})

	t.Run("authenticated - adding folder with existing folderConfig. Making sure PreferredOrg is preserved", func(t *testing.T) {
		engine, tokenService, loc, jsonRpcRecorder, repo, initParams := setupOrgSelectionTest(t)

		ensureInitialized(t, engine, tokenService, loc, initParams, nil)
		repoValidator := func(fc types.LspFolderConfig) {
			require.NotNil(t, fc.Settings[types.SettingOrgSetByUser])
			require.False(t, fc.Settings[types.SettingOrgSetByUser].Value.(bool))
			// PreferredOrg may be inherited from global org in auto mode
		}

		requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.LspFolderConfig){
			repo: repoValidator,
		})

		// add folder (LS has not seen before)
		fakeDirFolder, fakeDirFolderPath := addFakeDirAsWorkspaceFolder(t, loc)

		requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.LspFolderConfig){
			repo: repoValidator,
			fakeDirFolderPath: func(fc types.LspFolderConfig) {
				require.NotNil(t, fc.Settings[types.SettingOrgSetByUser])
				require.False(t, fc.Settings[types.SettingOrgSetByUser].Value.(bool), "OrgSetByUser should be false for new folder in auto mode")
				// PreferredOrg may be inherited from global org in auto mode
			},
		})

		// remove folder
		removeWorkSpaceFolder(t, loc, fakeDirFolder)
		requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.LspFolderConfig){
			repo: repoValidator,
		})

		engineConfig := engine.GetConfiguration()
		types.SetPreferredOrgAndOrgSetByUser(engineConfig, fakeDirFolderPath, "any", false)
		types.SetAutoDeterminedOrg(engineConfig, fakeDirFolderPath, "any")

		// re-add folder
		addWorkSpaceFolder(t, loc, fakeDirFolder)

		requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.LspFolderConfig){
			repo: repoValidator,
			fakeDirFolderPath: func(fc types.LspFolderConfig) {
				require.NotNil(t, fc.Settings[types.SettingOrgSetByUser])
				require.False(t, fc.Settings[types.SettingOrgSetByUser].Value.(bool), "OrgSetByUser must be preserved")
				require.NotNil(t, fc.Settings[types.SettingPreferredOrg], "PreferredOrg must be preserved")
				require.Equal(t, "any", fc.Settings[types.SettingPreferredOrg].Value, "PreferredOrg must be preserved")
			},
		})
	})

	t.Run("authenticated - user blanks folder-level org, so LS uses global org", func(t *testing.T) {
		engine, tokenService, loc, jsonRpcRecorder, repo, initParams := setupOrgSelectionTest(t)
		t.Cleanup(func() {
			s, _ := folderconfig.ConfigFile(engine.GetConfiguration().GetString(configuration.INTEGRATION_ENVIRONMENT))
			_ = os.Remove(s)
		})

		initialOrg := "user-chosen-org"
		globalOrg := "00000000-0000-0000-0000-000000000002" // Must be UUID to prevent resolution

		// Use LspFolderConfig to transmit folder configuration via LSP
		if initParams.InitializationOptions.Settings == nil {
			initParams.InitializationOptions.Settings = make(map[string]*types.ConfigSetting)
		}
		initParams.InitializationOptions.Settings[types.SettingOrganization] = &types.ConfigSetting{Value: globalOrg, Changed: true}
		initParams.InitializationOptions.FolderConfigs = []types.LspFolderConfig{
			{
				FolderPath: repo,
				Settings: map[string]*types.ConfigSetting{
					types.SettingPreferredOrg: {Value: initialOrg},
				},
			},
		}

		ensureInitialized(t, engine, tokenService, loc, initParams, nil)

		// Verify initial state
		requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.LspFolderConfig){
			repo: func(fc types.LspFolderConfig) {
				require.NotNil(t, fc.Settings[types.SettingOrgSetByUser])
				require.True(t, fc.Settings[types.SettingOrgSetByUser].Value.(bool))
				require.NotNil(t, fc.Settings[types.SettingPreferredOrg])
				require.Equal(t, initialOrg, fc.Settings[types.SettingPreferredOrg].Value)
			},
		})

		// Verify that the global org is still what we set it to
		require.Equal(t, globalOrg, engine.GetConfiguration().GetString(configuration.ORGANIZATION), "Global org should remain unchanged")

		// Verify that the folder's effective organization equals the preferred org
		require.Equal(t, initialOrg, config.FolderOrganization(engine.GetConfiguration(), repo, engine.GetLogger()), "Folder should use PreferredOrg when not blank and OrgSetByUser is true")

		// User blanks the folder-level org via configuration change
		sendModifiedFolderConfiguration(t, engine, loc, func(eng workflow.Engine, folderConfigs map[types.FilePath]*types.FolderConfig) {
			types.SetPreferredOrgAndOrgSetByUser(eng.GetConfiguration(), repo, "", true)
		})

		// Verify PreferredOrg is now empty and OrgSetByUser is true
		requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.LspFolderConfig){
			repo: func(fc types.LspFolderConfig) {
				require.NotNil(t, fc.Settings[types.SettingOrgSetByUser])
				require.True(t, fc.Settings[types.SettingOrgSetByUser].Value.(bool), "OrgSetByUser should remain true after user blanks org")
				require.Nil(t, fc.Settings[types.SettingPreferredOrg], "PreferredOrg should be nil after user blanks it")
			},
		})

		// Verify that the global org is still what we set it to
		assert.Equal(t, globalOrg, engine.GetConfiguration().GetString(configuration.ORGANIZATION), "Global org should remain unchanged")

		// Verify that the folder's effective organization equals the global org
		assert.Equal(t, globalOrg, config.FolderOrganization(engine.GetConfiguration(), repo, engine.GetLogger()), "Folder should use global org when PreferredOrg is blank and OrgSetByUser is true")
	})

	t.Run("unauthenticated - re-adding folder with changing the config through workspace/didChangeConfiguration", func(t *testing.T) {
		engine, tokenService, loc, jsonRpcRecorder, repo, initParams := setupOrgSelectionTest(t)
		t.Cleanup(func() {
			s, _ := folderconfig.ConfigFile(engine.GetConfiguration().GetString(configuration.INTEGRATION_ENVIRONMENT))
			_ = os.Remove(s)
		})
		t.Setenv("SNYK_TOKEN", "")

		ensureInitialized(t, engine, tokenService, loc, initParams, nil)

		repoValidator := func(fc types.LspFolderConfig) {
			require.NotNil(t, fc.Settings[types.SettingOrgSetByUser])
			require.False(t, fc.Settings[types.SettingOrgSetByUser].Value.(bool))
			// PreferredOrg may be inherited from global org; AutoDeterminedOrg may be set from LDX-Sync
		}
		requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.LspFolderConfig){
			repo: repoValidator,
		})

		// add folder
		fakeDirFolder, fakeDirFolderPath := addFakeDirAsWorkspaceFolder(t, loc)
		fakeDirFolderInitialValidator := func(fc types.LspFolderConfig) {
			require.NotNil(t, fc.Settings[types.SettingOrgSetByUser])
			require.False(t, fc.Settings[types.SettingOrgSetByUser].Value.(bool))
			// PreferredOrg may be inherited from global org
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
		sendModifiedFolderConfiguration(t, engine, loc, func(eng workflow.Engine, folderConfigs map[types.FilePath]*types.FolderConfig) {
			types.SetPreferredOrgAndOrgSetByUser(eng.GetConfiguration(), fakeDirFolderPath, "any", true)
		})

		requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.LspFolderConfig){
			repo: repoValidator,
			fakeDirFolderPath: func(fc types.LspFolderConfig) {
				require.NotNil(t, fc.Settings[types.SettingOrgSetByUser])
				require.True(t, fc.Settings[types.SettingOrgSetByUser].Value.(bool))
				require.NotNil(t, fc.Settings[types.SettingPreferredOrg])
				require.Equal(t, "any", fc.Settings[types.SettingPreferredOrg].Value)
				require.Nil(t, fc.Settings[types.SettingAutoDeterminedOrg])
			},
		})
	})

	t.Run("authenticated - user opts in to automatic org selection", func(t *testing.T) {
		engine, tokenService, loc, jsonRpcRecorder, repo, initParams := setupOrgSelectionTest(t)
		t.Cleanup(func() {
			s, _ := folderconfig.ConfigFile(engine.GetConfiguration().GetString(configuration.INTEGRATION_ENVIRONMENT))
			_ = os.Remove(s)
		})

		initialOrg := "user-chosen-org"
		globalOrg := "00000000-0000-0000-0000-000000000002" // Must be UUID to prevent resolution

		// Use LspFolderConfig to transmit folder configuration via LSP
		if initParams.InitializationOptions.Settings == nil {
			initParams.InitializationOptions.Settings = make(map[string]*types.ConfigSetting)
		}
		initParams.InitializationOptions.Settings[types.SettingOrganization] = &types.ConfigSetting{Value: globalOrg, Changed: true}
		initParams.InitializationOptions.FolderConfigs = []types.LspFolderConfig{
			{
				FolderPath: repo,
				Settings: map[string]*types.ConfigSetting{
					types.SettingPreferredOrg: {Value: initialOrg},
				},
			},
		}

		ensureInitialized(t, engine, tokenService, loc, initParams, nil)

		// Verify initial state - when OrgSetByUser=true, PreferredOrg is used
		requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.LspFolderConfig){
			repo: func(fc types.LspFolderConfig) {
				require.NotNil(t, fc.Settings[types.SettingOrgSetByUser])
				require.True(t, fc.Settings[types.SettingOrgSetByUser].Value.(bool))
				require.NotNil(t, fc.Settings[types.SettingPreferredOrg])
				require.Equal(t, initialOrg, fc.Settings[types.SettingPreferredOrg].Value)
			},
		})
		require.Equal(t, initialOrg, config.FolderOrganization(engine.GetConfiguration(), repo, engine.GetLogger()), "Folder should use PreferredOrg when not blank and OrgSetByUser is true")

		// User opts-in to automatic org selection for the folder
		sendModifiedFolderConfiguration(t, engine, loc, func(eng workflow.Engine, folderConfigs map[types.FilePath]*types.FolderConfig) {
			types.SetPreferredOrgAndOrgSetByUser(eng.GetConfiguration(), repo, "", false)
		})

		// Verify that OrgSetByUser is false
		requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.LspFolderConfig){
			repo: func(fc types.LspFolderConfig) {
				require.NotNil(t, fc.Settings[types.SettingOrgSetByUser])
				require.False(t, fc.Settings[types.SettingOrgSetByUser].Value.(bool), "OrgSetByUser should be false after user opts-in to auto org selection")
				// PreferredOrg may be inherited from global org in auto mode
			},
		})
		// When OrgSetByUser is false, effective org is AutoDeterminedOrg (if LDX-Sync succeeded) or global org (fallback)
		// Either way, it should NOT be the user's initialOrg anymore
		effectiveOrg := config.FolderOrganization(engine.GetConfiguration(), repo, engine.GetLogger())
		assert.NotEqual(t, initialOrg, effectiveOrg, "Folder should no longer use user's preferred org after opting in to auto selection")
		assert.NotEmpty(t, effectiveOrg, "Folder should have an effective org (either auto-determined or global fallback)")
	})

	t.Run("authenticated - user opts out of automatic org selection", func(t *testing.T) {
		engine, tokenService, loc, jsonRpcRecorder, repo, initParams := setupOrgSelectionTest(t)
		t.Cleanup(func() {
			s, _ := folderconfig.ConfigFile(engine.GetConfiguration().GetString(configuration.INTEGRATION_ENVIRONMENT))
			_ = os.Remove(s)
		})

		globalOrg := "00000000-0000-0000-0000-000000000002" // Must be UUID to prevent resolution

		// Start with auto-selection enabled (no PreferredOrg set)
		if initParams.InitializationOptions.Settings == nil {
			initParams.InitializationOptions.Settings = make(map[string]*types.ConfigSetting)
		}
		initParams.InitializationOptions.Settings[types.SettingOrganization] = &types.ConfigSetting{Value: globalOrg, Changed: true}

		ensureInitialized(t, engine, tokenService, loc, initParams, nil)

		// Verify initial state - when OrgSetByUser=false, effective org is AutoDeterminedOrg or global fallback
		requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.LspFolderConfig){
			repo: func(fc types.LspFolderConfig) {
				require.NotNil(t, fc.Settings[types.SettingOrgSetByUser])
				require.False(t, fc.Settings[types.SettingOrgSetByUser].Value.(bool))
				// PreferredOrg may be inherited from global org in auto mode
			},
		})
		// Effective org should be non-empty (either AutoDeterminedOrg or global fallback)
		require.NotEmpty(t, config.FolderOrganization(engine.GetConfiguration(), repo, engine.GetLogger()), "Folder should have an effective org when OrgSetByUser is false")

		// User opts-out of automatic org selection for the folder
		sendModifiedFolderConfiguration(t, engine, loc, func(eng workflow.Engine, folderConfigs map[types.FilePath]*types.FolderConfig) {
			types.SetPreferredOrgAndOrgSetByUser(eng.GetConfiguration(), repo, "", true)
		})

		// Verify that OrgSetByUser is true, and the folder's effective org is the global one
		requireLspFolderConfigNotification(t, jsonRpcRecorder, map[types.FilePath]func(fc types.LspFolderConfig){
			repo: func(fc types.LspFolderConfig) {
				require.NotNil(t, fc.Settings[types.SettingOrgSetByUser])
				require.True(t, fc.Settings[types.SettingOrgSetByUser].Value.(bool), "OrgSetByUser should be true after user opts-out of auto org selection")
				require.Nil(t, fc.Settings[types.SettingPreferredOrg], "PreferredOrg should be nil")
			},
		})
		// When OrgSetByUser=true and PreferredOrg is empty, effective org is global org
		assert.Equal(t, globalOrg, config.FolderOrganization(engine.GetConfiguration(), repo, engine.GetLogger()), "Folder should use global org when OrgSetByUser is true and PreferredOrg is empty")
	})
}

func ensureInitialized(t *testing.T, engine workflow.Engine, tokenService *config.TokenServiceImpl, loc server.Local, initParams types.InitializeParams, preInitSetupFunc func(workflow.Engine)) {
	t.Helper()
	config.SetLogLevel(zerolog.LevelInfoValue)
	t.Setenv("SNYK_LOG_LEVEL", config.GetLogLevel())
	config.SetupLogging(engine, tokenService, nil) // we don't need to send logs to the client
	engineConfig := engine.GetConfiguration()
	engineConfig.Set(configuration.DEBUG, engine.GetLogger().GetLevel() == zerolog.DebugLevel)

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

	_, err := loc.Client.Call(t.Context(), "initialize", initParams)
	assert.NoError(t, err)

	waitForNetwork(engine)

	// Run optional setup function after initialization but before call to initialized.
	// This allows tests to, for example, pre-populate storage to be read by the initialized call.
	if preInitSetupFunc != nil {
		preInitSetupFunc(engine)
	}

	_, err = loc.Client.Call(t.Context(), "initialized", nil)
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

	_, err := loc.Client.Call(t.Context(), "textDocument/didSave", didSaveParams)
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
	engine workflow.Engine,
	loc server.Local,
	modification func(engine workflow.Engine, folderConfigs map[types.FilePath]*types.FolderConfig),
) {
	t.Helper()
	engineConfig := engine.GetConfiguration()

	// Build folder configs from the workspace, not from stale folderConfig
	ws := config.GetWorkspace(engineConfig)
	folderConfigs := make(map[types.FilePath]*types.FolderConfig)
	if ws != nil {
		for _, folder := range ws.Folders() {
			fc := config.GetFolderConfigFromEngine(engine, testutil.DefaultConfigResolver(engine), folder.Path(), engine.GetLogger())
			if fc != nil {
				folderConfigs[folder.Path()] = fc
			}
		}
	}

	// Capture pre-modification snapshots of prefix keys
	snapshots := make(map[types.FilePath]types.FolderConfigSnapshot)
	for fp := range folderConfigs {
		snapshots[fp] = types.ReadFolderConfigSnapshot(engineConfig, types.PathKey(fp))
	}

	// Apply the modification (writes to prefix keys)
	modification(engine, folderConfigs)

	// Build LspFolderConfigs from the MODIFIED prefix keys
	var lspConfigs []types.LspFolderConfig
	for fp, fc := range folderConfigs {
		fc.ConfigResolver = types.NewMinimalConfigResolver(engineConfig)
		lspConfig := fc.ToLspFolderConfig()
		if lspConfig != nil {
			if lspConfig.Settings == nil {
				lspConfig.Settings = make(map[string]*types.ConfigSetting)
			}
			lspConfig.Settings[types.SettingPreferredOrg] = &types.ConfigSetting{Value: fc.PreferredOrg()}
			lspConfig.Settings[types.SettingOrgSetByUser] = &types.ConfigSetting{Value: fc.OrgSetByUser()}
			lspConfigs = append(lspConfigs, *lspConfig)
		}

		// Restore prefix keys to pre-modification state so the server sees the diff
		oldSnap := snapshots[fp]
		fk := string(types.PathKey(fp))
		if fk != "" {
			types.SetPreferredOrgAndOrgSetByUser(engineConfig, types.FilePath(fk), oldSnap.PreferredOrg, oldSnap.OrgSetByUser)
		}
	}

	params := buildSmokeTestSettings(engine)
	params.Settings.FolderConfigs = lspConfigs
	sendConfigurationDidChange(t, loc, params)
}

func sendConfigurationDidChange(t *testing.T, loc server.Local, params types.DidChangeConfigurationParams) {
	t.Helper()
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

const (
	monorepoRealScanProfileCPU         = "real_scan_cpu.pprof"
	monorepoRealScanProfileHeapBefore  = "real_scan_heap_before.pprof"
	monorepoRealScanProfileHeapAfter   = "real_scan_heap_after.pprof"
	monorepoRealScanProfileHeapSamples = "heap_samples.csv"
	monorepoRealScanHeapSampleInterval = 5 * time.Second
)

// withMonorepoRealScanPprof runs fn; if profileDir is non-empty, writes runtime/pprof CPU (whole fn) and heap snapshots before/after fn (for go tool pprof).
func withMonorepoRealScanPprof(t *testing.T, profileDir string, fn func()) {
	t.Helper()
	if profileDir == "" {
		fn()
		return
	}

	require.NoError(t, os.MkdirAll(profileDir, 0o750))

	heapSamplesPath := filepath.Join(profileDir, monorepoRealScanProfileHeapSamples)
	done := make(chan struct{})
	var heapWg sync.WaitGroup
	var stopHeapSamples sync.Once
	heapWg.Add(1)
	go func() {
		defer heapWg.Done()
		f, err := os.OpenFile(heapSamplesPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			t.Errorf("heap_samples: create %q: %v", heapSamplesPath, err)
			return
		}
		defer func() { _ = f.Close() }()
		w := bufio.NewWriter(f)
		if _, err := w.WriteString("unix_ns,heap_sys_bytes,heap_inuse_bytes,heap_alloc_bytes\n"); err != nil {
			t.Errorf("heap_samples: write header: %v", err)
			return
		}
		writeSample := func() {
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			_, _ = fmt.Fprintf(w, "%d,%d,%d,%d\n", time.Now().UnixNano(), ms.HeapSys, ms.HeapInuse, ms.HeapAlloc)
		}
		writeSample()
		ticker := time.NewTicker(monorepoRealScanHeapSampleInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				writeSample()
				_ = w.Flush()
				return
			case <-ticker.C:
				writeSample()
				_ = w.Flush()
			}
		}
	}()
	defer func() {
		stopHeapSamples.Do(func() { close(done) })
		heapWg.Wait()
	}()

	cpuPath := filepath.Join(profileDir, monorepoRealScanProfileCPU)
	heapBeforePath := filepath.Join(profileDir, monorepoRealScanProfileHeapBefore)
	heapAfterPath := filepath.Join(profileDir, monorepoRealScanProfileHeapAfter)

	cpuFile, err := os.Create(cpuPath)
	require.NoError(t, err)
	require.NoError(t, pprof.StartCPUProfile(cpuFile))
	defer func() {
		pprof.StopCPUProfile()
		_ = cpuFile.Close()
	}()

	runtime.GC()
	beforeFile, err := os.Create(heapBeforePath)
	require.NoError(t, err)
	require.NoError(t, pprof.WriteHeapProfile(beforeFile))
	require.NoError(t, beforeFile.Close())

	fn()

	runtime.GC()
	afterFile, err := os.Create(heapAfterPath)
	require.NoError(t, err)
	require.NoError(t, pprof.WriteHeapProfile(afterFile))
	require.NoError(t, afterFile.Close())

	t.Logf("monorepo real-scan profiles: cpu=%s heap_before=%s heap_after=%s heap_samples=%s", cpuPath, heapBeforePath, heapAfterPath, heapSamplesPath)
}

// monorepoPerLeafDiagnosticCoverageMaxLeaves caps how many code_* + oss_* leaves we require
// diagnostics for; above this, products may aggregate or omit paths and the check would be flaky.
const monorepoPerLeafDiagnosticCoverageMaxLeaves = 100

// monorepoRealScanPhaseMaxWait bounds waits for the full 500+500 fixture (working dir + reference OSS, large SARIF).
const monorepoRealScanPhaseMaxWait = 90 * time.Minute

// monorepoRealScanHarness holds state for Test_SmokeRealScanMonorepoFixture.
type monorepoRealScanHarness struct {
	cloneTarget     types.FilePath
	codeLeafFolders int
	ossLeafFolders  int
	engine          workflow.Engine
	tokenService    *config.TokenServiceImpl
	loc             server.Local
	jsonRPCRecorder *testsupport.JsonRPCRecorder
}

func setupMonorepoRealScanHarness(t *testing.T) *monorepoRealScanHarness {
	t.Helper()
	engine, tokenService := testutil.SmokeTestWithEngine(t, "")
	nCode, nOSS := monorepoBenchmarkFixtureScale(t)

	parent := types.FilePath(testutil.TempDirWithRetry(t))
	repoDir := filepath.Join(string(parent), "1")
	require.NoError(t, os.MkdirAll(repoDir, 0o755))
	require.NoError(t, benchmark.GenerateMonorepoFixtureCounts(t, repoDir, nCode, nOSS))
	initializeGitRepoForMonorepoBenchmark(t, repoDir)
	benchmark.AssertMonorepoFixtureLayout(t, repoDir, nCode, nOSS)
	cloneTarget := types.FilePath(repoDir)

	loc, jsonRPCRecorder := setupServer(t, engine, tokenService)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), true)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), false)
	cleanupChannels()
	di.Init(engine, tokenService)

	// Register after setupServer so this cleanup runs before shutdown (LIFO); capture aggregator
	// because di.ScanStateAggregator() is not reliable after shutdown has run.
	scanAgg := di.ScanStateAggregator()
	require.NotNil(t, scanAgg)
	t.Cleanup(func() {
		waitForAllScansToComplete(t, scanAgg)
	})

	initParams := prepareInitParams(t, cloneTarget, engine)
	ensureInitialized(t, engine, tokenService, loc, initParams, nil)

	return &monorepoRealScanHarness{
		cloneTarget:     cloneTarget,
		codeLeafFolders: nCode,
		ossLeafFolders:  nOSS,
		engine:          engine,
		tokenService:    tokenService,
		loc:             loc,
		jsonRPCRecorder: jsonRPCRecorder,
	}
}

func runMonorepoRealScanScanPhase(t *testing.T, h *monorepoRealScanHarness) {
	t.Helper()
	waitUntilWorkspaceFolderScanned(t, string(h.cloneTarget), h.engine, monorepoRealScanPhaseMaxWait, true)
	checkForScanParamsWithMaxWait(t, h.jsonRPCRecorder, string(h.cloneTarget), product.ProductCode, monorepoRealScanPhaseMaxWait)
	checkForScanParamsWithMaxWait(t, h.jsonRPCRecorder, string(h.cloneTarget), product.ProductOpenSource, monorepoRealScanPhaseMaxWait)

	require.Eventually(t, func() bool {
		codeIssues := getIssueListFromPublishDiagnosticsNotification(t, h.jsonRPCRecorder, product.ProductCode, h.cloneTarget)
		ossIssues := getIssueListFromPublishDiagnosticsNotification(t, h.jsonRPCRecorder, product.ProductOpenSource, h.cloneTarget)
		return len(codeIssues) > 0 && len(ossIssues) > 0
	}, monorepoRealScanPhaseMaxWait, time.Millisecond, "expected Snyk Code and OSS diagnostics for fixture workspace")

	if h.codeLeafFolders+h.ossLeafFolders <= monorepoPerLeafDiagnosticCoverageMaxLeaves {
		require.Eventually(t, func() bool {
			return monorepoLeafFoldersHaveMatchingDiagnostics(h.jsonRPCRecorder, h.cloneTarget, h.codeLeafFolders, h.ossLeafFolders)
		}, monorepoRealScanPhaseMaxWait, time.Millisecond,
			"expected at least one publishDiagnostics URI under each code_* and oss_* leaf for the matching product")
	} else {
		t.Logf("skipping per-leaf diagnostic coverage (code+oss leaves=%d > %d); disk layout was verified in harness",
			h.codeLeafFolders+h.ossLeafFolders, monorepoPerLeafDiagnosticCoverageMaxLeaves)
	}

	waitUntilDeltaScanComplete(t, di.ScanStateAggregator(), monorepoRealScanPhaseMaxWait, true)

	if os.Getenv(testsupport.BenchmarkRealScanMonorepoProfileDirEnvVar) != "" {
		h.jsonRPCRecorder.DrainRecordedTrafficForProfiling()
		runtime.GC()
	}
}

func monorepoCollectDiagnosticPathsBySource(jsonRPCRecorder *testsupport.JsonRPCRecorder, workspaceRoot types.FilePath) (codePaths, ossPaths map[types.FilePath]struct{}) {
	codePaths = make(map[types.FilePath]struct{})
	ossPaths = make(map[types.FilePath]struct{})
	for _, n := range jsonRPCRecorder.FindNotificationsByMethod("textDocument/publishDiagnostics") {
		var params types.PublishDiagnosticsParams
		_ = n.UnmarshalParams(&params)
		fp := uri.PathFromUri(params.URI)
		if !uri.FolderContains(workspaceRoot, fp) {
			continue
		}
		for _, diagnostic := range params.Diagnostics {
			diagnosticCode, ok := diagnostic.Code.(string)
			if ok && diagnosticCode == "Snyk Error" {
				continue
			}
			switch diagnostic.Source {
			case string(product.ProductCode):
				codePaths[fp] = struct{}{}
			case string(product.ProductOpenSource):
				ossPaths[fp] = struct{}{}
			}
		}
	}
	return codePaths, ossPaths
}

func monorepoLeafFolderHasDiagnostics(leafRoot types.FilePath, paths map[types.FilePath]struct{}) bool {
	for p := range paths {
		if uri.FolderContains(leafRoot, p) {
			return true
		}
	}
	return false
}

func monorepoLeafFoldersHaveMatchingDiagnostics(jsonRPCRecorder *testsupport.JsonRPCRecorder, workspaceRoot types.FilePath, nCode, nOSS int) bool {
	codePaths, ossPaths := monorepoCollectDiagnosticPathsBySource(jsonRPCRecorder, workspaceRoot)
	for i := range nCode {
		leaf := types.FilePath(filepath.Join(string(workspaceRoot), fmt.Sprintf("code_%03d", i)))
		if !monorepoLeafFolderHasDiagnostics(leaf, codePaths) {
			return false
		}
	}
	for i := range nOSS {
		leaf := types.FilePath(filepath.Join(string(workspaceRoot), fmt.Sprintf("oss_%03d", i)))
		if !monorepoLeafFolderHasDiagnostics(leaf, ossPaths) {
			return false
		}
	}
	return true
}

// Test_SmokeRealScanMonorepoFixture runs the real LS + Snyk Code + OSS (+ IaC) pipeline against the generated monorepo fixture (benchmark package).
// Opt-in: set SMOKE_TESTS=1 and BENCHMARK_REAL_SCAN_MONOREPO=1 (see testsupport.BenchmarkRealScanMonorepoEnvVar).
func Test_SmokeRealScanMonorepoFixture(t *testing.T) {
	testsupport.SkipUnlessBenchmarkRealScanMonorepo(t)

	testutil.CreateDummyProgressListener(t)
	if os.Getenv("SNYK_API") == "" {
		t.Setenv("SNYK_API", "https://api.snyk.io")
	}

	h := setupMonorepoRealScanHarness(t)
	withMonorepoRealScanPprof(t, os.Getenv(testsupport.BenchmarkRealScanMonorepoProfileDirEnvVar), func() {
		runMonorepoRealScanScanPhase(t, h)
	})
}

func monorepoBenchmarkFixtureScale(t *testing.T) (codeFolders, ossFolders int) {
	t.Helper()
	if os.Getenv("BENCHMARK_REALSCAN_FULL_FIXTURE") == "1" {
		return benchmark.CodeFolderCount, benchmark.OSSFolderCount
	}
	nCode, nOSS := 2, 2
	if v := os.Getenv("BENCHMARK_REALSCAN_FIXTURE_CODE"); v != "" {
		parsed, err := strconv.Atoi(v)
		require.NoError(t, err, "BENCHMARK_REALSCAN_FIXTURE_CODE")
		require.Greater(t, parsed, 0, "BENCHMARK_REALSCAN_FIXTURE_CODE must be > 0")
		nCode = parsed
	}
	if v := os.Getenv("BENCHMARK_REALSCAN_FIXTURE_OSS"); v != "" {
		parsed, err := strconv.Atoi(v)
		require.NoError(t, err, "BENCHMARK_REALSCAN_FIXTURE_OSS")
		require.Greater(t, parsed, 0, "BENCHMARK_REALSCAN_FIXTURE_OSS must be > 0")
		nOSS = parsed
	}
	return nCode, nOSS
}

func initializeGitRepoForMonorepoBenchmark(t *testing.T, repoDir string) {
	t.Helper()
	cmd := exec.Command("git", "init", "--initial-branch=main")
	cmd.Dir = repoDir
	require.NoError(t, cmd.Run())

	cmd = exec.Command("git", "config", "user.email", "test@example.com")
	cmd.Dir = repoDir
	require.NoError(t, cmd.Run())

	cmd = exec.Command("git", "config", "user.name", "Test User")
	cmd.Dir = repoDir
	require.NoError(t, cmd.Run())

	cmd = exec.Command("git", "add", ".")
	cmd.Dir = repoDir
	require.NoError(t, cmd.Run())

	cmd = exec.Command("git", "commit", "-m", "initial")
	cmd.Dir = repoDir
	require.NoError(t, cmd.Run())
}
