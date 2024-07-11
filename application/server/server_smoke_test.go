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
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/server"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

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
		endpoint             string
	}

	endpoint := os.Getenv("SNYK_API")
	if endpoint == "" {
		t.Setenv("SNYK_API", "https://api.snyk.io")
	}

	tests := []test{
		{
			name:                 "OSS and Code",
			repo:                 "https://github.com/snyk-labs/nodejs-goof",
			commit:               "0336589",
			file1:                ossFile,
			file2:                codeFile,
			useConsistentIgnores: false,
			hasVulns:             true,
		},
		{
			name:                 "OSS and Code with V1 endpoint",
			repo:                 "https://github.com/snyk-labs/nodejs-goof",
			commit:               "0336589",
			file1:                ossFile,
			file2:                codeFile,
			useConsistentIgnores: false,
			endpoint:             path.Join(endpoint, "/v1"),
		},
		{
			name:                 "OSS and Code with consistent ignores",
			repo:                 "https://github.com/snyk-labs/nodejs-goof",
			commit:               "0336589",
			file1:                ossFile,
			file2:                codeFile,
			useConsistentIgnores: true,
			hasVulns:             true,
		},
		{
			name:                 "IaC and Code",
			repo:                 "https://github.com/deepcodeg/snykcon-goof.git",
			commit:               "eba8407",
			file1:                iacFile,
			file2:                codeFile,
			useConsistentIgnores: false,
			hasVulns:             true,
		},
		{
			name:                 "Code without vulns",
			repo:                 "https://github.com/imagec/simple-repo",
			commit:               "75bcc55",
			file1:                "",
			file2:                "providers.tf",
			useConsistentIgnores: false,
			hasVulns:             false,
		},
		{
			name:                 "IaC and Code with consistent ignores",
			repo:                 "https://github.com/deepcodeg/snykcon-goof.git",
			commit:               "eba8407",
			file1:                iacFile,
			file2:                codeFile,
			useConsistentIgnores: true,
			hasVulns:             true,
		},
		{
			name:                 "Two upload batches",
			repo:                 "https://github.com/apache/maven",
			commit:               "18725ec1e",
			file1:                "",
			file2:                "maven-compat/src/test/java/org/apache/maven/repository/legacy/LegacyRepositorySystemTest.java",
			useConsistentIgnores: false,
			hasVulns:             true,
		},
		{
			name:                 "Two upload batches with consistent ignores",
			repo:                 "https://github.com/apache/maven",
			commit:               "18725ec1e",
			file1:                "",
			file2:                "maven-compat/src/test/java/org/apache/maven/repository/legacy/LegacyRepositorySystemTest.java",
			useConsistentIgnores: true,
			hasVulns:             true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runSmokeTest(t, tc.repo, tc.commit, tc.file1, tc.file2, tc.useConsistentIgnores, tc.hasVulns, "")
		})
	}
}

func Test_SmokeIssueCaching(t *testing.T) {
	t.Run("adds issues to cache correctly", func(t *testing.T) {
		loc, jsonRPCRecorder := setupServer(t)
		c := testutil.SmokeTest(t, false)
		c.EnableSnykCodeSecurity(true)
		c.EnableSnykCodeQuality(false)
		c.SetSnykOssEnabled(true)
		c.SetSnykIacEnabled(false)
		di.Init()

		var cloneTargetDirGoof = setupRepoAndInitialize(t, "https://github.com/snyk-labs/nodejs-goof", "0336589", loc, c)
		folderGoof := workspace.Get().GetFolderContaining(cloneTargetDirGoof)

		// wait till the whole workspace is scanned
		assert.Eventually(t, func() bool {
			return folderGoof != nil && folderGoof.IsScanned()
		}, maxIntegTestDuration, time.Millisecond)

		ossIssuesForFile := folderGoof.IssuesForFile(filepath.Join(cloneTargetDirGoof, "package.json"))
		require.Greater(t, len(ossIssuesForFile), 108) // 108 is the number of issues in the package.json file as of now

		codeIssuesForFile := folderGoof.IssuesForFile(filepath.Join(cloneTargetDirGoof, "app.js"))
		require.Greater(t, len(codeIssuesForFile), 5) // 5 is the number of issues in the app.js file as of now

		checkDiagnosticPublishingForCachingSmokeTest(t, jsonRPCRecorder, 1, 1, c)

		jsonRPCRecorder.ClearNotifications()
		jsonRPCRecorder.ClearCallbacks()

		// now we add juice shop as second folder/repo
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

		ossIssuesForFileSecondScan := folderGoof.IssuesForFile(filepath.Join(cloneTargetDirGoof, "package.json"))
		require.Equal(t, len(ossIssuesForFile), len(ossIssuesForFileSecondScan))

		codeIssuesForFileSecondScan := folderGoof.IssuesForFile(filepath.Join(cloneTargetDirGoof, "app.js"))
		require.Equal(t, len(codeIssuesForFile), len(codeIssuesForFileSecondScan))

		// OSS: empty, package.json goof, package.json juice = 3
		// Code: empty, app.js = 2
		checkDiagnosticPublishingForCachingSmokeTest(t, jsonRPCRecorder, 2, 3, c)
		checkScanResultsPublishingForCachingSmokeTest(t, jsonRPCRecorder, folderJuice, folderGoof, c)
	})
	t.Run("clears issues from cache correctly", func(t *testing.T) {
		loc, jsonRPCRecorder := setupServer(t)
		c := testutil.SmokeTest(t, false)
		c.EnableSnykCodeSecurity(true)
		c.EnableSnykCodeQuality(false)
		c.SetSnykOssEnabled(true)
		c.SetSnykIacEnabled(false)
		di.Init()

		var cloneTargetDirGoof = setupRepoAndInitialize(t, "https://github.com/snyk-labs/nodejs-goof", "0336589", loc, c)
		folderGoof := workspace.Get().GetFolderContaining(cloneTargetDirGoof)

		// wait till the whole workspace is scanned
		assert.Eventually(t, func() bool {
			return folderGoof != nil && folderGoof.IsScanned()
		}, maxIntegTestDuration, time.Millisecond)

		ossFilePath := "package.json"
		ossIssuesForFile := folderGoof.IssuesForFile(filepath.Join(cloneTargetDirGoof, ossFilePath))
		require.Greater(t, len(ossIssuesForFile), 108) // 108 is the number of issues in the package.json file as of now
		codeFilePath := "app.js"
		codeIssuesForFile := folderGoof.IssuesForFile(filepath.Join(cloneTargetDirGoof, codeFilePath))
		require.Greater(t, len(codeIssuesForFile), 5) // 5 is the number of issues in the app.js file as of now
		checkDiagnosticPublishingForCachingSmokeTest(t, jsonRPCRecorder, 1, 1, c)
		require.Greater(t, len(folderGoof.Issues()), 0)
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
				if filepath.Base(uri.PathFromUri(diagnostic.URI)) == ossFilePath && len(diagnostic.Diagnostics) == 0 {
					emptyOSSFound = true
				}
				if filepath.Base(uri.PathFromUri(diagnostic.URI)) == codeFilePath && len(diagnostic.Diagnostics) == 0 {
					emptyCodeFound = true
				}
			}
			return emptyOSSFound && emptyCodeFound
		}, time.Second*5, time.Second)

		// check issues deleted
		require.Empty(t, folderGoof.Issues())

		// check hovers deleted
		response, err := loc.Client.Call(context.Background(), "textDocument/hover", hover.Params{
			TextDocument: sglsp.TextDocumentIdentifier{URI: uri.PathToUri(filepath.Join(folderGoof.Path(), ossFilePath))},
			// at that file position, there should be a hover normally
			Position: sglsp.Position{Line: 27, Character: 20},
		})
		require.NoError(t, err)
		var emptyHover hover.Result
		require.NoError(t, response.UnmarshalResult(&emptyHover))
		require.Empty(t, emptyHover.Contents.Value)
	})
}

func addJuiceShopAsWorkspaceFolder(t *testing.T, loc server.Local, c *config.Config) *workspace.Folder {
	t.Helper()
	var cloneTargetDirJuice, err = setupCustomTestRepo(t, "https://github.com/juice-shop/juice-shop", "bc9cef127", c.Logger())
	require.NoError(t, err)

	juiceLspWorkspaceFolder := types.WorkspaceFolder{Uri: uri.PathToUri(cloneTargetDirJuice), Name: "juicy-mac-juice-face"}
	didChangeWorkspaceFoldersParams := types.DidChangeWorkspaceFoldersParams{
		Event: types.WorkspaceFoldersChangeEvent{Added: []types.WorkspaceFolder{juiceLspWorkspaceFolder}},
	}

	_, err = loc.Client.Call(context.Background(), "workspace/didChangeWorkspaceFolders", didChangeWorkspaceFoldersParams)
	require.NoError(t, err)

	folderJuice := workspace.Get().GetFolderContaining(cloneTargetDirJuice)
	require.NotNil(t, folderJuice)
	return folderJuice
}

// check that $/snyk.scan messages are sent
// check that they only contain issues that belong to the scanned folder
func checkScanResultsPublishingForCachingSmokeTest(
	t *testing.T,
	jsonRPCRecorder *testutil.JsonRPCRecorder,
	folderJuice *workspace.Folder,
	folderGoof *workspace.Folder,
	c *config.Config,
) {
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
					scanResultCodeGoofFound = true
					onlyIssuesForGoof = true
					for _, issue := range scanResult.Issues {
						issueContainedInGoof := folderGoof.Contains(issue.FilePath)
						onlyIssuesForGoof = onlyIssuesForGoof && issueContainedInGoof
					}
				case folderJuice.Path():
					scanResultCodeJuiceShopFound = true
					onlyIssuesForJuiceShop = true
					for _, issue := range scanResult.Issues {
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
// we expect one empty publishDiagnostics per changed file, and one for the new findings
func checkDiagnosticPublishingForCachingSmokeTest(
	t *testing.T,
	jsonRPCRecorder *testutil.JsonRPCRecorder,
	expectedCode, expectedOSS int,
	c *config.Config,
) {
	t.Helper()
	require.Eventually(t, func() bool {
		notifications := jsonRPCRecorder.FindNotificationsByMethod("textDocument/publishDiagnostics")
		appJsEmptyFound := false
		appJsNewFound := false
		packageJsonEmptyFound := false
		packageJsonNewFound := false
		appJsCount := 0
		packageJsonCount := 0

		for _, notification := range notifications {
			var param types.PublishDiagnosticsParams
			err := json.Unmarshal([]byte(notification.ParamString()), &param)
			require.NoError(t, err)
			if filepath.Base(uri.PathFromUri(param.URI)) == "package.json" {
				c.Logger().Debug().Any("notification", notification.ParamString()).Send()
				if len(param.Diagnostics) == 0 || expectedOSS == 1 { // if expected == 1, we don't expect empty
					packageJsonEmptyFound = true
				}
				if len(param.Diagnostics) > 0 {
					packageJsonNewFound = true
				}
				packageJsonCount++
			}

			if filepath.Base(uri.PathFromUri(param.URI)) == "app.js" {
				if len(param.Diagnostics) == 0 || expectedOSS == 1 { // if expected == 1, we don't expect empty
					appJsEmptyFound = true
				}
				if len(param.Diagnostics) > 0 {
					appJsNewFound = true
				}
				appJsCount++
			}
		}
		c.Logger().Debug().Bool("appJsEmptyFound", appJsEmptyFound).Send()
		c.Logger().Debug().Bool("appJsNewFound", appJsNewFound).Send()
		c.Logger().Debug().Bool("packageJsonNewFound", packageJsonNewFound).Send()
		c.Logger().Debug().Bool("packageJsonEmptyFound", packageJsonEmptyFound).Send()
		c.Logger().Debug().Int("appJsCount", appJsCount).Send()
		c.Logger().Debug().Int("packageJsonCount", packageJsonCount).Send()
		result := appJsEmptyFound &&
			appJsNewFound &&
			packageJsonNewFound &&
			packageJsonEmptyFound &&
			appJsCount == expectedCode &&
			packageJsonCount == expectedOSS

		return result
	}, time.Second*5, time.Second)
}

func runSmokeTest(t *testing.T, repo string, commit string, file1 string, file2 string, useConsistentIgnores bool,
	hasVulns bool, endpoint string) {
	t.Helper()
	if endpoint != "" && endpoint != "/v1" {
		t.Setenv("SNYK_API", endpoint)
	}
	loc, jsonRPCRecorder := setupServer(t)
	c := testutil.SmokeTest(t, useConsistentIgnores)
	c.SetSnykCodeEnabled(true)
	c.SetSnykIacEnabled(true)
	c.SetSnykOssEnabled(true)
	cleanupChannels()
	di.Init()

	cloneTargetDir := setupRepoAndInitialize(t, repo, commit, loc, c)

	// wait till the whole workspace is scanned
	assert.Eventually(t, func() bool {
		f := workspace.Get().GetFolderContaining(cloneTargetDir)
		return f != nil && f.IsScanned()
	}, maxIntegTestDuration, 2*time.Millisecond)

	jsonRPCRecorder.ClearNotifications()
	var testPath string
	if file1 != "" {
		testPath = filepath.Join(cloneTargetDir, file1)
		textDocumentDidSave(t, &loc, testPath)
		// serve diagnostics from file scan
		assert.Eventually(t, checkForPublishedDiagnostics(t, testPath, -1, jsonRPCRecorder), maxIntegTestDuration, 10*time.Millisecond)
	}

	jsonRPCRecorder.ClearNotifications()
	testPath = filepath.Join(cloneTargetDir, file2)
	textDocumentDidSave(t, &loc, testPath)

	assert.Eventually(t, checkForPublishedDiagnostics(t, testPath, -1, jsonRPCRecorder), maxIntegTestDuration, 10*time.Millisecond)

	// check for snyk scan message & check autofix
	var notifications []jrpc2.Request
	var scanParams types.SnykScanParams
	assert.Eventually(t, func() bool {
		notifications = jsonRPCRecorder.FindNotificationsByMethod("$/snyk.scan")
		for _, n := range notifications {
			_ = n.UnmarshalParams(&scanParams)
			if scanParams.Product != "code" ||
				scanParams.FolderPath != cloneTargetDir ||
				scanParams.Status != "success" {
				continue
			}
			return true
		}
		return false
	}, 10*time.Second, 10*time.Millisecond)

	if config.CurrentConfig().SnykCodeApi() != "https://deeproxy.snyk.io" {
		return
	}

	// check for autofix diff on mt-us
	if hasVulns {
		assert.Greater(t, len(scanParams.Issues), 0)
		for _, issue := range scanParams.Issues {
			codeIssueData, ok := issue.AdditionalData.(map[string]interface{})
			if !ok || codeIssueData["hasAIFix"] == false || codeIssueData["rule"] != "WebCookieSecureDisabledByDefault" {
				continue
			}
			call, err := loc.Client.Call(ctx, "workspace/executeCommand", sglsp.ExecuteCommandParams{
				Command:   types.CodeFixDiffsCommand,
				Arguments: []any{uri.PathToUri(scanParams.FolderPath), uri.PathToUri(issue.FilePath), issue.Id},
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

	checkFeatureFlagStatus(t, &loc, c)
}

func setupRepoAndInitialize(t *testing.T, repo string, commit string, loc server.Local, c *config.Config) string {
	t.Helper()
	var cloneTargetDir, err = setupCustomTestRepo(t, repo, commit, c.Logger())
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
			AuthenticationMethod:        types.TokenAuthentication,
		},
	}

	_, err = loc.Client.Call(ctx, "initialize", clientParams)
	if err != nil {
		t.Fatal(err, "Initialize failed")
	}
	_, err = loc.Client.Call(ctx, "initialized", nil)
	if err != nil {
		t.Fatal(err, "Initialized failed")
	}
	return cloneTargetDir
}

func checkFeatureFlagStatus(t *testing.T, loc *server.Local, c *config.Config) {
	t.Helper()

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
	assert.True(t, ok)
}

func Test_SmokeSnykCodeFileScan(t *testing.T) {
	loc, jsonRPCRecorder := setupServer(t)
	c := testutil.SmokeTest(t, false)
	c.SetSnykCodeEnabled(true)
	cleanupChannels()
	di.Init()

	var cloneTargetDir, err = setupCustomTestRepo(t, "https://github.com/snyk-labs/nodejs-goof", "0336589", c.Logger())
	defer func(path string) { _ = os.RemoveAll(path) }(cloneTargetDir)
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
		},
	}

	_, _ = loc.Client.Call(ctx, "initialize", clientParams)

	testPath := filepath.Join(cloneTargetDir, "app.js")

	w := workspace.Get()
	f := workspace.NewFolder(c, cloneTargetDir, "Test", di.Scanner(), di.HoverService(), di.ScanNotifier(), di.Notifier())
	w.AddFolder(f)

	_ = textDocumentDidSave(t, &loc, testPath)

	assert.Eventually(t, checkForPublishedDiagnostics(t, testPath, 6, jsonRPCRecorder), maxIntegTestDuration, 10*time.Millisecond)
}

func textDocumentDidSave(t *testing.T, loc *server.Local, testPath string) sglsp.DidSaveTextDocumentParams {
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
