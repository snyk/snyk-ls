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
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/server"
	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/internal/lsp"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/uri"
)

func Test_SmokeWorkspaceScan(t *testing.T) {
	ossFile := "package.json"
	iacFile := "main.tf"
	codeFile := "app.js"

	type test struct {
		name                 string
		repo                 string
		commit               string
		file1                string
		file2                string
		useConsistentIgnores bool
	}

	tests := []test{
		{
			name:                 "OSS and Code",
			repo:                 "https://github.com/snyk-labs/nodejs-goof",
			commit:               "0336589",
			file1:                ossFile,
			file2:                codeFile,
			useConsistentIgnores: false,
		},
		{
			name:                 "OSS and Code with consistent ignores",
			repo:                 "https://github.com/snyk-labs/nodejs-goof",
			commit:               "0336589",
			file1:                ossFile,
			file2:                codeFile,
			useConsistentIgnores: true,
		},
		{
			name:                 "IaC and Code",
			repo:                 "https://github.com/deepcodeg/snykcon-goof.git",
			commit:               "eba8407",
			file1:                iacFile,
			file2:                codeFile,
			useConsistentIgnores: false,
		},
		{
			name:                 "IaC and Code with consistent ignores",
			repo:                 "https://github.com/deepcodeg/snykcon-goof.git",
			commit:               "eba8407",
			file1:                iacFile,
			file2:                codeFile,
			useConsistentIgnores: true,
		},
		{
			name:                 "Two upload batches",
			repo:                 "https://github.com/apache/maven",
			commit:               "18725ec1e",
			file1:                "",
			file2:                "maven-compat/src/test/java/org/apache/maven/repository/legacy/LegacyRepositorySystemTest.java",
			useConsistentIgnores: false,
		},
		{
			name:                 "Two upload batches with consistent ignores",
			repo:                 "https://github.com/apache/maven",
			commit:               "18725ec1e",
			file1:                "",
			file2:                "maven-compat/src/test/java/org/apache/maven/repository/legacy/LegacyRepositorySystemTest.java",
			useConsistentIgnores: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runSmokeTest(t, tc.repo, tc.commit, tc.file1, tc.file2, tc.useConsistentIgnores)
		})
	}
}

func Test_SmokeIssueCaching(t *testing.T) {
	loc := setupServer(t)
	c := testutil.SmokeTest(t, false)
	c.SetSnykCodeEnabled(true)
	c.SetSnykOssEnabled(true)
	c.SetSnykIacEnabled(false)
	di.Init()

	var cloneTargetDir = setupRepoAndInitialize(t, "https://github.com/snyk-labs/nodejs-goof", "0336589", loc)
	folder := workspace.Get().GetFolderContaining(cloneTargetDir)

	// wait till the whole workspace is scanned
	assert.Eventually(t, func() bool {
		return folder != nil && folder.IsScanned()
	}, maxIntegTestDuration, time.Millisecond)

	ossIssuesForFile := folder.IssuesForFile(filepath.Join(cloneTargetDir, "package.json"))
	require.Greater(t, len(ossIssuesForFile), 108) // 108 is the number of issues in the package.json file as of now

	codeIssuesForFile := folder.IssuesForFile(filepath.Join(cloneTargetDir, "app.js"))
	require.Greater(t, len(codeIssuesForFile), 5) // 5 is the number of issues in the app.js file as of now

	_, err := loc.Client.Call(context.Background(), "workspace/executeCommand", sglsp.ExecuteCommandParams{
		Command: "snyk.workspace.scan",
	})
	require.NoError(t, err)

	// wait till the whole workspace is scanned
	assert.Eventually(t, func() bool {
		return folder != nil && folder.IsScanned()
	}, maxIntegTestDuration, time.Millisecond)

	ossIssuesForFileSecondScan := folder.IssuesForFile(filepath.Join(cloneTargetDir, "package.json"))
	require.Equal(t, len(ossIssuesForFile), len(ossIssuesForFileSecondScan))

	codeIssuesForFileSecondScan := folder.IssuesForFile(filepath.Join(cloneTargetDir, "app.js"))
	require.Equal(t, len(codeIssuesForFile), len(codeIssuesForFileSecondScan))

}

func runSmokeTest(t *testing.T, repo string, commit string, file1 string, file2 string, useConsistentIgnores bool) {
	t.Helper()
	loc := setupServer(t)
	c := testutil.SmokeTest(t, useConsistentIgnores)
	c.SetSnykCodeEnabled(true)
	c.SetSnykIacEnabled(true)
	c.SetSnykOssEnabled(true)
	jsonRPCRecorder.ClearCallbacks()
	jsonRPCRecorder.ClearNotifications()
	cleanupChannels()
	di.Init()

	cloneTargetDir := setupRepoAndInitialize(t, repo, commit, loc)

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
		assert.Eventually(t, checkForPublishedDiagnostics(testPath, -1), maxIntegTestDuration, 10*time.Millisecond)
	}

	jsonRPCRecorder.ClearNotifications()
	testPath = filepath.Join(cloneTargetDir, file2)
	textDocumentDidSave(t, &loc, testPath)

	assert.Eventually(t, checkForPublishedDiagnostics(testPath, -1), maxIntegTestDuration, 10*time.Millisecond)

	// check for snyk scan message & check autofix
	var notifications []jrpc2.Request
	var scanParams lsp.SnykScanParams
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
	assert.Greater(t, len(scanParams.Issues), 0)
	for _, issue := range scanParams.Issues {
		codeIssueData, ok := issue.AdditionalData.(map[string]interface{})
		if !ok || codeIssueData["hasAIFix"] == false {
			continue
		}
		call, err := loc.Client.Call(ctx, "workspace/executeCommand", sglsp.ExecuteCommandParams{
			Command:   snyk.CodeFixDiffsCommand,
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

	checkFeatureFlagStatus(t, &loc)
}

func setupRepoAndInitialize(t *testing.T, repo string, commit string, loc server.Local) string {
	t.Helper()
	var cloneTargetDir, err = setupCustomTestRepo(t, repo, commit)
	if err != nil {
		t.Fatal(err, "Couldn't setup test repo")
	}

	folder := lsp.WorkspaceFolder{
		Name: "Test Repo",
		Uri:  uri.PathToUri(cloneTargetDir),
	}

	clientParams := lsp.InitializeParams{
		WorkspaceFolders: []lsp.WorkspaceFolder{folder},
		InitializationOptions: lsp.Settings{
			Endpoint:                    os.Getenv("SNYK_API"),
			Token:                       os.Getenv("SNYK_TOKEN"),
			EnableTrustedFoldersFeature: "false",
			FilterSeverity:              lsp.DefaultSeverityFilter(),
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

func checkFeatureFlagStatus(t *testing.T, loc *server.Local) {
	t.Helper()

	call, err := loc.Client.Call(ctx, "workspace/executeCommand", sglsp.ExecuteCommandParams{
		Command:   snyk.GetFeatureFlagStatus,
		Arguments: []any{"bitbucketConnectApp"},
	})

	assert.NoError(t, err)

	if err := call.Error(); err != nil {
		log.Error().Err(err).Msg("FeatureFlagStatus Command failed")
	}

	log.Debug().Str("FeatureFlagStatus", call.ResultString()).Msg("Command result")

	var result map[string]any
	if err := json.Unmarshal([]byte(call.ResultString()), &result); err != nil {
		t.Fatal("Failed to parse the command result", err)
	}

	ok, _ := result["ok"].(bool)
	assert.True(t, ok)
}

func Test_SmokeSnykCodeFileScan(t *testing.T) {
	loc := setupServer(t)
	testutil.SmokeTest(t, false)
	config.CurrentConfig().SetSnykCodeEnabled(true)
	jsonRPCRecorder.ClearCallbacks()
	jsonRPCRecorder.ClearNotifications()
	cleanupChannels()
	di.Init()

	var cloneTargetDir, err = setupCustomTestRepo(t, "https://github.com/snyk-labs/nodejs-goof", "0336589")
	defer func(path string) { _ = os.RemoveAll(path) }(cloneTargetDir)
	if err != nil {
		t.Fatal(err, "Couldn't setup test repo")
	}

	folder := lsp.WorkspaceFolder{
		Name: "Test Repo",
		Uri:  uri.PathToUri(cloneTargetDir),
	}

	clientParams := lsp.InitializeParams{
		WorkspaceFolders: []lsp.WorkspaceFolder{folder},
		InitializationOptions: lsp.Settings{
			Endpoint:                    os.Getenv("SNYK_API"),
			Token:                       os.Getenv("SNYK_TOKEN"),
			EnableTrustedFoldersFeature: "false",
			FilterSeverity:              lsp.DefaultSeverityFilter(),
		},
	}

	_, _ = loc.Client.Call(ctx, "initialize", clientParams)

	testPath := filepath.Join(cloneTargetDir, "app.js")

	w := workspace.Get()
	f := workspace.NewFolder(cloneTargetDir, "Test", di.Scanner(), di.HoverService(), di.ScanNotifier(), di.Notifier())
	w.AddFolder(f)

	_ = textDocumentDidSave(t, &loc, testPath)

	assert.Eventually(t, checkForPublishedDiagnostics(testPath, 6), maxIntegTestDuration, 10*time.Millisecond)
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
