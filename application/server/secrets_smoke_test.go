/*
 * © 2026 Snyk Limited
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
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/folderconfig"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

const (
	secretsSmokeOrg = "9cff56cd-57d1-49b8-9238-69ebfde7142f" // devex_ide org
)

// Test_SmokeSecretsScan_UnsupportedFileDoesNotError validates IDE-1953:
// saving a binary (unsupported) file must not produce a "scan failed" error notification.
// The secrets engine filters binary files out (SNYK-CLI-0008) which should be treated as success.
func Test_SmokeSecretsScan_UnsupportedFileDoesNotError(t *testing.T) {
	engine, tokenService := testutil.SmokeTestWithEngine(t, "")
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingOrganization), secretsSmokeOrg)

	loc, jsonRPCRecorder := setupServer(t, engine, tokenService)
	enableOnlySecrets(engine)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingScanAutomatic), false)
	cleanupChannels()
	di.Init(engine, tokenService)

	// Workspace contains only a binary file — the secrets file filter rejects it
	// (returns SNYK-CLI-0008 / NoSupportedFilesFound), which should map to success, not error.
	workspaceDir := t.TempDir()
	binaryFile := filepath.Join(workspaceDir, "image.bin")
	// PNG magic bytes — definitively non-text, will be rejected by TextFileOnlyFilter
	require.NoError(t, os.WriteFile(binaryFile, []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a}, 0600))

	folderConfig := config.GetFolderConfigFromEngine(engine, di.ConfigResolver(), types.FilePath(workspaceDir), engine.GetLogger())
	require.NotNil(t, folderConfig)
	types.SetPreferredOrgAndOrgSetByUser(engine.GetConfiguration(), types.FilePath(workspaceDir), secretsSmokeOrg, true)

	// The server sends branch info in $/snyk.configuration only for git repos; init one so
	// receivedFolderConfigNotification can confirm the folder was registered.
	gitCmds := [][]string{
		{"init"},
		{"config", "user.email", "test@test.com"},
		{"config", "user.name", "test"},
		{"add", "image.bin"},
		{"commit", "-m", "initial"},
	}
	for _, args := range gitCmds {
		cmd := exec.Command("git", args...)
		cmd.Dir = workspaceDir
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "git %v: %s", args, out)
	}

	initParams := prepareInitParams(t, types.FilePath(workspaceDir), engine)
	initParams.ClientInfo.Name = "snyk-ls-secrets-smoke"
	initParams.InitializationOptions.IntegrationName = "ls-secrets-smoke"
	ensureInitialized(t, engine, tokenService, loc, initParams, nil)

	// Wait for the server to register the folder before configuring it
	require.Eventually(t, func() bool {
		notifications := jsonRPCRecorder.FindNotificationsByMethod("$/snyk.configuration")
		return receivedFolderConfigNotification(t, notifications, types.FilePath(workspaceDir))
	}, time.Minute, time.Millisecond, "did not receive folder config notification")

	_, err := loc.Client.Call(t.Context(), "workspace/executeCommand", sglsp.ExecuteCommandParams{
		Command:   "snyk.workspaceFolder.scan",
		Arguments: []any{workspaceDir},
	})
	require.NoError(t, err)

	waitForScan(t, workspaceDir, engine)

	// Assert at least one $/snyk.scan notification for secrets was received, then verify none is ErrorStatus.
	secretsProduct := product.ProductSecrets.ToProductCodename()
	require.Eventually(t, func() bool {
		for _, n := range jsonRPCRecorder.FindNotificationsByMethod("$/snyk.scan") {
			var p types.SnykScanParams
			_ = n.UnmarshalParams(&p)
			if p.Product == secretsProduct && p.FolderPath == types.FilePath(workspaceDir) && p.Status != types.InProgress {
				return true
			}
		}
		return false
	}, time.Minute, time.Millisecond, "expected at least one completed $/snyk.scan notification for secrets product")

	for _, n := range jsonRPCRecorder.FindNotificationsByMethod("$/snyk.scan") {
		var scanParams types.SnykScanParams
		_ = n.UnmarshalParams(&scanParams)
		if scanParams.Product != secretsProduct || scanParams.FolderPath != types.FilePath(workspaceDir) {
			continue
		}
		assert.NotEqual(t, types.ErrorStatus, scanParams.Status,
			"secrets scan of an unsupported binary file must not produce an error notification (IDE-1953)")
	}
}

func Test_SmokeSecretsScan(t *testing.T) {
	// Secret scanning is only available in pre-prod; use the pre-prod token
	engine, tokenService := testutil.SmokeTestWithEngine(t, "")
	engineConfig := engine.GetConfiguration()
	engineConfig.Set(configresolver.UserGlobalKey(types.SettingOrganization), secretsSmokeOrg)

	loc, jsonRPCRecorder := setupServer(t, engine, tokenService)
	enableOnlySecrets(engine)
	cleanupChannels()
	di.Init(engine, tokenService)

	// Clone the fake-leaks repo which contains intentional hardcoded secrets for testing
	cloneTargetDir, err := folderconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), testsupport.FakeLeaks, "", engine.GetLogger(), false)
	require.NoError(t, err)
	cloneTargetDirString := string(cloneTargetDir)

	// Configure the folder with the pre-prod org and enable the secrets feature flag
	folderConfig := config.GetFolderConfigFromEngine(engine, di.ConfigResolver(), types.FilePath(cloneTargetDirString), engine.GetLogger())
	types.SetPreferredOrgAndOrgSetByUser(engineConfig, folderConfig.FolderPath, secretsSmokeOrg, true)

	initParams := prepareInitParams(t, cloneTargetDir, engine)
	// Use short names to keep the User-Agent header under the 200-char API limit
	initParams.ClientInfo.Name = "snyk-ls-secrets-smoke"
	initParams.InitializationOptions.IntegrationName = "ls-secrets-smoke"
	ensureInitialized(t, engine, tokenService, loc, initParams, nil)

	// Wait for folder config to be received within $/snyk.configuration
	require.Eventually(t, func() bool {
		notifications := jsonRPCRecorder.FindNotificationsByMethod("$/snyk.configuration")
		return receivedFolderConfigNotification(t, notifications, cloneTargetDir)
	}, time.Minute, time.Millisecond, "did not receive folder configs in $/snyk.configuration")

	require.NotNil(t, folderConfig)

	require.NoError(t, err)

	// Trigger a workspace scan
	_, err = loc.Client.Call(t.Context(), "workspace/executeCommand", sglsp.ExecuteCommandParams{
		Command:   "snyk.workspaceFolder.scan",
		Arguments: []any{cloneTargetDirString},
	})
	require.NoError(t, err)

	waitForScan(t, cloneTargetDirString, engine)

	// Collect all secrets issues from diagnostics
	issueList := getIssueListFromPublishDiagnosticsNotification(t, jsonRPCRecorder, product.ProductSecrets, cloneTargetDir)

	require.NotEmpty(t, issueList, "expected at least one secret finding from fake-leaks repo")

	// Verify issue structure
	for _, issue := range issueList {
		assert.NotEmpty(t, issue.Id, "issue should have an ID")
		assert.NotEmpty(t, issue.Title, "issue should have a title")
		assert.NotEmpty(t, issue.FilePath, "issue should have a file path")
		assert.NotEmpty(t, issue.Severity, "issue should have a severity")
		assert.Equal(t, product.FilterableIssueTypeSecrets, issue.FilterableIssueType,
			"issue should be of type secret")

		// Verify additional data is SecretsIssueData
		if additionalData, ok := issue.AdditionalData.(map[string]interface{}); ok {
			assert.Contains(t, additionalData, "ruleId", "additional data should contain ruleId")
			assert.Contains(t, additionalData, "key", "additional data should contain key")
		} else if secretData, ok := issue.AdditionalData.(snyk.SecretsIssueData); ok {
			assert.NotEmpty(t, secretData.RuleId, "secret issue data should have ruleId")
			assert.NotEmpty(t, secretData.Key, "secret issue data should have key")
		}
	}
}

func enableOnlySecrets(engine workflow.Engine) {
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), false)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), false)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), false)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykSecretsEnabled), true)
}
