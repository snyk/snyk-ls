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

	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

const (
	secretsSmokeTokenEnvVar = "SNYK_DEV_TOKEN"
	secretsSmokeDefaultAPI  = "https://api.dev.snyk.io"
	secretsSmokeOrg         = "9cff56cd-57d1-49b8-9238-69ebfde7142f" // devex_ide org
)

// Test_SmokeSecretsScan_UnsupportedFileDoesNotError validates IDE-1953:
// saving a binary (unsupported) file must not produce a "scan failed" error
// notification. The secrets engine filters binary files out (SNYK-CLI-0008
// NoSupportedFilesFound) which should be treated as success.
func Test_SmokeSecretsScan_UnsupportedFileDoesNotError(t *testing.T) {
	if len(os.Getenv("CI")) > 0 {
		t.Skip("temporary skipped (still in CB)")
	}

	c := testutil.SmokeTest(t, "")

	loc, jsonRPCRecorder := setupServer(t, c)
	enableOnlySecrets(c)
	cleanupChannels()
	di.Init()

	// Workspace contains only a binary file — the secrets file filter rejects it
	// (returns SNYK-CLI-0008 / NoSupportedFilesFound), which should map to success, not error.
	workspaceDir := t.TempDir()
	binaryFile := filepath.Join(workspaceDir, "image.bin")
	// PNG magic bytes — definitively non-text, will be rejected by TextFileOnlyFilter
	require.NoError(t, os.WriteFile(binaryFile, []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a}, 0600))

	// The server only emits $/snyk.folderConfigs for git repos; init one so the
	// folder is treated as a real workspace and we get a folderConfig notification.
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

	initParams := prepareInitParams(t, types.FilePath(workspaceDir), c)
	initParams.ClientInfo.Name = "snyk-ls-secrets-smoke"
	initParams.InitializationOptions.IntegrationName = "ls-secrets-smoke"
	ensureInitialized(t, c, loc, initParams, nil)

	// Wait for the server to register the folder before configuring it.
	require.Eventually(t, func() bool {
		notifications := jsonRPCRecorder.FindNotificationsByMethod("$/snyk.folderConfigs")
		return receivedFolderConfigNotification(t, notifications, types.FilePath(workspaceDir))
	}, time.Minute, 100*time.Millisecond, "did not receive folder config notification")

	// Wire the pre-prod org and the secrets feature flag onto the folder.
	folderConfig := c.FolderConfig(types.FilePath(workspaceDir))
	require.NotNil(t, folderConfig)
	folderConfig.PreferredOrg = secretsSmokeOrg
	folderConfig.OrgSetByUser = true
	if folderConfig.FeatureFlags == nil {
		folderConfig.FeatureFlags = map[string]bool{}
	}
	folderConfig.FeatureFlags[featureflag.SnykSecretsEnabled] = true
	require.NoError(t, c.UpdateFolderConfig(folderConfig))

	_, err := loc.Client.Call(t.Context(), "workspace/executeCommand", sglsp.ExecuteCommandParams{
		Command:   "snyk.workspaceFolder.scan",
		Arguments: []any{workspaceDir},
	})
	require.NoError(t, err)

	waitForScan(t, workspaceDir, c)

	// Assert at least one $/snyk.scan notification for secrets was received, then verify none is ErrorStatus.
	secretsProduct := product.ProductSecrets.ToProductCodename()
	var scanParam types.SnykScanParams
	require.Eventually(t, func() bool {
		for _, n := range jsonRPCRecorder.FindNotificationsByMethod("$/snyk.scan") {
			var p types.SnykScanParams
			if err := n.UnmarshalParams(&p); err != nil {
				continue
			}
			if p.Product == secretsProduct && p.FolderPath == types.FilePath(workspaceDir) && p.Status != types.InProgress {
				scanParam = p
				return true
			}
		}
		return false
	}, time.Minute, 100*time.Millisecond, "expected at least one completed $/snyk.scan notification for secrets product")

	assert.NotEqual(t, types.ErrorStatus, scanParam.Status,
		"secrets scan of an unsupported binary file must not produce an error notification")
}

func enableOnlySecrets(c *config.Config) {
	c.SetSnykCodeEnabled(false)
	c.SetSnykOssEnabled(false)
	c.SetSnykIacEnabled(false)
	c.SetSnykSecretsEnabled(true)
	c.SetAutomaticScanning(false)
}

func Test_SmokeSecretsScan(t *testing.T) {
	t.Skip("skipping secrets smoke test until secret scanner is deployed to prod")
	// Secret scanning is only available in pre-prod; use the pre-prod token
	c := testutil.SmokeTest(t, secretsSmokeTokenEnvVar)
	// Point to the pre-prod API endpoint
	c.UpdateApiEndpoints(secretsSmokeDefaultAPI)

	loc, jsonRPCRecorder := setupServer(t, c)
	c.SetSnykCodeEnabled(false)
	c.SetSnykOssEnabled(false)
	c.SetSnykIacEnabled(false)
	c.SetSnykSecretsEnabled(true)
	c.SetAutomaticScanning(false)
	cleanupChannels()
	di.Init()

	// Clone the fake-leaks repo which contains intentional hardcoded secrets for testing
	cloneTargetDir, err := storedconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), testsupport.FakeLeaks, "", c.Logger(), false)
	require.NoError(t, err)
	cloneTargetDirString := string(cloneTargetDir)

	initParams := prepareInitParams(t, cloneTargetDir, c)
	// Use short names to keep the User-Agent header under the 200-char API limit
	initParams.ClientInfo.Name = "snyk-ls-secrets-smoke"
	initParams.InitializationOptions.IntegrationName = "ls-secrets-smoke"
	ensureInitialized(t, c, loc, initParams, nil)

	// Wait for folder config to be received
	require.Eventually(t, func() bool {
		notifications := jsonRPCRecorder.FindNotificationsByMethod("$/snyk.folderConfigs")
		return receivedFolderConfigNotification(t, notifications, cloneTargetDir)
	}, time.Minute, 100*time.Millisecond, "did not receive folder configs")

	// Configure the folder with the pre-prod org and enable the secrets feature flag
	folderConfig := c.FolderConfig(types.FilePath(cloneTargetDirString))
	require.NotNil(t, folderConfig)
	folderConfig.PreferredOrg = secretsSmokeOrg
	folderConfig.OrgSetByUser = true
	folderConfig.FeatureFlags[featureflag.SnykSecretsEnabled] = true

	err = c.UpdateFolderConfig(folderConfig)
	require.NoError(t, err)

	// Trigger a workspace scan
	_, err = loc.Client.Call(t.Context(), "workspace/executeCommand", sglsp.ExecuteCommandParams{
		Command:   "snyk.workspaceFolder.scan",
		Arguments: []any{cloneTargetDirString},
	})
	require.NoError(t, err)

	waitForScan(t, cloneTargetDirString, c)

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
