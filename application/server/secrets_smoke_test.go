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
	"testing"
	"time"

	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	secretsSmokeOrg         = "a16eb5a4-7283-45e9-949f-84696bd22bda" // devex_ide org
)

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

		// Verify additional data is SecretIssueData
		if additionalData, ok := issue.AdditionalData.(map[string]interface{}); ok {
			assert.Contains(t, additionalData, "ruleId", "additional data should contain ruleId")
			assert.Contains(t, additionalData, "key", "additional data should contain key")
		} else if secretData, ok := issue.AdditionalData.(snyk.SecretIssueData); ok {
			assert.NotEmpty(t, secretData.RuleId, "secret issue data should have ruleId")
			assert.NotEmpty(t, secretData.Key, "secret issue data should have key")
		}
	}
}
