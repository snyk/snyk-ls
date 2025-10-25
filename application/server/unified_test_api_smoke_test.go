/*
 * © 2025 Snyk Limited
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
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

const (
	tokenSecretNameForRiskScore = "SNYK_TOKEN_OSTEST"
	FeatureFlagRiskScore        = "feature_flag_experimental_risk_score"
	FeatureFlagRiskScoreInCLI   = "feature_flag_experimental_risk_score_in_cli"
)

func TestUnifiedTestApiSmokeTest(t *testing.T) {
	c, loc, jsonRPCRecorder := setupOSSComparisonTest(t)

	// -----------------------------------------
	// setup test repo
	// -----------------------------------------
	cloneTargetDir, err := storedconfig.SetupCustomTestRepo(t, types.FilePath(t.TempDir()), testsupport.NodejsGoof, "0336589", c.Logger())
	if err != nil {
		t.Fatal(err, "Couldn't setup test repo")
	}
	cloneTargetDirString := (string)(cloneTargetDir)

	// -----------------------------------------
	// initialize language server
	// -----------------------------------------
	manifestFile := "package.json"

	initParams := prepareInitParams(t, cloneTargetDir, c)
	ensureInitialized(t, c, loc, initParams, func(c *config.Config) {
		substituteDepGraphFlow(t, c, cloneTargetDirString, manifestFile)
		c.SetAutomaticScanning(false)
	})

	// -----------------------------------------
	// unified test api scan
	// -----------------------------------------

	setRiskScoreFeatureFlagsFromGafConfig(t, c, cloneTargetDirString, true)

	_, err = loc.Client.Call(t.Context(), "workspace/executeCommand", sglsp.ExecuteCommandParams{
		Command:   "snyk.workspaceFolder.scan",
		Arguments: []any{cloneTargetDirString},
	})

	require.NoError(t, err)
	waitForScan(t, cloneTargetDirString, c)

	testPath := types.FilePath(filepath.Join(cloneTargetDirString, manifestFile))

	assert.Eventually(t, checkForPublishedDiagnostics(t, c, testPath, -1, jsonRPCRecorder), maxIntegTestDuration, 10*time.Millisecond)

	notifications := jsonRPCRecorder.FindNotificationsByMethod("textDocument/publishDiagnostics")
	if len(notifications) < 1 {
		t.Fatal("expected at least one notification")
	}

	unifiedDiagnostics := extractDiagnostics(t, notifications, testPath)
	jsonRPCRecorder.ClearNotifications()
	_ = loc.Client.Close()
	loc.Server.Stop()

	// -----------------------------------------
	// legacy scan - reset
	// -----------------------------------------

	c, loc, jsonRPCRecorder = setupOSSComparisonTest(t)

	// -----------------------------------------
	// initialize language server
	// -----------------------------------------
	initParams = prepareInitParams(t, cloneTargetDir, c)
	ensureInitialized(t, c, loc, initParams, func(c *config.Config) {
		c.SetAutomaticScanning(false)
	})

	setRiskScoreFeatureFlagsFromGafConfig(t, c, cloneTargetDirString, false)

	_, err = loc.Client.Call(t.Context(), "workspace/executeCommand", sglsp.ExecuteCommandParams{
		Command:   "snyk.workspaceFolder.scan",
		Arguments: []any{cloneTargetDirString},
	})
	require.NoError(t, err)

	waitForScan(t, cloneTargetDirString, c)

	assert.Eventually(t, checkForPublishedDiagnostics(t, c, testPath, -1, jsonRPCRecorder), maxIntegTestDuration, 10*time.Millisecond)

	// save diagnostics
	legacyNotifications := jsonRPCRecorder.FindNotificationsByMethod("textDocument/publishDiagnostics")
	if len(notifications) < 1 {
		t.Fatal("expected at least one notification")
	}

	legacyDiagnostics := extractDiagnostics(t, legacyNotifications, testPath)

	// -----------------------------------------
	// compare diagnostics
	// -----------------------------------------
	assert.Equal(t, unifiedDiagnostics, legacyDiagnostics)
}

func setRiskScoreFeatureFlagsFromGafConfig(t *testing.T, c *config.Config, cloneTargetDirString string, enabled bool) {
	t.Helper()

	// -----------------------------------------
	// Set feature flags
	// -----------------------------------------
	engine := c.Engine()
	gafConfig := engine.GetConfiguration()
	gafConfig.Set(FeatureFlagRiskScore, enabled)
	gafConfig.Set(FeatureFlagRiskScoreInCLI, enabled)
	folderConfig := c.FolderConfig(types.FilePath(cloneTargetDirString))
	folderConfig.FeatureFlags["useExperimentalRiskScore"] = engine.GetConfiguration().GetBool(FeatureFlagRiskScore)
	folderConfig.FeatureFlags["useExperimentalRiskScoreInCLI"] = engine.GetConfiguration().GetBool(FeatureFlagRiskScoreInCLI)
	err := storedconfig.UpdateFolderConfig(gafConfig, folderConfig, c.Logger())
	if err != nil {
		t.Fatal(err, "unable to update folder config")
	}
}

func setupOSSComparisonTest(t *testing.T) (*config.Config, server.Local, *testsupport.JsonRPCRecorder) {
	c := testutil.SmokeTest(t, tokenSecretNameForRiskScore)
	testutil.CreateDummyProgressListener(t)
	endpoint := os.Getenv("SNYK_API")
	if endpoint == "" {
		t.Setenv("SNYK_API", "https://api.snyk.io")
	}

	if endpoint != "" && endpoint != "/v1" {
		t.Setenv("SNYK_API", endpoint)
	}
	loc, jsonRPCRecorder := setupServer(t, c)
	c.SetSnykCodeEnabled(false)
	c.SetSnykIacEnabled(false)
	c.SetSnykOssEnabled(true)
	cleanupChannels()
	di.Init()
	return c, loc, jsonRPCRecorder
}

func extractDiagnostics(t *testing.T, notifications []jrpc2.Request, testPath types.FilePath) []types.Diagnostic {
	t.Helper()
	diagnostics := []types.Diagnostic{}
	for _, n := range notifications {
		diagnosticsParams := types.PublishDiagnosticsParams{}
		_ = n.UnmarshalParams(&diagnosticsParams)
		if diagnosticsParams.URI != uri.PathToUri(testPath) {
			t.Fatal("expected diagnostics for testPath")
		}
		diagnostics = append(diagnostics, diagnosticsParams.Diagnostics...)
	}
	return diagnostics
}
