/*
 * © 2024-2025 Snyk Limited
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
	"strings"
	"testing"

	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/infrastructure/configuration"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// Test_SmokeConfigurationDialog verifies that the configuration dialog:
// 1. Can be triggered via workspace/executeCommand
// 2. Sends window/showDocument callback with correct URI
// 3. Generated HTML includes ALL settings fields from types.Settings
// 4. Generated HTML includes ALL sub-fields from FolderConfig
// 5. Includes authentication and logout triggers
func Test_SmokeConfigurationDialog(t *testing.T) {
	if os.Getenv("SMOKE_TESTS") != "1" {
		t.Skip("Skipping smoke test")
	}

	c := testutil.SmokeTest(t, "")
	testutil.CreateDummyProgressListener(t)

	t.Run("Configuration Command Execution via LSP", func(t *testing.T) {
		// Setup server with LSP client
		loc, jsonRPCRecorder := setupServer(t, c)
		di.Init()

		// Execute the configuration command via LSP
		_, err := loc.Client.Call(t.Context(), "workspace/executeCommand", sglsp.ExecuteCommandParams{
			Command:   types.WorkspaceConfigurationCommand,
			Arguments: []any{},
		})

		require.NoError(t, err, "Configuration command should execute successfully")

		// Verify window/showDocument callback was sent
		callbacks := jsonRPCRecorder.FindCallbacksByMethod("window/showDocument")
		require.Greater(t, len(callbacks), 0, "Should have sent window/showDocument callback")

		// Verify the callback parameters
		var showDocParams types.ShowDocumentParams
		err = callbacks[0].UnmarshalParams(&showDocParams)
		require.NoError(t, err)

		// Verify the URI is the settings URI
		assert.Equal(t, sglsp.DocumentURI("snyk://settings"), showDocParams.Uri, "Should show settings URI")
		assert.False(t, showDocParams.External, "Should open internally")
		assert.True(t, showDocParams.TakeFocus, "Should take focus")
	})

	t.Run("Configuration HTML Contains All Settings", func(t *testing.T) {
		// Setup server with LSP client
		loc, _ := setupServer(t, c)
		di.Init()

		// Execute command to trigger HTML generation
		_, err := loc.Client.Call(t.Context(), "workspace/executeCommand", sglsp.ExecuteCommandParams{
			Command:   types.WorkspaceConfigurationCommand,
			Arguments: []any{},
		})
		require.NoError(t, err)

		// Generate HTML directly to validate content (command execution is tested above)
		renderer, err := configuration.NewConfigHtmlRenderer(c)
		require.NoError(t, err)
		require.NotNil(t, renderer)

		// Create a comprehensive settings object with all fields populated
		settings := createComprehensiveSettings()

		// Generate HTML
		html := renderer.GetConfigHtml(settings)
		require.NotEmpty(t, html)

		// Verify all GLOBAL settings are present in HTML
		t.Run("Global Settings Fields", func(t *testing.T) {
			// Core authentication settings
			assertFieldPresent(t, html, "token", "Token field")
			assertFieldPresent(t, html, "endpoint", "Endpoint field")

			// Product activation settings
			assertFieldPresent(t, html, "activateSnykOpenSource", "ActivateSnykOpenSource field")
			assertFieldPresent(t, html, "activateSnykCode", "ActivateSnykCode field")
			assertFieldPresent(t, html, "activateSnykIac", "ActivateSnykIac field")
			assertFieldPresent(t, html, "activateSnykCodeSecurity", "ActivateSnykCodeSecurity field")
			assertFieldPresent(t, html, "activateSnykCodeQuality", "ActivateSnykCodeQuality field")

			// CLI and path settings
			assertFieldPresent(t, html, "cliPath", "CliPath field")
			assertFieldPresent(t, html, "path", "Path field")

			// Security and trust settings
			assertFieldPresent(t, html, "insecure", "Insecure field")
			assertFieldPresent(t, html, "enableTrustedFoldersFeature", "EnableTrustedFoldersFeature field")

			// Operational settings
			assertFieldPresent(t, html, "sendErrorReports", "SendErrorReports field")
			assertFieldPresent(t, html, "manageBinariesAutomatically", "ManageBinariesAutomatically field")
			assertFieldPresent(t, html, "scanningMode", "ScanningMode field")
			assertFieldPresent(t, html, "authenticationMethod", "AuthenticationMethod field")

			// Advanced settings
			assertFieldPresent(t, html, "snykCodeApi", "SnykCodeApi field")

			// Feature toggles
			assertFieldPresent(t, html, "enableSnykLearnCodeActions", "EnableSnykLearnCodeActions field")
			assertFieldPresent(t, html, "enableSnykOSSQuickFixCodeActions", "EnableSnykOSSQuickFixCodeActions field")
			assertFieldPresent(t, html, "enableSnykOpenBrowserActions", "EnableSnykOpenBrowserActions field")
			assertFieldPresent(t, html, "enableDeltaFindings", "EnableDeltaFindings field")

			// Filter and display settings
			assertFieldPresent(t, html, "filterSeverity", "FilterSeverity field")
			assertFieldPresent(t, html, "hoverVerbosity", "HoverVerbosity field")
			assertFieldPresent(t, html, "outputFormat", "OutputFormat field")

			// Legacy folder-level settings (TODO: move to folder config)
			assertFieldPresent(t, html, "additionalParams", "AdditionalParams field")
			assertFieldPresent(t, html, "additionalEnv", "AdditionalEnv field")
			assertFieldPresent(t, html, "trustedFolders", "TrustedFolders field")

			// Issue view options (complex object)
			assertFieldPresent(t, html, "issueViewOptions", "IssueViewOptions field")
		})

		t.Run("Folder-Specific Settings Fields", func(t *testing.T) {
			// Verify folder configs section exists
			assert.Contains(t, html, "Folder Settings", "Folder Settings section should be present")

			// Verify all FolderConfig fields are present
			assertFieldPresent(t, html, "folderPath", "FolderPath field")
			assertFieldPresent(t, html, "baseBranch", "BaseBranch field")
			assertFieldPresent(t, html, "localBranches", "LocalBranches field")
			assertFieldPresent(t, html, "additionalParameters", "AdditionalParameters field")
			assertFieldPresent(t, html, "referenceFolderPath", "ReferenceFolderPath field")
			assertFieldPresent(t, html, "preferredOrg", "PreferredOrg field")
			assertFieldPresent(t, html, "autoDeterminedOrg", "AutoDeterminedOrg field")
			assertFieldPresent(t, html, "orgMigratedFromGlobalConfig", "OrgMigratedFromGlobalConfig field")
			assertFieldPresent(t, html, "orgSetByUser", "OrgSetByUser field")
			assertFieldPresent(t, html, "featureFlags", "FeatureFlags field")
			assertFieldPresent(t, html, "riskScoreThreshold", "RiskScoreThreshold field")

			// Scan command config fields (pre/post scan commands per product)
			assertFieldPresent(t, html, "scanConfig_oss_preScanCommand", "ScanConfig OSS PreScanCommand field")
			assertFieldPresent(t, html, "scanConfig_oss_postScanCommand", "ScanConfig OSS PostScanCommand field")
			assertFieldPresent(t, html, "scanConfig_code_preScanCommand", "ScanConfig Code PreScanCommand field")
			assertFieldPresent(t, html, "scanConfig_iac_preScanCommand", "ScanConfig IaC PreScanCommand field")
		})

		t.Run("Authentication and Logout Triggers", func(t *testing.T) {
			// Verify authentication and logout buttons are present
			assert.Contains(t, html, "Authenticate", "Authentication button should be present")
			assert.Contains(t, html, "authenticate-btn", "Authentication button ID should be present")
			assert.Contains(t, html, "Logout", "Logout button should be present")
			assert.Contains(t, html, "logout-btn", "Logout button ID should be present")

			// Verify IDE function placeholders for injection
			assert.Contains(t, html, "${ideLogin}", "ideLogin placeholder should be present")
			assert.Contains(t, html, "${ideSaveConfig}", "ideSaveConfig placeholder should be present")
			assert.Contains(t, html, "${ideLogout}", "ideLogout placeholder should be present")
		})

		t.Run("Endpoint Validation Logic", func(t *testing.T) {
			// Verify endpoint validation is present in JavaScript
			assert.Contains(t, html, "validateEndpoint", "Endpoint validation function should be present")
			assert.Contains(t, html, "endpoint-error", "Endpoint error element should be present")

			// Verify regex patterns for Snyk API endpoints (accounting for escaping in JavaScript)
			// The regex patterns will be escaped in the JavaScript, so we check for the domain parts
			assert.Contains(t, html, "snyk.io", "Snyk API domain should be present in validation")
			assert.Contains(t, html, "snykgov.io", "Snyk Gov API domain should be present in validation")
		})

		t.Run("Form Data Collection", func(t *testing.T) {
			// Verify form data collection function exists
			assert.Contains(t, html, "collectData", "collectData function should be present")
			assert.Contains(t, html, "configForm", "config form ID should be present")

			// Verify save functionality
			assert.Contains(t, html, "save-config-btn", "Save button should be present")
			assert.Contains(t, html, "Save Configuration", "Save button text should be present")
		})

		t.Run("IE7 Compatibility", func(t *testing.T) {
			// Verify no ES6+ syntax is used
			assert.NotContains(t, html, "=>", "Should not contain arrow functions")
			assert.NotContains(t, html, "let ", "Should not use 'let' keyword")
			assert.NotContains(t, html, "const ", "Should not use 'const' keyword")
			assert.Contains(t, html, "var ", "Should use 'var' keyword")

			// Verify IE7-compatible event handling
			assert.Contains(t, html, "attachEvent", "Should have attachEvent for IE7 compatibility")
		})

		t.Run("Value Population", func(t *testing.T) {
			// Verify that the values from settings are populated in the HTML
			assert.Contains(t, html, settings.Token, "Token value should be populated")
			assert.Contains(t, html, settings.Endpoint, "Endpoint value should be populated")

			// Verify folder config values are populated
			if len(settings.FolderConfigs) > 0 {
				fc := settings.FolderConfigs[0]
				assert.Contains(t, html, string(fc.FolderPath), "FolderPath value should be populated")
				assert.Contains(t, html, fc.BaseBranch, "BaseBranch value should be populated")
			}
		})

		t.Run("Security - Password Masking", func(t *testing.T) {
			// Verify token field is of type password
			assert.Contains(t, html, "type=\"password\"", "Token field should be password type")
		})
	})
}

// createComprehensiveSettings creates a Settings object with all fields populated for testing
func createComprehensiveSettings() types.Settings {
	severity := types.SeverityFilter{
		Critical: true,
		High:     true,
		Medium:   true,
		Low:      false,
	}

	hoverVerbosity := 2
	outputFormat := "json"

	return types.Settings{
		// Core authentication
		Token:                   "test-token-value",
		Endpoint:                "https://api.snyk.io",
		Organization:            "test-org",
		AuthenticationMethod:    types.TokenAuthentication,
		AutomaticAuthentication: "true",

		// Product activation
		ActivateSnykOpenSource:   "true",
		ActivateSnykCode:         "true",
		ActivateSnykIac:          "true",
		ActivateSnykCodeSecurity: "true",
		ActivateSnykCodeQuality:  "false",

		// CLI and paths
		CliPath: "/usr/local/bin/snyk",
		Path:    "/custom/path",

		// Security settings
		Insecure:                    "false",
		EnableTrustedFoldersFeature: "true",

		// Operational settings
		SendErrorReports:            "true",
		ManageBinariesAutomatically: "true",
		ScanningMode:                "auto",

		// Integration info
		IntegrationName:    "vscode",
		IntegrationVersion: "1.0.0",
		DeviceId:           "test-device-id",

		// Advanced settings
		SnykCodeApi: "https://deeproxy.snyk.io",

		// Feature toggles
		EnableSnykLearnCodeActions:       "true",
		EnableSnykOSSQuickFixCodeActions: "true",
		EnableSnykOpenBrowserActions:     "true",
		EnableDeltaFindings:              "true",

		// Filters and display
		FilterSeverity: &severity,
		HoverVerbosity: &hoverVerbosity,
		OutputFormat:   &outputFormat,

		// System information
		OsPlatform:     "linux",
		OsArch:         "amd64",
		RuntimeVersion: "1.0.0",
		RuntimeName:    "go",

		// Protocol
		RequiredProtocolVersion: "1.0",

		// Legacy folder settings
		AdditionalParams: "--debug",
		AdditionalEnv:    "DEBUG=true",
		TrustedFolders:   []string{"/trusted/path1", "/trusted/path2"},

		// Folder configs
		FolderConfigs: []types.FolderConfig{
			{
				FolderPath:                  "/test/folder/path",
				BaseBranch:                  "main",
				LocalBranches:               []string{"feature-1", "feature-2"},
				AdditionalParameters:        []string{"--severity-threshold=high"},
				ReferenceFolderPath:         "/reference/path",
				PreferredOrg:                "preferred-org-id",
				AutoDeterminedOrg:           "auto-org-id",
				OrgMigratedFromGlobalConfig: false,
				OrgSetByUser:                true,
				FeatureFlags: map[string]bool{
					"enableNewFeature":  true,
					"disableOldFeature": false,
				},
			},
		},
	}
}

// assertFieldPresent checks if a field name/id is present in the HTML
func assertFieldPresent(t *testing.T, html, fieldName, description string) {
	t.Helper()

	// Check for various ways a field might be present in HTML:
	// 1. As a name attribute: name="fieldName"
	// 2. As an id attribute: id="fieldName"
	// 3. As a folder-specific field: folder_0_fieldName
	fieldPatterns := []string{
		"name=\"" + fieldName + "\"",
		"id=\"" + fieldName + "\"",
		"name=\"folder_0_" + fieldName + "\"",
		"id=\"folder_0_" + fieldName + "\"",
		"folder_{{$index}}_" + fieldName,
	}

	found := false
	for _, pattern := range fieldPatterns {
		if strings.Contains(html, pattern) {
			found = true
			break
		}
	}

	if !found {
		// Also check if it's mentioned as a label or in comments
		if strings.Contains(strings.ToLower(html), strings.ToLower(fieldName)) {
			found = true
		}
	}

	assert.True(t, found, "%s must be present in configuration HTML (field: %s)", description, fieldName)
}
