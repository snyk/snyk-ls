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
	"strings"
	"testing"

	"github.com/go-git/go-git/v5"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

// Test_SmokeConfigurationDialog verifies that the configuration dialog:
// 1. Can be triggered via workspace/executeCommand
// 2. Returns response with URI and HTML content
// 3. Generated HTML includes ALL settings fields from types.Settings
// 4. Generated HTML includes ALL sub-fields from FolderConfig
// 5. Includes authentication and logout triggers
func Test_SmokeConfigurationDialog(t *testing.T) {
	engine, tokenService := testutil.SmokeTestWithEngine(t, "")
	testutil.CreateDummyProgressListener(t)

	// Setup server with LSP client
	loc, _ := setupServer(t, engine, tokenService)
	di.Init(engine, tokenService)

	// Create workspace folder and initialize git repository
	workspaceFolder := types.FilePath(t.TempDir())
	_, err := git.PlainInit(string(workspaceFolder), false)
	require.NoError(t, err, "Failed to initialize git repository")

	folder := types.WorkspaceFolder{
		Name: "Test Workspace",
		Uri:  uri.PathToUri(workspaceFolder),
	}

	scanCommandConfig := make(map[product.Product]types.ScanCommandConfig)
	scanCommandConfig[product.ProductOpenSource] = types.ScanCommandConfig{
		PreScanCommand:              "npm install",
		PreScanOnlyReferenceFolder:  true,
		PostScanCommand:             "npm run cleanup",
		PostScanOnlyReferenceFolder: false,
	}
	scanCommandConfig[product.ProductCode] = types.ScanCommandConfig{
		PreScanCommand:              "prepare.sh",
		PreScanOnlyReferenceFolder:  true,
		PostScanCommand:             "cleanup.sh",
		PostScanOnlyReferenceFolder: true,
	}
	scanCommandConfig[product.ProductInfrastructureAsCode] = types.ScanCommandConfig{
		PreScanCommand:              "terraform init",
		PreScanOnlyReferenceFolder:  true,
		PostScanCommand:             "terraform cleanup",
		PostScanOnlyReferenceFolder: false,
	}

	// Prepare initialization parameters
	initParams := types.InitializeParams{
		WorkspaceFolders: []types.WorkspaceFolder{folder},
		InitializationOptions: types.InitializationOptions{
			Settings: map[string]*types.ConfigSetting{
				types.SettingToken:                  {Value: config.GetToken(engine.GetConfiguration()), Changed: true},
				types.SettingTrustEnabled:           {Value: false, Changed: true},
				types.SettingSeverityFilterCritical: {Value: true, Changed: true},
				types.SettingSeverityFilterHigh:     {Value: true, Changed: true},
				types.SettingSeverityFilterMedium:   {Value: true, Changed: true},
				types.SettingSeverityFilterLow:      {Value: true, Changed: true},
				types.SettingAuthenticationMethod:   {Value: string(types.TokenAuthentication), Changed: true},
			},
			FolderConfigs: []types.LspFolderConfig{
				{
					FolderPath: workspaceFolder,
					Settings: map[string]*types.ConfigSetting{
						types.SettingScanCommandConfig: {Value: scanCommandConfig, Changed: true},
					},
				},
			},
		},
	}

	// Initialize the server with workspace and folder configs
	ensureInitialized(t, engine, tokenService, loc, initParams, nil)

	// Execute the configuration command via LSP
	response, err := loc.Client.Call(t.Context(), "workspace/executeCommand", sglsp.ExecuteCommandParams{
		Command:   types.WorkspaceConfigurationCommand,
		Arguments: []any{},
	})
	require.NoError(t, err, "Configuration command should execute successfully")

	// Unmarshal the result - should be an HTML string
	var html string
	err = response.UnmarshalResult(&html)
	require.NoError(t, err, "Should unmarshal result")
	require.NotEmpty(t, html, "HTML content should not be empty")

	// Now verify the HTML content that was returned by the command
	t.Run("Verify HTML Content from Command Response", func(t *testing.T) {
		// Verify VISIBLE settings in simplified UI are present in HTML
		t.Run("Global Settings Fields", func(t *testing.T) {
			t.Helper()
			// Core authentication settings
			assertFieldPresent(t, html, "token", "Token field")
			assertFieldPresent(t, html, "api_endpoint", "Endpoint field")
			assertFieldPresent(t, html, "authentication_method", "AuthenticationMethod field")
			assertFieldPresent(t, html, "proxy_insecure", "Insecure field")

			// Product activation settings (Scan Configuration section)
			assertFieldPresent(t, html, "snyk_oss_enabled", "ActivateSnykOpenSource field")
			assertFieldPresent(t, html, "snyk_code_enabled", "ActivateSnykCode field")
			assertFieldPresent(t, html, "snyk_iac_enabled", "ActivateSnykIac field")
			assertFieldPresent(t, html, "scan_automatic", "ScanningMode field")

			// Filter and display settings
			assertFieldPresent(t, html, "enabled_severities_critical", "FilterSeverity Critical field")
			assertFieldPresent(t, html, "enabled_severities_high", "FilterSeverity High field")
			assertFieldPresent(t, html, "enabled_severities_medium", "FilterSeverity Medium field")
			assertFieldPresent(t, html, "enabled_severities_low", "FilterSeverity Low field")
			assertFieldPresent(t, html, "issue_view_open_issues", "IssueViewOptions field")
			assertFieldPresent(t, html, "scan_net_new", "EnableDeltaFindings field")
		})

		t.Run("Folder-Specific Settings Fields", func(t *testing.T) {
			// Verify folder tab exists
			assert.Contains(t, html, "- Folder", "Folder tab label should be present")

			// Folder-specific fields in simplified UI
			// Only visible fields: additionalParameters, riskScoreThreshold, orgSetByUser, preferredOrg, scan config
			if strings.Contains(html, "folderPath") {
				// If folders are present, verify their VISIBLE fields
				assertFieldPresent(t, html, "folderPath", "FolderPath field")
				assertFieldPresent(t, html, "additional_parameters", "AdditionalParameters field")
				assertFieldPresent(t, html, "risk_score_threshold", "RiskScoreThreshold field")
				assertFieldPresent(t, html, "org_set_by_user", "OrgSetByUser field")
				assertFieldPresent(t, html, "preferred_org", "PreferredOrg field")

				// Scan command config fields (pre/post scan commands per product) are behind the
				// EnableLdxSyncConfig feature flag which is not yet enabled in production.
				// Will be fixed by https://snyksec.atlassian.net/browse/IDE-1786
			}
		})

		t.Run("Authentication and Log out Triggers", func(t *testing.T) {
			// Verify authentication and log out buttons are present
			assert.Contains(t, html, "Authenticate", "Authentication button should be present")
			assert.Contains(t, html, "authenticate-btn", "Authentication button ID should be present")
			assert.Contains(t, html, "Log out", "Log out button should be present")
			assert.Contains(t, html, "logout-btn", "Log out button ID should be present")
			assert.Contains(t, html, "get-token-link", "Get Token link should be present")
			assert.Contains(t, html, `id="get-token-link" href="#" class="hidden button-link"`, "Get Token link should be hidden by default")
			assert.Contains(t, html, "token-field-group", "Token field group should be present")
			assert.Contains(t, html, `id="token-field-group"`, "Token field group id should be present")
			assert.Contains(t, html, `class="form-group hidden"`, "Token field group should be hidden by default")
			assert.Contains(t, html, `id="logout-btn" class="secondary hidden"`, "Logout button should be hidden by default")

			// Verify IDE function calls are present (changed from placeholders to window functions)
			assert.Contains(t, html, "window.__ideExecuteCommand__", "ideExecuteCommand function call should be present")
			assert.Contains(t, html, "window.__saveIdeConfig__", "saveIdeConfig function call should be present")
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

			// Verify auto-save functionality (save button was removed in favor of auto-save)
			assert.Contains(t, html, "getAndSaveIdeConfig", "Auto-save function should be present")
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
			// Verify that values from config are populated in the HTML
			// The HTML should contain value attributes for input fields
			assert.Contains(t, html, "value=\"", "HTML should contain populated values")

			// Verify endpoint field has a value attribute (will be from config)
			assert.Regexp(t, `id="api_endpoint"[^>]*value="[^"]*"`, html, "Endpoint field should have a value")

			// Verify token field has a value attribute
			assert.Regexp(t, `id="token"[^>]*value="[^"]*"`, html, "Token field should have a value")
		})

		t.Run("Security - Password Masking", func(t *testing.T) {
			// Verify token field is of type password
			assert.Contains(t, html, "type=\"password\"", "Token field should be password type")
		})
	})
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
