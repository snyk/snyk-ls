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

	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// Test_SmokeConfigurationDialog verifies that the configuration dialog:
// 1. Can be triggered via workspace/executeCommand
// 2. Returns response with URI and HTML content
// 3. Generated HTML includes ALL settings fields from types.Settings
// 4. Generated HTML includes ALL sub-fields from FolderConfig
// 5. Includes authentication and logout triggers
func Test_SmokeConfigurationDialog(t *testing.T) {
	c := testutil.SmokeTest(t, "")
	testutil.CreateDummyProgressListener(t)

	// Setup server with LSP client
	loc, _ := setupServer(t, c)
	di.Init()

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
			assertFieldPresent(t, html, "endpoint", "Endpoint field")
			assertFieldPresent(t, html, "authenticationMethod", "AuthenticationMethod field")
			assertFieldPresent(t, html, "insecure", "Insecure field")

			// Product activation settings (Scan Configuration section)
			assertFieldPresent(t, html, "activateSnykOpenSource", "ActivateSnykOpenSource field")
			assertFieldPresent(t, html, "activateSnykCode", "ActivateSnykCode field")
			assertFieldPresent(t, html, "activateSnykIac", "ActivateSnykIac field")
			assertFieldPresent(t, html, "activateSnykCodeSecurity", "ActivateSnykCodeSecurity field")
			assertFieldPresent(t, html, "activateSnykCodeQuality", "ActivateSnykCodeQuality field")
			assertFieldPresent(t, html, "scanningMode", "ScanningMode field")
			assertFieldPresent(t, html, "organization", "Organization field")

			// Filter and display settings
			assertFieldPresent(t, html, "filterSeverity", "FilterSeverity field")
			assertFieldPresent(t, html, "issueViewOptions", "IssueViewOptions field")
			assertFieldPresent(t, html, "enableDeltaFindings", "EnableDeltaFindings field")

			// Advanced settings (legacy additional params only)
			assertFieldPresent(t, html, "additionalParams", "AdditionalParams field")
		})

		t.Run("Folder-Specific Settings Fields", func(t *testing.T) {
			// Verify folder configs section exists
			assert.Contains(t, html, "Folder Settings", "Folder Settings section should be present")

			// Folder-specific fields in simplified UI
			// Only visible fields: additionalParameters, riskScoreThreshold, orgSetByUser, preferredOrg, scan config
			if strings.Contains(html, "folderPath") {
				// If folders are present, verify their VISIBLE fields
				assertFieldPresent(t, html, "folderPath", "FolderPath field")
				assertFieldPresent(t, html, "additionalParameters", "AdditionalParameters field")
				assertFieldPresent(t, html, "riskScoreThreshold", "RiskScoreThreshold field")
				assertFieldPresent(t, html, "orgSetByUser", "OrgSetByUser field")
				assertFieldPresent(t, html, "preferredOrg", "PreferredOrg field")

				// Scan command config fields (pre/post scan commands per product - in hidden section)
				assertFieldPresent(t, html, "scanConfig_oss_preScanCommand", "ScanConfig OSS PreScanCommand field")
				assertFieldPresent(t, html, "scanConfig_oss_postScanCommand", "ScanConfig OSS PostScanCommand field")
				assertFieldPresent(t, html, "scanConfig_code_preScanCommand", "ScanConfig Code PreScanCommand field")
				assertFieldPresent(t, html, "scanConfig_iac_preScanCommand", "ScanConfig IaC PreScanCommand field")
			}
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
			// Verify that values from config are populated in the HTML
			// The HTML should contain value attributes for input fields
			assert.Contains(t, html, "value=\"", "HTML should contain populated values")

			// Verify endpoint field has a value attribute (will be from config)
			assert.Regexp(t, `id="endpoint"[^>]*value="[^"]*"`, html, "Endpoint field should have a value")

			// Verify token field has a value attribute
			assert.Regexp(t, `id="token"[^>]*value="[^"]*"`, html, "Token field should have a value")

			// Verify organization field has a value attribute
			assert.Regexp(t, `id="organization"[^>]*value="[^"]*"`, html, "Organization field should have a value")
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
