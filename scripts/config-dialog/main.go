/*
 * © 2022-2026 Snyk Limited
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

// ABOUTME: Manual test script to generate configuration dialog HTML for visual inspection
// ABOUTME: Run with: go run scripts/config-dialog/main.go > config_output.html
// ABOUTME: Use -ldx-sync-config flag to enable the LDX-Sync config UI section
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"
	"github.com/snyk/snyk-ls/infrastructure/configuration"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

func main() {
	// Parse command line flags
	enableLdxSyncConfig := flag.Bool("ldx-sync-config", false, "Enable the LDX-Sync config UI section (hidden by default for backward compatibility)")
	flag.Parse()

	// Initialize config
	c := config.CurrentConfig()
	c.SetToken("00000000-0000-0000-0000-000000000001")
	c.SetOrganization("test-org-uuid")

	// Set integration name to test Visual Studio vs other IDEs
	// Change this to "VISUAL_STUDIO" to test Solution label
	c.SetIntegrationName("VISUAL_STUDIO")
	c.SetIntegrationVersion("1.0.0")

	// Create workspace with folders matching the StoredFolderConfigs below
	// This ensures folder settings are visible in the generated HTML
	notifier := notification.NewNotifier()
	instrumentor := performance.NewInstrumentor()
	testScanner := scanner.NewTestScanner()
	hoverService := hover.NewDefaultService(c)
	scanNotifier := scanner.NewMockScanNotifier()
	scanPersister := persistence.NewNopScanPersister()
	scanStateAggregator := scanstates.NewNoopStateAggregator()
	featureFlagService := featureflag.New(c)

	w := workspace.New(c, instrumentor, testScanner, hoverService, scanNotifier, notifier, scanPersister, scanStateAggregator, featureFlagService)

	// Add folders matching the FolderConfig paths
	folder1 := workspace.NewFolder(c, "/Users/username/workspace/my-project", "my-project", testScanner, hoverService, scanNotifier, notifier, scanPersister, scanStateAggregator, featureFlagService)
	folder2 := workspace.NewFolder(c, "/Users/username/workspace/your-project", "your-project", testScanner, hoverService, scanNotifier, notifier, scanPersister, scanStateAggregator, featureFlagService)
	w.AddFolder(folder1)
	w.AddFolder(folder2)

	c.SetWorkspace(w)

	// Create renderer
	renderer, err := configuration.NewConfigHtmlRenderer(c)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating renderer: %v\n", err)
		os.Exit(1)
	}

	// Create sample settings with folder configs
	settings := types.Settings{
		Token:                       c.Token(),
		Endpoint:                    c.Endpoint(),
		Organization:                c.Organization(),
		AuthenticationMethod:        "token",
		Insecure:                    "false",
		ActivateSnykOpenSource:      "true",
		ActivateSnykCode:            "true",
		ActivateSnykIac:             "true",
		ScanningMode:                "auto",
		AdditionalParams:            "--severity-threshold=high",
		IntegrationName:             c.IntegrationName(),
		IntegrationVersion:          c.IdeVersion(),
		EnableTrustedFoldersFeature: "true",
		TrustedFolders: []string{
			"/Users/username/workspace/my-project",
			"/Users/username/trusted/folder",
		},
		StoredFolderConfigs: []types.FolderConfig{
			{
				FolderPath:           "/Users/username/workspace/my-project",
				AdditionalParameters: []string{"--all-projects", "--detection-depth=3"},
				PreferredOrg:         "my-org-uuid-12345",
				AutoDeterminedOrg:    "auto-org-uuid-67890",
				OrgSetByUser:         true,
				// Add ScanCommandConfig to reproduce template error
				ScanCommandConfig: map[product.Product]types.ScanCommandConfig{
					product.ProductOpenSource: {
						PreScanCommand:              "npm install",
						PostScanCommand:             "npm test",
						PreScanOnlyReferenceFolder:  true,
						PostScanOnlyReferenceFolder: false,
					},
					product.ProductCode: {
						PreScanCommand:              "echo 'code scan'",
						PostScanOnlyReferenceFolder: false,
					},
					product.ProductInfrastructureAsCode: {
						PreScanCommand: "terraform init",
					},
				},
				// EffectiveConfig shows computed values with their sources
				EffectiveConfig: map[string]types.EffectiveValue{
					"scan_automatic": {
						Value:  "auto",
						Source: "global",
					},
					"scan_net_new": {
						Value:  false,
						Source: "ldx-sync", // Enforced by org but not locked
					},
					"enabled_severities": {
						Value: &types.SeverityFilter{
							Critical: true,
							High:     true,
							Medium:   false,
							Low:      false,
						},
						Source: "ldx-sync-locked", // Locked by org policy
					},
					"enabled_products": {
						Value:  []string{"oss", "code"},
						Source: "ldx-sync",
					},
					"issue_view_open_issues": {
						Value:  true,
						Source: "global",
					},
					"issue_view_ignored_issues": {
						Value:  false,
						Source: "default",
					},
					"risk_score_threshold": {
						Value:  500,
						Source: "ldx-sync-locked",
					},
				},
			},
			{
				FolderPath:        "/Users/username/workspace/your-project",
				PreferredOrg:      "manual-org-uuid-11111",
				AutoDeterminedOrg: "auto-determined-uuid-99999",
				OrgSetByUser:      false,
				// EffectiveConfig for second folder - different sources
				EffectiveConfig: map[string]types.EffectiveValue{
					"scan_automatic": {
						Value:  "manual",
						Source: "user-override", // User has overridden this
					},
					"scan_net_new": {
						Value:  true,
						Source: "global",
					},
					"enabled_severities": {
						Value: &types.SeverityFilter{
							Critical: true,
							High:     true,
							Medium:   true,
							Low:      true,
						},
						Source: "default",
					},
					"enabled_products": {
						Value:  []string{"oss", "code", "iac"},
						Source: "user-override",
					},
					"issue_view_open_issues": {
						Value:  true,
						Source: "default",
					},
					"issue_view_ignored_issues": {
						Value:  true,
						Source: "user-override",
					},
					"risk_score_threshold": {
						Value:  0,
						Source: "default",
					},
				},
			},
		},
	}

	// Add filter severity
	settings.FilterSeverity = &types.SeverityFilter{
		Critical: true,
		High:     false,
		Medium:   true,
		Low:      false,
	}

	// Add issue view options
	settings.IssueViewOptions = &types.IssueViewOptions{
		OpenIssues:    true,
		IgnoredIssues: false,
	}

	// Render HTML with configurable LDX-Sync config flag
	html := renderer.GetConfigHtmlWithOptions(settings, configuration.ConfigHtmlOptions{
		EnableLdxSyncConfig: *enableLdxSyncConfig,
	})
	if html == "" {
		fmt.Fprintf(os.Stderr, "Error: Failed to generate HTML\n")
		os.Exit(1)
	}

	// Add test script for dirty tracking demonstration
	// All CSS styles are properly scoped under #test-panel to prevent conflicts with production styles
	testScript := `
	<style nonce="ideNonce">
		#test-panel {
			position: fixed;
			top: 10px;
			right: 10px;
			background: white;
			border: 2px solid #333;
			border-radius: 8px;
			padding: 15px;
			box-shadow: 0 4px 6px rgba(0,0,0,0.1);
			font-family: monospace;
			font-size: 14px;
			z-index: 10000;
			min-width: 300px;
			max-width: 400px;
		}
		#test-panel .status-row {
			margin: 8px 0;
			display: flex;
			justify-content: space-between;
			align-items: center;
		}
		#test-panel .status-label {
			font-weight: bold;
		}
		#test-panel .status-valid {
			color: #28a745;
		}
		#test-panel .status-invalid {
			color: #dc3545;
		}
		#test-panel .status-dirty {
			color: #ffc107;
		}
		#test-panel .status-clean {
			color: #28a745;
		}
		#test-panel button {
			margin-top: 10px;
			width: 100%;
			padding: 8px;
			font-size: 14px;
			font-weight: bold;
			cursor: pointer;
		}
		#test-panel #json-output {
			display: none;
			margin-top: 10px;
			padding: 10px;
			background: #f5f5f5;
			border: 1px solid #ddd;
			border-radius: 4px;
			max-height: 400px;
			overflow-y: auto;
		}
		#test-panel #json-output pre {
			margin: 0;
			font-size: 12px;
			white-space: pre-wrap;
			word-wrap: break-word;
		}
		#test-panel #json-output .json-header {
			font-weight: bold;
			margin-bottom: 5px;
			display: flex;
			justify-content: space-between;
			align-items: center;
		}
		#test-panel #json-output .copy-btn {
			padding: 4px 8px;
			font-size: 12px;
			cursor: pointer;
			margin: 0;
		}
		#test-panel .toggle-switch {
			position: relative;
			display: inline-block;
			width: 48px;
			height: 24px;
		}
		#test-panel .toggle-switch input {
			opacity: 0;
			width: 0;
			height: 0;
		}
		#test-panel .toggle-slider {
			position: absolute;
			cursor: pointer;
			top: 0;
			left: 0;
			right: 0;
			bottom: 0;
			background-color: #ccc;
			transition: 0.3s;
			border-radius: 24px;
		}
		#test-panel .toggle-slider:before {
			position: absolute;
			content: "";
			height: 18px;
			width: 18px;
			left: 3px;
			bottom: 3px;
			background-color: white;
			transition: 0.3s;
			border-radius: 50%;
		}
		#test-panel input:checked + .toggle-slider {
			background-color: #28a745;
		}
		#test-panel input:checked + .toggle-slider:before {
			transform: translateX(24px);
		}
	</style>
	<div id="test-panel">
		<div class="status-row">
			<span class="status-label">Form Valid:</span>
			<span id="status-valid" class="status-valid">✅ Yes</span>
		</div>
		<div class="status-row">
			<span class="status-label">Form Dirty:</span>
			<span id="status-dirty" class="status-clean">✅ Clean</span>
		</div>
		<div class="status-row">
			<span class="status-label">Auto-Save:</span>
			<label class="toggle-switch">
				<input type="checkbox" id="auto-save-toggle" checked>
				<span class="toggle-slider"></span>
			</label>
		</div>
		<button id="test-save-btn" type="button">💾 Save Configuration</button>
		<div id="json-output">
			<div class="json-header">
				<button class="copy-btn" id="copy-json-btn">Copy</button>
			</div>
			<pre id="json-content"></pre>
		</div>
	</div>
	<script nonce="ideNonce">
		// Initialize IDE auto-save flag (default to true for testing)
		if (typeof window.__IS_IDE_AUTOSAVE_ENABLED__ === 'undefined') {
			window.__IS_IDE_AUTOSAVE_ENABLED__ = true;
		}

		// Update validation status display
		function updateValidationStatus() {
			var validationInfo = window.ConfigApp.validation.getFormValidationInfo();
			var statusElement = document.getElementById('status-valid');
			if (validationInfo.isValid) {
				statusElement.textContent = '✅ Yes';
				statusElement.className = 'status-valid';
			} else {
				statusElement.textContent = '❌ No';
				statusElement.className = 'status-invalid';
			}
		}

		// Test handler for dirty state changes
		window.__onFormDirtyChange__ = function(isDirty) {
			var statusElement = document.getElementById('status-dirty');
			if (isDirty) {
				statusElement.textContent = '⚠️ Dirty';
				statusElement.className = 'status-dirty';
			} else {
				statusElement.textContent = '✅ Clean';
				statusElement.className = 'status-clean';
			}
		};

		// Mock save function for testing (called by auto-save when form changes)
		window.__saveIdeConfig__ = function(jsonString) {
			var formatted = JSON.stringify(JSON.parse(jsonString), null, 2);
			var jsonOutput = document.getElementById('json-output');
			var jsonContent = document.getElementById('json-content');
			jsonContent.textContent = formatted;
			jsonOutput.style.display = 'block';

			// Store for copy functionality
			window._lastSavedJson = formatted;
		};

		// Mock login/logout for testing
		window.__ideLogin__ = function() {
			alert("🔐 Login triggered");
		};

		window.__ideLogout__ = function() {
			alert("🚪 Logout triggered");
		};

		// Initialize toggle to match IDE auto-save state
		document.getElementById('auto-save-toggle').checked = window.__IS_IDE_AUTOSAVE_ENABLED__;

		// Wire up auto-save toggle
		document.getElementById('auto-save-toggle').addEventListener('change', function(e) {
			window.__IS_IDE_AUTOSAVE_ENABLED__ = e.target.checked;
		});

		// Wire up test save button
		document.getElementById('test-save-btn').addEventListener('click', function() {
			updateValidationStatus();
			window.ConfigApp.autoSave.getAndSaveIdeConfig();
		});

		// Wire up copy button
		document.getElementById('copy-json-btn').addEventListener('click', function() {
			if (window._lastSavedJson) {
				navigator.clipboard.writeText(window._lastSavedJson).then(function() {
					var btn = document.getElementById('copy-json-btn');
					var originalText = btn.textContent;
					btn.textContent = '✓ Copied!';
					setTimeout(function() {
						btn.textContent = originalText;
					}, 2000);
				});
			}
		});

		// Monitor validation state changes
		setInterval(updateValidationStatus, 100);
	</script>
</body>
</html>`

	// Replace closing tags with test script
	html = html[:len(html)-len("</body>\n</html>")-1] + testScript

	// Output HTML
	fmt.Fprintln(os.Stdout, html)
}
