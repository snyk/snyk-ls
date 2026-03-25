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
// ABOUTME: Use --dummy-data to skip authentication and use fabricated test data
// ABOUTME: Use --folders /path/one,/path/two to specify real workspace folders
// ABOUTME: Use --integration VISUAL_STUDIO to test IDE-specific labels
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/snyk/go-application-framework/pkg/auth"
	gafconfig "github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"

	snykauth "github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/infrastructure/configuration"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

func main() {
	dummyData := flag.Bool("dummy-data", false, "Use fabricated test data instead of real authenticated data")
	singleFolder := flag.Bool("single-folder", false, "Use only one folder in dummy data mode (to test single-folder UI)")
	noFolders := flag.Bool("no-folders", false, "Use no folders in dummy data mode (to test zero-folder UI)")
	folders := flag.String("folders", "", "Comma-separated list of real folder paths to use as workspace folders")
	integration := flag.String("integration", "VISUAL_STUDIO", "Integration name to simulate (e.g. VISUAL_STUDIO, ECLIPSE, JETBRAINS)")
	flag.Parse()

	// Initialize config
	engine, ts := config.InitEngine(nil)
	gafConf := engine.GetConfiguration()
	logger := engine.GetLogger()

	gafConf.Set(gafconfig.INTEGRATION_NAME, *integration)
	gafConf.Set(gafconfig.INTEGRATION_VERSION, "1.0.0")

	// Set up config resolver
	fs := pflag.NewFlagSet("config-dialog", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	_ = gafConf.AddFlagSet(fs)
	fm := workflow.ConfigurationOptionsFromFlagset(fs)

	resolver := types.NewConfigResolver(logger)
	resolver.SetPrefixKeyResolver(configresolver.New(gafConf, fm), gafConf, fm)

	// Set up workspace infrastructure (needed by both paths)
	notifier := notification.NewNotifier()
	instrumentor := performance.NewInstrumentor()
	testScanner := scanner.NewTestScanner()
	hoverService := hover.NewDefaultService(logger)
	scanNotifier := scanner.NewMockScanNotifier()
	scanPersister := persistence.NewNopScanPersister()
	scanStateAggregator := scanstates.NewNoopStateAggregator()
	featureFlagService := featureflag.New(gafConf, logger, engine, resolver)
	w := workspace.New(gafConf, logger, instrumentor, testScanner, hoverService, scanNotifier, notifier, scanPersister, scanStateAggregator, featureFlagService, resolver, engine)

	var settings types.Settings

	if *dummyData {
		fmt.Fprintln(os.Stderr, "Using dummy data (no authentication required)")
		ts.SetToken(gafConf, "00000000-0000-0000-0000-000000000001")
		settings = buildDummySettings(gafConf, resolver, w, testScanner, hoverService, scanNotifier, notifier, scanPersister, scanStateAggregator, featureFlagService, engine, *singleFolder, *noFolders)
	} else {
		if err := ensureAuthenticated(engine); err != nil {
			fmt.Fprintf(os.Stderr, "Authentication failed: %v\nTip: use --dummy-data to skip authentication\n", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "Authenticated successfully")
		settings = buildRealSettings(engine, gafConf, resolver, w, *folders, testScanner, hoverService, scanNotifier, notifier, scanPersister, scanStateAggregator, featureFlagService)
	}

	config.SetWorkspace(gafConf, w)

	// Create renderer
	renderer, err := configuration.NewConfigHtmlRenderer(engine)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating renderer: %v\n", err)
		os.Exit(1)
	}

	// Render HTML
	html := renderer.GetConfigHtml(settings)
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

// buildRealSettings constructs settings from real authenticated configuration data.
func buildRealSettings(
	engine workflow.Engine,
	gafConf gafconfig.Configuration,
	resolver *types.ConfigResolver,
	w *workspace.Workspace,
	folderPaths string,
	sc scanner.Scanner,
	hoverSvc hover.Service,
	scanNot scanner.ScanNotifier,
	not notification.Notifier,
	scanPers persistence.ScanSnapshotPersister,
	scanStateAgg scanstates.Aggregator,
	ffService featureflag.Service,
) types.Settings {
	logger := engine.GetLogger()

	if folderPaths != "" {
		for _, fp := range strings.Split(folderPaths, ",") {
			fp = strings.TrimSpace(fp)
			absPath, absErr := filepath.Abs(fp)
			if absErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not resolve path %s: %v\n", fp, absErr)
				continue
			}
			name := filepath.Base(absPath)
			folder := workspace.NewFolder(gafConf, logger, types.FilePath(absPath), name, sc, hoverSvc, scanNot, not, scanPers, scanStateAgg, ffService, resolver, engine)
			w.AddFolder(folder)
			fmt.Fprintf(os.Stderr, "Added folder: %s\n", absPath)
		}
	} else {
		fmt.Fprintln(os.Stderr, "No --folders specified; settings will have no folder-specific configurations")
	}

	config.SetWorkspace(gafConf, w)
	settings := command.ConstructSettingsFromConfig(engine, resolver)

	fmt.Fprintf(os.Stderr, "Built settings with %d folder(s)\n", len(settings.StoredFolderConfigs))
	return settings
}

// buildDummySettings constructs settings from hardcoded fabricated data for visual testing.
func buildDummySettings(
	gafConf gafconfig.Configuration,
	resolver *types.ConfigResolver,
	w *workspace.Workspace,
	sc scanner.Scanner,
	hoverSvc hover.Service,
	scanNot scanner.ScanNotifier,
	not notification.Notifier,
	scanPers persistence.ScanSnapshotPersister,
	scanStateAgg scanstates.Aggregator,
	ffService featureflag.Service,
	engine workflow.Engine,
	singleFolder bool,
	noFolders bool,
) types.Settings {
	logger := engine.GetLogger()

	// Add dummy folders
	if !noFolders {
		folder1 := workspace.NewFolder(gafConf, logger, "/Users/username/workspace/my-project", "my-project", sc, hoverSvc, scanNot, not, scanPers, scanStateAgg, ffService, resolver, engine)
		w.AddFolder(folder1)
		if !singleFolder {
			folder2 := workspace.NewFolder(gafConf, logger, "/Users/username/workspace/your-project", "your-project", sc, hoverSvc, scanNot, not, scanPers, scanStateAgg, ffService, resolver, engine)
			w.AddFolder(folder2)
		}
	}

	var folderConfigs []types.FolderConfig

	if !noFolders {
		// Populate configuration with sample folder config values
		conf := gafConf
		fp1 := string(types.PathKey("/Users/username/workspace/my-project"))
		fp2 := string(types.PathKey("/Users/username/workspace/your-project"))
		setUser := func(fp, name string, val any) {
			conf.Set(configresolver.UserFolderKey(fp, name), &configresolver.LocalConfigField{Value: val, Changed: true})
		}
		setMeta := func(fp, name string, val any) {
			conf.Set(configresolver.FolderMetadataKey(fp, name), val)
		}
		scanCfg1 := map[product.Product]types.ScanCommandConfig{
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
		}
		setUser(fp1, types.SettingPreferredOrg, "my-org-uuid-12345")
		setMeta(fp1, types.SettingAutoDeterminedOrg, "auto-org-uuid-67890")
		setUser(fp1, types.SettingOrgSetByUser, true)
		setUser(fp1, types.SettingAdditionalParameters, []string{"--all-projects", "--detection-depth=3"})
		setUser(fp1, types.SettingScanCommandConfig, scanCfg1)
		if !singleFolder {
			setUser(fp2, types.SettingPreferredOrg, "manual-org-uuid-11111")
			setMeta(fp2, types.SettingAutoDeterminedOrg, "auto-determined-uuid-99999")
			setUser(fp2, types.SettingOrgSetByUser, false)
		}

		folderConfigs = []types.FolderConfig{
			{
				FolderPath:     "/Users/username/workspace/my-project",
				ConfigResolver: resolver,
				EffectiveConfig: map[string]types.EffectiveValue{
					"scan_automatic": {
						Value:  "auto",
						Source: "global",
					},
					"scan_net_new": {
						Value:  false,
						Source: "ldx-sync",
					},
					"enabled_severities": {
						Value: &types.SeverityFilter{
							Critical: true,
							High:     true,
							Medium:   false,
							Low:      false,
						},
						Source: "ldx-sync-locked",
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
		}
		if !singleFolder {
			folderConfigs = append(folderConfigs, types.FolderConfig{
				FolderPath:     "/Users/username/workspace/your-project",
				ConfigResolver: resolver,
				EffectiveConfig: map[string]types.EffectiveValue{
					"scan_automatic": {
						Value:  "manual",
						Source: "user-override",
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
			})
		}
	}

	return types.Settings{
		Token:                       "fake-token-for-display",
		Endpoint:                    "https://api.snyk.io",
		Organization:                util.Ptr("test-org-uuid"),
		AuthenticationMethod:        "token",
		Insecure:                    "false",
		ActivateSnykOpenSource:      "true",
		ActivateSnykCode:            "true",
		ActivateSnykIac:             "true",
		ScanningMode:                "auto",
		AdditionalParams:            "--severity-threshold=high",
		IntegrationName:             gafConf.GetString(gafconfig.INTEGRATION_NAME),
		IntegrationVersion:          gafConf.GetString(gafconfig.INTEGRATION_ENVIRONMENT_VERSION),
		EnableTrustedFoldersFeature: "true",
		TrustedFolders: []string{
			"/Users/username/workspace/my-project",
			"/Users/username/trusted/folder",
		},
		FilterSeverity: &types.SeverityFilter{
			Critical: true,
			High:     false,
			Medium:   true,
			Low:      false,
		},
		IssueViewOptions: &types.IssueViewOptions{
			OpenIssues:    true,
			IgnoredIssues: false,
		},
		StoredFolderConfigs: folderConfigs,
	}
}

// ensureAuthenticated checks for an existing valid token, and if none is found,
// triggers an OAuth browser authentication flow.
func ensureAuthenticated(engine workflow.Engine) error {
	user, err := snykauth.GetActiveUser(engine)
	if err == nil && user != nil {
		fmt.Fprintf(os.Stderr, "Already authenticated as %s (%s)\n", user.UserName, user.Id)
		return nil
	}

	fmt.Fprintln(os.Stderr, "No valid credentials found. Opening browser for authentication...")

	conf := engine.GetConfiguration()
	conf.Set(gafconfig.FF_OAUTH_AUTH_FLOW_ENABLED, true)

	authenticator := auth.NewOAuth2AuthenticatorWithOpts(
		conf,
		auth.WithOpenBrowserFunc(types.DefaultOpenBrowserFunc),
		auth.WithLogger(engine.GetLogger()),
		auth.WithHttpClient(engine.GetNetworkAccess().GetUnauthorizedHttpClient()),
	)

	err = authenticator.CancelableAuthenticate(context.Background())
	if err != nil {
		return fmt.Errorf("OAuth authentication failed: %w", err)
	}

	user, err = snykauth.GetActiveUser(engine)
	if err != nil {
		return fmt.Errorf("authentication verification failed: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Authenticated as %s (%s)\n", user.UserName, user.Id)
	return nil
}
