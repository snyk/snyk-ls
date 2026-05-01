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
// ABOUTME: Use --single-folder to only produce dummy data for a single project
// ABOUTME: Use --no-folders to show what is shown when no projects are open
// ABOUTME: Use --folders /path/one,/path/two to specify real workspace folders
// ABOUTME: Use --integration VISUAL_STUDIO to test IDE-specific labels
// ABOUTME: Use --output-file <path> to write to a file instead of stdout
// ABOUTME: Use --secrets to enable the secrets FF on the org-set project
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/pkg/app"
	"github.com/snyk/go-application-framework/pkg/auth"
	gafconfig "github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	frameworkLogging "github.com/snyk/go-application-framework/pkg/logging"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"
	snykauth "github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/infrastructure/cli/cli_constants"
	"github.com/snyk/snyk-ls/infrastructure/configuration"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/folderconfig"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/types"
)

//go:generate go run $GOFILE --dummy-data --secrets --integration ECLIPSE --output-file config_output_multi_project.html
//go:generate go run $GOFILE --dummy-data --single-folder --integration VISUAL_STUDIO --output-file config_output_single_solution.html
//go:generate go run $GOFILE --dummy-data --no-folders --integration JETBRAINS --output-file config_output_no_projects.html

func main() {
	// Parse command line flags
	dummyData := flag.Bool("dummy-data", false, "Use fabricated test data instead of real authenticated data")
	singleFolder := flag.Bool("single-folder", false, "Use only one folder in dummy data mode (to test single-folder UI)")
	noFolders := flag.Bool("no-folders", false, "Use no folders in dummy data mode (to test zero-folder UI)")
	folders := flag.String("folders", "", "Comma-separated list of real folder paths to use as workspace folders")
	integration := flag.String("integration", "VISUAL_STUDIO", "Integration name to simulate (e.g. VISUAL_STUDIO, ECLIPSE, JETBRAINS)")
	noPanel := flag.Bool("no-panel", false, "Omit the interactive test panel (use for JS test fixtures)")
	outputFile := flag.String("output-file", "", "Write HTML to file instead of stdout")
	secrets := flag.Bool("secrets", false, "Enable secrets feature flag on org folder in dummy data mode")
	flag.Parse()

	// Initialize config - for dummy data, disable automatic environment to prevent API calls
	var engine workflow.Engine
	var ts types.TokenService
	if *dummyData {
		// Create engine without automatic environment to prevent 401 errors during initialization
		conf := gafconfig.NewWithOpts()
		conf.PersistInStorage(folderconfig.ConfigMainKey)
		conf.Set(cli_constants.EXECUTION_MODE_KEY, cli_constants.EXECUTION_MODE_VALUE_STANDALONE)
		engine = app.CreateAppEngineWithOptions(app.WithConfiguration(conf))
		// Skip engine.Init() for dummy data to avoid API calls.
		// Skip workflow initialization for dummy data, it isn't needed.
		// Set up console writer for human-readable logs instead of JSON.
		sw := frameworkLogging.NewScrubbingWriter(zerolog.MultiLevelWriter(os.Stderr), make(frameworkLogging.ScrubbingDict))
		writer := newConsoleWriter(sw)
		logger := zerolog.New(writer).With().Timestamp().Str("separator", "-").Str("method", "").Str("ext", "").Logger().Level(zerolog.WarnLevel)
		engine.SetLogger(&logger)
		ts = config.NewTokenService(nil, &logger)
		config.SetEngineDefaults(engine, &logger)
	} else {
		// Real mode: use standard initialization with automatic environment
		engine, ts = config.InitEngine(nil)
	}
	gafConf := engine.GetConfiguration()
	logger := engine.GetLogger()

	gafConf.Set(gafconfig.INTEGRATION_NAME, *integration)
	gafConf.Set(gafconfig.INTEGRATION_ENVIRONMENT, *integration)
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

	var settings map[string]any
	var folderConfigs []types.FolderConfig
	var featureFlagService featureflag.Service
	var w *workspace.Workspace

	if *dummyData {
		logger.Debug().Msg("Using dummy data (no authentication required)")
		ts.SetToken(gafConf, "00000000-0000-0000-0000-000000000001")
		featureFlagService = featureflag.NewFakeService()
		w = workspace.New(gafConf, logger, instrumentor, testScanner, hoverService, scanNotifier, notifier, scanPersister, scanStateAggregator, featureFlagService, resolver, engine)
		settings, folderConfigs = buildDummySettings(gafConf, resolver, w, testScanner, hoverService, scanNotifier, notifier, scanPersister, scanStateAggregator, featureFlagService, engine, *singleFolder, *noFolders, *secrets)
	} else {
		if err := ensureAuthenticated(engine); err != nil {
			logger.Fatal().Err(err).Msg("Authentication failed. Tip: use --dummy-data to skip authentication")
			os.Exit(1)
		}
		logger.Debug().Msg("Authenticated successfully")
		featureFlagService = featureflag.New(gafConf, logger, engine, resolver)
		w = workspace.New(gafConf, logger, instrumentor, testScanner, hoverService, scanNotifier, notifier, scanPersister, scanStateAggregator, featureFlagService, resolver, engine)
		settings, folderConfigs = buildRealSettings(engine, gafConf, resolver, w, *folders, testScanner, hoverService, scanNotifier, notifier, scanPersister, scanStateAggregator, featureFlagService)
	}

	config.SetWorkspace(gafConf, w)

	// Create renderer
	renderer, err := configuration.NewConfigHtmlRenderer(engine)
	if err != nil {
		logger.Fatal().Err(err).Msg("Error creating renderer")
		os.Exit(1)
	}

	// Render HTML
	html := renderer.GetConfigHtml(settings, folderConfigs)
	if html == "" {
		logger.Fatal().Msg("Error: Failed to generate HTML")
		os.Exit(1)
	}

	if *noPanel {
		fmt.Fprintln(os.Stdout, html)
		return
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
			transition: all 0.35s ease;
		}
		#test-panel .collapsible-header {
			color: #333 !important;
			padding: 0 !important;
			margin: 0 !important;
		}
		#test-panel .collapsible-header:hover {
			color: #000 !important;
			background-color: transparent !important;
		}
		#test-panel .collapsible-header:focus {
			outline: 1px solid #007acc !important;
			background-color: transparent !important;
		}
		#test-panel.collapsed {
			min-width: auto;
			max-width: auto;
			width: 50px;
			height: 50px;
			padding: 8px;
			border-radius: 50%;
			display: flex;
			align-items: center;
			justify-content: center;
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
		<button type="button" class="collapsible-header w-100 d-flex justify-content-between align-items-center" data-toggle="collapse" data-target="#testPanelContent" aria-expanded="true" aria-controls="testPanelContent">
			<span>Test Panel</span>
			<span class="collapse-icon">▼</span>
		</button>
		<div id="testPanelContent" class="collapse show">
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
	</div>
	<script nonce="ideNonce">
		// Initialize IDE auto-save flag (default to true for testing)
		if (typeof window.__IS_IDE_AUTOSAVE_ENABLED__ === 'undefined') {
			window.__IS_IDE_AUTOSAVE_ENABLED__ = true;
		}

		// Handle test panel collapse/expand
		var testPanelContent = document.getElementById('testPanelContent');
		var testPanel = document.getElementById('test-panel');

		if (testPanelContent) {
			testPanelContent.addEventListener('hide.bs.collapse', function() {
				testPanel.classList.add('collapsed');
			});

			testPanelContent.addEventListener('show.bs.collapse', function() {
				testPanel.classList.remove('collapsed');
			});
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
	if *outputFile != "" {
		err := os.WriteFile(*outputFile, []byte(html), 0o644)
		if err != nil {
			logger.Fatal().Err(err).Msgf("Error writing to file %s", *outputFile)
			os.Exit(1)
		}
		logger.Debug().Msgf("Output written to %s", *outputFile)
	} else {
		fmt.Fprintln(os.Stdout, html)
	}
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
) (map[string]any, []types.FolderConfig) {
	logger := engine.GetLogger()

	if folderPaths != "" {
		for _, fp := range strings.Split(folderPaths, ",") {
			fp = strings.TrimSpace(fp)
			absPath, absErr := filepath.Abs(fp)
			if absErr != nil {
				logger.Warn().Err(absErr).Msgf("could not resolve path %s", fp)
				continue
			}
			name := filepath.Base(absPath)
			folder := workspace.NewFolder(gafConf, logger, types.FilePath(absPath), name, sc, hoverSvc, scanNot, not, scanPers, scanStateAgg, ffService, resolver, engine)
			w.AddFolder(folder)
			logger.Debug().Msgf("Added folder: %s", absPath)
		}
	} else {
		logger.Warn().Msg("No --folders specified; settings will have no folder-specific configurations")
	}

	config.SetWorkspace(gafConf, w)
	settings, folderConfigs := command.ConstructSettingsFromConfig(engine, resolver)

	logger.Debug().Msgf("Built settings with %d folder(s)", len(folderConfigs))
	return settings, folderConfigs
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
	enableSecrets bool,
) (map[string]any, []types.FolderConfig) {
	logger := engine.GetLogger()

	// Add dummy folders
	if !noFolders {
		folderPaths := []struct {
			path string
			name string
		}{
			{"/Users/username/workspace/defaults-project", "defaults-project"},
			{"/Users/username/workspace/org-set-project", "org-set-project"},
			{"/Users/username/workspace/org-locked-project", "org-locked-project"},
			{"/Users/username/workspace/user-override-project", "user-override-project"},
		}

		for _, fp := range folderPaths {
			folder := workspace.NewFolder(gafConf, logger, types.FilePath(fp.path), fp.name, sc, hoverSvc, scanNot, not, scanPers, scanStateAgg, ffService, resolver, engine)
			w.AddFolder(folder)
			if singleFolder {
				break
			}
		}
	}

	var folderConfigs []types.FolderConfig

	if !noFolders {
		// Populate configuration with sample folder config values
		conf := gafConf
		setUser := func(fp, name string, val any) {
			conf.Set(configresolver.UserFolderKey(fp, name), &configresolver.LocalConfigField{Value: val, Changed: true})
		}
		setMeta := func(fp, name string, val any) {
			conf.Set(configresolver.FolderMetadataKey(fp, name), val)
		}

		// Helper to create EffectiveConfig with all org-scope settings
		createEffectiveConfig := func(source string) map[string]types.EffectiveValue {
			return map[string]types.EffectiveValue{
				"snyk_oss_enabled": {
					Value:  true,
					Source: source,
				},
				"snyk_code_enabled": {
					Value:  true,
					Source: source,
				},
				"snyk_iac_enabled": {
					Value:  false,
					Source: source,
				},
				"snyk_secrets_enabled": {
					Value:  false,
					Source: source,
				},
				"scan_automatic": {
					Value:  "auto",
					Source: source,
				},
				"scan_net_new": {
					Value:  false,
					Source: source,
				},
				"severity_filter_critical": {
					Value:  true,
					Source: source,
				},
				"severity_filter_high": {
					Value:  true,
					Source: source,
				},
				"severity_filter_medium": {
					Value:  false,
					Source: source,
				},
				"severity_filter_low": {
					Value:  false,
					Source: source,
				},
				"issue_view_open_issues": {
					Value:  true,
					Source: source,
				},
				"issue_view_ignored_issues": {
					Value:  false,
					Source: source,
				},
				"risk_score_threshold": {
					Value:  500,
					Source: source,
				},
			}
		}

		// Project 1: defaults-project (all settings match project defaults)
		fp1 := string(types.PathKey("/Users/username/workspace/defaults-project"))
		setMeta(fp1, types.SettingAutoDeterminedOrg, "auto-org-uuid-11111")
		setUser(fp1, types.SettingOrgSetByUser, false)
		folderConfigs = append(folderConfigs, types.FolderConfig{
			FolderPath:     "/Users/username/workspace/defaults-project",
			ConfigResolver: resolver,
			EffectiveConfig: map[string]types.EffectiveValue{
				"snyk_oss_enabled": {
					Value:  true,
					Source: "default",
				},
				"snyk_code_enabled": {
					Value:  true,
					Source: "default",
				},
				"snyk_iac_enabled": {
					Value:  true,
					Source: "default",
				},
				"snyk_secrets_enabled": {
					Value:  false,
					Source: "default",
				},
				"scan_automatic": {
					Value:  "auto",
					Source: "default",
				},
				"scan_net_new": {
					Value:  false,
					Source: "default",
				},
				"severity_filter_critical": {
					Value:  true,
					Source: "default",
				},
				"severity_filter_high": {
					Value:  false,
					Source: "default",
				},
				"severity_filter_medium": {
					Value:  true,
					Source: "default",
				},
				"severity_filter_low": {
					Value:  false,
					Source: "default",
				},
				"issue_view_open_issues": {
					Value:  true,
					Source: "default",
				},
				"issue_view_ignored_issues": {
					Value:  false,
					Source: "default",
				},
				"risk_score_threshold": {
					Value:  0,
					Source: "default",
				},
			},
		})

		// Project 2: org-set-project (all ldx-sync, unlocked, varied values)
		fp2 := string(types.PathKey("/Users/username/workspace/org-set-project"))
		setMeta(fp2, types.SettingAutoDeterminedOrg, "auto-org-uuid-22222")
		setUser(fp2, types.SettingOrgSetByUser, false)
		folderConfigs = append(folderConfigs, types.FolderConfig{
			FolderPath:     "/Users/username/workspace/org-set-project",
			ConfigResolver: resolver,
			EffectiveConfig: map[string]types.EffectiveValue{
				"snyk_oss_enabled": {
					Value:  false,
					Source: "ldx-sync",
				},
				"snyk_code_enabled": {
					Value:  true,
					Source: "ldx-sync",
				},
				"snyk_iac_enabled": {
					Value:  true,
					Source: "ldx-sync",
				},
				"snyk_secrets_enabled": {
					Value:  true,
					Source: "ldx-sync",
				},
				"scan_automatic": {
					Value:  "manual",
					Source: "ldx-sync",
				},
				"scan_net_new": {
					Value:  true,
					Source: "ldx-sync",
				},
				"severity_filter_critical": {
					Value:  true,
					Source: "ldx-sync",
				},
				"severity_filter_high": {
					Value:  false,
					Source: "ldx-sync",
				},
				"severity_filter_medium": {
					Value:  false,
					Source: "ldx-sync",
				},
				"severity_filter_low": {
					Value:  false,
					Source: "ldx-sync",
				},
				"issue_view_open_issues": {
					Value:  false,
					Source: "ldx-sync",
				},
				"issue_view_ignored_issues": {
					Value:  true,
					Source: "ldx-sync",
				},
				"risk_score_threshold": {
					Value:  750,
					Source: "ldx-sync",
				},
			},
		})

		// Project 3: org-locked-project (all ldx-sync-locked, different varied values)
		fp3 := string(types.PathKey("/Users/username/workspace/org-locked-project"))
		setMeta(fp3, types.SettingAutoDeterminedOrg, "auto-org-uuid-33333")
		setUser(fp3, types.SettingOrgSetByUser, false)
		folderConfigs = append(folderConfigs, types.FolderConfig{
			FolderPath:     "/Users/username/workspace/org-locked-project",
			ConfigResolver: resolver,
			EffectiveConfig: map[string]types.EffectiveValue{
				"snyk_oss_enabled": {
					Value:  true,
					Source: "ldx-sync-locked",
				},
				"snyk_code_enabled": {
					Value:  false,
					Source: "ldx-sync-locked",
				},
				"snyk_iac_enabled": {
					Value:  false,
					Source: "ldx-sync-locked",
				},
				"snyk_secrets_enabled": {
					Value:  true,
					Source: "ldx-sync-locked",
				},
				"scan_automatic": {
					Value:  "auto",
					Source: "ldx-sync-locked",
				},
				"scan_net_new": {
					Value:  false,
					Source: "ldx-sync-locked",
				},
				"severity_filter_critical": {
					Value:  false,
					Source: "ldx-sync-locked",
				},
				"severity_filter_high": {
					Value:  true,
					Source: "ldx-sync-locked",
				},
				"severity_filter_medium": {
					Value:  true,
					Source: "ldx-sync-locked",
				},
				"severity_filter_low": {
					Value:  true,
					Source: "ldx-sync-locked",
				},
				"issue_view_open_issues": {
					Value:  true,
					Source: "ldx-sync-locked",
				},
				"issue_view_ignored_issues": {
					Value:  false,
					Source: "ldx-sync-locked",
				},
				"risk_score_threshold": {
					Value:  250,
					Source: "ldx-sync-locked",
				},
			},
		})

		// Project 4: user-override-project (all user-override)
		fp4 := string(types.PathKey("/Users/username/workspace/user-override-project"))
		setUser(fp4, types.SettingPreferredOrg, "manual-org-uuid-44444")
		setMeta(fp4, types.SettingAutoDeterminedOrg, "auto-org-uuid-44444")
		setUser(fp4, types.SettingOrgSetByUser, true)
		folderConfigs = append(folderConfigs, types.FolderConfig{
			FolderPath:      "/Users/username/workspace/user-override-project",
			ConfigResolver:  resolver,
			EffectiveConfig: createEffectiveConfig("user-override"),
		})

		// If single-folder mode, keep only the first one
		if singleFolder {
			folderConfigs = folderConfigs[:1]
		}

		// Enable secrets feature flag on org-set-project if requested
		if enableSecrets && len(folderConfigs) > 1 {
			ffKey := configresolver.FolderMetadataKey(fp2, types.FeatureFlagPrefix+featureflag.SnykSecretsEnabled)
			gafConf.PersistInStorage(ffKey)
			gafConf.Set(ffKey, true)
		}
	}

	// Dummy data constants for global settings (project defaults)
	const (
		dummyToken                  = "fake-token-for-display"
		dummyAuthMethod             = "token"
		dummyAdditionalParams       = "--severity-threshold=high"
		dummyOrgUUID                = "manual-org-uuid-global"
		dummyOssEnabled             = true
		dummyCodeEnabled            = true
		dummyIacEnabled             = false
		dummySeverityFilterCritical = true
		dummySeverityFilterHigh     = false
		dummyIssueViewIgnoredIssues = true
	)

	// Set global/project-default settings to demonstrate different scopes
	setGlobal := func(name string, val any) {
		gafConf.Set(configresolver.UserGlobalKey(name), val)
	}
	setGlobal(types.SettingSnykOssEnabled, dummyOssEnabled)
	setGlobal(types.SettingSnykCodeEnabled, dummyCodeEnabled)
	setGlobal(types.SettingSnykIacEnabled, dummyIacEnabled)
	setGlobal(types.SettingOrganization, dummyOrgUUID)
	setGlobal(types.SettingSeverityFilterCritical, dummySeverityFilterCritical)
	setGlobal(types.SettingSeverityFilterHigh, dummySeverityFilterHigh)
	setGlobal(types.SettingIssueViewIgnoredIssues, dummyIssueViewIgnoredIssues)

	settings := map[string]any{
		types.SettingToken:                  dummyToken,
		types.SettingApiEndpoint:            "https://api.snyk.io",
		types.SettingOrganization:           dummyOrgUUID,
		types.SettingAuthenticationMethod:   dummyAuthMethod,
		types.SettingProxyInsecure:          false,
		types.SettingSnykOssEnabled:         dummyOssEnabled,
		types.SettingSnykCodeEnabled:        dummyCodeEnabled,
		types.SettingSnykIacEnabled:         dummyIacEnabled,
		types.SettingScanAutomatic:          true,
		types.SettingSeverityFilterCritical: dummySeverityFilterCritical,
		types.SettingSeverityFilterHigh:     dummySeverityFilterHigh,
		types.SettingSeverityFilterMedium:   true,
		types.SettingSeverityFilterLow:      true,
		types.SettingIssueViewOpenIssues:    true,
		types.SettingIssueViewIgnoredIssues: dummyIssueViewIgnoredIssues,
		types.SettingTrustedFolders: []string{
			"/Users/username/workspace/defaults-project",
			"/Users/username/trusted/folder",
		},
	}
	_ = dummyAdditionalParams
	return settings, folderConfigs
}

// ensureAuthenticated checks for an existing valid token, and if none is found,
// triggers an OAuth browser authentication flow.
func ensureAuthenticated(engine workflow.Engine) error {
	logger := engine.GetLogger()
	user, err := snykauth.GetActiveUser(engine)
	if err == nil && user != nil {
		logger.Debug().Msgf("Already authenticated as %s (%s)\n", user.UserName, user.Id)
		return nil
	}

	logger.Debug().Msg("No valid credentials found. Opening browser for authentication...")

	conf := engine.GetConfiguration()
	conf.Set(gafconfig.FF_OAUTH_AUTH_FLOW_ENABLED, true)

	authenticator := auth.NewOAuth2AuthenticatorWithOpts(
		conf,
		auth.WithOpenBrowserFunc(types.DefaultOpenBrowserFunc),
		auth.WithLogger(logger),
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
	logger.Debug().Msgf("Authenticated as %s (%s)", user.UserName, user.Id)
	return nil
}

func newConsoleWriter(writer io.Writer) zerolog.ConsoleWriter {
	w := zerolog.NewConsoleWriter(func(w *zerolog.ConsoleWriter) {
		w.Out = writer
		w.NoColor = true
		w.TimeFormat = time.RFC3339Nano
		w.PartsOrder = []string{
			zerolog.TimestampFieldName,
			zerolog.LevelFieldName,
			"method",
			"ext",
			"separator",
			zerolog.CallerFieldName,
			zerolog.MessageFieldName,
		}
		w.FieldsExclude = []string{"method", "separator", "ext"}
	})
	return w
}
