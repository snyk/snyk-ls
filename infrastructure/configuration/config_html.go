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

// Package configuration provides HTML rendering for the configuration dialog.
// It uses Go templates to generate the configuration UI that is displayed to users
// via the LSP protocol's window/showDocument mechanism.
package configuration

import (
	"bytes"
	_ "embed"
	"html/template"
	"path/filepath"
	"strings"

	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

//go:embed template/config.html
var configHtmlTemplate string

//go:embed template/styles.css
var configStylesTemplate string

// Core utilities
//
//go:embed template/js/core/utils.js
var configUtilsTemplate string

//go:embed template/js/core/dom.js
var configDomTemplate string

//go:embed template/js/core/polyfills.js
var configPolyfillsTemplate string

// State management
//
//go:embed template/js/state/dirty-tracker.js
var configDirtyTrackerTemplate string

//go:embed template/js/state/form-state.js
var configFormStateTemplate string

// IDE integration
//
//go:embed template/js/ide/bridge.js
var configIdeBridgeTemplate string

// Features
//
//go:embed template/js/features/validation.js
var configValidationTemplate string

//go:embed template/js/features/auto-save.js
var configAutoSaveTemplate string

//go:embed template/js/features/authentication.js
var configAuthenticationTemplate string

//go:embed template/js/features/auth-field-monitor.js
var configAuthFieldMonitorTemplate string

//go:embed template/js/features/folders.js
var configFoldersTemplate string

// UI
//
//go:embed template/js/ui/form-handler.js
var configFormHandlerTemplate string

//go:embed template/js/ui/tooltips.js
var configTooltipsTemplate string

//go:embed template/js/ui/reset-handler.js
var configResetHandlerTemplate string

//go:embed template/js/ui/tabs.js
var configTabsTemplate string

// App initialization
//
//go:embed template/js/app.js
var configAppTemplate string

//go:embed template/vendor/bootstrap.min.css
var bootstrapCssTemplate string

//go:embed template/vendor/jquery.slim.min.js
var jqueryJsTemplate string

//go:embed template/vendor/bootstrap.bundle.min.js
var bootstrapJsTemplate string

type ConfigHtmlRenderer struct {
	engine   workflow.Engine
	template *template.Template
}

// Template helper functions (extracted to reduce cyclomatic complexity)

func tmplGetScanConfig(scanConfigMap map[product.Product]types.ScanCommandConfig, productName string) *types.ScanCommandConfig {
	cfg, exists := scanConfigMap[product.Product(productName)]
	if !exists {
		return nil
	}
	return &cfg
}

func tmplGetEffectiveValue(effectiveConfig map[string]types.EffectiveValue, settingName string) *types.EffectiveValue {
	if effectiveConfig == nil {
		return nil
	}
	val, exists := effectiveConfig[settingName]
	if !exists {
		return nil
	}
	return &val
}

func tmplIsLocked(effectiveConfig map[string]types.EffectiveValue, settingName string) bool {
	if effectiveConfig == nil {
		return false
	}
	val, exists := effectiveConfig[settingName]
	if !exists {
		return false
	}
	return val.Source == "ldx-sync-locked"
}

func tmplGetSource(effectiveConfig map[string]types.EffectiveValue, settingName string) string {
	if effectiveConfig == nil {
		return ""
	}
	val, exists := effectiveConfig[settingName]
	if !exists {
		return ""
	}
	return val.Source
}

func tmplGetSourceLabel(effectiveConfig map[string]types.EffectiveValue, settingName string) string {
	if effectiveConfig == nil {
		return ""
	}
	val, exists := effectiveConfig[settingName]
	if !exists {
		return ""
	}
	return sourceToLabel(val.Source)
}

func tmplGetSourceClass(effectiveConfig map[string]types.EffectiveValue, settingName string) string {
	if effectiveConfig == nil {
		return ""
	}
	val, exists := effectiveConfig[settingName]
	if !exists {
		return ""
	}
	return sourceToClass(val.Source)
}

func sourceToLabel(source string) string {
	switch source {
	case "ldx-sync-locked":
		return "Organization (Locked)"
	case "ldx-sync":
		return "Organization"
	case "user-override":
		return "Your Override"
	case "global":
		return "Global Setting"
	case "default":
		return "Default"
	default:
		return source
	}
}

func sourceToClass(source string) string {
	switch source {
	case "ldx-sync-locked":
		return "source-org-locked"
	case "ldx-sync":
		return "source-org"
	case "user-override":
		return "source-override"
	case "global":
		return "source-global"
	case "default":
		return "source-default"
	default:
		return ""
	}
}

func tmplIsSecretsFeatureEnabled(fc types.FolderConfig) bool {
	return fc.GetFeatureFlag(featureflag.SnykSecretsEnabled)
}

// tmplIsAutoScan checks if the scan_automatic value represents "auto" mode.
// Handles both string ("auto"/"manual") and boolean (true/false) values.
func tmplIsAutoScan(value any) bool {
	if value == nil {
		return true // default to auto
	}
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return v == "auto" || v == ""
	default:
		return true
	}
}

// tmplSourceIndicator returns HTML for source indicators (icons with tooltips).
// Returns: "🏢🔒" for locked, "🏢" for organization, empty for override (instead indicated by CSS border), empty for global/default.
func tmplSourceIndicator(effectiveConfig map[string]types.EffectiveValue, settingName string) template.HTML {
	if effectiveConfig == nil {
		return ""
	}
	val, exists := effectiveConfig[settingName]
	if !exists {
		return ""
	}

	switch val.Source {
	case "ldx-sync-locked":
		return template.HTML(`<span class="source-indicator" data-toggle="tooltip" title="Locked due to organization settings">🏢🔒</span>`)
	case "ldx-sync":
		return template.HTML(`<span class="source-indicator" data-toggle="tooltip" title="Set by your organization settings">🏢</span>`)
	default:
		return ""
	}
}

func NewConfigHtmlRenderer(engine workflow.Engine) (*ConfigHtmlRenderer, error) {
	// Register custom template functions for better template reusability
	funcMap := template.FuncMap{
		"toLower":                 strings.ToLower,
		"getScanConfig":           tmplGetScanConfig,
		"getEffectiveValue":       tmplGetEffectiveValue,
		"isLocked":                tmplIsLocked,
		"getSource":               tmplGetSource,
		"getSourceLabel":          tmplGetSourceLabel,
		"getSourceClass":          tmplGetSourceClass,
		"isAutoScan":              tmplIsAutoScan,
		"isSecretsFeatureEnabled": tmplIsSecretsFeatureEnabled,
		"sourceIndicator":         tmplSourceIndicator,
	}

	tmpl, err := template.New("config").Funcs(funcMap).Parse(configHtmlTemplate)
	if err != nil {
		engine.GetLogger().Error().Msgf("Failed to parse config template: %s", err)
		return nil, err
	}

	return &ConfigHtmlRenderer{
		engine:   engine,
		template: tmpl,
	}, nil
}

// GetConfigHtml renders the configuration dialog HTML using the provided settings.
// The IDE extension must inject JavaScript functions on the window object:
// - window.__saveIdeConfig__(jsonString): Save configuration
// - window.__ideExecuteCommand__(cmd, args, callback): Execute an LSP command (e.g. "snyk.login", "snyk.logout")
// - window.__onFormDirtyChange__(isDirty): [Optional] Called when form dirty state changes
// The IDE can optionally set window.__IS_IDE_AUTOSAVE_ENABLED__ = true to enable auto-save on form changes.
// The IDE can also call window.getAndSaveIdeConfig() to retrieve and save current form values.
// The IDE can call window.setAuthToken(token, apiUrl) to inject an authentication token and optional API URL.
// Token validation is performed based on the selected authentication method (OAuth2, PAT, or Legacy API Token).
// Note: Settings should be populated using populateFolderConfigs which ensures only workspace folders are included.
func (r *ConfigHtmlRenderer) GetConfigHtml(settings types.Settings) string {
	// Determine solution/project label based on IDE
	// For every IDE we'll call them "Projects" even if not technically correct,
	// as it's more user-friendly. Other than Visual Studio, which we will respect.
	folderLabel := "Project"
	if isVisualStudio(settings.IntegrationName) {
		folderLabel = "Solution"
	}

	// Build folder display names aligned with StoredFolderConfigs order
	ws := config.GetWorkspace(r.engine.GetConfiguration())
	folderNames := make([]string, len(settings.StoredFolderConfigs))
	for i, fc := range settings.StoredFolderConfigs {
		if ws != nil {
			for _, f := range ws.Folders() {
				if types.PathKey(f.Path()) == fc.FolderPath {
					folderNames[i] = f.Name()
					break
				}
			}
		}
		if folderNames[i] == "" {
			folderNames[i] = filepath.Base(string(fc.FolderPath))
		}
	}

	// Get CLI release channel from runtime version
	cliReleaseChannel := getCliReleaseChannel(r.engine)

	data := map[string]any{
		"Settings":     settings,
		"BootstrapCSS": template.CSS(bootstrapCssTemplate),
		"Styles":       template.CSS(configStylesTemplate),
		"JQuery":       template.JS(jqueryJsTemplate),
		"BootstrapJS":  template.JS(bootstrapJsTemplate),
		// Core modules
		"Polyfills": template.JS(configPolyfillsTemplate),
		"Dom":       template.JS(configDomTemplate),
		"Utils":     template.JS(configUtilsTemplate),
		// State management
		"DirtyTracker": template.JS(configDirtyTrackerTemplate),
		"FormState":    template.JS(configFormStateTemplate),
		// IDE integration
		"IdeBridge": template.JS(configIdeBridgeTemplate),
		// Features
		"Validation":       template.JS(configValidationTemplate),
		"AutoSave":         template.JS(configAutoSaveTemplate),
		"Authentication":   template.JS(configAuthenticationTemplate),
		"AuthFieldMonitor": template.JS(configAuthFieldMonitorTemplate),
		"Folders":          template.JS(configFoldersTemplate),
		// UI
		"FormHandler":  template.JS(configFormHandlerTemplate),
		"Tooltips":     template.JS(configTooltipsTemplate),
		"ResetHandler": template.JS(configResetHandlerTemplate),
		"Tabs":         template.JS(configTabsTemplate),
		// App initialization
		"App":                     template.JS(configAppTemplate),
		"Nonce":                   "ideNonce", // Replaced by IDE extension
		"FolderLabel":             folderLabel,
		"FolderNames":             folderNames,
		"CliReleaseChannel":       cliReleaseChannel,
		"IsSecretsFeatureEnabled": isAnyFolderSecretsEnabled(settings),
	}

	var buffer bytes.Buffer
	if err := r.template.Execute(&buffer, data); err != nil {
		r.engine.GetLogger().Error().Msgf("Failed to execute config template: %v", err)
		return ""
	}

	return buffer.String()
}

// isAnyFolderSecretsEnabled returns true if any folder in settings has the Snyk Secrets feature flag enabled
func isAnyFolderSecretsEnabled(settings types.Settings) bool {
	for _, fc := range settings.StoredFolderConfigs {
		if fc.GetFeatureFlag(featureflag.SnykSecretsEnabled) {
			return true
		}
	}
	return false
}

// isVisualStudio checks if the integration name indicates Visual Studio
func isVisualStudio(integrationName string) bool {
	return integrationName == "VISUAL_STUDIO" || integrationName == "Visual Studio"
}

// getCliReleaseChannel derives the CLI release channel from the runtime version
func getCliReleaseChannel(engine workflow.Engine) string {
	info := engine.GetRuntimeInfo()
	if info == nil {
		return "stable"
	}
	version := info.GetVersion()
	if strings.Contains(version, "-preview.") {
		return "preview"
	}
	if strings.Contains(version, "-rc.") {
		return "rc"
	}
	return "stable"
}
