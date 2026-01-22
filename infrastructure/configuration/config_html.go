// Package configuration provides HTML rendering for the configuration dialog.
// It uses Go templates to generate the configuration UI that is displayed to users
// via the LSP protocol's window/showDocument mechanism.
package configuration

import (
	"bytes"
	_ "embed"
	"html/template"
	"strings"

	"github.com/snyk/snyk-ls/application/config"
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

//go:embed template/js/features/folders.js
var configFoldersTemplate string

// UI
//
//go:embed template/js/ui/form-handler.js
var configFormHandlerTemplate string

//go:embed template/js/ui/tooltips.js
var configTooltipsTemplate string

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
	c        *config.Config
	template *template.Template
}

func NewConfigHtmlRenderer(c *config.Config) (*ConfigHtmlRenderer, error) {
	// Register custom template functions for better template reusability
	funcMap := template.FuncMap{
		"toLower": strings.ToLower,
		// getScanConfig retrieves scan command config for a product from the map
		"getScanConfig": func(scanConfigMap map[product.Product]types.ScanCommandConfig, productName string) *types.ScanCommandConfig {
			config, exists := scanConfigMap[product.Product(productName)]
			if !exists {
				return nil
			}
			return &config
		},
	}

	tmpl, err := template.New("config").Funcs(funcMap).Parse(configHtmlTemplate)
	if err != nil {
		c.Logger().Error().Msgf("Failed to parse config template: %s", err)
		return nil, err
	}

	return &ConfigHtmlRenderer{
		c:        c,
		template: tmpl,
	}, nil
}

// GetConfigHtml renders the configuration dialog HTML using the provided settings.
// The IDE extension must inject JavaScript functions on the window object:
// - window.__saveIdeConfig__(jsonString): Save configuration
// - window.__ideLogin__(): Trigger authentication
// - window.__ideLogout__(): Trigger logout
// - window.__onFormDirtyChange__(isDirty): [Optional] Called when form dirty state changes
// The IDE can optionally set window.__IS_IDE_AUTOSAVE_ENABLED__ = true to enable auto-save on form changes.
// The IDE can also call window.getAndSaveIdeConfig() to retrieve and save current form values.
// The IDE can call window.setAuthToken(token) to inject an authentication token into the token input field.
// Token validation is performed based on the selected authentication method (OAuth2, PAT, or Legacy API Token).
// Note: Settings should be populated using populateFolderConfigs which ensures only workspace folders are included.
func (r *ConfigHtmlRenderer) GetConfigHtml(settings types.Settings) string {
	// Determine folder/solution/project label based on IDE
	folderLabel := "Folder"
	if isVisualStudio(settings.IntegrationName) {
		folderLabel = "Solution"
	} else if isEclipse(settings.IntegrationName) {
		folderLabel = "Project"
	}

	// Get CLI release channel from runtime version
	cliReleaseChannel := getCliReleaseChannel(r.c)

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
		"Validation":     template.JS(configValidationTemplate),
		"AutoSave":       template.JS(configAutoSaveTemplate),
		"Authentication": template.JS(configAuthenticationTemplate),
		"Folders":        template.JS(configFoldersTemplate),
		// UI
		"FormHandler": template.JS(configFormHandlerTemplate),
		"Tooltips":    template.JS(configTooltipsTemplate),
		// App initialization
		"App":               template.JS(configAppTemplate),
		"Nonce":             "ideNonce", // Replaced by IDE extension
		"FolderLabel":       folderLabel,
		"CliReleaseChannel": cliReleaseChannel,
	}

	var buffer bytes.Buffer
	if err := r.template.Execute(&buffer, data); err != nil {
		r.c.Logger().Error().Msgf("Failed to execute config template: %v", err)
		return ""
	}

	return buffer.String()
}

// isVisualStudio checks if the integration name indicates Visual Studio
func isVisualStudio(integrationName string) bool {
	return integrationName == "VISUAL_STUDIO" || integrationName == "Visual Studio"
}

// isEclipse checks if the integration name indicates Eclipse
func isEclipse(integrationName string) bool {
	return integrationName == "ECLIPSE" || integrationName == "Eclipse"
}

// getCliReleaseChannel derives the CLI release channel from the runtime version
func getCliReleaseChannel(c *config.Config) string {
	info := c.Engine().GetRuntimeInfo()
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
