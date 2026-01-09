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

//go:embed template/js/utils.js
var configUtilsTemplate string

//go:embed template/js/dirty-tracker.js
var configDirtyTrackerTemplate string

//go:embed template/js/helpers.js
var configHelpersTemplate string

//go:embed template/js/validation.js
var configValidationTemplate string

//go:embed template/js/form-data.js
var configFormDataTemplate string

//go:embed template/js/auto-save.js
var configAutoSaveTemplate string

//go:embed template/js/authentication.js
var configAuthenticationTemplate string

//go:embed template/js/folder-management.js
var configFolderManagementTemplate string

//go:embed template/js/trusted-folders.js
var configTrustedFoldersTemplate string

//go:embed template/js/dirty-tracking.js
var configDirtyTrackingModuleTemplate string

//go:embed template/js/init.js
var configInitTemplate string

type ConfigHtmlRenderer struct {
	c        *config.Config
	template *template.Template
}

func NewConfigHtmlRenderer(c *config.Config) (*ConfigHtmlRenderer, error) {
	// Register custom template functions for better template reusability
	funcMap := template.FuncMap{
		"list": func(items ...interface{}) []interface{} {
			return items
		},
		"dict": func(values ...interface{}) map[string]interface{} {
			if len(values)%2 != 0 {
				return nil
			}
			dict := make(map[string]interface{}, len(values)/2)
			for i := 0; i < len(values); i += 2 {
				key, ok := values[i].(string)
				if !ok {
					return nil
				}
				dict[key] = values[i+1]
			}
			return dict
		},
		// toLower converts a string to lowercase
		"toLower": func(s string) string {
			return strings.ToLower(s)
		},
		// getScanConfig retrieves scan configuration for a specific product from a map
		"getScanConfig": func(scanConfigMap map[product.Product]types.ScanCommandConfig, productName string) *types.ScanCommandConfig {
			if scanConfigMap == nil {
				return nil
			}
			var prod product.Product
			switch productName {
			case "oss", "Snyk Open Source":
				prod = product.ProductOpenSource
			case "code", "Snyk Code":
				prod = product.ProductCode
			case "iac", "Snyk IaC":
				prod = product.ProductInfrastructureAsCode
			default:
				return nil
			}
			if config, ok := scanConfigMap[prod]; ok {
				return &config
			}
			return nil
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
// The IDE can query dirty state via window.__isFormDirty__() or reset it via window.__resetDirtyState__().
// Folder configs are filtered to only show folders that are currently in the workspace.
func (r *ConfigHtmlRenderer) GetConfigHtml(settings types.Settings) string {
	// Determine folder/solution/project label based on IDE
	folderLabel := "Folder"
	if isVisualStudio(settings.IntegrationName) {
		folderLabel = "Solution"
	} else if isEclipse(settings.IntegrationName) {
		folderLabel = "Project"
	}

	// Filter folder configs to only include those in the current workspace
	filteredSettings := filterFolderConfigs(settings, r.c)

	// Get CLI release channel from runtime version
	cliReleaseChannel := getCliReleaseChannel(r.c)

	data := map[string]interface{}{
		"Settings":            filteredSettings,
		"Styles":              template.CSS(configStylesTemplate),
		"Utils":               template.JS(configUtilsTemplate),
		"DirtyTracker":        template.JS(configDirtyTrackerTemplate),
		"Helpers":             template.JS(configHelpersTemplate),
		"Validation":          template.JS(configValidationTemplate),
		"FormData":            template.JS(configFormDataTemplate),
		"AutoSave":            template.JS(configAutoSaveTemplate),
		"Authentication":      template.JS(configAuthenticationTemplate),
		"FolderManagement":    template.JS(configFolderManagementTemplate),
		"TrustedFolders":      template.JS(configTrustedFoldersTemplate),
		"DirtyTrackingModule": template.JS(configDirtyTrackingModuleTemplate),
		"Init":                template.JS(configInitTemplate),
		"Nonce":               "ideNonce", // Replaced by IDE extension
		"FolderLabel":         folderLabel,
		"CliReleaseChannel":   cliReleaseChannel,
	}

	var buffer bytes.Buffer
	if err := r.template.Execute(&buffer, data); err != nil {
		r.c.Logger().Error().Msgf("Failed to execute config template: %v", err)
		return ""
	}

	return buffer.String()
}

// filterFolderConfigs filters the settings to only include folder configs
// that correspond to folders currently in the workspace.
func filterFolderConfigs(settings types.Settings, c *config.Config) types.Settings {
	// If no workspace, return settings with empty folder configs
	if c.Workspace() == nil {
		settings.FolderConfigs = []types.FolderConfig{}
		return settings
	}

	// Build a map of workspace folder paths for O(1) lookup
	workspaceFolders := make(map[types.FilePath]bool)
	for _, folder := range c.Workspace().Folders() {
		workspaceFolders[folder.Path()] = true
	}

	// Filter folder configs to only include those in the workspace
	filteredConfigs := make([]types.FolderConfig, 0, len(settings.FolderConfigs))
	for _, fc := range settings.FolderConfigs {
		if workspaceFolders[fc.FolderPath] {
			filteredConfigs = append(filteredConfigs, fc)
		}
	}

	settings.FolderConfigs = filteredConfigs
	return settings
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
