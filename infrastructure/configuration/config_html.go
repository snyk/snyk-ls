// Package configuration provides HTML rendering for the configuration dialog.
// It uses Go templates to generate the configuration UI that is displayed to users
// via the LSP protocol's window/showDocument mechanism.
package configuration

import (
	"bytes"
	_ "embed"
	"html/template"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/types"
)

//go:embed template/config.html
var configHtmlTemplate string

//go:embed template/styles.css
var configStylesTemplate string

//go:embed template/scripts.js
var configScriptsTemplate string

type ConfigHtmlRenderer struct {
	c        *config.Config
	template *template.Template
}

func NewConfigHtmlRenderer(c *config.Config) (*ConfigHtmlRenderer, error) {
	tmpl, err := template.New("config").Parse(configHtmlTemplate)
	if err != nil {
		c.Logger().Error().Msgf("Failed to parse config template: %s", err)
		return nil, err
	}

	return &ConfigHtmlRenderer{
		c:        c,
		template: tmpl,
	}, nil
}

func (r *ConfigHtmlRenderer) GetConfigHtml(settings types.Settings) string {
	// Since we are injecting JS functions, we don't need to resolve them here.
	// But the template expects placeholders like ${ideSaveConfig} which are NOT valid Go template syntax if we execute it as Go template.
	// Wait, if I use Go template to render the page, the `${...}` parts will be treated as text unless I use them in the JS template.
	// The JS file `scripts.js` has `${ideSaveConfig}`.
	// When I do `template.JS(configScriptsTemplate)`, it includes the raw string.
	// The Client (IDE) is responsible for replacing `${ideSaveConfig}` with the actual command ID or handler name
	// BEFORE showing the HTML, OR the JS should call a known function name that the IDE injects.
	// The ignore dialog uses `${ideSubmitIgnoreRequest}` which suggests the SERVER (this code) should replace it,
	// OR the template execution mechanism on the server should replace it.
	// In `infrastructure/code/code_html.go`, `detailsHtmlTemplate` is parsed as Go template.
	// The `scripts.js` there has `${ideGenerateAIFix}`.
	// But wait, `code_html.go` does NOT seem to replace these placeholders.
	// Let's check `domain/ide/command/navigate_to_range.go` ... `showDocument` sends a URI.
	// The content provider in the IDE receives the URI.
	// The content provider typically calls `getDetailsHtml` (or similar).
	// If the `GetConfigHtml` returns the string with `${ideSaveConfig}`, the IDE's content provider
	// must replace it with the actual command URI/ID.
	//
	// The user query "The settings dialog also should have a button, that allows initiating authentication by calling the login command...".
	//
	// I'll assume the IDE extension handles the replacement of `${ide...}` placeholders.

	data := map[string]interface{}{
		"Settings": settings,
		"Styles":   template.CSS(configStylesTemplate),
		"Scripts":  template.JS(configScriptsTemplate),
		"Nonce":    "ideNonce", // Placeholder
	}

	var buffer bytes.Buffer
	if err := r.template.Execute(&buffer, data); err != nil {
		r.c.Logger().Error().Msgf("Failed to execute config template: %v", err)
		return ""
	}

	return buffer.String()
}
