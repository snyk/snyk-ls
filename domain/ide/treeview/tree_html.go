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

package treeview

import (
	"bytes"
	_ "embed"
	"html/template"
	"strings"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/fileicon"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

//go:embed template/tree.html
var treeHtmlTemplate string

//go:embed template/styles.css
var treeStylesTemplate string

//go:embed template/tree.js
var treeJsTemplate string

// TreeHtmlRenderer renders tree view data into HTML using Go templates.
type TreeHtmlRenderer struct {
	c              *config.Config
	globalTemplate *template.Template
}

// NewTreeHtmlRenderer creates a new TreeHtmlRenderer with the embedded template.
func NewTreeHtmlRenderer(c *config.Config) (*TreeHtmlRenderer, error) {
	logger := c.Logger().With().Str("method", "NewTreeHtmlRenderer").Logger()

	funcMap := template.FuncMap{
		"severityClass":     severityClass,
		"severityLetter":    severityLetter,
		"severitySVG":       func(s types.Severity) template.HTML { return template.HTML(severitySVG(s)) },
		"severitySVGByName": severitySVGByName,
		"productSVG":        func(p product.Product) template.HTML { return template.HTML(productSVG(p)) },
		"checkmarkSVG":      func() template.HTML { return template.HTML(checkmarkSVG()) },
		"fileIcon":          fileIconFunc,
		"isEnabled":         isEnabledFunc,
		"joinStrings":       func(s []string, sep string) string { return strings.Join(s, sep) },
	}

	globalTemplate, err := template.New("treeView").Funcs(funcMap).Parse(treeHtmlTemplate)
	if err != nil {
		logger.Error().Msgf("Failed to parse tree view template: %s", err)
		return nil, err
	}

	return &TreeHtmlRenderer{
		c:              c,
		globalTemplate: globalTemplate,
	}, nil
}

// RenderTreeView renders the tree view data into an HTML string.
func (r *TreeHtmlRenderer) RenderTreeView(data TreeViewData) string {
	logger := r.c.Logger().With().Str("method", "RenderTreeView").Logger()

	templateData := map[string]interface{}{
		"Styles":      template.CSS(treeStylesTemplate),
		"Script":      template.JS(treeJsTemplate),
		"Nodes":       data.Nodes,
		"FilterState": data.FilterState,
		"TotalIssues": data.TotalIssues,
		"MultiRoot":   data.MultiRoot,
	}

	var buffer bytes.Buffer
	if err := r.globalTemplate.Execute(&buffer, templateData); err != nil {
		logger.Error().Msgf("Failed to execute tree view template: %v", err)
		return ""
	}

	return buffer.String()
}

func severityClass(s types.Severity) string {
	return strings.ToLower(s.String())
}

func severityLetter(s types.Severity) string {
	switch s {
	case types.Critical:
		return "C"
	case types.High:
		return "H"
	case types.Medium:
		return "M"
	case types.Low:
		return "L"
	default:
		return "?"
	}
}

// severitySVGByName returns inline SVG HTML for a severity name string (used in filter toolbar template).
func severitySVGByName(name string) template.HTML {
	switch strings.ToLower(name) {
	case "critical":
		return template.HTML(svgSeverityCritical)
	case "high":
		return template.HTML(svgSeverityHigh)
	case "medium":
		return template.HTML(svgSeverityMedium)
	case "low":
		return template.HTML(svgSeverityLow)
	default:
		return ""
	}
}

// severitySVG returns the inline SVG icon for a severity level.
func severitySVG(s types.Severity) string {
	switch s {
	case types.Critical:
		return svgSeverityCritical
	case types.High:
		return svgSeverityHigh
	case types.Medium:
		return svgSeverityMedium
	case types.Low:
		return svgSeverityLow
	default:
		return ""
	}
}

// productSVG returns the inline SVG icon for a product.
func productSVG(p product.Product) string {
	switch p {
	case product.ProductCode:
		return svgProductCode
	case product.ProductOpenSource:
		return svgProductOSS
	case product.ProductInfrastructureAsCode:
		return svgProductIaC
	case product.ProductSecrets:
		return svgProductSecrets
	default:
		return ""
	}
}

// checkmarkSVG returns the green checkmark SVG icon.
func checkmarkSVG() string {
	return svgCheckmark
}

// isEnabledFunc returns true if the Enabled pointer is nil (default=enabled) or points to true.
func isEnabledFunc(enabled *bool) bool {
	return enabled == nil || *enabled
}

// fileIconFunc returns a pre-rendered file icon HTML fragment as trusted template.HTML.
// When the input is empty (no icon resolved by the builder), the generic file SVG is used.
func fileIconFunc(iconHTML string) template.HTML {
	if iconHTML == "" {
		return template.HTML(fileicon.GetOSFileIcon(""))
	}
	return template.HTML(iconHTML)
}
