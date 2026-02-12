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
	"github.com/snyk/snyk-ls/internal/types"
)

//go:embed template/tree.html
var treeHtmlTemplate string

//go:embed template/styles.css
var treeStylesTemplate string

// TreeHtmlRenderer renders tree view data into HTML using Go templates.
type TreeHtmlRenderer struct {
	c              *config.Config
	globalTemplate *template.Template
}

// NewTreeHtmlRenderer creates a new TreeHtmlRenderer with the embedded template.
func NewTreeHtmlRenderer(c *config.Config) (*TreeHtmlRenderer, error) {
	logger := c.Logger().With().Str("method", "NewTreeHtmlRenderer").Logger()

	funcMap := template.FuncMap{
		"severityClass":  severityClass,
		"severityLetter": severityLetter,
		"indentLevel":    indentLevel,
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
		"Styles":         template.CSS(treeStylesTemplate),
		"Nodes":          data.Nodes,
		"FilterState":    data.FilterState,
		"ScanInProgress": data.ScanInProgress,
		"MultiRoot":      data.MultiRoot,
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

func indentLevel(nodeType NodeType) int {
	switch nodeType {
	case NodeTypeFolder:
		return 0
	case NodeTypeProduct:
		return 0
	case NodeTypeFile:
		return 1
	case NodeTypeIssue:
		return 2
	case NodeTypeInfo:
		return 1
	default:
		return 0
	}
}
