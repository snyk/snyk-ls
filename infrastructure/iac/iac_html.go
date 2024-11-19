/*
 * © 2024 Snyk Limited
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

package iac

import (
	"bytes"
	_ "embed"
	"html/template"
	"strings"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/html"
	"github.com/snyk/snyk-ls/internal/product"
)

type HtmlRenderer struct {
	c              *config.Config
	globalTemplate *template.Template
}

type TemplateData struct {
	Styles       template.CSS
	Scripts      template.JS
	Issue        snyk.Issue
	SeverityIcon template.HTML
	Description  template.HTML
	Remediation  template.HTML
	ResourcePath template.HTML
	FilePath     template.HTML
	Nonce        template.HTML
}

//go:embed template/index.html
var detailsHtmlTemplate string

//go:embed template/styles.css
var stylesCSS string

//go:embed template/scripts.js
var scripts string

func NewHtmlRenderer(c *config.Config) (*HtmlRenderer, error) {
	tmp, err := template.New(string(product.ProductInfrastructureAsCode)).Parse(detailsHtmlTemplate)
	if err != nil {
		c.Logger().Error().Msgf("Failed to parse IaC template: %s", err)
		return nil, err
	}

	return &HtmlRenderer{
		c:              c,
		globalTemplate: tmp,
	}, nil
}

func getStyles() template.CSS {
	return template.CSS(stylesCSS)
}

func getScripts() template.JS {
	return template.JS(scripts)
}

// Function to get the rendered HTML with issue details and CSS
func (service *HtmlRenderer) GetDetailsHtml(issue snyk.Issue) string {
	var htmlTemplate bytes.Buffer

	nonce, err := html.GenerateSecurityNonce()
	if err != nil {
		service.c.Logger().Warn().Msgf("Failed to generate nonce: %s", err)
		return ""
	}

	issueData, ok := issue.AdditionalData.(snyk.IaCIssueData)
	if !ok {
		service.c.Logger().Error().Msgf("Failed to parse IaC issue")
		return htmlTemplate.String()
	}

	data := TemplateData{
		Styles:       getStyles(),
		Scripts:      getScripts(),
		Issue:        issue,
		SeverityIcon: html.SeverityIcon(issue),
		Description:  html.MarkdownToHTML(issue.Message),
		Remediation:  html.MarkdownToHTML(issueData.Resolve),
		ResourcePath: formatPath(issueData.Path),
		FilePath:     template.HTML(issue.Path()),
		Nonce:        template.HTML(nonce),
	}

	err = service.globalTemplate.Execute(&htmlTemplate, data)
	if err != nil {
		service.c.Logger().Error().Msgf("Failed to execute IaC template: %s", err)
	}

	return htmlTemplate.String()
}

func formatPath(path []string) template.HTML {
	return template.HTML(strings.Join(path, " > "))
}
