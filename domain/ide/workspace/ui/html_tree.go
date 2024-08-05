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

package ui

import (
	"bytes"
	_ "embed"
	"html/template"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

//go:embed template/tree.html
var treeHtmlTemplate string
var treeTemplate *template.Template

func init() {
	logger := config.CurrentConfig().Logger().With().Str("method", "ui.init").Logger()
	funcMap := map[string]any{}
	var err error
	treeTemplate, err = template.New("treeTemplate").Funcs(funcMap).Parse(treeHtmlTemplate)
	if err != nil {
		logger.Err(err).Msg("failed to parse template")
		return
	}
}

func SendTree(c *config.Config, p product.Product, issuesByFile snyk.IssuesByFile, notifier notification.Notifier) {
	logger := c.Logger().With().Str("method", "ui.SendTree").Logger()
	var productIssues []snyk.Issue
	for _, issues := range issuesByFile {
		productIssues = append(productIssues, issues...)
	}

	if p != "" {
		type TemplateData struct {
			Issues []snyk.Issue
		}

		data := TemplateData{
			Issues: productIssues,
		}

		var html bytes.Buffer
		if err := treeTemplate.Execute(&html, data); err != nil {
			logger.Error().Msgf("Failed to generate tree html with tree template: %v", err)
			return
		}

		treeParams := types.TreeParams{Product: p.ToProductCodename(), Html: html.String()}
		notifier.Send(treeParams)
		logger.Debug().Msgf("sent tree html for product %s", p)
		logger.Trace().
			Int("issueCount", len(productIssues)).
			Any("treeParams", treeParams).
			Msg("detailed tree data")
	}
}
