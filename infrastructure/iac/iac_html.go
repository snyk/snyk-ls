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
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"fmt"
	"html/template"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	iac "github.com/snyk/snyk-ls/infrastructure/iac/template/assets"
	"github.com/snyk/snyk-ls/internal/product"
)

type IacHtmlRender struct {
	Config         *config.Config
	GlobalTemplate *template.Template
}

type TemplateData struct {
	Styles       template.CSS
	Issue        snyk.Issue
	SeverityIcon template.HTML
	Nonce        string
}

//go:embed template/index.html
var detailsHtmlTemplate string

//go:embed template/styles.css
var stylesCSS string

func NewIacHtmlRender(cfg *config.Config) (*IacHtmlRender, error) {
	tmp, err := template.New(string(product.ProductInfrastructureAsCode)).Parse(detailsHtmlTemplate)
	if err != nil {
		cfg.Logger().Error().Msgf("Failed to parse IaC template: %s", err)
		return nil, err
	}

	return &IacHtmlRender{
		Config:         cfg,
		GlobalTemplate: tmp,
	}, nil
}

func getStyles() template.CSS {
	return template.CSS(stylesCSS)
}

// Function to get the rendered HTML with issue details and CSS
func (service *IacHtmlRender) getDetailsHtml(issue snyk.Issue) string {
	var html bytes.Buffer

	nonce, err := generateSecurityNonce()
	if err != nil {
		service.Config.Logger().Warn().Msgf("Failed to generate nonce: %s", err)
		return ""
	}

	data := TemplateData{
		Styles:       getStyles(),
		Issue:        issue,
		SeverityIcon: iac.GetSeverityIconSvg(issue),
		Nonce:        nonce,
	}

	err = service.GlobalTemplate.Execute(&html, data)
	if err != nil {
		service.Config.Logger().Error().Msgf("Failed to execute IaC template: %s", err)
	}

	return html.String()
}

// generateSecurityNonce generates a cryptographically secure random nonce.
// A nonce is used in the Content Security Policy (CSP) to allow specific
// inline styles and scripts, helping to prevent Cross-Site Scripting (XSS) attacks.
func generateSecurityNonce() (string, error) {
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", fmt.Errorf("error generating nonce: %v", err)
	}
	return base64.StdEncoding.EncodeToString(nonceBytes), nil
}
