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
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"fmt"
	"html/template"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/html"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

//go:embed template/diagnosticsOverview.html
var diagnosticsOverviewTemplatePath string

//go:embed template/diagnosticsOverview.css
var diagnosticsOverviewTemplateCSS string
var diagnosticsOverviewTemplate *template.Template

func init() {
	logger := config.CurrentConfig().Logger().With().Str("method", "ui.init").Logger()
	funcMap := map[string]any{}
	var err error
	diagnosticsOverviewTemplate, err = template.New("diagnosticsOverviewTemplate").Funcs(funcMap).Parse(diagnosticsOverviewTemplatePath)
	if err != nil {
		logger.Err(err).Msg("failed to parse template")
		return
	}
}

type TemplateData struct {
	// Root nodes
	RootNodes []Node
	// File node with underlying slice of issue nodes
	Issues map[Node][]Node
	Styles template.CSS
	Nonce  string
}

// Node represents a tree node
type Node struct {
	Icon template.HTML
	Text template.HTML
}

func SendDiagnosticsOverview(c *config.Config, p product.Product, issuesByFile snyk.IssuesByFile, notifier notification.Notifier) {
	logger := c.Logger().With().Str("method", "ui.SendDiagnosticsOverview").Logger()
	if p != "" {
		rootNodes := getRootNodes(c, p, issuesByFile)
		nonce, err := generateSecurityNonce()
		if err != nil {
			logger.Err(err).Msgf("Failed to generate nonce")
			return
		}

		fileNodes := getFileNodes(issuesByFile)

		data := TemplateData{
			RootNodes: rootNodes,
			Issues:    fileNodes,
			Styles:    template.CSS(diagnosticsOverviewTemplateCSS),
			Nonce:     nonce,
		}

		var htmlBuffer bytes.Buffer
		if err = diagnosticsOverviewTemplate.Execute(&htmlBuffer, data); err != nil {
			logger.Error().Msgf("Failed to generate tree htmlBuffer with tree template: %v", err)
			return
		}

		diagnosticsOverviewParams := types.DiagnosticsOverviewParams{Product: p.ToProductCodename(), Html: htmlBuffer.String()}
		notifier.Send(diagnosticsOverviewParams)
		logger.Debug().Msgf("sent diagnostics overview htmlBuffer for product %s", p)
		logger.Trace().
			Int("issueCount", len(issuesByFile)).
			Any("diagnosticsOverviewParams", diagnosticsOverviewParams).
			Msg("detailed tree data")
	}
}

func getFileNodes(issuesByFile snyk.IssuesByFile) map[Node][]Node {
	fileNodes := make(map[Node][]Node)
	for path, issues := range issuesByFile {
		fileNode := Node{
			Icon: getFileTypeIcon(),
			Text: template.HTML(path),
		}
		issueNodes := []Node{}
		for _, issue := range issues {
			issueNodes = append(issueNodes, Node{
				Icon: html.GetSeverityIconSvg(issue),
				Text: template.HTML(issue.AdditionalData.GetTitle()),
			})
		}
		fileNodes[fileNode] = issueNodes
	}
	return fileNodes
}

func getFileTypeIcon() template.HTML {
	return ""
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

func getRootNodes(c *config.Config, p product.Product, issuesByFile snyk.IssuesByFile) []Node {
	var icon template.HTML

	if isProductEnabled(c, p) {
		icon = html.GetProductIcon(p)
	} else {
		icon = html.GetProductIconDisabled(p)
	}

	rootNodeTitle := getRootNodeText(issuesByFile, p)

	rootNodes := append([]Node{}, Node{
		Icon: icon,
		Text: template.HTML(rootNodeTitle),
	})

	fixableCount := issuesByFile.FixableCount()
	if fixableCount > 0 {
		plural := ""
		if fixableCount > 1 {
			plural = "s"
		}
		rootNodes = append(rootNodes, Node{
			Text: template.HTML(fmt.Sprintf("%d issue%s can be fixed automatically", fixableCount, plural)),
		})
	}

	return rootNodes
}

func getRootNodeText(issuesByFile snyk.IssuesByFile, p product.Product) string {
	total, critical, high, medium, low := issuesByFile.SeverityCounts()

	pluralSuffix := ""
	if total > 1 {
		pluralSuffix = "s"
	}

	var rootNodeTitle = fmt.Sprintf("%s - No issues found", p.ToFilterableIssueType()[0])
	if total > 0 {
		rootNodeTitle = fmt.Sprintf(
			"%s - %d unique issue%s: %s",
			p.ToFilterableIssueType()[0],
			total,
			pluralSuffix,
			issuesByFile.SeverityCountsAsString(critical, high, medium, low),
		)
	}
	return rootNodeTitle
}

func isProductEnabled(c *config.Config, p product.Product) bool {
	switch p {
	case product.ProductOpenSource:
		return c.IsSnykOssEnabled()
	case product.ProductCode:
		return c.IsSnykCodeEnabled()
	case product.ProductInfrastructureAsCode:
		return c.IsSnykIacEnabled()
	default:
		return false
	}
}
