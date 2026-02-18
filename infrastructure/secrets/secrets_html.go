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

package secrets

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"net/url"

	codeClientSarif "github.com/snyk/code-client-go/sarif"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/html"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

//go:embed template/details.html
var detailsHtmlTemplate string

//go:embed template/styles.css
var panelStylesTemplate string

//go:embed template/scripts.js
var customScripts string

type HtmlRenderer struct {
	c                  *config.Config
	globalTemplate     *template.Template
	cciEnabled         bool
	featureFlagService featureflag.Service
}

func NewHtmlRenderer(c *config.Config, featureFlagService featureflag.Service) (*HtmlRenderer, error) {
	if featureFlagService == nil {
		return nil, fmt.Errorf("passed featureFlagService is nil")
	}

	funcMap := template.FuncMap{
		"trimCWEPrefix": html.TrimCWEPrefix,
		"idxMinusOne":   html.IdxMinusOne,
	}

	globalTemplate, err := template.New(string(product.ProductSecrets)).Funcs(funcMap).Parse(detailsHtmlTemplate)
	if err != nil {
		c.Logger().Error().Msgf("Failed to parse secrets details template: %s", err)
		return nil, err
	}

	return &HtmlRenderer{
		c:                  c,
		globalTemplate:     globalTemplate,
		featureFlagService: featureFlagService,
	}, nil
}

func (renderer *HtmlRenderer) determineFolderPath(filePath types.FilePath) types.FilePath {
	ws := renderer.c.Workspace()
	if ws == nil {
		return ""
	}
	for _, folder := range ws.Folders() {
		folderPath := folder.Path()
		if uri.FolderContains(folderPath, filePath) {
			return folderPath
		}
	}
	return ""
}

func (renderer *HtmlRenderer) updateFeatureFlags(folder types.FilePath) {
	renderer.cciEnabled = renderer.featureFlagService.GetFromFolderConfig(folder, featureflag.SnykCodeConsistentIgnores)
}

func (renderer *HtmlRenderer) GetDetailsHtml(issue types.Issue) string {
	additionalData, ok := issue.GetAdditionalData().(snyk.SecretIssueData)
	if !ok {
		renderer.c.Logger().Error().Msg("Failed to cast additional data to SecretIssueData")
		return ""
	}

	nonce, err := html.GenerateSecurityNonce()
	if err != nil {
		renderer.c.Logger().Warn().Msgf("Failed to generate security nonce: %s", err)
		return ""
	}

	folderPath := renderer.determineFolderPath(issue.GetAffectedFilePath())
	renderer.updateFeatureFlags(folderPath)

	isPending := false
	ignoreDetailsRow := []html.IgnoreDetail{}
	ignoreReason := ""
	if ignoreDetails := issue.GetIgnoreDetails(); ignoreDetails != nil {
		isPending = ignoreDetails.Status == codeClientSarif.UnderReview
		ignoreDetailsRow = html.PrepareIgnoreDetailsRow(ignoreDetails)
		ignoreReason = ignoreDetails.Reason
	}

	appLink := renderer.c.SnykUI()
	if isPending {
		orgSlug := renderer.c.FolderOrganizationSlug(folderPath)
		pendingIgnoreURL, err := url.JoinPath(renderer.c.SnykUI(), "org", orgSlug, "ignore-requests")
		if err != nil {
			renderer.c.Logger().Error().Err(err).Msg("Failed to construct pending ignore link")
		} else {
			appLink = pendingIgnoreURL
		}
	}

	data := map[string]any{
		"IssueTitle":       additionalData.Title,
		"IssueMessage":     additionalData.Message,
		"SeverityIcon":     html.SeverityIcon(issue),
		"CWEs":             issue.GetCWEs(),
		"IsIgnored":        issue.GetIsIgnored(),
		"IsPending":        isPending,
		"IgnoreDetails":    ignoreDetailsRow,
		"IgnoreReason":     ignoreReason,
		"CCIEnabled":       renderer.cciEnabled,
		"IgnoreLineAction": getLineToIgnoreAction(issue),
		"SnykWebUrl":       appLink,
		"RuleName":         additionalData.RuleName,
		"Categories":       additionalData.Categories,
		"FolderPath":       string(folderPath),
		"FilePath":         string(issue.GetAffectedFilePath()),
		"IssueId":          issue.GetAdditionalData().GetKey(),
		"Styles":           template.CSS(panelStylesTemplate),
		"Scripts":          template.JS(customScripts),
		"Nonce":            nonce,
	}

	var buffer bytes.Buffer
	if err := renderer.globalTemplate.Execute(&buffer, data); err != nil {
		renderer.c.Logger().Error().Msgf("Failed to execute secrets details template: %v", err)
		return ""
	}

	return buffer.String()
}

func getLineToIgnoreAction(issue types.Issue) int {
	return issue.GetRange().Start.Line + 1
}
