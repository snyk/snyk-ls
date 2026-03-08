/*
 * © 2025-2026 Snyk Limited
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

package scanstates

import (
	"bytes"
	_ "embed"
	"html/template"
	"strings"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/domain/snyk/delta"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

//go:embed template/details.html
var summaryHtmlTemplate string

//go:embed template/styles.css
var summaryStylesTemplate string

type HtmlRenderer struct {
	conf           configuration.Configuration
	logger         *zerolog.Logger
	globalTemplate *template.Template
}

func NewHtmlRenderer(conf configuration.Configuration, logger *zerolog.Logger) (*HtmlRenderer, error) {
	initLogger := logger.With().Str("method", "NewHtmlRenderer").Logger()
	globalTemplate, err := template.New("summary").Parse(summaryHtmlTemplate)
	if err != nil {
		initLogger.Error().Msgf("Failed to parse details template: %s", err)
		return nil, err
	}

	return &HtmlRenderer{
		conf:           conf,
		logger:         logger,
		globalTemplate: globalTemplate,
	}, nil
}

func (renderer *HtmlRenderer) GetSummaryHtml(state StateSnapshot) string {
	logger := renderer.logger.With().Str("method", "GetSummaryHtml").Logger()
	var allIssues []types.Issue
	var deltaIssues []types.Issue
	var currentIssuesFound int
	var currentFixableIssueCount int
	var currentIgnoredIssueCount int
	isDeltaEnabled := renderer.isDeltaEnabledInAnyFolder()
	logger.Debug().Msgf("has wd scans in progress %t, has ref scans in progress %t", state.AnyScanInProgressWorkingDirectory, state.AnyScanInProgressReference)
	logger.Debug().Msgf("scans in progress count %d, ref scans in progress count %d", state.ScansInProgressCount, state.ScansInProgressCount)
	var orgSlugs []string
	if state.AnyScanSucceededReference || state.AnyScanSucceededWorkingDirectory {
		allIssues, deltaIssues, orgSlugs = renderer.getIssuesFromFolders()

		if isDeltaEnabled {
			currentIssuesFound = len(deltaIssues)
			currentFixableIssueCount, currentIgnoredIssueCount = countIssues(deltaIssues)
		} else {
			currentIssuesFound = len(allIssues)
			currentFixableIssueCount, currentIgnoredIssueCount = countIssues(allIssues)
		}
	}

	data := map[string]interface{}{
		"Styles":                            template.CSS(summaryStylesTemplate),
		"IssuesFound":                       len(allIssues),
		"NewIssuesFound":                    len(deltaIssues),
		"CurrentIssuesFound":                currentIssuesFound,
		"CurrentFixableIssueCount":          currentFixableIssueCount,
		"CurrentIgnoredIssueCount":          currentIgnoredIssueCount,
		"AllScansStartedReference":          state.AllScansStartedReference,
		"AllScansStartedWorkingDirectory":   state.AllScansStartedWorkingDirectory,
		"AnyScanInProgressReference":        state.AnyScanInProgressReference,
		"AnyScanInProgressWorkingDirectory": state.AnyScanInProgressWorkingDirectory,
		"AnyScanSucceededReference":         state.AnyScanSucceededReference,
		"AnyScanSucceededWorkingDirectory":  state.AnyScanSucceededWorkingDirectory,
		"AllScansSucceededReference":        state.AllScansSucceededReference,
		"AllScansSucceededWorkingDirectory": state.AllScansSucceededWorkingDirectory,
		"AnyScanErrorReference":             state.AnyScanErrorReference,
		"AnyScanErrorWorkingDirectory":      state.AnyScanErrorWorkingDirectory,
		"TotalScansCount":                   state.TotalScansCount,
		"RunningScansCount":                 state.ScansSuccessCount + state.ScansErrorCount,
		"IsDeltaEnabled":                    isDeltaEnabled,
		"IsSnykAgentFixEnabled":             renderer.isAutofixEnabledInAnyFolder(),
		"Organizations":                     strings.Join(orgSlugs, ", "),
	}
	var buffer bytes.Buffer
	if err := renderer.globalTemplate.Execute(&buffer, data); err != nil {
		logger.Error().Msgf("Failed to execute main summary template: %v", err)
		return ""
	}

	return buffer.String()
}

func (renderer *HtmlRenderer) getIssuesFromFolders() (allIssues []types.Issue, deltaIssues []types.Issue, orgSlugs []string) {
	logger := renderer.logger.With().Str("method", "getIssuesFromFolders").Logger()

	seen := map[string]bool{}
	for _, f := range config.GetWorkspace(renderer.conf).Folders() {
		issueTypes := f.DisplayableIssueTypes()

		if slug := config.FolderOrganizationSlug(renderer.conf, f.Path(), renderer.logger); slug != "" && !seen[slug] {
			seen[slug] = true
			orgSlugs = append(orgSlugs, slug)
		}

		if ip, ok := f.(snyk.FilteringIssueProvider); ok {
			// Note that IssueProvider.Issues() does not return enriched issues (i.e, we don't know if they're new). so we
			// also need to get the deltas as a separate operation later.
			// TODO Find the root cause of the issues not being enriched. This is likely an unwanted pointer dereference.
			for _, issues := range ip.Issues() {
				allIssues = append(allIssues, issues...)
			}
		} else {
			logger.Error().Msgf("Failed to get cast folder %s to interface snyk.FilteringIssueProvider", f.Name())
			continue
		}

		if dp, ok := f.(delta.Provider); ok {
			deltaIssues = append(deltaIssues, dp.GetDeltaForAllProducts(issueTypes)...)
		} else {
			logger.Error().Msgf("Failed to get cast folder %s to interface delta.Provider", f.Name())
		}
	}

	return allIssues, deltaIssues, orgSlugs
}

func countIssues(issues []types.Issue) (fixable int, ignored int) {
	for _, issue := range issues {
		if issue.GetProduct() == product.ProductCode && issue.GetAdditionalData() != nil && issue.GetAdditionalData().IsFixable() {
			fixable++
		}
		if issue.GetIsIgnored() {
			ignored++
		}
	}
	return fixable, ignored
}

// isAutofixEnabledInAnyFolder checks if autofix is enabled in any folders' SAST settings
func (renderer *HtmlRenderer) isAutofixEnabledInAnyFolder() bool {
	ws := config.GetWorkspace(renderer.conf)
	if ws == nil {
		return false
	}

	for _, folder := range ws.Folders() {
		// TODO: move to DI
		folderConfig := config.GetFolderConfigFromEngine(config.CurrentConfig().Engine(), config.CurrentConfig().GetConfigResolver(), folder.Path(), renderer.logger)
		if folderConfig != nil {
			if sastSettings := types.GetSastSettings(folderConfig.Conf(), folderConfig.FolderPath); sastSettings != nil && sastSettings.AutofixEnabled {
				return true
			}
		}
	}
	return false
}

// isDeltaEnabledInAnyFolder checks if delta findings is enabled in any folder
func (renderer *HtmlRenderer) isDeltaEnabledInAnyFolder() bool {
	ws := config.GetWorkspace(renderer.conf)
	if ws == nil {
		return false
	}

	for _, folder := range ws.Folders() {
		if folder.IsDeltaFindingsEnabled() {
			return true
		}
	}
	return false
}
