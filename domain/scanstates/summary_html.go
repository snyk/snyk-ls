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
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
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
	engine         workflow.Engine
	configResolver types.ConfigResolverInterface
	globalTemplate *template.Template
}

func NewHtmlRenderer(conf configuration.Configuration, logger *zerolog.Logger, engine workflow.Engine, configResolver types.ConfigResolverInterface) (*HtmlRenderer, error) {
	initLogger := logger.With().Str("method", "NewHtmlRenderer").Logger()
	globalTemplate, err := template.New("summary").Parse(summaryHtmlTemplate)
	if err != nil {
		initLogger.Error().Msgf("Failed to parse details template: %s", err)
		return nil, err
	}

	return &HtmlRenderer{
		conf:           conf,
		logger:         logger,
		engine:         engine,
		configResolver: configResolver,
		globalTemplate: globalTemplate,
	}, nil
}

func (renderer *HtmlRenderer) GetSummaryHtml(state StateSnapshot) string {
	logger := renderer.logger.With().Str("method", "GetSummaryHtml").Logger()
	var currentIssuesFound int
	var currentFixableIssueCount int
	var currentIgnoredIssueCount int
	isDeltaEnabled := renderer.isDeltaEnabledInAnyFolder()
	logger.Debug().Msgf("has wd scans in progress %t, has ref scans in progress %t", state.AnyScanInProgressWorkingDirectory, state.AnyScanInProgressReference)
	logger.Debug().Msgf("scans in progress count %d, ref scans in progress count %d", state.ScansInProgressCount, state.ScansInProgressCount)
	var orgSlugs []string
	var allCounts, deltaCounts summaryCounts
	if state.AnyScanSucceededReference || state.AnyScanSucceededWorkingDirectory {
		var rawAll, rawDelta []types.Issue
		rawAll, rawDelta, orgSlugs = renderer.getIssuesFromFolders()
		allCounts = deduplicateAndCount(rawAll)
		deltaCounts = deduplicateAndCount(rawDelta)

		if isDeltaEnabled {
			currentIssuesFound = deltaCounts.uniqueCount
			currentFixableIssueCount = deltaCounts.fixableCount
			currentIgnoredIssueCount = deltaCounts.ignoredCount
		} else {
			currentIssuesFound = allCounts.uniqueCount
			currentFixableIssueCount = allCounts.fixableCount
			currentIgnoredIssueCount = allCounts.ignoredCount
		}
	}

	data := map[string]interface{}{
		"Styles":                            template.CSS(summaryStylesTemplate),
		"IssuesFound":                       allCounts.uniqueCount,
		"NewIssuesFound":                    deltaCounts.uniqueCount,
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
		if slug := config.FolderOrganizationSlug(renderer.conf, f.Path(), renderer.logger); slug != "" && !seen[slug] {
			seen[slug] = true
			orgSlugs = append(orgSlugs, slug)
		}

		if ip, ok := f.(snyk.FilteringIssueProvider); ok {
			if cp, ok := f.(snyk.CachedIssuePaths); ok {
				for _, path := range cp.CachedPaths() {
					allIssues = append(allIssues, ip.IssuesForFile(path)...)
				}
			} else {
				for _, issues := range ip.Issues() {
					allIssues = append(allIssues, issues...)
				}
			}
		} else {
			logger.Error().Msgf("Failed to get cast folder %s to interface snyk.FilteringIssueProvider", f.Name())
			continue
		}
	}

	// Issues are enriched with IsNew by enrichCachedIssuesWithDelta (called after both WD and ref scans).
	for _, issue := range allIssues {
		if issue.GetIsNew() {
			deltaIssues = append(deltaIssues, issue)
		}
	}

	return allIssues, deltaIssues, orgSlugs
}

type summaryCounts struct {
	uniqueCount  int
	fixableCount int
	ignoredCount int
}

// deduplicateAndCount deduplicates issues by fingerprint and computes fixable/ignored counts in a single pass.
func deduplicateAndCount(issues []types.Issue) summaryCounts {
	seen := make(map[string]bool, len(issues))
	var counts summaryCounts
	for _, issue := range issues {
		fp := issue.GetFingerprint()
		if fp != "" && seen[fp] {
			continue
		}
		if fp != "" {
			seen[fp] = true
		}
		counts.uniqueCount++
		if issue.GetProduct() == product.ProductCode && issue.GetAdditionalData() != nil && issue.GetAdditionalData().IsFixable() {
			counts.fixableCount++
		}
		if issue.GetIsIgnored() {
			counts.ignoredCount++
		}
	}
	return counts
}

// isAutofixEnabledInAnyFolder checks if autofix is enabled in any folders' SAST settings
func (renderer *HtmlRenderer) isAutofixEnabledInAnyFolder() bool {
	ws := config.GetWorkspace(renderer.conf)
	if ws == nil {
		return false
	}

	for _, folder := range ws.Folders() {
		folderConfig := config.GetUnenrichedFolderConfigFromEngine(renderer.engine, renderer.configResolver, folder.Path(), renderer.logger)
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
