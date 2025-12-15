/*
 * © 2025 Snyk Limited
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
	"fmt"
	"html/template"

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
	c              *config.Config
	globalTemplate *template.Template
}

func NewHtmlRenderer(c *config.Config) (*HtmlRenderer, error) {
	logger := c.Logger().With().Str("method", "NewHtmlRenderer").Logger()
	globalTemplate, err := template.New("summary").Parse(summaryHtmlTemplate)
	if err != nil {
		logger.Error().Msgf("Failed to parse details template: %s", err)
		return nil, err
	}

	return &HtmlRenderer{
		c:              c,
		globalTemplate: globalTemplate,
	}, nil
}

func (renderer *HtmlRenderer) GetSummaryHtml(state StateSnapshot) string {
	logger := renderer.c.Logger().With().Str("method", "GetSummaryHtml").Logger()
	var allIssues []types.Issue
	var deltaIssues []types.Issue
	var unfilteredIssuesCount int
	var currentIssuesFound int
	var currentFixableIssueCount int
	isDeltaEnabled := renderer.c.IsDeltaFindingsEnabled()
	logger.Debug().Msgf("has wd scans in progress %t, has ref scans in progress %t", state.AnyScanInProgressWorkingDirectory, state.AnyScanInProgressReference)
	logger.Debug().Msgf("scans in progress count %d, ref scans in progress count %d", state.ScansInProgressCount, state.ScansInProgressCount)
	if state.AnyScanSucceededReference || state.AnyScanSucceededWorkingDirectory {
		allIssues, deltaIssues, unfilteredIssuesCount = renderer.getIssuesFromFolders()

		if isDeltaEnabled {
			currentIssuesFound = len(deltaIssues)
			currentFixableIssueCount = fixableIssueCount(deltaIssues)
		} else {
			currentIssuesFound = len(allIssues)
			currentFixableIssueCount = fixableIssueCount(allIssues)
		}
	}

	filterInfo := renderer.getFilterInfo()
	hiddenIssuesCount := unfilteredIssuesCount - currentIssuesFound

	data := map[string]interface{}{
		"Styles":                            template.CSS(summaryStylesTemplate),
		"IssuesFound":                       len(allIssues),
		"NewIssuesFound":                    len(deltaIssues),
		"CurrentIssuesFound":                currentIssuesFound,
		"CurrentFixableIssueCount":          currentFixableIssueCount,
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
		"HasActiveFilters":                  filterInfo.HasActiveFilters,
		"FilterTooltip":                     filterInfo.Tooltip,
		"HiddenIssuesCount":                 hiddenIssuesCount,
	}
	var buffer bytes.Buffer
	if err := renderer.globalTemplate.Execute(&buffer, data); err != nil {
		logger.Error().Msgf("Failed to execute main summary template: %v", err)
		return ""
	}

	return buffer.String()
}

func (renderer *HtmlRenderer) getIssuesFromFolders() (filteredIssues []types.Issue, filteredDeltaIssues []types.Issue, unfilteredCount int) {
	logger := renderer.c.Logger().With().Str("method", "getIssuesFromFolders").Logger()
	issueTypes := renderer.c.DisplayableIssueTypes()

	for _, f := range renderer.c.Workspace().Folders() {
		if ip, ok := f.(snyk.FilteringIssueProvider); ok {
			// Get unfiltered issues for counting
			unfilteredIssuesByFile := ip.Issues()
			for _, issues := range unfilteredIssuesByFile {
				unfilteredCount += len(issues)
			}

			// Get filtered issues
			filteredIssuesByFile := ip.FilterIssues(unfilteredIssuesByFile, issueTypes)
			for _, issues := range filteredIssuesByFile {
				filteredIssues = append(filteredIssues, issues...)
			}
		} else {
			logger.Error().Msgf("Failed to cast folder %s to interface snyk.FilteringIssueProvider", f.Name())
			return filteredIssues, filteredDeltaIssues, unfilteredCount
		}

		if dp, ok := f.(delta.Provider); ok {
			filteredDeltaIssues = append(filteredDeltaIssues, dp.GetDeltaForAllProducts(issueTypes)...)
		} else {
			logger.Error().Msgf("Failed to cast folder %s to interface delta.Provider", f.Name())
		}
	}

	return filteredIssues, filteredDeltaIssues, unfilteredCount
}

func fixableIssueCount(issues []types.Issue) (fixableIssueCount int) {
	for _, issue := range issues {
		if issue.GetAdditionalData().IsFixable() && issue.GetProduct() == product.ProductCode {
			fixableIssueCount++
		}
	}
	return fixableIssueCount
}

// isAutofixEnabledInAnyFolder checks if autofix is enabled in any folders' SAST settings
func (renderer *HtmlRenderer) isAutofixEnabledInAnyFolder() bool {
	if renderer.c.Workspace() == nil {
		return false
	}

	for _, folder := range renderer.c.Workspace().Folders() {
		folderConfig := renderer.c.FolderConfig(folder.Path())
		if folderConfig != nil && folderConfig.SastSettings != nil && folderConfig.SastSettings.AutofixEnabled {
			return true
		}
	}
	return false
}

type FilterInfo struct {
	HasActiveFilters bool
	Tooltip          string
}

// getFilterInfo generates filter information for the summary HTML
func (renderer *HtmlRenderer) getFilterInfo() FilterInfo {
	var filters []string
	hasActiveFilters := false

	// Check severity filter
	severityFilter := renderer.c.FilterSeverity()
	defaultSeverity := types.DefaultSeverityFilter()
	if severityFilter != defaultSeverity {
		hasActiveFilters = true
		var enabledSeverities []string
		if severityFilter.Critical {
			enabledSeverities = append(enabledSeverities, "Critical")
		}
		if severityFilter.High {
			enabledSeverities = append(enabledSeverities, "High")
		}
		if severityFilter.Medium {
			enabledSeverities = append(enabledSeverities, "Medium")
		}
		if severityFilter.Low {
			enabledSeverities = append(enabledSeverities, "Low")
		}
		if len(enabledSeverities) > 0 {
			filters = append(filters, "Severity: "+joinStrings(enabledSeverities, ", "))
		} else {
			filters = append(filters, "Severity: None")
		}
	}

	// Check risk score threshold
	riskScoreThreshold := renderer.c.RiskScoreThreshold()
	if riskScoreThreshold > 0 {
		hasActiveFilters = true
		filters = append(filters, fmt.Sprintf("Risk Score: ≥%d", riskScoreThreshold))
	}

	// Check issue view options
	issueViewOptions := renderer.c.IssueViewOptions()
	defaultIssueViewOptions := types.DefaultIssueViewOptions()
	if issueViewOptions != defaultIssueViewOptions {
		hasActiveFilters = true
		var viewTypes []string
		if issueViewOptions.OpenIssues {
			viewTypes = append(viewTypes, "Open")
		}
		if issueViewOptions.IgnoredIssues {
			viewTypes = append(viewTypes, "Ignored")
		}
		if len(viewTypes) > 0 {
			filters = append(filters, "Issues: "+joinStrings(viewTypes, ", "))
		} else {
			filters = append(filters, "Issues: None")
		}
	}

	// Use newlines to separate filters for better tooltip readability
	tooltip := "Active filters:\n" + joinStrings(filters, "\n")
	return FilterInfo{
		HasActiveFilters: hasActiveFilters,
		Tooltip:          tooltip,
	}
}

func joinStrings(strs []string, sep string) string {
	result := ""
	for i, s := range strs {
		if i > 0 {
			result += sep
		}
		result += s
	}
	return result
}
