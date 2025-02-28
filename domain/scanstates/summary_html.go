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
	"html/template"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
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
	var currentIssuesFound int
	var currentFixableIssueCount int
	isDeltaEnabled := renderer.c.IsDeltaFindingsEnabled()

	if state.AnyScanSucceededReference || state.AnyScanSucceededWorkingDirectory {
		allIssues = renderer.getIssuesFromFolders()
		deltaIssues = []types.Issue{}

		for _, issue := range allIssues {
			if issue.GetIsNew() {
				deltaIssues = append(deltaIssues, issue)
			}
		}

		if isDeltaEnabled {
			currentIssuesFound = len(deltaIssues)
			currentFixableIssueCount = fixableIssueCount(deltaIssues)
		} else {
			currentIssuesFound = len(allIssues)
			currentFixableIssueCount = fixableIssueCount(allIssues)
		}
	}

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
	}
	var buffer bytes.Buffer
	if err := renderer.globalTemplate.Execute(&buffer, data); err != nil {
		logger.Error().Msgf("Failed to execute main summary template: %v", err)
		return ""
	}

	return buffer.String()
}

func (renderer *HtmlRenderer) getIssuesFromFolders() (allIssues []types.Issue) {
	logger := renderer.c.Logger().With().Str("method", "getIssuesFromFolders").Logger()

	for _, f := range renderer.c.Workspace().Folders() {
		//if dp, ok := f.(delta.Provider); ok {
		//	deltaIssues = append(deltaIssues, renderer.getDeltaIssuesForFolder(dp)...)
		//} else {
		//	logger.Error().Msgf("Failed to get cast folder %s to interface delta.Provider", f.Name())
		//}

		ip, ok := f.(snyk.IssueProvider)
		if !ok {
			logger.Error().Msgf("Failed to get cast folder %s to interface snyk.IssueProvider", f.Name())
			return allIssues
		}
		for _, issues := range ip.Issues() {
			allIssues = append(allIssues, issues...)
		}
	}

	return allIssues
}

func fixableIssueCount(issues []types.Issue) (fixableIssueCount int) {
	for _, issue := range issues {
		if issue.GetAdditionalData().IsFixable() {
			fixableIssueCount++
		}
	}
	return fixableIssueCount
}
