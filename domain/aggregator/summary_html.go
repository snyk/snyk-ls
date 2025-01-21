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

package aggregator

import (
	"bytes"
	_ "embed"
	"html/template"

	"github.com/snyk/snyk-ls/domain/snyk"

	"github.com/snyk/snyk-ls/application/config"
)

//go:embed template/details.html
var summaryHtmlTemplate string

//go:embed template/styles.css
var panelStylesTemplate string

type HtmlRenderer struct {
	c              *config.Config
	globalTemplate *template.Template
}

func NewHtmlRenderer(c *config.Config) (*HtmlRenderer, error) {
	globalTemplate, err := template.New("summary").Parse(summaryHtmlTemplate)
	if err != nil {
		c.Logger().Error().Msgf("Failed to parse details template: %s", err)
		return nil, err
	}

	return &HtmlRenderer{
		c:              c,
		globalTemplate: globalTemplate,
	}, nil
}

func (renderer *HtmlRenderer) GetSummaryHtml(stateAggregator StateAggregator) string {
	issueCount := renderer.getIssuesFromFolders()
	data := map[string]interface{}{
		"Styles":                            template.CSS(panelStylesTemplate),
		"IssuesFound":                       issueCount,
		"FixableIssueCount":                 7,
		"AllScansStartedReference":          stateAggregator.AllScansStarted(true),
		"AllScansStartedWorkingDirectory":   stateAggregator.AllScansStarted(false),
		"AnyScanInProgressReference":        stateAggregator.AnyScanInProgress(true),
		"AnyScanInProgressWorkingDirectory": stateAggregator.AnyScanInProgress(false),
		"AnyScanSucceededReference":         stateAggregator.AnyScanSucceeded(true),
		"AnyScanSucceededWorkingDirectory":  stateAggregator.AnyScanSucceeded(false),
		"AllScansSucceededReference":        stateAggregator.AllScansSucceeded(true),
		"AllScansSucceededWorkingDirectory": stateAggregator.AllScansSucceeded(false),
		"AnyScanErrorReference":             stateAggregator.AnyScanError(true),
		"AnyScanErrorWorkingDirectory":      stateAggregator.AnyScanError(false),
	}
	var buffer bytes.Buffer
	if err := renderer.globalTemplate.Execute(&buffer, data); err != nil {
		renderer.c.Logger().Error().Msgf("Failed to execute main summary template: %v", err)
		return ""
	}

	return buffer.String()
}

func (renderer *HtmlRenderer) getIssuesFromFolders() int {
	var allIssues []snyk.Issue

	ip, ok := renderer.c.Workspace().(snyk.IssueProvider)
	if !ok {
		return 0
	}

	for _, issues := range ip.Issues() {
		allIssues = append(allIssues, issues...)
	}
	return len(allIssues)

}
