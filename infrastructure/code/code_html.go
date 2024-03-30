/*
 * © 2023-2024 Snyk Limited
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

package code

import (
	_ "embed"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/domain/snyk"
)

//go:embed template/details.html
var detailsHtmlTemplate string

func replaceVariableInHtml(html string, variableName string, variableValue string) string {
	return strings.ReplaceAll(html, fmt.Sprintf("${%s}", variableName), variableValue)
}

func getDataFlowHtml(issue snyk.CodeIssueData) string {
	dataFlowHtml := ""
	for i, flow := range issue.DataFlow {
		dataFlowHtml += fmt.Sprintf(`
		<div class="data-flow-row">
		  <span class="data-flow-number">%d</span>
		  <span class="data-flow-blank"> </span>
		  <span class="data-flow-filepath">%s:%d</span>
		  <span class="data-flow-delimiter">|</span>
		  <span class="data-flow-text">%s</span>
		</div>`, i+1, flow.FilePath, flow.FlowRange.Start.Line+1, flow.Content)
	}
	return dataFlowHtml
}

func getCodeDiffHtml(fix snyk.ExampleCommitFix) string {
	linesHtml := ""
	for _, commit := range fix.Lines {
		linesHtml += fmt.Sprintf(`
		<div class="example-line %s"><code>%s</code></div>`, commit.LineChange, commit.Line)
	}
	return linesHtml
}

func getTabsHtml(fixes []snyk.ExampleCommitFix) string {
	tabsHtml := `<div class="tabs-nav">`

	for i, fix := range fixes {
		// Add the is-selected class to the first tab item only
		// The IDE handles the tab switching with the is-selected class
		isSelectedClass := ""
		if i == 0 {
			isSelectedClass = "is-selected"
		}
		tabsHtml += fmt.Sprintf(`<span class="tab-item %s" id="tab-link-%d">%s</span>`, isSelectedClass, i, fix.CommitURL)
	}

	tabsHtml += "</div>"

	// Generate the contents for each tab
	for i, fix := range fixes {
		// Add the is-selected class to the first tab content only
		// The IDE handles the content display with the is-selected class
		isSelectedClass := ""
		if i == 0 {
			isSelectedClass = "is-selected"
		}
		contentHtml := getCodeDiffHtml(fix)
		tabsHtml += fmt.Sprintf(`<div id="tab-content-%d" class="tab-content %s">%s</div>`, i, isSelectedClass, contentHtml)
	}

	return tabsHtml
}

func getDetailsHtml(issue snyk.Issue) string {
	additionalData, ok := issue.AdditionalData.(snyk.CodeIssueData)
	if !ok {
		log.Error().Msg("Failed to cast additional data to CodeIssueData")
		return ""
	}

	dataFlowHtml := getDataFlowHtml(additionalData)

	// Header
	html := replaceVariableInHtml(detailsHtmlTemplate, "issueId", issue.ID)
	html = replaceVariableInHtml(html, "issueTitle", additionalData.Title)
	html = replaceVariableInHtml(html, "issueType", getIssueType(additionalData))
	html = replaceVariableInHtml(html, "severityText", issue.Severity.String())

	// Data flow
	html = replaceVariableInHtml(html, "dataFlowCount", fmt.Sprintf("%d", len(additionalData.DataFlow)))
	html = replaceVariableInHtml(html, "dataFlow", dataFlowHtml)

	// External example fixes
	html = replaceVariableInHtml(html, "repoCount", fmt.Sprintf("%d", additionalData.RepoDatasetSize))
	html = replaceVariableInHtml(html, "exampleCount", fmt.Sprintf("%d", len(additionalData.ExampleCommitFixes)))
	html = replaceVariableInHtml(html, "tabsNav", getTabsHtml(additionalData.ExampleCommitFixes))

	return html
}

func getIssueType(additionalData snyk.CodeIssueData) string {
	if additionalData.IsSecurityType {
		return "Vulnerability"
	}
	return "Quality Issue"
}
