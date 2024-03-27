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

func getExampleFixCodeDiffHtml(fix snyk.ExampleCommitFix) string {
	linesHtml := ""
	for _, commit := range fix.Lines {
		linesHtml += fmt.Sprintf(`
		<div class="tab-content example-line %s"><code>%s</code></div>`, commit.LineChange, commit.Line)
	}
	return linesHtml
}

func getDetailsHtml(issue snyk.Issue) string {
	additionalData, ok := issue.AdditionalData.(snyk.CodeIssueData)
	if !ok {
		log.Error().Msg("Failed to cast additional data to CodeIssueData")
		return ""
	}

	dataFlowHtml := getDataFlowHtml(additionalData)

	html := replaceVariableInHtml(detailsHtmlTemplate, "issueId", issue.ID)
	html = replaceVariableInHtml(html, "issueTitle", additionalData.Title)
	html = replaceVariableInHtml(html, "severityText", issue.Severity.String())
	html = replaceVariableInHtml(html, "dataFlow", dataFlowHtml)
	html = replaceVariableInHtml(html, "dataFlowCount", fmt.Sprintf("%d", len(additionalData.DataFlow)))

	return html
}
