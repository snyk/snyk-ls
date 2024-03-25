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

func getDetailsHtml(issue snyk.Issue) string {
	dataFlowHtml := getDataFlowHtml(issue.AdditionalData.(snyk.CodeIssueData))

	html := replaceVariableInHtml(detailsHtmlTemplate, "issueId", issue.ID)
	html = replaceVariableInHtml(html, "issueTitle", issue.AdditionalData.(snyk.CodeIssueData).Title)
	html = replaceVariableInHtml(html, "severityText", issue.Severity.String())
	html = replaceVariableInHtml(html, "dataFlow", dataFlowHtml)
	html = replaceVariableInHtml(html, "dataFlowCount", fmt.Sprintf("%d", len(issue.AdditionalData.(snyk.CodeIssueData).DataFlow)))

	return html
}
