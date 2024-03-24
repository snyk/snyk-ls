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
)

//go:embed template/details.html
var detailsHtmlTemplate string

func replaceVariableInHtml(html string, variableName string, variableValue string) string {
	return strings.ReplaceAll(html, fmt.Sprintf("${%s}", variableName), variableValue)
}

func getLearnLink(issue *codeIssue) string {
	if issue.lesson == nil {
		return ""
	}

	return fmt.Sprintf("<a class='learn--link' id='learn--link' href='%s'>Learn about this vulnerability</a>",
		issue.lesson.Url)
}

func getDataFlowHtml(issue *codeIssue) string {
	dataFlowHtml := ""
	for i, flow := range issue.DataFlow {
		dataFlowHtml += fmt.Sprintf(`
		<div class="data-flow-row">
		  <span class="data-flow-number">%d</span>
		  <span class="data-flow-blank"> </span>
		  <span class="data-flow-filepath">%s:%d</span>
		  <span class="data-flow-delimiter">|</span>
		  <span class="data-flow-text">%s</span>
		</div>`, i+1, flow.FilePath, flow.Position, flow.Content)
	}
	return dataFlowHtml
}

func getDetailsHtml(issue *codeIssue) string {
	dataFlowHtml := getDataFlowHtml(issue)

	html := replaceVariableInHtml(detailsHtmlTemplate, "issueId", issue.Id)
	html = replaceVariableInHtml(html, "issueTitle", issue.Title)
	html = replaceVariableInHtml(html, "severityText", issue.Severity)
	html = replaceVariableInHtml(html, "vulnerableModule", issue.Name)
	html = replaceVariableInHtml(html, "learnLink", getLearnLink(issue))
	html = replaceVariableInHtml(html, "dataFlow", dataFlowHtml)
	html = replaceVariableInHtml(html, "dataFlowCount", fmt.Sprintf("%d", len(issue.DataFlow)))

	return html
}
