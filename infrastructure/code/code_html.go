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
	"html"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/domain/snyk"
)

//go:embed template/details.html
var detailsHtmlTemplate string

func replaceVariableInHtml(html string, variableName string, variableValue string) string {
	return strings.ReplaceAll(html, fmt.Sprintf("${%s}", variableName), variableValue)
}

func getDataFlowHeadingHtml(issue snyk.CodeIssueData) string {
	dataFlowCount := len(issue.DataFlow)
	stepWord := "step"

	if dataFlowCount > 1 {
		stepWord += "s"
	}
	return fmt.Sprintf("Data Flow - %d %s", dataFlowCount, stepWord)
}

func getIgnoreDetailsHtml(isIgnored bool, ignoreDetails *snyk.IgnoreDetails) (ignoreDetailsHtml string, visibilityClass string) {
	if !isIgnored {
		return "", "hidden"
	}

	labels := []string{"Category", "Ignored On", "Expiration", "Ignored By"}

	detailsMap := map[string]string{
		"Category":   ignoreDetails.Category,
		"Ignored On": formatDate(ignoreDetails.IgnoredOn),
		"Expiration": ignoreDetails.Expiration,
		"Ignored By": ignoreDetails.IgnoredBy,
	}

	pairs := `<div class="ignore-details-wrapper">`
	for _, label := range labels {
		value := detailsMap[label]
		pairs += fmt.Sprintf(`<div class="ignore-details-row">
		<div class="ignore-details-label">%s</div>
		<div class="ignore-details-value">%s</div>
		</div>`, label, value)
	}
	pairs += `</div>`

	reason := fmt.Sprintf(`<div class="ignore-details-reason-wrapper">
		<div class="ignore-details-reason-label">Reason</div>
		<div class="ignore-details-reason-text">%s</div>
	</div>`, ignoreDetails.Reason)

	warning := `<div class="ignore-next-step-text">Ignores are currently managed in the Snyk web app.
		To edit or remove the ignore please go to: <a class="styled-link" href="https://app.snyk.io" target="_blank" rel="noopener noreferrer" >https://app.snyk.io</a>.</div>`

	ignoreDetailsHtml = pairs + reason + warning
	return ignoreDetailsHtml, ""
}

func getDataFlowHtml(issue snyk.CodeIssueData) string {
	dataFlowHtml := `<table class="data-flow-body"><tbody>`

	for i, flow := range issue.DataFlow {
		fileName := filepath.Base(flow.FilePath)
		dataFlowHtml += fmt.Sprintf(`
		  <tr class="data-flow-row">
		    <td class="data-flow-number">%d</td>
		    <td class="data-flow-clickable-row" file-path="%s" start-line="%d" end-line="%d" start-character="%d" end-character="%d">%s:%d</td>
		    <td class="data-flow-delimiter">|</td>
		    <td class="data-flow-text">%s</td>
		  </tr>`,
			i+1,
			html.EscapeString(flow.FilePath),
			flow.FlowRange.Start.Line,
			flow.FlowRange.End.Line,
			flow.FlowRange.Start.Character,
			flow.FlowRange.End.Character,
			html.EscapeString(fileName),
			flow.FlowRange.Start.Line+1,
			html.EscapeString(flow.Content))
	}

	dataFlowHtml += `</tbody></table>`
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
		isSelectedClass := ""
		if i == 0 {
			isSelectedClass = "is-selected"
		}

		vendorIcon := getVendorIconSvg()
		repoName := getRepoName(fix.CommitURL)
		tabsHtml += fmt.Sprintf(`<span class="tab-item %s" id="tab-link-%d">%s %s</span>`, isSelectedClass, i, vendorIcon, repoName)
	}

	tabsHtml += `</div><div class="tab-container">`

	// Generate the contents for each tab
	for i, fix := range fixes {
		isSelectedClass := ""
		if i == 0 {
			isSelectedClass = "is-selected"
		}
		contentHtml := getCodeDiffHtml(fix)
		tabsHtml += fmt.Sprintf(`<div id="tab-content-%d" class="tab-content %s">%s</div>`, i, isSelectedClass, contentHtml)
	}

	tabsHtml += `</div>`

	return tabsHtml
}

func getDetailsHtml(issue snyk.Issue) string {
	additionalData, ok := issue.AdditionalData.(snyk.CodeIssueData)
	if !ok {
		log.Error().Msg("Failed to cast additional data to CodeIssueData")
		return ""
	}

	// Header
	html := replaceVariableInHtml(detailsHtmlTemplate, "issueId", issue.ID)
	html = replaceVariableInHtml(html, "issueTitle", additionalData.Title)
	html = replaceVariableInHtml(html, "issueType", getIssueType(additionalData))
	html = replaceVariableInHtml(html, "severityText", issue.Severity.String())
	html = replaceVariableInHtml(html, "severityIcon", getSeverityIconSvg(issue))
	html = replaceVariableInHtml(html, "cwes", getRowOfCWEs(issue.CWEs))

	html = replaceVariableInHtml(html, "issueOverview", additionalData.Message)

	// Ignore details
	ignoreDetailsHtml, visibilityClass := getIgnoreDetailsHtml(issue.IsIgnored, issue.IgnoreDetails)
	html = replaceVariableInHtml(html, "visibilityClass", visibilityClass)
	html = replaceVariableInHtml(html, "ignoreDetails", ignoreDetailsHtml)

	// Data flow
	dataFlowHtml := getDataFlowHtml(additionalData)
	html = replaceVariableInHtml(html, "dataFlowHeading", getDataFlowHeadingHtml(additionalData))
	html = replaceVariableInHtml(html, "dataFlow", dataFlowHtml)

	// External example fixes
	html = replaceVariableInHtml(html, "repoCount", fmt.Sprintf("%d", additionalData.RepoDatasetSize))
	html = replaceVariableInHtml(html, "exampleCount", fmt.Sprintf("%d", len(additionalData.ExampleCommitFixes)))
	html = replaceVariableInHtml(html, "tabsNav", getTabsHtml(additionalData.ExampleCommitFixes))

	return html
}

func getRowOfCWEs(cwes []string) string {
	delimeter := `<span class="delimiter"></span>`
	html := delimeter
	for i, cwe := range cwes {
		href := getCWELabel(cwe)
		html += fmt.Sprintf(`<a class="cwe styled-link" target="_blank" rel="noopener noreferrer" href="%s">%s</a>`, href, cwe)
		if i != len(cwes)-1 {
			html += delimeter
		}
	}
	return html
}

func getIssueType(additionalData snyk.CodeIssueData) string {
	if additionalData.IsSecurityType {
		return "Vulnerability"
	}
	return "Quality Issue"
}

func getRepoName(commitURL string) string {
	trimmedURL := strings.TrimPrefix(commitURL, "https://")

	re := regexp.MustCompile(`/commit/.*`)
	shortURL := re.ReplaceAllString(trimmedURL, "")

	tabTitle := shortURL
	if strings.HasPrefix(shortURL, "github.com/") {
		tabTitle = strings.TrimPrefix(shortURL, "github.com/")
	}

	if len(tabTitle) > 50 {
		tabTitle = tabTitle[:50] + "..."
	}

	return tabTitle
}

func getSeverityIconSvg(issue snyk.Issue) string {
	switch issue.Severity {
	case snyk.Critical:
		return `<svg fill="none" xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 16 16">
			<rect width="16" height="16" rx="2" fill="#AB1A1A"/>
			<path d="M9.975 9.64h2.011a3.603 3.603 0 0 1-.545 1.743 3.24 3.24 0 0 1-1.338 1.19c-.57.284-1.256.427-2.06.427-.627 0-1.19-.107-1.688-.32a3.594 3.594 0 0 1-1.278-.936 4.158 4.158 0 0 1-.801-1.47C4.092 9.7 4 9.057 4 8.345v-.675c0-.712.094-1.356.283-1.93a4.255 4.255 0 0 1 .82-1.476 3.657 3.657 0 0 1 1.286-.936A4.114 4.114 0 0 1 8.057 3c.817 0 1.505.147 2.066.44.565.295 1.002.7 1.312 1.217.314.516.502 1.104.565 1.763H9.982c-.023-.392-.101-.723-.236-.995a1.331 1.331 0 0 0-.612-.621c-.27-.143-.628-.214-1.077-.214-.336 0-.63.062-.881.187a1.632 1.632 0 0 0-.633.568c-.17.254-.298.574-.383.962a6.61 6.61 0 0 0-.121 1.349v.688c0 .503.038.946.114 1.33.076.378.193.699.35.961.161.259.368.454.619.588.256.13.563.194.922.194.421 0 .769-.067 1.043-.2a1.39 1.39 0 0 0 .625-.595c.148-.263.236-.59.263-.982Z" fill="#fff"/>
		</svg>`
	case snyk.High:
		return `<svg fill="none" xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 16 16">
			<rect width="16" height="16" rx="2" fill="#CE5019"/>
			<path d="M10.5 7v2h-5V7h5ZM6 3v10H4V3h2Zm6 0v10h-2V3h2Z" fill="#fff"/>
		</svg>`
	case snyk.Medium:
		return `<svg fill="none" xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 16 16">
			<rect width="16" height="16" rx="2" fill="#D68000"/>
			<path d="M3 3h2l2.997 7.607L11 3h2L9 13H7L3 3Zm0 0h2v10l-2-.001V3.001Zm8 0h2V13h-2V3Z" fill="#fff"/>
		</svg>`
	case snyk.Low:
		return `<svg fill="none" xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 16 16">
			<rect width="16" height="16" rx="2" fill="#88879E"/>
			<path d="M11 11v2H6.705v-2H11ZM7 3v10H5V3h2Z" fill="#fff"/>
		</svg>`
	default:
		return ``
	}
}

func getVendorIconSvg() string {
	return `<svg class="tab-item-icon" width="18" height="16" viewBox="0 0 98 96" xmlns="http://www.w3.org/2000/svg">
		<path
			fill-rule="evenodd"
			clip-rule="evenodd"
			d="M48.854 0C21.839 0 0 22 0 49.217c0 21.756 13.993 40.172 33.405 46.69 2.427.49 3.316-1.059 3.316-2.362 0-1.141-.08-5.052-.08-9.127-13.59 2.934-16.42-5.867-16.42-5.867-2.184-5.704-5.42-7.17-5.42-7.17-4.448-3.015.324-3.015.324-3.015 4.934.326 7.523 5.052 7.523 5.052 4.367 7.496 11.404 5.378 14.235 4.074.404-3.178 1.699-5.378 3.074-6.6-10.839-1.141-22.243-5.378-22.243-24.283 0-5.378 1.94-9.778 5.014-13.2-.485-1.222-2.184-6.275.486-13.038 0 0 4.125-1.304 13.426 5.052a46.97 46.97 0 0 1 12.214-1.63c4.125 0 8.33.571 12.213 1.63 9.302-6.356 13.427-5.052 13.427-5.052 2.67 6.763.97 11.816.485 13.038 3.155 3.422 5.015 7.822 5.015 13.2 0 18.905-11.404 23.06-22.324 24.283 1.78 1.548 3.316 4.481 3.316 9.126 0 6.6-.08 11.897-.08 13.526 0 1.304.89 2.853 3.316 2.364 19.412-6.52 33.405-24.935 33.405-46.691C97.707 22 75.788 0 48.854 0z"
			fill="#fff"/>
	</svg>`
}

func getCWELabel(cwe string) string {
	return fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", strings.TrimPrefix(cwe, "CWE-"))
}

func formatDate(date time.Time) string {
	month := date.Format("January")
	return fmt.Sprintf("%s %02d, %d", month, date.Day(), date.Year())
}
