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
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/domain/snyk"
)

type DataFlowItem struct {
	Number         int
	FilePath       string
	StartLine      int
	EndLine        int
	StartCharacter int
	EndCharacter   int
	FileName       string
	Content        string
	StartLineValue int
}

type IgnoreDetail struct {
	Label string
	Value string
}

//go:embed template/details.html
var detailsHtmlTemplate string

func replaceVariableInHtml(html string, variableName string, variableValue string) string {
	return strings.ReplaceAll(html, fmt.Sprintf("${%s}", variableName), variableValue)
}

func getCWELinks(cwes []string) string {
	tmpl := `
	{{range $cwe :=.}}
		<a class="cwe styled-link" target="_blank" rel="noopener noreferrer" href={{href}}">{{$cwe}}</a>
		{{if ne $cwe (index . -1)}}<span class="delimiter"></span>{{end}}
	{{end}}`

	funcMap := template.FuncMap{"href": getCWELabel}

	html, err := templateHelperWithFuncMap(tmpl, "cweLinks", cwes, funcMap)
	if err != nil {
		log.Error().Msg(err.Error())
		return ""
	}

	return html
}

func getIgnoreDetailsHtml(isIgnored bool, ignoreDetails *snyk.IgnoreDetails) (ignoreDetailsHtml string, visibilityClass string) {
	if !isIgnored {
		return "", "hidden"
	}

	detailsRow := []IgnoreDetail{
		{"Category", ignoreDetails.Category},
		{"Ignored On", formatDate(ignoreDetails.IgnoredOn)},
		{"Expiration", ignoreDetails.Expiration},
		{"Ignored By", ignoreDetails.IgnoredBy},
	}

	tmpl := `
	<div class="ignore-details-wrapper">
		{{range .}}
			<div class="ignore-details-row">
				<div class="ignore-details-label">{{.Label}}</div>
				<div class="ignore-details-value">{{.Value}}</div>
			</div>
		{{end}}
	</div>`

	details, err := templateHelper(tmpl, "ignoreDetails", detailsRow)
	if err != nil {
		log.Error().Msg(err.Error())
		return "", "hidden"
	}

	reasonHtml := getIgnoreReasonHtml(ignoreDetails)
	warningHtml := getWarningHtml()

	ignoreDetailsHtml = details + reasonHtml + warningHtml

	return ignoreDetailsHtml, ""
}

func getIgnoreReasonHtml(ignoreDetails *snyk.IgnoreDetails) string {
	tmpl := `
	<div class="ignore-details-reason-wrapper">
		<div class="ignore-details-reason-label">Reason</div>
		<div class="ignore-details-reason-text">{{.}}</div>
	</div>`

	html, err := templateHelper(tmpl, "ignoreReason", ignoreDetails.Reason)
	if err != nil {
		log.Error().Msg(err.Error())
		return ""
	}
	return html
}

func getWarningHtml() string {
	return `<div class="ignore-next-step-text">Ignores are currently managed in the Snyk web app.
		To edit or remove the ignore please go to: <a class="styled-link" href="https://app.snyk.io" target="_blank" rel="noopener noreferrer" >https://app.snyk.io</a>.</div>`
}

func getDataFlowHeadingHtml(issue snyk.CodeIssueData) string {
	tmp := `Data Flow - {{len .DataFlow}} {{if gt (len .DataFlow) 1}}steps{{else}}step{{end}}`

	html, err := templateHelper(tmp, "dataFlowHeading", issue)
	if err != nil {
		log.Error().Msg(err.Error())
		return ""
	}

	return html
}

func getDataFlowTableHtml(issue snyk.CodeIssueData) string {
	var items []DataFlowItem
	for i, flow := range issue.DataFlow {
		items = append(items, DataFlowItem{
			Number:         i + 1,
			FilePath:       flow.FilePath,
			StartLine:      flow.FlowRange.Start.Line,
			EndLine:        flow.FlowRange.End.Line,
			StartCharacter: flow.FlowRange.Start.Character,
			EndCharacter:   flow.FlowRange.End.Character,
			FileName:       filepath.Base(flow.FilePath),
			Content:        flow.Content,
			StartLineValue: flow.FlowRange.Start.Line + 1,
		})
	}

	tmpl := `
	<table class="data-flow-body"><tbody>
		{{range .}}
			<tr class="data-flow-row">
				<td class="data-flow-number">{{.Number}}</td>
				<td class="data-flow-clickable-row"
						file-path="{{.FilePath}}"
						start-line="{{.StartLine}}"
						end-line="{{.EndLine}}"
						start-character="{{.StartCharacter}}"
						end-character="{{.EndCharacter}}">
							{{.FileName}}:{{.StartLineValue}}
				</td>
				<td class="data-flow-delimiter">|</td>
				<td class="data-flow-text">{{.Content}}</td>
			</tr>
		{{end}}
	</tbody></table>`

	html, err := templateHelper(tmpl, "dataFlow", items)
	if err != nil {
		log.Error().Msg(err.Error())
		return ""
	}

	return html
}

func getCodeDiffHtml(fix snyk.ExampleCommitFix) template.HTML {
	tmpl := `
	{{range .}}
		<div class="example-line {{.LineChange}}">
			<code>{{.Line}}</code>
		</div>
	{{end}}`

	html, err := templateHelper(tmpl, "codeDiff", fix.Lines)
	if err != nil {
		log.Error().Msg(err.Error())
		return ""
	}

	return template.HTML(html)
}

func getExampleCommitFixesHtml(fixes []snyk.ExampleCommitFix) string {
	tmpl := `
	<div class="tabs-nav">
		{{range $index, $fix := .}}
			<span class="tab-item {{if eq $index 0}}is-selected{{end}}" id="tab-link-{{$index}}">
				{{vendorIconSvg}} {{repoName $fix.CommitURL}}
			</span>
		{{end}}
	</div>
	<div class="tab-container">
		{{range $index, $fix := .}}
			<div id="tab-content-{{$index}}" class="tab-content {{if eq $index 0}}is-selected{{end}}">
				{{codeDiffHtml $fix}}
			</div>
		{{end}}
	</div>`

	funcMap := template.FuncMap{
		"vendorIconSvg": getVendorIconSvg,
		"repoName":      getRepoName,
		"codeDiffHtml":  getCodeDiffHtml,
	}

	html, err := templateHelperWithFuncMap(tmpl, "exampleCommitFixes", fixes, funcMap)
	if err != nil {
		log.Error().Msg(err.Error())
		return ""
	}

	return html
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
	html = replaceVariableInHtml(html, "severityIcon", string(getSeverityIconSvg(issue)))
	html = replaceVariableInHtml(html, "cweLinks", getCWELinks(issue.CWEs))

	html = replaceVariableInHtml(html, "issueOverview", additionalData.Message)

	// Ignore details
	ignoreDetailsHtml, visibilityClass := getIgnoreDetailsHtml(issue.IsIgnored, issue.IgnoreDetails)
	html = replaceVariableInHtml(html, "visibilityClass", visibilityClass)
	html = replaceVariableInHtml(html, "ignoreDetails", ignoreDetailsHtml)

	// Data flow
	html = replaceVariableInHtml(html, "dataFlowHeading", getDataFlowHeadingHtml(additionalData))
	html = replaceVariableInHtml(html, "dataFlowTable", getDataFlowTableHtml(additionalData))

	// External example fixes
	html = replaceVariableInHtml(html, "repoCount", fmt.Sprintf("%d", additionalData.RepoDatasetSize))
	html = replaceVariableInHtml(html, "exampleCount", fmt.Sprintf("%d", len(additionalData.ExampleCommitFixes)))
	html = replaceVariableInHtml(html, "exampleCommitFixes", getExampleCommitFixesHtml(additionalData.ExampleCommitFixes))

	log.Debug().Msgf(html)
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

func getCWELabel(cwe string) string {
	return fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", strings.TrimPrefix(cwe, "CWE-"))
}

func formatDate(date time.Time) string {
	month := date.Format("January")
	return fmt.Sprintf("%s %02d, %d", month, date.Day(), date.Year())
}

// templateHelpers returns formatted text where the formatting depends on the data.
// The helper uses the Go `template/html` package, which automatically escapes HTML content.
func templateHelper(tmplString string, tmplName string, data interface{}) (string, error) {
	return templateHelperWithFuncMap(tmplString, tmplName, data, nil)
}

func templateHelperWithFuncMap(tmplString string, tmplName string, data interface{}, funcMap template.FuncMap) (string, error) {
	t := template.New(tmplName)

	if funcMap != nil {
		t = t.Funcs(funcMap)
	}

	t, err := t.Parse(tmplString)

	if err != nil {
		return "", fmt.Errorf("failed to parse %s template: %w", tmplName, err)
	}

	var tmpl bytes.Buffer
	if err = t.Execute(&tmpl, data); err != nil {
		return "", fmt.Errorf("failed to execute %s template: %w", tmplName, err)
	}

	return tmpl.String(), nil
}

func getSeverityIconSvg(issue snyk.Issue) template.HTML {
	switch issue.Severity {
	case snyk.Critical:
		return template.HTML(`<svg fill="none" xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 16 16">
			<rect width="16" height="16" rx="2" fill="#AB1A1A"/>
			<path d="M9.975 9.64h2.011a3.603 3.603 0 0 1-.545 1.743 3.24 3.24 0 0 1-1.338 1.19c-.57.284-1.256.427-2.06.427-.627 0-1.19-.107-1.688-.32a3.594 3.594 0 0 1-1.278-.936 4.158 4.158 0 0 1-.801-1.47C4.092 9.7 4 9.057 4 8.345v-.675c0-.712.094-1.356.283-1.93a4.255 4.255 0 0 1 .82-1.476 3.657 3.657 0 0 1 1.286-.936A4.114 4.114 0 0 1 8.057 3c.817 0 1.505.147 2.066.44.565.295 1.002.7 1.312 1.217.314.516.502 1.104.565 1.763H9.982c-.023-.392-.101-.723-.236-.995a1.331 1.331 0 0 0-.612-.621c-.27-.143-.628-.214-1.077-.214-.336 0-.63.062-.881.187a1.632 1.632 0 0 0-.633.568c-.17.254-.298.574-.383.962a6.61 6.61 0 0 0-.121 1.349v.688c0 .503.038.946.114 1.33.076.378.193.699.35.961.161.259.368.454.619.588.256.13.563.194.922.194.421 0 .769-.067 1.043-.2a1.39 1.39 0 0 0 .625-.595c.148-.263.236-.59.263-.982Z" fill="#fff"/>
		</svg>`)
	case snyk.High:
		return template.HTML(`<svg fill="none" xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 16 16">
			<rect width="16" height="16" rx="2" fill="#CE5019"/>
			<path d="M10.5 7v2h-5V7h5ZM6 3v10H4V3h2Zm6 0v10h-2V3h2Z" fill="#fff"/>
		</svg>`)
	case snyk.Medium:
		return template.HTML(`<svg fill="none" xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 16 16">
			<rect width="16" height="16" rx="2" fill="#D68000"/>
			<path d="M3 3h2l2.997 7.607L11 3h2L9 13H7L3 3Zm0 0h2v10l-2-.001V3.001Zm8 0h2V13h-2V3Z" fill="#fff"/>
		</svg>`)
	case snyk.Low:
		return template.HTML(`<svg fill="none" xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 16 16">
			<rect width="16" height="16" rx="2" fill="#88879E"/>
			<path d="M11 11v2H6.705v-2H11ZM7 3v10H5V3h2Z" fill="#fff"/>
		</svg>`)
	default:
		return ``
	}
}

func getVendorIconSvg() template.HTML {
	return template.HTML(`<svg class="tab-item-icon" width="18" height="16" viewBox="0 0 98 96" xmlns="http://www.w3.org/2000/svg">
		<path
			fill-rule="evenodd"
			clip-rule="evenodd"
			d="M48.854 0C21.839 0 0 22 0 49.217c0 21.756 13.993 40.172 33.405 46.69 2.427.49 3.316-1.059 3.316-2.362 0-1.141-.08-5.052-.08-9.127-13.59 2.934-16.42-5.867-16.42-5.867-2.184-5.704-5.42-7.17-5.42-7.17-4.448-3.015.324-3.015.324-3.015 4.934.326 7.523 5.052 7.523 5.052 4.367 7.496 11.404 5.378 14.235 4.074.404-3.178 1.699-5.378 3.074-6.6-10.839-1.141-22.243-5.378-22.243-24.283 0-5.378 1.94-9.778 5.014-13.2-.485-1.222-2.184-6.275.486-13.038 0 0 4.125-1.304 13.426 5.052a46.97 46.97 0 0 1 12.214-1.63c4.125 0 8.33.571 12.213 1.63 9.302-6.356 13.427-5.052 13.427-5.052 2.67 6.763.97 11.816.485 13.038 3.155 3.422 5.015 7.822 5.015 13.2 0 18.905-11.404 23.06-22.324 24.283 1.78 1.548 3.316 4.481 3.316 9.126 0 6.6-.08 11.897-.08 13.526 0 1.304.89 2.853 3.316 2.364 19.412-6.52 33.405-24.935 33.405-46.691C97.707 22 75.788 0 48.854 0z"
			fill="#fff"/>
	</svg>`)
}
