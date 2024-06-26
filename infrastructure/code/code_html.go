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
	"encoding/json"
	"fmt"
	"html/template"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gomarkdown/markdown"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
)

type IgnoreDetail struct {
	Label string
	Value string
}

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

type ExampleCommit struct {
	CommitURL    string
	RepoName     string
	RepoLink     string
	ExampleLines []ExampleLines
}

//go:embed template/details.html
var detailsHtmlTemplate string

var globalTemplate *template.Template

func init() {
	funcMap := template.FuncMap{
		"repoName":      getRepoName,
		"trimCWEPrefix": TrimCWEPrefix,
		"idxMinusOne":   IdxMinusOne,
	}

	var err error
	globalTemplate, err = template.New(string(product.ProductCode)).Funcs(funcMap).Parse(detailsHtmlTemplate)
	if err != nil {
		config.CurrentConfig().Logger().Error().Msgf("Failed to parse details template: %s", err)
	}
}

func getCodeDetailsHtml(issue snyk.Issue) string {
	c := config.CurrentConfig()
	additionalData, ok := issue.AdditionalData.(snyk.CodeIssueData)
	if !ok {
		c.Logger().Error().Msg("Failed to cast additional data to CodeIssueData")
		return ""
	}

	exampleCommits := prepareExampleCommits(additionalData.ExampleCommitFixes)
	commitFixes := parseExampleCommitsToTemplateJS(exampleCommits)

	data := map[string]interface{}{
		"IssueTitle":         additionalData.Title,
		"IssueMessage":       additionalData.Message,
		"IssueType":          getIssueType(additionalData),
		"SeverityIcon":       GetSeverityIconSvg(issue),
		"CWEs":               issue.CWEs,
		"IssueOverview":      markdownToHTML(additionalData.Text),
		"IsIgnored":          issue.IsIgnored,
		"DataFlow":           additionalData.DataFlow,
		"DataFlowTable":      prepareDataFlowTable(additionalData),
		"RepoCount":          additionalData.RepoDatasetSize,
		"ExampleCount":       len(additionalData.ExampleCommitFixes),
		"ExampleCommitFixes": exampleCommits,
		"CommitFixes":        commitFixes,
		"PriorityScore":      additionalData.PriorityScore,
		"SnykWebUrl":         config.CurrentConfig().SnykUi(),
		"LessonUrl":          issue.LessonUrl,
		"LessonIcon":         GetLessonIconSvg(),
		"IgnoreLineAction":   getLineToIgnoreAction(issue),
		"HasAIFix":           additionalData.HasAIFix,
		"ExternalIcon":       getExternalIconSvg(),
		"ScanAnimation":      getScanAnimationSvg(),
		"GitHubIcon":         getGitHubIconSvg(),
		"ArrowLeftDark":      getArrowLeftDarkSvg(),
		"ArrowLeftLight":     getArrowLeftLightSvg(),
		"ArrowRightDark":     getArrowRightDarkSvg(),
		"ArrowRightLight":    getArrowRightLightSvg(),
		"FileIcon":           getFileIconSvg(),
	}

	if issue.IsIgnored {
		data["IgnoreDetails"] = prepareIgnoreDetailsRow(issue.IgnoreDetails)
		data["IgnoreReason"] = issue.IgnoreDetails.Reason
	}

	var html bytes.Buffer
	if err := globalTemplate.Execute(&html, data); err != nil {
		c.Logger().Error().Msgf("Failed to execute main details template: %v", err)
		return ""
	}

	return html.String()
}

func markdownToHTML(md string) template.HTML {
	html := markdown.ToHTML([]byte(md), nil, nil)
	return template.HTML(html)
}

func getLineToIgnoreAction(issue snyk.Issue) int {
	return issue.Range.Start.Line + 1
}

func IdxMinusOne(n int) int {
	return n - 1
}

func TrimCWEPrefix(cwe string) string {
	return strings.TrimPrefix(cwe, "CWE-")
}

func prepareIgnoreDetailsRow(ignoreDetails *snyk.IgnoreDetails) []IgnoreDetail {
	return []IgnoreDetail{
		{"Category", parseCategory(ignoreDetails.Category)},
		{"Expiration", ignoreDetails.Expiration},
		{"Ignored On", formatDate(ignoreDetails.IgnoredOn)},
		{"Ignored By", ignoreDetails.IgnoredBy},
		{"Reason", ignoreDetails.Reason},
	}
}

func parseCategory(category string) string {
	categoryMap := map[string]string{
		"not-vulnerable":   "Not vulnerable",
		"temporary-ignore": "Ignored temporarily",
		"wont-fix":         "Ignored permanently",
	}

	if result, ok := categoryMap[category]; ok {
		return result
	}
	return category
}

func prepareDataFlowTable(issue snyk.CodeIssueData) map[string][]DataFlowItem {
	items := make(map[string][]DataFlowItem, 0)

	for i, flow := range issue.DataFlow {
		fileName := filepath.Base(flow.FilePath)
		if items[fileName] == nil {
			items[fileName] = []DataFlowItem{}
		}
		items[fileName] = append(items[fileName], DataFlowItem{
			Number:         i + 1,
			FilePath:       flow.FilePath,
			StartLine:      flow.FlowRange.Start.Line,
			EndLine:        flow.FlowRange.End.Line,
			StartCharacter: flow.FlowRange.Start.Character,
			EndCharacter:   flow.FlowRange.End.Character,
			FileName:       fileName,
			Content:        flow.Content,
			StartLineValue: flow.FlowRange.Start.Line + 1,
		})
	}
	return items
}

type ExampleLines struct {
	LineNumber int
	Line       string
	LineChange string
}

func prepareExampleLines(lines []snyk.CommitChangeLine) []ExampleLines {
	var exampleLines []ExampleLines
	for _, line := range lines {
		exampleLines = append(exampleLines, ExampleLines{
			LineNumber: line.LineNumber,
			Line:       line.Line,
			LineChange: line.LineChange,
		})
	}
	return exampleLines
}

func prepareExampleCommits(fixes []snyk.ExampleCommitFix) []ExampleCommit {
	var fixData []ExampleCommit
	for _, fix := range fixes {
		fixData = append(fixData, ExampleCommit{
			CommitURL:    fix.CommitURL,
			RepoName:     getRepoName(fix.CommitURL),
			RepoLink:     fix.CommitURL,
			ExampleLines: prepareExampleLines(fix.Lines),
		})
	}
	return fixData
}

func parseExampleCommitsToTemplateJS(fixes []ExampleCommit) template.JS {
	jsonFixes, err := json.Marshal(fixes)
	if err != nil {
		config.CurrentConfig().Logger().Error().Msgf("Failed to marshal example commit fixes: %v", err)
		return ""
	}
	return template.JS(jsonFixes)
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

func formatDate(date time.Time) string {
	month := date.Format("January")
	return fmt.Sprintf("%s %d, %d", month, date.Day(), date.Year())
}

func getFileIconSvg() template.HTML {
	return template.HTML(`<svg class="data-flow-file-icon" width="16" height="16" viewBox="0 0 32 32" xmlns="http
://www.w3.
org/2000/svg" fill="none"">
	<path d="M20.414,2H5V30H27V8.586ZM7,28V4H19v6h6V28Z" fill="#888"/></svg>`)
}

func getExternalIconSvg() template.HTML {
	return template.HTML(` <svg class="is-external-icon" width="9" height="9" viewBox="0 0 9 9" xmlns="http://www.w3.org/2000/svg" fill="none">
		<path d="M4.99998 0L6.64648 1.6465L3.14648 5.1465L3.85348 5.8535L7.35348 2.3535L8.99998 4V0H4.99998Z" fill="#888"/>
		<path d="M8 8H1V1H4.5L3.5 0H1C0.4485 0 0 0.4485 0 1V8C0 8.5515 0.4485 9 1 9H8C8.5515 9 9 8.5515 9 8V5.5L8 4.5V8Z" fill="#888"/>
	</svg>`)
}

func GetSeverityIconSvg(issue snyk.Issue) template.HTML {
	switch issue.Severity {
	case snyk.Critical:
		return template.HTML(`<svg id="critical" fill="none" xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 16 16">
			 <rect width="16" height="16" rx="2" fill="#AB1A1A"/>
			 <path d="M9.975 9.64h2.011a3.603 3.603 0 0 1-.545 1.743 3.24 3.24 0 0 1-1.338 1.19c-.57.284-1.256.427-2.06.427-.627 0-1.19-.107-1.688-.32a3.594 3.594 0 0 1-1.278-.936 4.158 4.158 0 0 1-.801-1.47C4.092 9.7 4 9.057 4 8.345v-.675c0-.712.094-1.356.283-1.93a4.255 4.255 0 0 1 .82-1.476 3.657 3.657 0 0 1 1.286-.936A4.114 4.114 0 0 1 8.057 3c.817 0 1.505.147 2.066.44.565.295 1.002.7 1.312 1.217.314.516.502 1.104.565 1.763H9.982c-.023-.392-.101-.723-.236-.995a1.331 1.331 0 0 0-.612-.621c-.27-.143-.628-.214-1.077-.214-.336 0-.63.062-.881.187a1.632 1.632 0 0 0-.633.568c-.17.254-.298.574-.383.962a6.61 6.61 0 0 0-.121 1.349v.688c0 .503.038.946.114 1.33.076.378.193.699.35.961.161.259.368.454.619.588.256.13.563.194.922.194.421 0 .769-.067 1.043-.2a1.39 1.39 0 0 0 .625-.595c.148-.263.236-.59.263-.982Z" fill="#fff"/>
		 </svg>`)
	case snyk.High:
		return template.HTML(`<svg id="high" fill="none" xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 16 16">
			 <rect width="16" height="16" rx="2" fill="#CE5019"/>
			 <path d="M10.5 7v2h-5V7h5ZM6 3v10H4V3h2Zm6 0v10h-2V3h2Z" fill="#fff"/>
		 </svg>`)
	case snyk.Medium:
		return template.HTML(`<svg id="medium" fill="none" xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 16 16">
			 <rect width="16" height="16" rx="2" fill="#D68000"/>
			 <path d="M3 3h2l2.997 7.607L11 3h2L9 13H7L3 3Zm0 0h2v10l-2-.001V3.001Zm8 0h2V13h-2V3Z" fill="#fff"/>
		 </svg>`)
	case snyk.Low:
		return template.HTML(`<svg id="low" fill="none" xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 16 16">
			 <rect width="16" height="16" rx="2" fill="#88879E"/>
			 <path d="M11 11v2H6.705v-2H11ZM7 3v10H5V3h2Z" fill="#fff"/>
		 </svg>`)
	default:
		return ``
	}
}

func getGitHubIconSvg() template.HTML {
	return template.HTML(`<svg class="tab-item-icon" width="18" height="16" viewBox="0 0 98 96" xmlns="http://www.w3.org/2000/svg">
		<path
			fill-rule="evenodd"
			clip-rule="evenodd"
			d="M48.854 0C21.839 0 0 22 0 49.217c0 21.756 13.993 40.172 33.405 46.69 2.427.49 3.316-1.059 3.316-2.362 0-1.141-.08-5.052-.08-9.127-13.59 2.934-16.42-5.867-16.42-5.867-2.184-5.704-5.42-7.17-5.42-7.17-4.448-3.015.324-3.015.324-3.015 4.934.326 7.523 5.052 7.523 5.052 4.367 7.496 11.404 5.378 14.235 4.074.404-3.178 1.699-5.378 3.074-6.6-10.839-1.141-22.243-5.378-22.243-24.283 0-5.378 1.94-9.778 5.014-13.2-.485-1.222-2.184-6.275.486-13.038 0 0 4.125-1.304 13.426 5.052a46.97 46.97 0 0 1 12.214-1.63c4.125 0 8.33.571 12.213 1.63 9.302-6.356 13.427-5.052 13.427-5.052 2.67 6.763.97 11.816.485 13.038 3.155 3.422 5.015 7.822 5.015 13.2 0 18.905-11.404 23.06-22.324 24.283 1.78 1.548 3.316 4.481 3.316 9.126 0 6.6-.08 11.897-.08 13.526 0 1.304.89 2.853 3.316 2.364 19.412-6.52 33.405-24.935 33.405-46.691C97.707 22 75.788 0 48.854 0z"
		/>
	</svg>`)
}

func GetLessonIconSvg() template.HTML {
	return template.HTML(`<svg width="17" height="14" viewBox="0 0 17 14" fill="none" xmlns="http://www.w3.org/2000/svg">
	<path d="M8.25 0L0 4.5L3 6.135V10.635L8.25 13.5L13.5 10.635V6.135L15 5.3175V10.5H16.5V4.5L8.25 0ZM13.365 4.5L8.25 7.29L3.135 4.5L8.25 1.71L13.365 4.5ZM12 9.75L8.25 11.79L4.5 9.75V6.9525L8.25 9L12 6.9525V9.75Z" fill="#888"/>
	</svg>
	`)
}

func getScanAnimationSvg() template.HTML {
	return template.HTML(`<svg id="scan-animation" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 248 204" shape-rendering="geometricPrecision">
	<defs>
		<linearGradient id="mg" x1="16.0903" y1="180" x2="92.743" y2="107.462" spreadMethod="pad"
			gradientUnits="userSpaceOnUse" gradientTransform="translate(0 0)">
			<stop id="eQeHIUZsTfX2-fill-0" offset="0%" stop-color="#145deb" />
			<stop id="eQeHIUZsTfX2-fill-1" offset="100%" stop-color="#441c99" />
		</linearGradient>
		<linearGradient id="sg" x1="116" y1="0" x2="116" y2="64" spreadMethod="pad" gradientUnits="userSpaceOnUse"
			gradientTransform="translate(0 0)">
			<stop id="eQeHIUZsTfX26-fill-0" offset="0%" stop-color="#ff78e1" />
			<stop id="eQeHIUZsTfX26-fill-1" offset="100%" stop-color="rgba(255,120,225,0)" />
		</linearGradient>
	</defs>
	<rect width="224" height="180" rx="16" ry="16" transform="translate(12 12)" fill="url(#mg)" />
	<circle r="4" transform="translate(28 28)" opacity="0.3" fill="#fff" />
	<circle r="4" transform="translate(40 28)" opacity="0.25" fill="#fff" />
	<circle r="4" transform="translate(52 28)" opacity="0.2" fill="#fff" />
	<rect width="48" height="12" rx="6" ry="6" transform="translate(162 56)" opacity="0.2" fill="#fff" />
	<rect width="80" height="12" rx="6" ry="6" transform="translate(32 92)" opacity="0.2" fill="#fff" />
	<rect width="72" height="12" rx="6" ry="6" transform="translate(96 164)" opacity="0.2" fill="#fff" />
	<rect width="56" height="12" rx="6" ry="6" transform="translate(156 128)" opacity="0.2" fill="#fff" />
	<rect id="l3" width="80" height="12" rx="6" ry="6" transform="translate(64 128)" />
	<rect id="l2" width="64" height="12" rx="6" ry="6" transform="translate(150 92)" />
	<rect id="l1" width="117" height="12" rx="6" ry="6" transform="translate(32 56)" />
	<g id="b3">
		<rect width="32" height="32" rx="6" ry="6" transform="translate(48 118)" fill="#43b59a" />
		<path
			d="M54.5991,134c.7987-.816,2.0938-.816,2.8926,0l2.8926,2.955l10.124-10.343c.7988-.816,2.0939-.816,2.8926,0c.7988.816.7988,2.139,0,2.955L61.8306,141.388c-.7988.816-2.0939.816-2.8926,0l-4.3389-4.433c-.7988-.816-.7988-2.139,0-2.955Z"
			fill="#fff" />
	</g>
	<g id="b2">
		<rect width="32" height="32" rx="6" ry="6" transform="translate(124 81)" fill="#f97a99" />
		<path
			d="M142,91c0,.7685-.433,5.3087-1.069,8h-1.862c-.636-2.6913-1.069-7.2315-1.069-8c0-1.1046.895-2,2-2s2,.8954,2,2Z"
			fill="#fff" />
		<path d="M140,104c1.105,0,2-.895,2-2s-.895-2-2-2-2,.895-2,2s.895,2,2,2Z" fill="#fff" />
	</g>
	<g id="b1">
		<rect width="24" height="24" rx="6" ry="6" transform="translate(28 50)" fill="#f97a99" />
		<path
			d="M42,56c0,.7685-.4335,5.3087-1.0693,8h-1.8614C38.4335,61.3087,38,56.7685,38,56c0-1.1046.8954-2,2-2s2,.8954,2,2Z"
			fill="#fff" />
		<path d="M40,69c1.1046,0,2-.8954,2-2s-.8954-2-2-2-2,.8954-2,2s.8954,2,2,2Z" fill="#fff" />
	</g>
	<g id="s0" transform="translate(124,-40)">
		<g transform="translate(-124,-40)">
			<rect width="232" height="64" rx="0" ry="0" transform="matrix(1 0 0-1 8 64)" opacity="0.5" fill="url(#sg)" />
			<rect width="248" height="16" rx="8" ry="8" transform="translate(0 64)" fill="#e555ac" />
		</g>
	</g>
	</svg>`)
}

func getArrowLeftDarkSvg() template.HTML {
	return template.HTML(`<svg class="arrow-icon dark-only" width="10" height="12" viewBox="0 0 10 12" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path
    d="M8.86723 11.4303L8.86721 11.4302L0.641823 6.22447L0.387031 6.62706L0.641821 6.22447C0.532336 6.15518 0.5 6.06763 0.5 6.00001C0.5 5.93239 0.532336 5.84484 0.641821 5.77555L0.641824 5.77555L8.86721 0.569741L8.86723 0.569731C9.00417 0.483055 9.17298 0.480315 9.31053 0.543871C9.44734 0.607082 9.5 0.705333 9.5 0.79421V11.2058C9.5 11.2947 9.44734 11.3929 9.31054 11.4561C9.173 11.5197 9.00418 11.5169 8.86723 11.4303Z"
    stroke="#CCCCCC" />
	</svg>`)
}

func getArrowLeftLightSvg() template.HTML {
	return template.HTML(`<svg class="arrow-icon light-only" width="10" height="12" viewBox="0 0 10 12" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path
    d="M8.86723 11.4303L8.86721 11.4302L0.641823 6.22447L0.387031 6.62706L0.641821 6.22447C0.532336 6.15518 0.5 6.06763 0.5 6.00001C0.5 5.93239 0.532336 5.84484 0.641821 5.77555L0.641824 5.77555L8.86721 0.569741L8.86723 0.569731C9.00417 0.483055 9.17298 0.480315 9.31053 0.543871C9.44734 0.607082 9.5 0.705333 9.5 0.79421V11.2058C9.5 11.2947 9.44734 11.3929 9.31054 11.4561C9.173 11.5197 9.00418 11.5169 8.86723 11.4303Z"
    stroke="#3B3B3B" />
	</svg>`)
}

func getArrowRightDarkSvg() template.HTML {
	return template.HTML(`
	<svg class="arrow-icon dark-only" width="10" height="12" viewBox="0 0 10 12" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path
    d="M1.13277 11.4303L1.13279 11.4302L9.35818 6.22447L9.61297 6.62706L9.35818 6.22447C9.46766 6.15518 9.5 6.06763 9.5 6.00001C9.5 5.93239 9.46766 5.84484 9.35818 5.77555L9.35818 5.77555L1.13279 0.569741L1.13277 0.569731C0.995832 0.483055 0.827023 0.480315 0.689467 0.543871C0.55266 0.607082 0.5 0.705333 0.5 0.79421V11.2058C0.5 11.2947 0.552661 11.3929 0.689456 11.4561C0.827003 11.5197 0.99582 11.5169 1.13277 11.4303Z"
    stroke="#CCCCCC" />
	</svg>`)
}

func getArrowRightLightSvg() template.HTML {
	return template.HTML(`<svg class="arrow-icon light-only" width="10" height="12" viewBox="0 0 10 12" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path
    d="M1.13277 11.4303L1.13279 11.4302L9.35818 6.22447L9.61297 6.62706L9.35818 6.22447C9.46766 6.15518 9.5 6.06763 9.5 6.00001C9.5 5.93239 9.46766 5.84484 9.35818 5.77555L9.35818 5.77555L1.13279 0.569741L1.13277 0.569731C0.995832 0.483055 0.827023 0.480315 0.689467 0.543871C0.55266 0.607082 0.5 0.705333 0.5 0.79421V11.2058C0.5 11.2947 0.552661 11.3929 0.689456 11.4561C0.827003 11.5197 0.99582 11.5169 1.13277 11.4303Z"
    stroke="#3B3B3B" />
	</svg>`)
}
