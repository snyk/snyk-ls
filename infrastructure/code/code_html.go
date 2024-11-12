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

	"github.com/rs/zerolog"

	"github.com/snyk/snyk-ls/internal/uri"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/html"
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

type HtmlRenderer struct {
	c              *config.Config
	globalTemplate *template.Template
}

func NewHtmlRenderer(c *config.Config) (*HtmlRenderer, error) {
	funcMap := template.FuncMap{
		"repoName":      getRepoName,
		"trimCWEPrefix": html.TrimCWEPrefix,
		"idxMinusOne":   html.IdxMinusOne,
	}

	globalTemplate, err := template.New(string(product.ProductCode)).Funcs(funcMap).Parse(detailsHtmlTemplate)
	if err != nil {
		c.Logger().Error().Msgf("Failed to parse details template: %s", err)
		return nil, err
	}

	return &HtmlRenderer{
		c:              c,
		globalTemplate: globalTemplate,
	}, nil
}

func (renderer *HtmlRenderer) determineFolderPath(filePath string) string {
	ws := renderer.c.Workspace()
	if ws == nil {
		return ""
	}
	for _, folder := range ws.Folders() {
		folderPath := folder.Path()
		if uri.FolderContains(folderPath, filePath) {
			return folderPath
		}
	}
	return ""
}

func (renderer *HtmlRenderer) GetDetailsHtml(issue snyk.Issue) string {
	additionalData, ok := issue.AdditionalData.(snyk.CodeIssueData)
	if !ok {
		renderer.c.Logger().Error().Msg("Failed to cast additional data to CodeIssueData")
		return ""
	}
	folderPath := renderer.determineFolderPath(issue.AffectedFilePath)
	exampleCommits := prepareExampleCommits(additionalData.ExampleCommitFixes)
	commitFixes := parseExampleCommitsToTemplateJS(exampleCommits, renderer.c.Logger())

	data := map[string]interface{}{
		"IssueTitle":         additionalData.Title,
		"IssueMessage":       additionalData.Message,
		"IssueType":          getIssueType(additionalData),
		"SeverityIcon":       html.SeverityIcon(issue),
		"CWEs":               issue.CWEs,
		"IssueOverview":      html.MarkdownToHTML(additionalData.Text),
		"IsIgnored":          issue.IsIgnored,
		"DataFlow":           additionalData.DataFlow,
		"DataFlowTable":      prepareDataFlowTable(additionalData),
		"RepoCount":          additionalData.RepoDatasetSize,
		"ExampleCount":       len(additionalData.ExampleCommitFixes),
		"ExampleCommitFixes": exampleCommits,
		"CommitFixes":        commitFixes,
		"PriorityScore":      additionalData.PriorityScore,
		"SnykWebUrl":         renderer.c.SnykUI(),
		"LessonUrl":          issue.LessonUrl,
		"LessonIcon":         html.LessonIcon(),
		"IgnoreLineAction":   getLineToIgnoreAction(issue),
		"HasAIFix":           additionalData.HasAIFix,
		"ExternalIcon":       html.ExternalIcon(),
		"ScanAnimation":      html.ScanAnimation(),
		"GitHubIcon":         html.GitHubIcon(),
		"ArrowLeftDark":      html.ArrowLeftDark(),
		"ArrowLeftLight":     html.ArrowLeftLight(),
		"ArrowRightDark":     html.ArrowRightDark(),
		"ArrowRightLight":    html.ArrowRightLight(),
		"FileIcon":           html.FileIcon(),
		"FolderPath":         folderPath,
		"FilePath":           issue.Path(),
		"IssueId":            issue.AdditionalData.GetKey(),
	}

	if issue.IsIgnored {
		data["IgnoreDetails"] = prepareIgnoreDetailsRow(issue.IgnoreDetails)
		data["IgnoreReason"] = issue.IgnoreDetails.Reason
	}

	var buffer bytes.Buffer
	if err := renderer.globalTemplate.Execute(&buffer, data); err != nil {
		renderer.c.Logger().Error().Msgf("Failed to execute main details template: %v", err)
		return ""
	}

	return buffer.String()
}

func getLineToIgnoreAction(issue snyk.Issue) int {
	return issue.Range.Start.Line + 1
}

func prepareIgnoreDetailsRow(ignoreDetails *snyk.IgnoreDetails) []IgnoreDetail {
	return []IgnoreDetail{
		{"Category", parseCategory(ignoreDetails.Category)},
		{"Expiration", formatExpirationDate(ignoreDetails.Expiration)},
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

func parseExampleCommitsToTemplateJS(fixes []ExampleCommit, logger *zerolog.Logger) template.JS {
	jsonFixes, err := json.Marshal(fixes)
	if err != nil {
		logger.Error().Msgf("Failed to marshal example commit fixes: %v", err)
		return ""
	}
	return template.JS(jsonFixes)
}

func getIssueType(additionalData snyk.CodeIssueData) string {
	if additionalData.IsSecurityType {
		return "Issue"
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

func formatExpirationDate(expiration string) string {
	if expiration == "" {
		return "No expiration"
	}
	parsedDate, err := time.Parse(time.RFC3339, expiration)
	if err != nil {
		return expiration // Original string if parsing fails
	}

	// Calculate the difference in days
	daysRemaining := int(time.Until(parsedDate).Hours() / 24)

	if daysRemaining < 0 {
		return "Expired"
	} else if daysRemaining == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", daysRemaining)
}

func formatDate(date time.Time) string {
	month := date.Format("January")
	return fmt.Sprintf("%s %d, %d", month, date.Day(), date.Year())
}
