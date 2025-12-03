package secrets

import (
	"bytes"
	_ "embed"
	"html/template"
	"strings"

	codeClientSarif "github.com/snyk/code-client-go/sarif"
	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/html"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

//go:embed template/details.html
var detailsHtmlTemplate string

//go:embed template/styles.css
var panelStylesTemplate string

//go:embed template/scripts.js
var customScripts string

type HtmlRenderer struct {
	c              *config.Config
	globalTemplate *template.Template
}

func NewHtmlRenderer(c *config.Config) (*HtmlRenderer, error) {
	funcMap := template.FuncMap{
		"trimCWEPrefix": html.TrimCWEPrefix,
		"idxMinusOne":   html.IdxMinusOne,
		"join":          join,
	}
	globalTemplate, err := template.New(string(product.ProductSecrets)).Funcs(funcMap).Parse(detailsHtmlTemplate)
	if err != nil {
		c.Logger().Error().Msgf("Failed to parse secrets details template: %s", err)
		return nil, err
	}

	return &HtmlRenderer{
		c:              c,
		globalTemplate: globalTemplate,
	}, nil
}

func (renderer *HtmlRenderer) GetDetailsHtml(issue types.Issue) string {
	additionalData, ok := issue.GetAdditionalData().(snyk.SecretsIssueData)
	if !ok {
		renderer.c.Logger().Error().Msg("Failed to cast additional data to SecretsIssueData")
		return ""
	}

	nonce, err := html.GenerateSecurityNonce()
	if err != nil {
		renderer.c.Logger().Warn().Msgf("Failed to generate secrets security nonce: %s", err)
		return ""
	}
	folderPath := renderer.determineFolderPath(issue.GetAffectedFilePath())

	data := map[string]interface{}{
		"IssueTitle":       additionalData.Title,
		"IssueMessage":     additionalData.Message,
		"IssueType":        issue.GetIssueType(),
		"SeverityIcon":     html.SeverityIcon(issue),
		"CWEs":             issue.GetCWEs(),
		"IssueOverview":    html.MarkdownToHTML(additionalData.Message),
		"IsIgnored":        issue.GetIsIgnored(),
		"IsPending":        isPending(issue),
		"IgnoreDetails":    issue.GetIgnoreDetails(),
		"IgnoreReason":     issue.GetIgnoreDetails().Reason,
		"Regions":          additionalData.Regions,
		"PriorityScore":    additionalData.PriorityScore,
		"LessonUrl":        issue.GetLessonUrl(),
		"LessonIcon":       html.LessonIcon(),
		"IgnoreLineAction": getLineToIgnoreAction(issue),
		"ExternalIcon":     html.ExternalIcon(),
		"ScanAnimation":    html.ScanAnimation(),
		"GitHubIcon":       html.GitHubIcon(),
		"ArrowLeftDark":    html.ArrowLeftDark(),
		"ArrowLeftLight":   html.ArrowLeftLight(),
		"ArrowRightDark":   html.ArrowRightDark(),
		"ArrowRightLight":  html.ArrowRightLight(),
		"FileIcon":         html.FileIcon(),
		"FolderPath":       folderPath,
		"FilePath":         string(issue.GetAffectedFilePath()),
		"IssueId":          issue.GetAdditionalData().GetKey(),
		"Styles":           template.CSS(panelStylesTemplate),
		"Scripts":          template.JS(customScripts),
		"Nonce":            nonce,
	}

	var htmlBuffer bytes.Buffer
	if err := renderer.globalTemplate.Execute(&htmlBuffer, data); err != nil {
		renderer.c.Logger().Error().Msgf("Failed to execute main details template for Secrets: %v", err)
		return ""
	}

	return htmlBuffer.String()
}

func (renderer *HtmlRenderer) determineFolderPath(filePath types.FilePath) types.FilePath {
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

func join(sep string, s []string) string {
	return strings.Join(s, sep)
}

func getLineToIgnoreAction(issue types.Issue) int {
	return issue.GetRange().Start.Line + 1
}

func isPending(issue types.Issue) bool {
	if issue.GetIgnoreDetails() == nil {
		return false
	}
	if issue.GetIgnoreDetails().Status != codeClientSarif.UnderReview {
		return false
	}
	return true
}
