package secrets

import (
	"bytes"
	_ "embed"
	"html/template"
	"strings"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/html"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
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
	_, ok := issue.GetAdditionalData().(snyk.SecretsIssueData)
	if !ok {
		renderer.c.Logger().Error().Msg("Failed to cast additional data to SecretsIssueData")
		return ""
	}

	data := map[string]interface{}{
		//"IssueTitle":           additionalData.Title,
		//"IssueMessage":         additionalData.Message,
		//"IssueType":            getIssueType(),
		//"SeverityIcon":         html.SeverityIcon(issue),
		//"CWEs":                 issue.GetCWEs(),
		//"IssueOverview":        html.MarkdownToHTML(additionalData.Text),
		//"IsIgnored":            issue.GetIsIgnored(),
		//"IsPending":            isPending,
		//"IgnoreDetails":        ignoreDetailsRow,
		//"IgnoreReason":         ignoreReason,
		//"IAWEnabled":           renderer.iawEnabled,
		//"InlineIgnoresEnabled": renderer.inlineIgnoresEnabled,
		//"Regions":              additionalData.Regions,
		//"PriorityScore":        additionalData.PriorityScore,
		//"SnykWebUrl":           appLink,
		//"LessonUrl":            issue.GetLessonUrl(),
		//"LessonIcon":           html.LessonIcon(),
		//"IgnoreLineAction":     getLineToIgnoreAction(issue),
		//"ExternalIcon":         html.ExternalIcon(),
		//"ScanAnimation":        html.ScanAnimation(),
		//"GitHubIcon":           html.GitHubIcon(),
		//"ArrowLeftDark":        html.ArrowLeftDark(),
		//"ArrowLeftLight":       html.ArrowLeftLight(),
		//"ArrowRightDark":       html.ArrowRightDark(),
		//"ArrowRightLight":      html.ArrowRightLight(),
		//"FileIcon":             html.FileIcon(),
		//"FolderPath":           string(folderPath),
		//"FilePath":             string(issue.GetAffectedFilePath()),
		//"IssueId":              issue.GetAdditionalData().GetKey(),
		//"Styles":               template.CSS(panelStylesTemplate),
		//"Scripts":              template.JS(customScripts),
		//"Nonce":                nonce,
	}

	var htmlBuffer bytes.Buffer
	if err := renderer.globalTemplate.Execute(&htmlBuffer, data); err != nil {
		renderer.c.Logger().Error().Msgf("Failed to execute main details template for Secrets: %v", err)
		return ""
	}

	return htmlBuffer.String()
}

func join(sep string, s []string) string {
	return strings.Join(s, sep)
}
