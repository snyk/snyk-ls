/*
 * © 2024 Snyk Limited
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

package ui

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/rs/zerolog"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/html"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

//go:embed template/diagnosticsOverview.html
var diagnosticsOverviewTemplatePath string

//go:embed template/diagnosticsOverview.css
var diagnosticsOverviewTemplateCSS string
var diagnosticsOverviewTemplate *template.Template
var templateParsingMutex sync.RWMutex

type TemplateData struct {
	// Root nodes
	RootNodes []Node
	// File node with underlying slice of issue nodes
	Issues               map[Node][]Node
	Styles               template.CSS
	Nonce                template.HTML
	DeltaFindingsEnabled bool
}

// Node represents a tree node
type Node struct {
	Icon           template.HTML
	Text           template.HTML
	ProductEnabled bool
}

func SendDiagnosticsOverview(c *config.Config, p product.Product, issuesByFile snyk.IssuesByFile, folderPath string, notifier notification.Notifier) {
	logger := c.Logger().With().Str("method", "ui.SendDiagnosticsOverview").Logger()

	html, err := generateHtml(c, p, issuesByFile, folderPath, logger)
	if err != nil {
		logger.Err(err).Msg("failed to get diagnostics overview template data")
		return
	}

	diagnosticsOverview := types.DiagnosticsOverviewParams{Product: p.ToProductCodename(), Html: html, FolderPath: folderPath}
	notifier.Send(diagnosticsOverview)

	logger.Debug().Msgf("sent diagnostics overview htmlBuffer for product %s", p)
	logger.Trace().
		Int("issueCount", len(issuesByFile)).
		Any("diagnosticsOverview", diagnosticsOverview).
		Msg("detailed tree data")
}

func initializeTemplate() error {
	templateParsingMutex.RLock()
	if diagnosticsOverviewTemplate == nil {
		templateParsingMutex.RUnlock()
		templateParsingMutex.Lock()
		defer templateParsingMutex.Unlock()

		funcMap := map[string]any{}
		var err error

		diagnosticsOverviewTemplate, err = template.New("diagnosticsOverviewTemplate").Funcs(funcMap).Parse(diagnosticsOverviewTemplatePath)
		if err != nil {
			return err
		}
	}
	return nil
}

func generateHtml(c *config.Config, p product.Product, issuesByFile snyk.IssuesByFile, folderPath string, logger zerolog.Logger) (string, error) {
	err := initializeTemplate()
	if err != nil {
		logger.Err(err).Msg("failed to initialize diagnostics overview template. Not sending overview")
		return "", err
	}

	if p == "" {
		logger.Warn().Str("method", "ui.generateHtml").Msg("no product specified, this is unexpected")
		return "", fmt.Errorf("no product specified")
	}

	rootNodes := getRootNodes(c, p, issuesByFile)
	nonce, err := html.GenerateSecurityNonce()
	if err != nil {
		logger.Err(err).Msgf("Failed to generate nonce")
		return "", err
	}

	fileNodes := getFileNodes(issuesByFile, folderPath)

	data := TemplateData{
		RootNodes:            rootNodes,
		Issues:               fileNodes,
		Styles:               template.CSS(diagnosticsOverviewTemplateCSS),
		Nonce:                template.HTML(nonce),
		DeltaFindingsEnabled: c.IsDeltaFindingsEnabled(),
	}

	var htmlBuffer bytes.Buffer
	if err = diagnosticsOverviewTemplate.Execute(&htmlBuffer, data); err != nil {
		logger.Error().Msgf("Failed to generate tree htmlBuffer with tree template: %v", err)
		return "", err
	}

	return htmlBuffer.String(), nil
}

func getFileNodes(issuesByFile snyk.IssuesByFile, folderPath string) map[Node][]Node {
	fileNodes := make(map[Node][]Node)
	for path, issues := range issuesByFile {
		path = normalizeFilePath(path, folderPath) // Normalize path to be rendered in the UI
		fileNode := Node{
			Icon: getFileTypeIcon(),
			Text: template.HTML(path),
		}

		sortedIssues := sortIssuesBySeverity(issues)
		issueNodes := []Node{}
		for _, issue := range sortedIssues {
			issueNodes = append(issueNodes, Node{
				Icon: html.SeverityIcon(issue),
				Text: template.HTML(issue.AdditionalData.GetTitle()),
			})
		}
		fileNodes[fileNode] = issueNodes
	}
	return fileNodes
}

// TODO: which icon? Like Go, NPM, etc.?
func getFileTypeIcon() template.HTML {
	return ""
}

func getRootNodes(c *config.Config, p product.Product, issuesByFile snyk.IssuesByFile) []Node {
	var icon template.HTML

	productEnabled := c.IsProductEnabled(p)
	if productEnabled {
		icon = html.GetProductIcon(p)
	} else {
		icon = html.GetProductIconDisabled(p)
	}

	rootNodeTitle := getRootNodeText(issuesByFile, p)

	rootNodes := append([]Node{}, Node{
		Icon:           icon,
		Text:           template.HTML(rootNodeTitle),
		ProductEnabled: productEnabled,
	})

	fixableCount := issuesByFile.FixableCount()
	if fixableCount > 0 {
		plural := ""
		if fixableCount > 1 {
			plural = "s"
		}
		rootNodes = append(rootNodes, Node{
			Text: template.HTML(fmt.Sprintf("⚡️ %d issue%s can be fixed automatically", fixableCount, plural)),
		})
	}

	return rootNodes
}

func getRootNodeText(issuesByFile snyk.IssuesByFile, p product.Product) string {
	total, critical, high, medium, low := issuesByFile.SeverityCounts()

	pluralSuffix := ""
	if total > 1 {
		pluralSuffix = "s"
	}

	severityParts := []string{}
	if critical > 0 {
		severityParts = append(severityParts, fmt.Sprintf("%d critical", critical))
	}
	if high > 0 {
		severityParts = append(severityParts, fmt.Sprintf("%d high", high))
	}
	if medium > 0 {
		severityParts = append(severityParts, fmt.Sprintf("%d medium", medium))
	}
	if low > 0 {
		severityParts = append(severityParts, fmt.Sprintf("%d low", low))
	}

	severityString := strings.Join(severityParts, ", ")

	rootNodeTitle := fmt.Sprintf("%s - No issues found", p.ToFilterableIssueType()[0])
	if total > 0 {
		rootNodeTitle = fmt.Sprintf(
			"%s - %d unique issue%s: %s",
			p.ToFilterableIssueType()[0],
			total,
			pluralSuffix,
			severityString,
		)
	}

	return rootNodeTitle
}

func normalizeFilePath(filePath string, folderPath string) string {
	filePath = filepath.Clean(filePath)
	folderPath = filepath.Clean(folderPath)

	relativePath, err := filepath.Rel(folderPath, filePath)
	if err != nil {
		return filePath
	}

	return filepath.Join(filepath.Base(folderPath), relativePath)
}

func sortIssuesBySeverity(issues []snyk.Issue) []snyk.Issue {
	sort.Slice(issues, func(i, j int) bool {
		return issues[i].Severity < issues[j].Severity
	})
	return issues
}
