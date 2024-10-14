/*
 * © 2022-2023 Snyk Limited
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

package oss

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"strings"

	"github.com/gomarkdown/markdown"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/html"
	"github.com/snyk/snyk-ls/internal/product"
)

//go:embed template/details.html
var detailsHtmlTemplate string

var htmlRendererInstance *HtmlRenderer

type HtmlRenderer struct {
	c              *config.Config
	globalTemplate *template.Template
}

func NewHtmlRenderer(c *config.Config) (*HtmlRenderer, error) {
	if htmlRendererInstance != nil {
		return htmlRendererInstance, nil
	}
	funcMap := template.FuncMap{
		"trimCWEPrefix": html.TrimCWEPrefix,
		"idxMinusOne":   html.IdxMinusOne,
		"join":          join,
	}
	globalTemplate, err := template.New(string(product.ProductOpenSource)).Funcs(funcMap).Parse(detailsHtmlTemplate)
	if err != nil {
		c.Logger().Error().Msgf("Failed to parse details template: %s", err)
		return nil, err
	}

	htmlRendererInstance = &HtmlRenderer{
		c:              c,
		globalTemplate: globalTemplate,
	}

	return htmlRendererInstance, nil
}

func join(sep string, s []string) string {
	return strings.Join(s, sep)
}

func (renderer *HtmlRenderer) GetDetailsHtml(issue snyk.Issue) string {
	additionalData, ok := issue.AdditionalData.(snyk.OssIssueData)
	if !ok {
		renderer.c.Logger().Error().Msg("Failed to cast additional data to OssIssueData")
		return ""
	}

	overview := markdown.ToHTML([]byte(additionalData.Description), nil, nil)

	detailedPaths := getDetailedPaths(additionalData)

	data := map[string]interface{}{
		"IssueId":            issue.ID,
		"IssueName":          additionalData.Name,
		"IssueTitle":         additionalData.Title,
		"IssueType":          getIssueType(additionalData),
		"SeverityText":       issue.Severity.String(),
		"SeverityIcon":       html.SeverityIcon(issue),
		"VulnerableModule":   additionalData.Name,
		"IssueOverview":      html.MarkdownToHTML(string(overview)),
		"CVEs":               additionalData.Identifiers.CVE,
		"CWEs":               additionalData.Identifiers.CWE,
		"CVSSv3":             template.URL(additionalData.CVSSv3),
		"CvssScore":          fmt.Sprintf("%.1f", additionalData.CvssScore),
		"ExploitMaturity":    getExploitMaturity(additionalData),
		"IntroducedThroughs": getIntroducedThroughs(additionalData, renderer.c.SnykUI()),
		"LessonUrl":          additionalData.Lesson,
		"LessonIcon":         html.LessonIcon(),
		"FixedIn":            additionalData.FixedIn,
		"DetailedPaths":      detailedPaths,
		"MoreDetailedPaths":  len(detailedPaths) - 3,
		"Policy":             buildPolicyMap(additionalData),
	}

	var htmlBuffer bytes.Buffer
	if err := renderer.globalTemplate.Execute(&htmlBuffer, data); err != nil {
		renderer.c.Logger().Error().Msgf("Failed to execute main details template: %v", err)
		return ""
	}

	return htmlBuffer.String()
}

func buildPolicyMap(additionalData snyk.OssIssueData) map[string]interface{} {
	policy := map[string]interface{}{}
	severityChange := additionalData.AppliedPolicyRules.SeverityChange
	annotation := additionalData.AppliedPolicyRules.Annotation

	hasPolicy := severityChange.OriginalSeverity != "" || annotation.Value != "" || annotation.Reason != ""
	hasUserNote := annotation.Value != ""
	hasNotes := severityChange.Reason != "" || annotation.Reason != ""

	if severityChange.OriginalSeverity != "" {
		policy["OriginalSeverity"] = severityChange.OriginalSeverity
		policy["NewSeverity"] = severityChange.NewSeverity
	}

	if severityChange.Reason != "" {
		policy["NoteReason"] = severityChange.Reason
	}

	if annotation.Value != "" {
		policy["UserNote"] = annotation.Value
	}

	if annotation.Reason != "" {
		policy["NoteReason"] = annotation.Reason
	}

	policy["HasPolicy"] = hasPolicy
	policy["HasNotes"] = hasNotes
	policy["HasUserNote"] = hasUserNote

	return policy
}

func getIssueType(issue snyk.OssIssueData) string {
	if len(issue.License) > 0 {
		return "License"
	}

	return "Vulnerability"
}

func getExploitMaturity(issue snyk.OssIssueData) string {
	if len(issue.Exploit) > 0 {
		return issue.Exploit
	} else {
		return ""
	}
}

type IntroducedThrough struct {
	SnykUI         string
	PackageManager string
	Module         string
}

func getIntroducedThroughs(issue snyk.OssIssueData, snykUI string) []IntroducedThrough {
	var introducedThroughs []IntroducedThrough

	if len(issue.From) > 0 {
		for _, v := range issue.MatchingIssues {
			if len(v.From) > 1 {
				introducedThroughs = append(introducedThroughs, IntroducedThrough{
					SnykUI:         snykUI,
					PackageManager: issue.PackageManager,
					Module:         v.From[1],
				})
			}
		}
	}
	return introducedThroughs
}

type DetailedPath struct {
	From        []string
	Remediation string
}

func getDetailedPaths(issue snyk.OssIssueData) []DetailedPath {
	var detailedPaths = make([]DetailedPath, len(issue.MatchingIssues))

	for i, matchingIssue := range issue.MatchingIssues {
		remediationAdvice := getRemediationAdvice(matchingIssue)

		detailedPaths[i] = DetailedPath{
			From:        matchingIssue.From,
			Remediation: remediationAdvice,
		}
	}
	return detailedPaths
}

func getRemediationAdvice(issue snyk.OssIssueData) string {
	hasUpgradePath := len(issue.UpgradePath) > 1
	isOutdated := hasUpgradePath && issue.UpgradePath[1] == issue.From[1]
	remediationAdvice := "No remediation advice available"
	upgradeMessage := ""
	if issue.IsUpgradable || issue.IsPatchable {
		if hasUpgradePath {
			upgradeMessage = "Upgrade to " + issue.UpgradePath[1].(string)
		}

		if isOutdated {
			if issue.IsPatchable {
				remediationAdvice = upgradeMessage
			} else {
				remediationAdvice = getOutdatedDependencyMessage(issue)
			}
		} else {
			remediationAdvice = upgradeMessage
		}
	}
	return remediationAdvice
}

func getOutdatedDependencyMessage(issue snyk.OssIssueData) string {
	remediationAdvice := fmt.Sprintf("Your dependencies are out of date, "+
		"otherwise you would be using a newer %s than %s@%s. ", issue.Name, issue.Name, issue.Version)

	if issue.PackageManager == "npm" || issue.PackageManager == "yarn" || issue.PackageManager == "yarn-workspace" {
		remediationAdvice += "Try relocking your lockfile or deleting node_modules and reinstalling" +
			" your dependencies. If the problem persists, one of your dependencies may be bundling outdated modules."
	} else {
		remediationAdvice += "Try reinstalling your dependencies. If the problem persists, one of your dependencies may be bundling outdated modules."
	}
	return remediationAdvice
}
