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
	_ "embed"
	"fmt"
	"strings"

	"github.com/gomarkdown/markdown"
	"golang.org/x/exp/maps"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
)

//go:embed template/details.html
var detailsHtmlTemplate string

func replaceVariableInHtml(html string, variableName string, variableValue string) string {
	return strings.ReplaceAll(html, fmt.Sprintf("${%s}", variableName), variableValue)
}

func getIdentifiers(id string, issue snyk.OssIssueData) string {
	identifierList := []string{""}

	issueTypeString := "Vulnerability"
	if len(issue.License) > 0 {
		issueTypeString = "License"
	}

	for _, id := range issue.Identifiers.CVE {
		url := "https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + id
		htmlAnchor := fmt.Sprintf("<a href='%s'>%s</a>", url, id)
		identifierList = append(identifierList, htmlAnchor)
	}

	for _, id := range issue.Identifiers.CWE {
		linkId := strings.ReplaceAll(strings.ToUpper(id), "CWE-", "")
		htmlAnchor := fmt.Sprintf("<a href='https://cwe.mitre.org/data/definitions/%s.html'>%s</a>", linkId, id)
		identifierList = append(identifierList, htmlAnchor)
	}

	if issue.CvssScore > 0 {
		htmlAnchor := fmt.Sprintf("<span>CVSS %.1f</span>", issue.CvssScore)
		identifierList = append(identifierList, htmlAnchor)
	}

	htmlAnchor := fmt.Sprintf("<a href='https://snyk.io/vuln/%s'>%s</a>", id, strings.ToUpper(id))
	identifierList = append(identifierList, htmlAnchor)

	return fmt.Sprintf("%s %s", issueTypeString, strings.Join(identifierList, "<span class='delimiter'> </span> "))
}

func getExploitMaturity(issue snyk.OssIssueData) string {
	if len(issue.Exploit) > 0 {
		return fmt.Sprintf("<div class='summary-item maturity'><div class='label font-light'>Exploit maturity</div>"+
			"<div class='content'>%s</div></div>", issue.Exploit)
	} else {
		return ""
	}
}

func getIntroducedBy(issue snyk.OssIssueData) string {
	m := make(map[string]string)

	if len(issue.From) > 0 {
		for _, v := range issue.MatchingIssues {
			if len(v.From) > 1 {
				module := v.From[1]
				htmlAnchor := getVulnHtmlAnchor(issue.PackageManager, module)
				m[module] = htmlAnchor
			}
		}

		return fmt.Sprintf("<div class='summary-item introduced-through'><div class='label font-light'>Introduced through</div>"+
			"<div class='content'>%s</div></div>", strings.Join(maps.Values(m), ", "))
	} else {
		return ""
	}
}

func getVulnHtmlAnchor(packageManager string, module string) string {
	snykUi := config.CurrentConfig().SnykUi()
	return fmt.Sprintf("<a href='%s/test/%s'>%s</a>", snykUi, packageManager, module)
}

func getLearnLink(issue snyk.OssIssueData) string {
	if issue.Lesson == "" {
		return ""
	}

	return fmt.Sprintf("<a class='learn--link' id='learn--link' href='%s'>Learn about this vulnerability</a>",
		issue.Lesson)
}

func getFixedIn(issue snyk.OssIssueData) string {
	if len(issue.FixedIn) == 0 {
		return "Not fixed"
	}

	result := "%s@%v"
	return fmt.Sprintf(result, issue.Name, strings.Join(issue.FixedIn, ", "))
}

func getDetailedPaths(issue snyk.OssIssueData) string {
	detailedPathHtml := ""

	for _, matchingIssue := range issue.MatchingIssues {
		remediationAdvice := matchingIssue.Remediation
		introducedThrough := strings.Join(matchingIssue.From, " > ")

		detailedPathHtml += fmt.Sprintf(`<div class="summary-item path">
						<div class="label font-light">Introduced through</div>
						<div class="content">%s</div>
					</div>
					<div class="summary-item remediation">
						<div class="label font-light">Remediation</div>
						<div class="content">%s</div>
					</div>`, introducedThrough, remediationAdvice)
	}

	return detailedPathHtml
}

func getDetailsHtml(issue snyk.Issue) string {
	additionalData, ok := issue.AdditionalData.(snyk.OssIssueData)
	if !ok {
		config.CurrentConfig().Logger().Error().Msg("Failed to cast additional data to OssIssueData")
		return ""
	}
	overview := markdown.ToHTML([]byte(additionalData.Description), nil, nil)

	html := replaceVariableInHtml(detailsHtmlTemplate, "issueId", issue.ID)
	html = replaceVariableInHtml(html, "issueTitle", additionalData.Title)
	html = replaceVariableInHtml(html, "severityText", issue.Severity.String())
	html = replaceVariableInHtml(html, "vulnerableModule", additionalData.Name)
	html = replaceVariableInHtml(html, "overview", string(overview))
	html = replaceVariableInHtml(html, "identifiers", getIdentifiers(issue.ID, additionalData))
	html = replaceVariableInHtml(html, "exploitMaturity", getExploitMaturity(additionalData))
	html = replaceVariableInHtml(html, "introducedThrough", getIntroducedBy(additionalData))
	html = replaceVariableInHtml(html, "learnLink", getLearnLink(additionalData))
	html = replaceVariableInHtml(html, "fixedIn", getFixedIn(additionalData))
	html = replaceVariableInHtml(html, "detailedPaths", getDetailedPaths(additionalData))

	return html
}
