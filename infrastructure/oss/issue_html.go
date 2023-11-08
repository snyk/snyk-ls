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
)

//go:embed template/details.html
var detailsHtmlTemplate string

func replaceVariableInHtml(html string, variableName string, variableValue string) string {
	return strings.ReplaceAll(html, fmt.Sprintf("${%s}", variableName), variableValue)
}

func getIdentifiers(issue *ossIssue) string {
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

	htmlAnchor := fmt.Sprintf("<a href='https://snyk.io/vuln/%s'>%s</a>", issue.Id, strings.ToUpper(issue.Id))
	identifierList = append(identifierList, htmlAnchor)

	return fmt.Sprintf("%s %s", issueTypeString, strings.Join(identifierList, "<span class='delimiter' />"))
}

func getExploitMaturity(issue *ossIssue) string {
	if len(issue.Exploit) > 0 {
		return fmt.Sprintf("<div class='summary-item maturity'><div class='label font-light'>Exploit maturity</div>"+
			"<div class='content'>%s</div></div>", issue.Exploit)
	} else {
		return ""
	}
}

func getIntroducedBy(issue *ossIssue) string {
	m := make(map[string]string)

	if len(issue.From) > 0 {
		for _, v := range issue.matchingIssues {
			if len(v.From) > 0 {
				module := v.From[1]
				url := fmt.Sprintf("https://app.snyk.io/test/%s/%s", issue.PackageManager, module)
				htmlAnchor := fmt.Sprintf("<a href='%s'>%s</a>", url, module)
				m[module] = htmlAnchor
			}
		}

		return fmt.Sprintf("<div class='summary-item introduced-through'><div class='label font-light'>Introduced through</div>"+
			"<div class='content'>%s</div></div>", strings.Join(maps.Values(m), ", "))
	} else {
		return ""
	}
}

func getLearnLink(issue *ossIssue) string {
	if issue.lesson == nil {
		return ""
	}

	return fmt.Sprintf("<a class='learn--link' id='learn--link' href='%s'>Learn about this vulnerability</a>",
		issue.lesson.Url)
}

func getFixedIn(issue *ossIssue) string {
	if len(issue.FixedIn) == 0 {
		return "Not fixed"
	}

	result := "%s@%v"
	return fmt.Sprintf(result, issue.Name, strings.Join(issue.FixedIn, ", "))
}

func getOutdatedDependencyMessage(vuln *ossIssue) string {
	remediationAdvice := fmt.Sprintf("Your dependencies are out of date, "+
		"otherwise you would be using a newer %s than %s@%s.", vuln.Name, vuln.Name, vuln.Version)

	if vuln.PackageManager == "npm" || vuln.PackageManager == "yarn" || vuln.PackageManager == "yarn-workspace" {
		remediationAdvice += "Try relocking your lockfile or deleting <code>node_modules</code> and reinstalling" +
			" your dependencies. If the problem persists, one of your dependencies may be bundling outdated modules."
	} else {
		remediationAdvice += "Try reinstalling your dependencies. If the problem persists, one of your dependencies may be bundling outdated modules."
	}
	return remediationAdvice
}

func getDetailedPaths(issue *ossIssue) string {
	detailedPathHtml := ""

	for _, vuln := range issue.matchingIssues {
		hasUpgradePath := len(vuln.UpgradePath) > 0
		introducedThrough := strings.Join(vuln.From, " > ")
		isOutdated := hasUpgradePath && vuln.UpgradePath[1] == vuln.From[1]
		remediationAdvice := "none"
		upgradeMessage := ""

		if vuln.IsUpgradable || vuln.IsPatchable {
			if hasUpgradePath {
				upgradeMessage = "Upgrade to " + vuln.UpgradePath[1].(string)
			}

			if isOutdated {
				if vuln.IsPatchable {
					remediationAdvice = upgradeMessage
				} else {
					remediationAdvice = getOutdatedDependencyMessage(vuln)
				}
			} else {
				remediationAdvice = upgradeMessage
			}
		}

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

func getDetailsHtml(issue *ossIssue) string {
	overview := markdown.ToHTML([]byte(issue.Description), nil, nil)

	html := replaceVariableInHtml(detailsHtmlTemplate, "issueId", issue.Id)
	html = replaceVariableInHtml(html, "issueTitle", issue.Title)
	html = replaceVariableInHtml(html, "severityText", issue.Severity)
	html = replaceVariableInHtml(html, "vulnerableModule", issue.Name)
	html = replaceVariableInHtml(html, "overview", string(overview))
	html = replaceVariableInHtml(html, "identifiers", getIdentifiers(issue))
	html = replaceVariableInHtml(html, "exploitMaturity", getExploitMaturity(issue))
	html = replaceVariableInHtml(html, "introducedThrough", getIntroducedBy(issue))
	html = replaceVariableInHtml(html, "learnLink", getLearnLink(issue))
	html = replaceVariableInHtml(html, "fixedIn", getFixedIn(issue))
	html = replaceVariableInHtml(html, "detailedPaths", getDetailedPaths(issue))

	return html
}
