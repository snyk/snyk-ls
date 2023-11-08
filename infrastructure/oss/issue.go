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
	"net/url"
	"strings"

	"github.com/gomarkdown/markdown"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"golang.org/x/exp/maps"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/internal/product"
)

//go:embed template/details.html
var detailsHtmlTemplate string

var issuesSeverity = map[string]snyk.Severity{
	"critical": snyk.Critical,
	"high":     snyk.High,
	"low":      snyk.Low,
	"medium":   snyk.Medium,
}

func (i *ossIssue) AddCodeActions(learnService learn.Service, ep error_reporting.ErrorReporter) (actions []snyk.
	CodeAction) {
	title := fmt.Sprintf("Open description of '%s affecting package %s' in browser (Snyk)", i.Title, i.PackageName)
	command := &snyk.CommandData{
		Title:     title,
		CommandId: snyk.OpenBrowserCommand,
		Arguments: []any{i.CreateIssueURL().String()},
	}

	action, _ := snyk.NewCodeAction(title, nil, command)
	actions = append(actions, action)

	codeAction := i.AddSnykLearnAction(learnService, ep)
	if codeAction != nil {
		actions = append(actions, *codeAction)
	}
	return actions
}

func (i *ossIssue) AddSnykLearnAction(learnService learn.Service, ep error_reporting.ErrorReporter) (action *snyk.
	CodeAction) {
	if config.CurrentConfig().IsSnykLearnCodeActionsEnabled() {
		lesson, err := learnService.GetLesson(i.PackageManager, i.Id, i.Identifiers.CWE, i.Identifiers.CVE, snyk.DependencyVulnerability)
		if err != nil {
			msg := "failed to get lesson"
			log.Err(err).Msg(msg)
			ep.CaptureError(errors.WithMessage(err, msg))
			return nil
		}

		if lesson != nil && lesson.Url != "" {
			title := fmt.Sprintf("Learn more about %s (Snyk)", i.Title)
			action = &snyk.CodeAction{
				Title: title,
				Command: &snyk.CommandData{
					Title:     title,
					CommandId: snyk.OpenBrowserCommand,
					Arguments: []any{lesson.Url},
				},
			}
			i.lesson = lesson
			log.Debug().Str("method", "oss.issue.AddSnykLearnAction").Msgf("Learn action: %v", action)
		}
	}
	return action
}

func (i *ossIssue) GetExtendedMessage(issue ossIssue) string {
	title := issue.Title
	description := issue.Description

	if config.CurrentConfig().Format() == config.FormatHtml {
		title = string(markdown.ToHTML([]byte(title), nil, nil))
		description = string(markdown.ToHTML([]byte(description), nil, nil))
	}
	summary := fmt.Sprintf("### Vulnerability %s %s %s \n **Fixed in: %s | Exploit maturity: %s**",
		issue.createCveLink(),
		issue.createCweLink(),
		issue.createIssueUrlMarkdown(),
		issue.createFixedIn(),
		strings.ToUpper(issue.Severity),
	)

	return fmt.Sprintf("\n### %s: %s affecting %s package \n%s \n%s",
		issue.Id,
		title,
		issue.PackageName,
		summary,
		description)
}

func (i *ossIssue) createCveLink() string {
	var formattedCve string
	for _, c := range i.Identifiers.CVE {
		formattedCve += fmt.Sprintf("| [%s](https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s)", c, c)
	}
	return formattedCve
}

func (i *ossIssue) createIssueUrlMarkdown() string {
	return fmt.Sprintf("| [%s](%s)", i.Id, i.CreateIssueURL().String())
}

func (i *ossIssue) CreateIssueURL() *url.URL {
	parse, err := url.Parse("https://snyk.io/vuln/" + i.Id)
	if err != nil {
		log.Err(err).Msg("Unable to create issue link for issue:" + i.Id)
	}
	return parse
}

func (i *ossIssue) createFixedIn() string {
	var f string
	if len(i.FixedIn) < 1 {
		f += "Not Fixed"
	} else {
		f += "@" + i.FixedIn[0]
		for _, version := range i.FixedIn[1:] {
			f += fmt.Sprintf(", %s", version)
		}
	}
	return f
}

func (i *ossIssue) createCweLink() string {
	var formattedCwe string
	for _, c := range i.Identifiers.CWE {
		id := strings.Replace(c, "CWE-", "", -1)
		formattedCwe += fmt.Sprintf("| [%s](https://cwe.mitre.org/data/definitions/%s.html)", c, id)
	}
	return formattedCwe
}

func (i *ossIssue) ToIssueSeverity() snyk.Severity {
	sev, ok := issuesSeverity[i.Severity]
	if !ok {
		return snyk.Low
	}
	return sev
}

func toIssue(
	affectedFilePath string,
	issue ossIssue,
	scanResult *scanResult,
	issueRange snyk.Range,
	learnService learn.Service,
	ep error_reporting.ErrorReporter,
) snyk.Issue {
	title := issue.Title

	if config.CurrentConfig().Format() == config.FormatHtml {
		title = string(markdown.ToHTML([]byte(title), nil, nil))
	}
	var action = "No fix available."
	var resolution = ""
	if issue.IsUpgradable {
		action = "Upgrade to:"
		resolution = issue.UpgradePath[len(issue.UpgradePath)-1].(string)
	} else {
		if len(issue.FixedIn) > 0 {
			action = "No direct upgrade path, fixed in:"
			resolution = fmt.Sprintf("%s@%s", issue.PackageName, issue.FixedIn[0])
		}
	}

	// find all issues with the same id
	matchingIssues := []ossIssue{}
	for _, otherIssue := range scanResult.Vulnerabilities {
		if otherIssue.Id == issue.Id {
			matchingIssues = append(matchingIssues, otherIssue)
		}
	}
	issue.matchingIssues = matchingIssues

	message := fmt.Sprintf(
		"%s affecting package %s. %s %s (Snyk)",
		title,
		issue.PackageName,
		action,
		resolution,
	)
	return snyk.Issue{
		ID:                  issue.Id,
		Message:             message,
		FormattedMessage:    issue.GetExtendedMessage(issue),
		Range:               issueRange,
		Severity:            issue.ToIssueSeverity(),
		AffectedFilePath:    affectedFilePath,
		Product:             product.ProductOpenSource,
		IssueDescriptionURL: issue.CreateIssueURL(),
		IssueType:           snyk.DependencyVulnerability,
		CodeActions:         issue.AddCodeActions(learnService, ep),
		Ecosystem:           issue.PackageManager,
		CWEs:                issue.Identifiers.CWE,
		CVEs:                issue.Identifiers.CVE,
		AdditionalData:      issue.toAdditionalData(affectedFilePath, scanResult),
	}
}

func replaceVariableInHtml(html string, variableName string, variableValue string) string {
	return strings.ReplaceAll(html, fmt.Sprintf("${%s}", variableName), variableValue)
}

func getIdentifiers(issue *ossIssue) string {
	identifierList := []string{}

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
		htmlAnchor := fmt.Sprintf("CVSS %.1f", issue.CvssScore)
		identifierList = append(identifierList, htmlAnchor)
	}

	htmlAnchor := fmt.Sprintf("<a href='https://snyk.io/vuln/%s'>%s</a>", issue.Id, strings.ToUpper(issue.Id))
	identifierList = append(identifierList, htmlAnchor)

	return fmt.Sprintf("%s %s", issueTypeString, strings.Join(identifierList, " "))
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

/**
function fillDetailedPaths() {
      const paths = document.querySelector('.detailed-paths')!;
      paths.innerHTML = ''; // reset node

      vulnerability.matchingIdVulnerabilities.forEach(vuln => {
        const introducedThrough = vuln.from.join(' > ');

        const isOutdated = vuln.upgradePath && vuln.upgradePath[1] === vuln.from[1];

        // The logic as in registry
        // https://github.com/snyk/registry/blob/5fe141a3c5eeb6b2c5e62cfa2b5a8643df29403d/frontend/src/components/IssueCardVulnerablePath/IssueCardVulnerablePath.vue#L109
        let remediationAdvice: string;
        const upgradeMessage = `Upgrade to ${vuln.upgradePath[1]}`;

        if (vuln.isUpgradable || vuln.isPatchable) {
          if (isOutdated) {
            remediationAdvice = vuln.isPatchable ? upgradeMessage : getOutdatedDependencyMessage(vuln);
          } else {
            remediationAdvice = upgradeMessage;
          }
        } else {
          remediationAdvice = 'none';
        }

        const html = `
        <div class="summary-item path">
          <div class="label font-light">Introduced through</div>
          <div class="content">${introducedThrough}</div>
        </div>
        <div class="summary-item remediation">
          <div class="label font-light">Remediation</div>
          <div class="content">${remediationAdvice}</div>
        </div>`;

        const path = document.createElement('div');
        path.className = 'detailed-path';
        path.innerHTML = html;
        paths.append(path);
      });
    }
*/

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

			if isOutdated && vuln.IsPatchable {
				remediationAdvice = upgradeMessage
			} else if isOutdated {
				remediationAdvice = upgradeMessage
			} else {
				remediationAdvice = fmt.Sprintf("Your dependencies are out of date, "+
					"otherwise you would be using a newer %s than %s@%s.", vuln.Name, vuln.Name, vuln.Version)

				if vuln.PackageManager == "npm" || vuln.PackageManager == "yarn" || vuln.PackageManager == "yarn-workspace" {
					remediationAdvice += "Try relocking your lockfile or deleting <code>node_modules</code> and reinstalling" +
						"your dependencies. If the problem persists, one of your dependencies may be bundling outdated modules."
				} else {
					remediationAdvice += "Try reinstalling your dependencies. If the problem persists, one of your dependencies may be bundling outdated modules."
				}
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

func (o ossIssue) toAdditionalData(filepath string, scanResult *scanResult) snyk.OssIssueData {
	var additionalData snyk.OssIssueData
	additionalData.Key = o.Id
	additionalData.Title = o.Title
	additionalData.Name = o.Name
	additionalData.LineNumber = o.LineNumber
	additionalData.Description = o.Description
	additionalData.References = o.toReferences()
	additionalData.Version = o.Version
	additionalData.License = o.License
	additionalData.PackageManager = o.PackageManager
	additionalData.PackageName = o.PackageName
	additionalData.From = o.From
	additionalData.FixedIn = o.FixedIn
	additionalData.UpgradePath = o.UpgradePath
	additionalData.IsUpgradable = o.IsUpgradable
	additionalData.CVSSv3 = o.CVSSv3
	additionalData.CvssScore = o.CvssScore
	additionalData.Exploit = o.Exploit
	additionalData.IsPatchable = o.IsPatchable
	additionalData.ProjectName = scanResult.ProjectName
	additionalData.DisplayTargetFile = scanResult.DisplayTargetFile
	additionalData.Language = o.Language
	additionalData.Details = getDetailsHtml(&o)

	return additionalData
}

func (o ossIssue) toReferences() []snyk.Reference {
	var references []snyk.Reference
	for _, ref := range o.References {
		references = append(references, ref.toReference())
	}
	return references
}

func (r reference) toReference() snyk.Reference {
	url, err := url.Parse(string(r.Url))
	if err != nil {
		log.Err(err).Msg("Unable to parse reference url: " + string(r.Url))
	}
	return snyk.Reference{
		Url:   url,
		Title: r.Title,
	}
}

func convertScanResultToIssues(
	res *scanResult,
	path string,
	fileContent []byte,
	ls learn.Service,
	ep error_reporting.ErrorReporter,
	packageIssueCache map[string][]snyk.Issue,
) []snyk.Issue {
	var issues []snyk.Issue

	duplicateCheckMap := map[string]bool{}

	for _, issue := range res.Vulnerabilities {
		packageKey := issue.PackageName + "@" + issue.Version
		duplicateKey := issue.Id + "|" + issue.PackageName
		if duplicateCheckMap[duplicateKey] {
			continue
		}
		issueRange := findRange(issue, path, fileContent)
		snykIssue := toIssue(path, issue, res, issueRange, ls, ep)
		packageIssueCache[packageKey] = append(packageIssueCache[packageKey], snykIssue)
		issues = append(issues, snykIssue)
		duplicateCheckMap[duplicateKey] = true
	}
	return issues
}
