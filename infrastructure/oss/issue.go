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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/gomarkdown/markdown"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/internal/product"
)

var issuesSeverity = map[string]snyk.Severity{
	"critical": snyk.High,
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

func (o ossIssue) toAdditionalData(filepath string, scanResult *scanResult) snyk.OssIssueData {
	var additionalData snyk.OssIssueData
	additionalData.Key = getIssueKey(filepath, o)
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

func getIssueKey(affectedFilePath string, issue ossIssue) string {
	id := sha256.Sum256([]byte(affectedFilePath + strconv.Itoa(issue.LineNumber) + issue.Id))
	return hex.EncodeToString(id[:16])
}
