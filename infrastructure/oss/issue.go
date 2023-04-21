/*
 * © 2022 Snyk Limited All rights reserved.
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
	"fmt"
	"net/url"
	"strings"

	"github.com/gomarkdown/markdown"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/learn"
)

func (i *ossIssue) GetCodeActions(learnService learn.Service, ep error_reporting.ErrorReporter) (actions []snyk.CodeAction) {
	title := fmt.Sprintf("Open description of '%s affecting package %s' in browser (Snyk)", i.Title, i.PackageName)
	command := &snyk.CommandData{
		Title:     title,
		CommandId: snyk.OpenBrowserCommand,
		Arguments: []any{i.createIssueURL().String()},
	}

	action, _ := snyk.NewCodeAction(title, nil, command)
	actions = append(actions, action)

	codeAction := i.addSnykLearnAction(learnService, ep)
	if codeAction != nil {
		actions = append(actions, *codeAction)
	}
	return actions
}

func (i *ossIssue) addSnykLearnAction(learnService learn.Service, ep error_reporting.ErrorReporter) (action *snyk.CodeAction) {
	if config.CurrentConfig().IsSnykLearnCodeActionsEnabled() {
		lesson, err := learnService.GetLesson(i.PackageManager, i.Id, i.Identifiers.CWE, i.Identifiers.CVE, snyk.DependencyVulnerability)
		if err != nil {
			msg := "failed to get lesson"
			log.Err(err).Msg(msg)
			ep.CaptureError(errors.WithMessage(err, msg))
			return nil
		}

		if lesson.Url != "" {
			title := fmt.Sprintf("Learn more about %s (Snyk)", i.Title)
			action = &snyk.CodeAction{
				Title: title,
				Command: &snyk.CommandData{
					Title:     title,
					CommandId: snyk.OpenBrowserCommand,
					Arguments: []any{lesson.Url},
				},
			}
			log.Debug().Str("method", "oss.issue.addSnykLearnAction").Msgf("Learn action: %v", action)
		}
	}
	return action
}

func (i *ossIssue) getExtendedMessage(issue ossIssue) string {
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
	return fmt.Sprintf("| [%s](%s)", i.Id, i.createIssueURL().String())
}

func (i *ossIssue) createIssueURL() *url.URL {
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

func (i *ossIssue) toIssueSeverity() snyk.Severity {
	sev, ok := issuesSeverity[i.Severity]
	if !ok {
		return snyk.Low
	}
	return sev
}
