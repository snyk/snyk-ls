package oss

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/gomarkdown/markdown"
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
)

func (i *ossIssue) GetCodeActions() (actions []snyk.CodeAction) {
	title := fmt.Sprintf("Open description of '%s affecting package %s' in browser (Snyk)", i.Title, i.PackageName)
	return []snyk.CodeAction{
		{
			Title:       title,
			Issues:      []snyk.Issue{},
			IsPreferred: true,
			Edit:        snyk.WorkspaceEdit{},
			Command: snyk.Command{
				Title:     title,
				Command:   snyk.OpenBrowserCommand,
				Arguments: []interface{}{i.createIssueURL().String()},
			},
		},
	}
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

	return fmt.Sprintf("\n### %s: %s affecting %s package \n%s \n%s", issue.Id, title, issue.PackageName, summary, description)
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
