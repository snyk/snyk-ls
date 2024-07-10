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
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gomarkdown/markdown"
	"github.com/pkg/errors"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/internal/lsp"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

type identifiers struct {
	CWE  []string `json:"CWE,omitempty"`
	GHSA []string `json:"GHSA,omitempty"`
	CVE  []string `json:"CVE,omitempty"`
}

type reference struct {
	Title string  `json:"title"`
	Url   lsp.Uri `json:"url"`
}

type ossIssue struct {
	Id                 string             `json:"id"`
	Name               string             `json:"name"`
	Title              string             `json:"title"`
	Severity           string             `json:"severity"`
	LineNumber         int                `json:"lineNumber"`
	Description        string             `json:"description"`
	References         []reference        `json:"references,omitempty"`
	Version            string             `json:"version"`
	PackageManager     string             `json:"packageManager"`
	PackageName        string             `json:"packageName"`
	From               []string           `json:"from"`
	Identifiers        identifiers        `json:"identifiers,omitempty"`
	FixedIn            []string           `json:"fixedIn,omitempty"`
	UpgradePath        []any              `json:"upgradePath,omitempty"`
	IsUpgradable       bool               `json:"isUpgradable,omitempty"`
	CVSSv3             string             `json:"CVSSv3,omitempty"`
	CvssScore          float64            `json:"cvssScore,omitempty"`
	Exploit            string             `json:"exploit,omitempty"`
	IsPatchable        bool               `json:"isPatchable"`
	License            string             `json:"license,omitempty"`
	Language           string             `json:"language,omitempty"`
	lesson             *learn.Lesson      `json:"-"`
	AppliedPolicyRules AppliedPolicyRules `json:"appliedPolicyRules,omitempty"`
}

type AppliedPolicyRules struct {
	Annotation Annotation `json:"annotation,omitempty"`
}

type Annotation struct {
	Value  string `json:"value,omitempty"`
	Reason string `json:"reason,omitempty"`
}

func (i *ossIssue) toAdditionalData(scanResult *scanResult, matchingIssues []snyk.OssIssueData) snyk.OssIssueData {
	var additionalData snyk.OssIssueData
	additionalData.Key = util.GetIssueKey(i.Id, scanResult.DisplayTargetFile, i.LineNumber, i.LineNumber, 0, 0)
	additionalData.Title = i.Title
	additionalData.Name = i.Name
	additionalData.Identifiers = snyk.Identifiers{
		CWE: i.Identifiers.CWE,
		CVE: i.Identifiers.CVE,
	}
	additionalData.LineNumber = i.LineNumber
	additionalData.Description = i.Description
	additionalData.References = i.toReferences()
	additionalData.Version = i.Version
	additionalData.License = i.License
	additionalData.PackageManager = i.PackageManager
	additionalData.PackageName = i.PackageName
	additionalData.From = i.From
	additionalData.FixedIn = i.FixedIn
	additionalData.UpgradePath = i.UpgradePath
	additionalData.IsUpgradable = i.IsUpgradable
	additionalData.CVSSv3 = i.CVSSv3
	additionalData.CvssScore = i.CvssScore
	additionalData.Exploit = i.Exploit
	additionalData.IsPatchable = i.IsPatchable
	additionalData.ProjectName = scanResult.ProjectName
	additionalData.DisplayTargetFile = scanResult.DisplayTargetFile
	additionalData.Language = i.Language
	additionalData.MatchingIssues = matchingIssues
	if i.lesson != nil {
		additionalData.Lesson = i.lesson.Url
	}
	additionalData.Remediation = i.GetRemediation()
	additionalData.AppliedPolicyRules = snyk.AppliedPolicyRules{
		Annotation: snyk.Annotation{
			Value:  i.AppliedPolicyRules.Annotation.Value,
			Reason: i.AppliedPolicyRules.Annotation.Reason,
		},
	}

	return additionalData
}

func (i *ossIssue) toReferences() []snyk.Reference {
	var references []snyk.Reference
	for _, ref := range i.References {
		references = append(references, ref.toReference())
	}
	return references
}

func (r reference) toReference() snyk.Reference {
	u, err := url.Parse(string(r.Url))
	if err != nil {
		config.CurrentConfig().Logger().Err(err).Msg("Unable to parse reference url: " + string(r.Url))
	}
	return snyk.Reference{
		Url:   u,
		Title: r.Title,
	}
}

func (i *ossIssue) getUpgradeMessage() string {
	hasUpgradePath := len(i.UpgradePath) > 1
	if hasUpgradePath {
		return "Upgrade to " + i.UpgradePath[1].(string)
	}
	return ""
}

func (i *ossIssue) getOutdatedDependencyMessage() string {
	remediationAdvice := fmt.Sprintf("Your dependencies are out of date, "+
		"otherwise you would be using a newer %s than %s@%s. ", i.Name, i.Name, i.Version)

	if i.PackageManager == "npm" || i.PackageManager == "yarn" || i.PackageManager == "yarn-workspace" {
		remediationAdvice += "Try relocking your lockfile or deleting node_modules and reinstalling" +
			" your dependencies. If the problem persists, one of your dependencies may be bundling outdated modules."
	} else {
		remediationAdvice += "Try reinstalling your dependencies. If the problem persists, one of your dependencies may be bundling outdated modules."
	}
	return remediationAdvice
}

func (i *ossIssue) GetRemediation() string {
	upgradeMessage := i.getUpgradeMessage()
	isOutdated := upgradeMessage != "" && i.UpgradePath[1] == i.From[1]
	if i.IsUpgradable || i.IsPatchable {
		if isOutdated {
			if i.IsPatchable {
				return upgradeMessage
			} else {
				return i.getOutdatedDependencyMessage()
			}
		} else {
			return upgradeMessage
		}
	}
	return "No remediation advice available"
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
		config.CurrentConfig().Logger().Err(err).Msg("Unable to create issue link for issue:" + i.Id)
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
func (i *ossIssue) AddCodeActions(learnService learn.Service, ep error_reporting.ErrorReporter,
	affectedFilePath string, issueRange snyk.Range) (actions []snyk.
	CodeAction) {
	quickFixAction := i.AddQuickFixAction(affectedFilePath, issueRange)
	if quickFixAction != nil {
		actions = append(actions, *quickFixAction)
	}

	title := fmt.Sprintf("Open description of '%s affecting package %s' in browser (Snyk)", i.Title, i.PackageName)
	command := &types.CommandData{
		Title:     title,
		CommandId: types.OpenBrowserCommand,
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
			config.CurrentConfig().Logger().Err(err).Msg(msg)
			ep.CaptureError(errors.WithMessage(err, msg))
			return nil
		}

		if lesson != nil && lesson.Url != "" {
			title := fmt.Sprintf("Learn more about %s (Snyk)", i.Title)
			action = &snyk.CodeAction{
				Title: title,
				Command: &types.CommandData{
					Title:     title,
					CommandId: types.OpenBrowserCommand,
					Arguments: []any{lesson.Url},
				},
			}
			i.lesson = lesson
			config.CurrentConfig().Logger().Debug().Str("method", "oss.issue.AddSnykLearnAction").Msgf("Learn action: %v", action)
		}
	}
	return action
}

func (i *ossIssue) AddQuickFixAction(affectedFilePath string, issueRange snyk.Range) *snyk.CodeAction {
	if !config.CurrentConfig().IsSnyOSSQuickFixCodeActionsEnabled() {
		return nil
	}
	log.Debug().Msg("create deferred quickfix code action")
	quickfixEdit := i.getQuickfixEdit(affectedFilePath)
	if quickfixEdit == "" {
		return nil
	}
	upgradeMessage := "Upgrade to " + quickfixEdit + " (Snyk)"
	autofixEditCallback := func() *snyk.WorkspaceEdit {
		edit := &snyk.WorkspaceEdit{}
		singleTextEdit := snyk.TextEdit{
			Range:   issueRange,
			NewText: quickfixEdit,
		}
		edit.Changes = make(map[string][]snyk.TextEdit)
		edit.Changes[affectedFilePath] = []snyk.TextEdit{singleTextEdit}
		return edit
	}

	action, err := snyk.NewDeferredCodeAction(upgradeMessage, &autofixEditCallback, nil)
	if err != nil {
		log.Error().Msg("failed to create deferred quickfix code action")
		return nil
	}
	return &action
}

func (i *ossIssue) getQuickfixEdit(affectedFilePath string) string {
	hasUpgradePath := len(i.UpgradePath) > 1
	if !hasUpgradePath {
		return ""
	}

	// UpgradePath[0] is the upgrade for the package that was scanned
	// UpgradePath[1] is the upgrade for the root dependency
	rootDependencyUpgrade := strings.Split(i.UpgradePath[1].(string), "@")
	depName := strings.Join(rootDependencyUpgrade[:len(rootDependencyUpgrade)-1], "@")
	depVersion := rootDependencyUpgrade[len(rootDependencyUpgrade)-1]
	if i.PackageManager == "npm" || i.PackageManager == "yarn" || i.PackageManager == "yarn-workspace" {
		return fmt.Sprintf("\"%s\": \"%s\"", depName, depVersion)
	} else if i.PackageManager == "maven" {
		depNameSplit := strings.Split(depName, ":")
		depName = depNameSplit[len(depNameSplit)-1]
		// TODO: remove once https://snyksec.atlassian.net/browse/OSM-1775 is fixed
		if strings.Contains(affectedFilePath, "build.gradle") {
			return fmt.Sprintf("%s:%s", depName, depVersion)
		}
		return depVersion
	} else if i.PackageManager == "gradle" {
		depNameSplit := strings.Split(depName, ":")
		depName = depNameSplit[len(depNameSplit)-1]
		return fmt.Sprintf("%s:%s", depName, depVersion)
	}
	if i.PackageManager == "gomodules" {
		return fmt.Sprintf("v%s", depVersion)
	}

	return ""
}

type licensesPolicy struct {
	Severities struct {
	} `json:"severities"`
	OrgLicenseRules struct {
		GPL20 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"GPL-2.0"`
		GPL30 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"GPL-3.0"`
		LGPL20 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"LGPL-2.0"`
		LGPL30 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"LGPL-3.0"`
		EPL10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"EPL-1.0"`
		EPL20 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"EPL-2.0"`
		CPOL102 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CPOL-1.02"`
		MPL10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"MPL-1.0"`
		MPL11 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"MPL-1.1"`
		MPL20 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"MPL-2.0"`
		MPL20NoCopyleftException struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"MPL-2.0-no-copyleft-exception"`
		AGPL30 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"AGPL-3.0"`
		AGPL10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"AGPL-1.0"`
		MSRL struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"MS-RL"`
		GPL20WithClasspathException struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"GPL-2.0-with-classpath-exception"`
		APSL10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"APSL-1.0"`
		APSL11 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"APSL-1.1"`
		APSL12 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"APSL-1.2"`
		APSL20 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"APSL-2.0"`
		CPAL10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CPAL-1.0"`
		EUPL10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"EUPL-1.0"`
		EUPL11 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"EUPL-1.1"`
		OSL30 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"OSL-3.0"`
		Artistic10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"Artistic-1.0"`
		Artistic10Perl struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"Artistic-1.0-Perl"`
		Artistic10Cl8 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"Artistic-1.0-cl8"`
		Artistic20 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"Artistic-2.0"`
		RPSL10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"RPSL-1.0"`
		RPL11 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"RPL-1.1"`
		RPL15 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"RPL-1.5"`
		CCBYNC10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-NC-1.0"`
		CCBYNC20 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-NC-2.0"`
		CCBYNC25 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-NC-2.5"`
		CCBYNC30 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-NC-3.0"`
		CCBYNC40 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-NC-4.0"`
		CCBYNCND10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-NC-ND-1.0"`
		CCBYNCND20 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-NC-ND-2.0"`
		CCBYNCND25 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-NC-ND-2.5"`
		CCBYNCND30 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-NC-ND-3.0"`
		CCBYNCND40 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-NC-ND-4.0"`
		CCBYNCSA10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-NC-SA-1.0"`
		CCBYNCSA20 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-NC-SA-2.0"`
		CCBYNCSA25 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-NC-SA-2.5"`
		CCBYNCSA30 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-NC-SA-3.0"`
		CCBYNCSA40 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-NC-SA-4.0"`
		CCBYND10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-ND-1.0"`
		CCBYND20 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-ND-2.0"`
		CCBYND25 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-ND-2.5"`
		CCBYND30 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-ND-3.0"`
		CCBYND40 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-ND-4.0"`
		CCBYSA10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-SA-1.0"`
		CCBYSA40 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-SA-4.0"`
		CCBYSA30 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-SA-3.0"`
		CCBYSA25 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-SA-2.5"`
		CCBYSA20 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-SA-2.0"`
		GPL10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"GPL-1.0"`
		LGPL21 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"LGPL-2.1"`
		CDDL10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CDDL-1.0"`
		CDDL11 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CDDL-1.1"`
		OSL10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"OSL-1.0"`
		OSL11 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"OSL-1.1"`
		OSL20 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"OSL-2.0"`
		OSL21 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"OSL-2.1"`
		CPL10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CPL-1.0"`
		Sleepycat struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"Sleepycat"`
		AFL11 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"AFL-1.1"`
		AFL12 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"AFL-1.2"`
		AFL20 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"AFL-2.0"`
		AFL21 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"AFL-2.1"`
		AFL30 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"AFL-3.0"`
		OCLC20 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"OCLC-2.0"`
		LGPLLR struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"LGPLLR"`
		QPL10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"QPL-1.0"`
		SISSL struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"SISSL"`
		SISSL12 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"SISSL-1.2"`
		Watcom10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"Watcom-1.0"`
		CECILL10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CECILL-1.0"`
		CECILL11 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CECILL-1.1"`
		CECILL20 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CECILL-2.0"`
		CECILL21 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CECILL-2.1"`
		CECILLB struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CECILL-B"`
		CECILLC struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CECILL-C"`
	} `json:"orgLicenseRules"`
}

type ignoreSettings struct {
	AdminOnly                  bool `json:"adminOnly"`
	ReasonRequired             bool `json:"reasonRequired"`
	DisregardFilesystemIgnores bool `json:"disregardFilesystemIgnores"`
}

type Insights struct {
	TriageAdvice any `json:"triageAdvice"`
}

type remediation struct {
	Unresolved []struct {
		CVSSv3           string      `json:"CVSSv3,omitempty"`
		AlternativeIds   []any       `json:"alternativeIds,omitempty"`
		CreationTime     time.Time   `json:"creationTime"`
		Credit           []string    `json:"credit,omitempty"`
		CvssScore        float64     `json:"cvssScore,omitempty"`
		Description      string      `json:"description"`
		DisclosureTime   time.Time   `json:"disclosureTime,omitempty"`
		Exploit          string      `json:"exploit,omitempty"`
		Functions        []any       `json:"functions,omitempty"`
		FixedIn          []string    `json:"fixedIn,omitempty"`
		Id               string      `json:"id"`
		Identifiers      identifiers `json:"identifiers,omitempty"`
		Language         string      `json:"language"`
		Malicious        bool        `json:"malicious,omitempty"`
		ModificationTime time.Time   `json:"modificationTime,omitempty"`
		ModuleName       string      `json:"moduleName,omitempty"`
		PackageManager   string      `json:"packageManager"`
		PackageName      string      `json:"packageName"`
		Patches          []any       `json:"patches,omitempty"`
		Proprietary      bool        `json:"proprietary,omitempty"`
		PublicationTime  time.Time   `json:"publicationTime"`
		References       []reference `json:"references,omitempty"`
		Severity         string      `json:"severity"`
		SocialTrendAlert bool        `json:"socialTrendAlert,omitempty"`
		Title            string      `json:"title"`
		Insights         Insights    `json:"insights,omitempty"`
		FunctionsNew     []any       `json:"functions_new,omitempty"`
		Semver           struct {
			Vulnerable []string `json:"vulnerable"`
		} `json:"semver"`
		MavenModuleName struct {
			GroupId    string `json:"groupId"`
			ArtifactId string `json:"artifactId"`
		} `json:"mavenModuleName,omitempty"`
		From                 []string `json:"from"`
		UpgradePath          []any    `json:"upgradePath"`
		IsUpgradable         bool     `json:"isUpgradable"`
		IsPatchable          bool     `json:"isPatchable"`
		IsPinnable           bool     `json:"isPinnable"`
		IsRuntime            bool     `json:"isRuntime"`
		Name                 string   `json:"name"`
		Version              string   `json:"version"`
		SeverityWithCritical string   `json:"severityWithCritical"`
		License              string   `json:"license,omitempty"`
		Type                 string   `json:"type,omitempty"`
	} `json:"unresolved"`
	Upgrade struct {
	} `json:"upgrade"`
	Patch struct {
	} `json:"patch"`
	Ignore struct {
	} `json:"ignore"`
	Pin struct {
	} `json:"pin"`
}

type scanResult struct {
	Vulnerabilities   []ossIssue     `json:"vulnerabilities"`
	Ok                bool           `json:"ok"`
	DependencyCount   int            `json:"dependencyCount"`
	Policy            string         `json:"policy"`
	IsPrivate         bool           `json:"isPrivate"`
	LicensesPolicy    licensesPolicy `json:"licensesPolicy"`
	PackageManager    string         `json:"packageManager"`
	IgnoreSettings    ignoreSettings `json:"ignoreSettings"`
	Summary           string         `json:"summary"`
	FilesystemPolicy  bool           `json:"filesystemPolicy"`
	UniqueCount       int            `json:"uniqueCount"`
	ProjectName       string         `json:"projectName"`
	FoundProjectCount int            `json:"foundProjectCount"`
	DisplayTargetFile string         `json:"displayTargetFile"`
	Path              string         `json:"path"`
	Remediation       remediation    `json:"remediation,omitempty"`
	Filtered          struct {
		Ignore []any `json:"ignore"`
		Patch  []any `json:"patch"`
	} `json:"filtered,omitempty"`
}
