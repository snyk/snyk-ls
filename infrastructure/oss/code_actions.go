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

package oss

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/mod/semver"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/types"
)

func (i *ossIssue) AddCodeActions(learnService learn.Service, ep error_reporting.ErrorReporter, affectedFilePath string, issueRange snyk.Range) (actions []snyk.CodeAction) {
	c := config.CurrentConfig()
	if reflect.DeepEqual(issueRange, snyk.Range{}) {
		c.Logger().Debug().Str("issue", i.Id).Msg("skipping adding code action, as issueRange is empty")
		return actions
	}

	quickFixAction := i.AddQuickFixAction(affectedFilePath, issueRange)
	if quickFixAction != nil {
		actions = append(actions, *quickFixAction)
	}

	if c.IsSnykOpenBrowserActionEnabled() {
		title := fmt.Sprintf("Open description of '%s affecting package %s' in browser (Snyk)", i.Title, i.PackageName)
		command := &types.CommandData{
			Title:     title,
			CommandId: types.OpenBrowserCommand,
			Arguments: []any{i.CreateIssueURL().String()},
		}

		action, err := snyk.NewCodeAction(title, nil, command)
		if err != nil {
			c.Logger().Err(err).Msgf("could not create code action %s", title)
		} else {
			actions = append(actions, action)
		}
	}

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
	logger := config.CurrentConfig().Logger().With().Str("method", "oss.AddQuickFixAction").Logger()
	if !config.CurrentConfig().IsSnykOSSQuickFixCodeActionsEnabled() {
		return nil
	}
	logger.Debug().Msg("create deferred quickfix code action")
	quickfixEdit := i.getQuickfixEdit(affectedFilePath)
	if quickfixEdit == "" {
		return nil
	}
	upgradeMessage := "⚡️ Upgrade to " + quickfixEdit
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

	// out grouping key for oss quickfixes is the dependency name
	groupingKey, groupingValue := i.getUpgradedPathParts()

	action, err := snyk.NewDeferredCodeAction(upgradeMessage, &autofixEditCallback, nil, types.Key(groupingKey), groupingValue)
	if err != nil {
		logger.Error().Msg("failed to create deferred quickfix code action")
		return nil
	}
	return &action
}

func (i *ossIssue) getQuickfixEdit(affectedFilePath string) string {
	logger := config.CurrentConfig().Logger().With().Str("method", "oss.getQuickfixEdit").Logger()
	hasUpgradePath := len(i.UpgradePath) > 1
	if !hasUpgradePath {
		return ""
	}

	// UpgradePath[0] is the upgrade for the package that was scanned
	// UpgradePath[1] is the upgrade for the root dependency
	depName, depVersion := i.getUpgradedPathParts()
	logger.Debug().Msgf("comparing %s with %s", i.UpgradePath[1], i.From[1])
	// from[1] contains the package that caused this issue
	normalizedCurrentVersion := strings.Split(i.From[1], "@")[1]
	if semver.Compare("v"+depVersion, "v"+normalizedCurrentVersion) == 0 {
		logger.Warn().Msg("proposed upgrade version is the same version as the current, not adding quickfix")
		return ""
	}
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

func (i *ossIssue) getUpgradedPathParts() (string, string) {
	rootDependencyUpgrade := strings.Split(i.UpgradePath[1].(string), "@")
	depName := strings.Join(rootDependencyUpgrade[:len(rootDependencyUpgrade)-1], "@")
	depVersion := rootDependencyUpgrade[len(rootDependencyUpgrade)-1]
	return depName, depVersion
}
