/*
 * © 2024-2025 Snyk Limited
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
	"os"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"golang.org/x/mod/semver"

	"github.com/snyk/snyk-ls/ast"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/types"
)

// openBrowserOSSDescriptionTitleCache deduplicates the long "open in browser" action title
// built from vuln title + package name (megaproject: many findings repeat the same pair).
var openBrowserOSSDescriptionTitleCache sync.Map // key: openBrowserOSSDescriptionTitleKey -> string

type openBrowserOSSDescriptionTitleKey struct {
	vulnTitle, packageName string
}

func memoOpenBrowserOSSDescriptionTitle(vulnTitle, packageName string) string {
	k := openBrowserOSSDescriptionTitleKey{vulnTitle: vulnTitle, packageName: packageName}
	if v, ok := openBrowserOSSDescriptionTitleCache.Load(k); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	s := fmt.Sprintf("Open description of '%s affecting package %s' in browser (Snyk)", vulnTitle, packageName)
	openBrowserOSSDescriptionTitleCache.Store(k, s)
	return s
}

// learnCodeActionLookupCache memoizes Snyk Learn lesson resolution for identical OSS lookup
// tuples (aligned with learn.Service lessonsLookupParams: ecosystem, rule, first CWE/CVE only).
// Title is not part of the key — GetLesson does not use it; display strings are rebuilt on hit.
// Each cache hit still allocates a fresh *snyk.CodeAction so callers cannot mutate shared state.
var learnCodeActionLookupCache sync.Map // key: learnCodeActionLookupCacheKey -> learnCodeActionLookupCacheValue

type learnCodeActionLookupCacheKey struct {
	packageManager, vulnID, cwe0, cve0 string
}

type learnCodeActionLookupCacheValue struct {
	// hasAction false means "no learn code action" (nil return) was observed for this key.
	hasAction bool
	url       string // only when hasAction; lesson URL from learn.Service (ide suffix applied there)
}

func learnCodeActionCacheKey(packageManager, vulnID string, cwes, cves []string) learnCodeActionLookupCacheKey {
	cwe0, cve0 := "", ""
	if len(cwes) > 0 && len(cwes[0]) > 0 {
		cwe0 = cwes[0]
	}
	if len(cves) > 0 && len(cves[0]) > 0 {
		cve0 = cves[0]
	}
	return learnCodeActionLookupCacheKey{
		packageManager: packageManager, vulnID: vulnID,
		cwe0: cwe0, cve0: cve0,
	}
}

// resetOSSCodeActionMemoCachesForTest clears package-level memoization (tests may run with -count>1).
func resetOSSCodeActionMemoCachesForTest() {
	learnCodeActionLookupCache = sync.Map{}
	openBrowserOSSDescriptionTitleCache = sync.Map{}
}

func cloneLearnCodeActionFromCache(displayTitle, url string) types.CodeAction {
	return &snyk.CodeAction{
		Title:         displayTitle,
		OriginalTitle: displayTitle,
		Command: &types.CommandData{
			Title:     displayTitle,
			CommandId: types.OpenBrowserCommand,
			Arguments: []any{url},
		},
	}
}

func GetCodeActions(engine workflow.Engine, configResolver types.ConfigResolverInterface, learnService learn.Service, ep error_reporting.ErrorReporter, affectedFilePath types.FilePath, issueDepNode *ast.Node, issue types.Issue, folderConfig *types.FolderConfig) (actions []types.CodeAction) {
	if issueDepNode == nil {
		engine.GetLogger().Debug().Str("issue", issue.GetRuleID()).Msg("skipping adding code action, as issueDepNode is empty")
		return actions
	}

	ossIssueData, ok := issue.GetAdditionalData().(snyk.OssIssueData)
	if !ok {
		engine.GetLogger().Warn().Str("issue", issue.GetRuleID()).Msg("skipping adding code action as ossIssueData is missing")
		return actions
	}

	// let's see if we can offer a quickfix here
	// value has the version information, so if it's empty, we'll need to look at the parent
	var quickFixAction types.CodeAction
	if issueDepNode.Tree != nil && issueDepNode.Value == "" {
		fixNode := issueDepNode.LinkedParentDependencyNode
		if fixNode != nil {
			quickFixAction = AddQuickFixAction(
				engine,
				configResolver,
				types.FilePath(fixNode.Tree.Document),
				getRangeFromNode(fixNode),
				[]byte(fixNode.Tree.Root.Value),
				true,
				ossIssueData.PackageManager,
				ossIssueData.From,
				ossIssueData.UpgradePath,
				folderConfig,
			)
		}
	} else {
		quickFixAction = AddQuickFixAction(
			engine,
			configResolver,
			affectedFilePath,
			getRangeFromNode(issueDepNode),
			nil,
			false,
			ossIssueData.PackageManager,
			ossIssueData.From,
			ossIssueData.UpgradePath,
			folderConfig,
		)
	}
	if quickFixAction != nil {
		actions = append(actions, quickFixAction)
	}

	if configResolver.GetBool(types.SettingEnableSnykOpenBrowserActions, folderConfig) {
		title := memoOpenBrowserOSSDescriptionTitle(ossIssueData.Title, ossIssueData.PackageName)
		command := &types.CommandData{
			Title:     title,
			CommandId: types.OpenBrowserCommand,
			Arguments: []any{CreateIssueURL(engine, issue.GetRuleID()).String()},
		}

		action, err := snyk.NewCodeAction(title, nil, command)
		if err != nil {
			engine.GetLogger().Err(err).Msgf("could not create code action %s", title)
		} else {
			actions = append(actions, action)
		}
	}

	codeAction := AddSnykLearnAction(
		engine,
		configResolver,
		learnService,
		ep,
		ossIssueData.Title,
		ossIssueData.PackageManager,
		issue.GetRuleID(),
		ossIssueData.Identifiers.CWE,
		ossIssueData.Identifiers.CVE,
		folderConfig,
	)

	if codeAction != nil {
		actions = append(actions, codeAction)
	}

	return actions
}

func AddSnykLearnAction(
	engine workflow.Engine,
	configResolver types.ConfigResolverInterface,
	learnService learn.Service,
	ep error_reporting.ErrorReporter,
	title string,
	packageManager string,
	vulnId string,
	cwes []string,
	cves []string,
	folderConfig *types.FolderConfig,
) (action types.CodeAction) {
	if configResolver.GetBool(types.SettingEnableSnykLearnCodeActions, folderConfig) {
		cacheKey := learnCodeActionCacheKey(packageManager, vulnId, cwes, cves)
		if v, ok := learnCodeActionLookupCache.Load(cacheKey); ok {
			entry, ok := v.(learnCodeActionLookupCacheValue)
			if ok && !entry.hasAction {
				return nil
			}
			if ok && entry.hasAction {
				displayTitle := fmt.Sprintf("Learn more about %s (Snyk)", title)
				a := cloneLearnCodeActionFromCache(displayTitle, entry.url)
				engine.GetLogger().Debug().Str("method", "oss.issue.AddSnykLearnAction").Msgf("Learn action (cached lookup): %v", a)
				return a
			}
		}

		lesson, err := learnService.GetLesson(packageManager, vulnId, cwes, cves, types.DependencyVulnerability)
		if err != nil {
			msg := "failed to get lesson"
			engine.GetLogger().Err(err).Msg(msg)
			ep.CaptureError(errors.WithMessage(err, msg))
			return nil
		}

		if lesson != nil && lesson.Url != "" {
			displayTitle := fmt.Sprintf("Learn more about %s (Snyk)", title)
			learnCodeActionLookupCache.Store(cacheKey, learnCodeActionLookupCacheValue{
				hasAction: true,
				url:       lesson.Url,
			})
			action = cloneLearnCodeActionFromCache(displayTitle, lesson.Url)
			engine.GetLogger().Debug().Str("method", "oss.issue.AddSnykLearnAction").Msgf("Learn action: %v", action)
		} else {
			// Negative cache: if the Learn catalog gains a lesson later, restart is required to pick it up.
			learnCodeActionLookupCache.Store(cacheKey, learnCodeActionLookupCacheValue{hasAction: false})
		}
	}
	return action
}

func AddQuickFixAction(engine workflow.Engine, configResolver types.ConfigResolverInterface, affectedFilePath types.FilePath, issueRange types.Range, fileContent []byte, addFileNameToFixTitle bool, packageManager string, dependencyPath []string, upgradePath []any, folderConfig *types.FolderConfig) types.CodeAction {
	logger := engine.GetLogger().With().Str("method", "oss.AddQuickFixAction").Logger()
	if !configResolver.GetBool(types.SettingEnableSnykOssQuickFixActions, folderConfig) {
		return nil
	}
	logger.Debug().Msg("create deferred quickfix code action")
	filePathString := string(affectedFilePath)
	quickfixEdit := getQuickfixEdit(engine, affectedFilePath, upgradePath, dependencyPath, packageManager)
	if quickfixEdit == "" {
		return nil
	}
	upgradeMessage := "⚡️ Upgrade to " + quickfixEdit
	if addFileNameToFixTitle {
		upgradeMessage += " [ in file: " + filePathString + " ]"
	}
	autofixEditCallback := func() *types.WorkspaceEdit {
		edit := &types.WorkspaceEdit{}
		var err error
		if fileContent == nil {
			fileContent, err = os.ReadFile(filePathString)
			if err != nil {
				logger.Error().Err(err).Str("file", filePathString).Msg("could not open file")
				return edit
			}
		}

		singleTextEdit := types.TextEdit{
			Range:   issueRange,
			NewText: quickfixEdit,
		}
		edit.Changes = make(map[string][]types.TextEdit)
		edit.Changes[filePathString] = []types.TextEdit{singleTextEdit}
		return edit
	}

	// our grouping key for oss quickfixes is the dependency name
	groupingKey, groupingValue, err := getUpgradedPathParts(upgradePath)
	if err != nil {
		logger.Warn().Err(err).Msg("could not get the upgrade path, so cannot add quickfix.")
		return nil
	}

	action, err := snyk.NewDeferredCodeAction(upgradeMessage, &autofixEditCallback, nil, types.Key(groupingKey), groupingValue)
	if err != nil {
		logger.Error().Msg("failed to create deferred quickfix code action")
		return nil
	}
	return &action
}

func getQuickfixEdit(engine workflow.Engine, affectedFilePath types.FilePath, upgradePath []any, dependencyPath []string, packageManager any) string {
	logger := engine.GetLogger().With().Str("method", "oss.getQuickfixEdit").Logger()
	hasUpgradePath := len(upgradePath) > 1
	if !hasUpgradePath {
		return ""
	}

	// upgradePath[0] is the upgrade for the package that was scanned
	// upgradePath[1] is the upgrade for the root dependency
	depName, depVersion, err := getUpgradedPathParts(upgradePath)
	if err != nil {
		logger.Warn().Err(err).Msg("could not get the upgrade path, so cannot add quickfix.")
		return ""
	}
	logger.Debug().Msgf("comparing %s with %s", upgradePath[1], dependencyPath[1])
	// from[1] contains the package that caused this issue
	normalizedCurrentVersion := strings.Split(dependencyPath[1], "@")[1]
	if semver.Compare("v"+depVersion, "v"+normalizedCurrentVersion) == 0 {
		logger.Warn().Msg("proposed upgrade version is the same version as the current, not adding quickfix")
		return ""
	}
	switch packageManager {
	case "npm", "yarn", "yarn-workspace":
		return fmt.Sprintf("\"%s\": \"%s\"", depName, depVersion)
	case "maven":
		depNameSplit := strings.Split(depName, ":")
		depName = depNameSplit[len(depNameSplit)-1]
		// TODO: remove once https://snyksec.atlassian.net/browse/OSM-1775 is fixed
		if strings.Contains(string(affectedFilePath), "build.gradle") {
			return fmt.Sprintf("%s:%s", depName, depVersion)
		}
		return depVersion
	case "gradle":
		depNameSplit := strings.Split(depName, ":")
		depName = depNameSplit[len(depNameSplit)-1]
		return fmt.Sprintf("%s:%s", depName, depVersion)
	}
	if packageManager == "gomodules" {
		return fmt.Sprintf("v%s", depVersion)
	}

	return ""
}

func getUpgradedPathParts(upgradePath []any) (string, string, error) {
	s, ok := upgradePath[1].(string)
	if !ok {
		return "", "", errors.New("invalid upgrade path, could not cast to string")
	}
	rootDependencyUpgrade := strings.Split(s, "@")
	depName := strings.Join(rootDependencyUpgrade[:len(rootDependencyUpgrade)-1], "@")
	depVersion := rootDependencyUpgrade[len(rootDependencyUpgrade)-1]
	return depName, depVersion, nil
}
