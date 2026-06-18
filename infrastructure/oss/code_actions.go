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
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"golang.org/x/mod/semver"

	"github.com/snyk/snyk-ls/ast"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/types"
)

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
			quickFixAction = addQuickFixAction(
				engine,
				configResolver,
				types.FilePath(fixNode.Tree.Document),
				getRangeFromNode(fixNode),
				[]byte(fixNode.Tree.Root.Value),
				nil,
				true,
				ossIssueData.PackageManager,
				ossIssueData.From,
				ossIssueData.UpgradePath,
				folderConfig,
			)
		}
	} else {
		fixFilePath := affectedFilePath
		fixRange := getRangeFromNode(issueDepNode)
		var originalContent []byte
		if issueDepNode.Tree != nil {
			originalContent = []byte(issueDepNode.Tree.Root.Value)
		}

		// Maven versions are frequently declared indirectly via a property
		// reference, e.g. <version>${foo.version}</version>. Hardcoding the
		// upgraded version into the dependency block leaves the property
		// orphaned and, on a second apply over the now-shorter text, corrupts
		// the file. When the property can be resolved, redirect the edit to the
		// matching <properties> entry instead.
		if ossIssueData.PackageManager == "maven" {
			if propNode := resolveMavenPropertyNode(issueDepNode); propNode != nil {
				fixFilePath = types.FilePath(propNode.Tree.Document)
				fixRange = getRangeFromNode(propNode)
				originalContent = []byte(propNode.Tree.Root.Value)
			}
		}

		quickFixAction = addQuickFixAction(
			engine,
			configResolver,
			fixFilePath,
			fixRange,
			nil,
			originalContent,
			fixFilePath != affectedFilePath,
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
		title := fmt.Sprintf("Open description of '%s affecting package %s' in browser (Snyk)", ossIssueData.Title, ossIssueData.PackageName)
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
		lesson, err := learnService.GetLesson(packageManager, vulnId, cwes, cves, types.DependencyVulnerability)
		if err != nil {
			msg := "failed to get lesson"
			engine.GetLogger().Err(err).Msg(msg)
			ep.CaptureError(errors.WithMessage(err, msg))
			return nil
		}

		if lesson != nil && lesson.Url != "" {
			t := fmt.Sprintf("Learn more about %s (Snyk)", title)
			action = &snyk.CodeAction{
				Title:         t,
				OriginalTitle: t,
				Command: &types.CommandData{
					Title:     t,
					CommandId: types.OpenBrowserCommand,
					Arguments: []any{lesson.Url},
				},
			}
			engine.GetLogger().Debug().Str("method", "oss.issue.AddSnykLearnAction").Msgf("Learn action: %v", action)
		}
	}
	return action
}

// addQuickFixAction builds a deferred "upgrade" code action. fileContent, when
// non-nil, is the document content used at apply time (otherwise the file is
// read from disk on apply). originalContent is a snapshot of the document at
// action-creation time; it is used to capture the exact text the edit expects
// to replace so a stale edit can be refused at apply time.
func addQuickFixAction(engine workflow.Engine, configResolver types.ConfigResolverInterface, affectedFilePath types.FilePath, issueRange types.Range, fileContent []byte, originalContent []byte, addFileNameToFixTitle bool, packageManager string, dependencyPath []string, upgradePath []any, folderConfig *types.FolderConfig) types.CodeAction {
	logger := engine.GetLogger().With().Str("method", "oss.addQuickFixAction").Logger()
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

	// Snapshot the text the edit is meant to replace, so the deferred edit can
	// detect that the file has changed (e.g. the fix was already applied) and
	// refuse to re-apply a stale, absolute-offset edit that would corrupt the
	// file.
	snapshot := originalContent
	if snapshot == nil {
		snapshot = fileContent
	}
	expectedText, haveExpectedText := textAtRange(snapshot, issueRange)
	// A snapshot was provided but we could not read the text at the fix range
	// (multi-line range, out-of-bounds, etc.). The snapshot is unreliable for
	// guarding this edit, so rather than silently creating an unguarded action,
	// drop it. (When no snapshot is provided at all there is nothing to guard and
	// legacy callers keep working.)
	if snapshot != nil && !haveExpectedText {
		logger.Warn().
			Str("file", filePathString).
			Msg("snapshot provided but text at fix range could not be read; refusing to create an unguarded quickfix")
		return nil
	}

	// applied latches once this action has produced its edit. The disk-based guard
	// below only sees on-disk content; when the client applies the edit in-memory
	// without flushing (the IDE-2139 re-apply scenario), the disk is unchanged and
	// the guard would pass, letting a second apply over the now-shifted buffer
	// corrupt the value. The latch makes the deferred action single-shot, which the
	// disk guard cannot guarantee.
	var applied bool
	autofixEditCallback := func() *types.WorkspaceEdit {
		edit := &types.WorkspaceEdit{}
		if applied {
			logger.Warn().Str("file", filePathString).Msg("quickfix already applied; refusing to re-apply")
			return edit
		}
		content := fileContent
		if content == nil {
			var err error
			content, err = os.ReadFile(filePathString)
			if err != nil {
				logger.Error().Err(err).Str("file", filePathString).Msg("could not open file")
				return edit
			}
		}

		if haveExpectedText {
			currentText, ok := textAtRange(content, issueRange)
			if !ok || strings.TrimSpace(currentText) != strings.TrimSpace(expectedText) {
				logger.Warn().
					Str("file", filePathString).
					Str("expected", expectedText).
					Str("actual", currentText).
					Msg("file content at the fix range has changed since the quickfix was created; refusing to apply a stale edit")
				return edit
			}
		}

		singleTextEdit := types.TextEdit{
			Range:   issueRange,
			NewText: quickfixEdit,
		}
		edit.Changes = make(map[string][]types.TextEdit)
		edit.Changes[filePathString] = []types.TextEdit{singleTextEdit}
		applied = true
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

var mavenPropertyRefRegexp = regexp.MustCompile(`^\s*\$\{([^}]+)\}\s*$`)

// maxPropertyIndirectionDepth bounds how many property-to-property references are
// followed when resolving a Maven version, guarding against reference cycles.
const maxPropertyIndirectionDepth = 16

// resolveMavenPropertyNode returns the <properties> node holding the concrete
// version a dependency refers to when the version is a property reference (e.g.
// ${foo.version}), searching the current pom and walking up the parent pom
// hierarchy. A property whose value is itself a ${other} reference is followed
// (bounded by maxPropertyIndirectionDepth, with cycle detection) so the edit
// targets the property that actually holds the version string. It returns nil
// when the version is not a property reference, the chain cannot be fully
// resolved to a concrete value, or a cycle/depth limit is hit.
func resolveMavenPropertyNode(depNode *ast.Node) *ast.Node {
	if depNode == nil {
		return nil
	}
	matches := mavenPropertyRefRegexp.FindStringSubmatch(depNode.Value)
	if matches == nil {
		return nil
	}
	// The capture group is everything between ${ and }; trim so a reference
	// written with padding (e.g. ${ foo.version }) still matches the property key.
	propertyName := strings.TrimSpace(matches[1])

	seen := map[string]bool{}
	for range maxPropertyIndirectionDepth {
		if seen[propertyName] {
			// reference cycle, e.g. a -> b -> a
			return nil
		}
		seen[propertyName] = true

		node := lookupMavenProperty(depNode.Tree, propertyName)
		if node == nil {
			return nil
		}

		next := mavenPropertyRefRegexp.FindStringSubmatch(node.Value)
		if next == nil {
			// concrete (non-reference) value reached
			return node
		}
		propertyName = strings.TrimSpace(next[1])
	}
	return nil
}

// lookupMavenProperty finds a property by name in start's pom and any parent pom
// in the hierarchy, returning nil when it is not defined.
func lookupMavenProperty(start *ast.Tree, name string) *ast.Node {
	for tree := start; tree != nil; tree = tree.ParentTree {
		if node, ok := tree.Properties[name]; ok && node != nil && node.Tree != nil {
			return node
		}
	}
	return nil
}

// textAtRange returns the substring of content covered by the given single-line
// range. ok is false when content is nil or the range falls outside it (e.g.
// the file got shorter because the fix was already applied).
func textAtRange(content []byte, r types.Range) (text string, ok bool) {
	if content == nil {
		return "", false
	}
	lines := strings.Split(string(content), "\n")
	if r.Start.Line != r.End.Line || r.Start.Line < 0 || r.Start.Line >= len(lines) {
		return "", false
	}
	line := lines[r.Start.Line]
	if r.Start.Character < 0 || r.Start.Character > r.End.Character || r.End.Character > len(line) {
		return "", false
	}
	return line[r.Start.Character:r.End.Character], true
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
