/*
 * © 2023-2025 Snyk Limited
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

// Package codeaction implements the code action functionality
package codeaction

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/ide/filter"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

type dirtyFilesWatcher interface {
	IsDirty(path sglsp.DocumentURI) bool
}

// CodeActionsService is an application-layer service for handling code actions.
type CodeActionsService struct {
	IssuesProvider     snyk.IssueProvider
	featureFlagService featureflag.Service

	// actionsCache holds all the issues that were returns by the GetCodeActions method.
	// This is used to resolve the code actions later on in ResolveCodeAction.
	actionsCache map[uuid.UUID]cachedAction
	c            *config.Config
	logger       zerolog.Logger
	fileWatcher  dirtyFilesWatcher
	notifier     noti.Notifier
}

type cachedAction struct {
	issue  types.Issue
	action types.CodeAction
}

func NewService(c *config.Config, provider snyk.IssueProvider, fileWatcher dirtyFilesWatcher, notifier noti.Notifier, featureFlagService featureflag.Service) *CodeActionsService {
	return &CodeActionsService{
		IssuesProvider:     provider,
		featureFlagService: featureFlagService,
		actionsCache:       make(map[uuid.UUID]cachedAction),
		c:                  c,
		logger:             c.Logger().With().Str("service", "CodeActionsService").Logger(),
		fileWatcher:        fileWatcher,
		notifier:           notifier,
	}
}

func (c *CodeActionsService) GetCodeActions(params types.CodeActionParams) []types.LSPCodeAction {
	c.logger.Debug().Msg("Received code action request")
	if c.fileWatcher.IsDirty(params.TextDocument.URI) {
		c.logger.Debug().Msg("File is dirty, skipping code actions")
		return nil
	}
	path := uri.PathFromUri(params.TextDocument.URI)
	folder := c.c.Workspace().GetFolderContaining(path)
	if folder == nil {
		c.logger.Debug().Any("path", path).Msg("file not in workspace folder, skipping code actions")
		return nil
	}

	r := converter.FromRange(params.Range)
	issues := c.IssuesProvider.IssuesForRange(path, r)
	c.logger.Debug().Any("path", path).Any("range", r).Msgf("Found %d issues", len(issues))

	// Apply all filters: severity, risk score, and issue view options
	filteredIssues := filter.FilterIssues(issues, c.c, folder.Path())
	c.logger.Debug().Any("path", path).Any("range", r).Msgf("Filtered to %d issues", len(filteredIssues))

	// Get quickfix groupables from both filtered and all issues
	filteredQuickFixGroupables := c.getQuickFixGroupablesAndCache(filteredIssues)
	allQuickFixGroupables := c.getQuickFixGroupablesFromAllIssues(issues)

	var updatedIssues []types.Issue
	if len(filteredQuickFixGroupables) != 0 || len(allQuickFixGroupables) != 0 {
		updatedIssues = c.UpdateIssuesWithQuickFixes(filteredQuickFixGroupables, allQuickFixGroupables, filteredIssues, issues)
	} else {
		updatedIssues = filteredIssues
	}

	actions := converter.ToCodeActions(updatedIssues)
	c.logger.Debug().Msg(fmt.Sprint("Returning ", len(actions), " code actions"))
	return actions
}

// UpdateIssuesWithQuickFixes creates quickfix actions: one or two depending on filtering
func (c *CodeActionsService) UpdateIssuesWithQuickFixes(filteredGroupables, allGroupables []types.Groupable, filteredIssues, allIssues []types.Issue) []types.Issue {
	var quickFixActions []types.CodeAction

	// Count fixable issues for both filtered and all
	fixableDisplayed := c.countIssuesWithQuickfixes(filteredIssues)
	fixableAll := c.countIssuesWithQuickfixes(allIssues)

	// If the issue counts and fixable counts are the same, only show one action (without "displayed")
	// We check both because unfixable counts might differ even if fixable counts are the same
	if fixableDisplayed == fixableAll && len(filteredIssues) == len(allIssues) {
		if len(allGroupables) > 0 {
			allAction := c.getQuickFixAction(allGroupables)
			if allAction != nil {
				allActionCopy := c.cloneQuickFixAction(allAction)
				originalTitle := allActionCopy.GetOriginalTitle()
				unfixable := len(allIssues) - fixableAll
				allTitle := c.formatAllIssuesTitle(originalTitle, fixableAll, unfixable)
				allActionCopy.SetTitle(allTitle)
				quickFixActions = append(quickFixActions, allActionCopy)
			}
		}
	} else {
		// Show both actions: "displayed" and "all"
		// Create "displayed issues" action
		if len(filteredGroupables) > 0 {
			displayedAction := c.getQuickFixAction(filteredGroupables)
			if displayedAction != nil {
				displayedActionCopy := c.cloneQuickFixAction(displayedAction)
				originalTitle := displayedActionCopy.GetOriginalTitle()
				unfixable := len(filteredIssues) - fixableDisplayed
				displayedTitle := c.formatDisplayedIssuesTitle(originalTitle, fixableDisplayed, unfixable)
				displayedActionCopy.SetTitle(displayedTitle)
				quickFixActions = append(quickFixActions, displayedActionCopy)
			}
		}

		// Create "all issues" action
		if len(allGroupables) > 0 {
			allAction := c.getQuickFixAction(allGroupables)
			if allAction != nil {
				allActionCopy := c.cloneQuickFixAction(allAction)
				originalTitle := allActionCopy.GetOriginalTitle()
				unfixable := len(allIssues) - fixableAll
				allTitle := c.formatAllIssuesTitle(originalTitle, fixableAll, unfixable)
				allActionCopy.SetTitle(allTitle)
				quickFixActions = append(quickFixActions, allActionCopy)
			}
		}
	}

	// If no quickfix actions were created, return issues unchanged
	if len(quickFixActions) == 0 {
		return filteredIssues
	}

	// Add quickfix actions to all filtered issues
	updatedIssues := make([]types.Issue, 0, len(filteredIssues))
	for _, issue := range filteredIssues {
		groupedActions := append([]types.CodeAction{}, quickFixActions...)

		for _, action := range issue.GetCodeActions() {
			if action.GetGroupingType() == types.Quickfix {
				continue
			}
			groupedActions = append(groupedActions, action)
		}

		issue.SetCodeActions(groupedActions)
		updatedIssues = append(updatedIssues, issue)
	}

	return updatedIssues
}

func (c *CodeActionsService) getQuickFixAction(quickFixGroupables []types.Groupable) types.CodeAction {
	// right now we can always group by max semver version, as
	// code only has one quickfix available, and iac none at all
	var quickFix types.CodeAction
	qf, ok := types.MaxSemver(c.logger)(quickFixGroupables).(types.CodeAction)
	if qf == nil || !ok {
		c.logger.Warn().Msg("grouping quick fix actions failed")
		quickFix = nil
	} else {
		quickFix = qf
		c.logger.Debug().Msgf("chose quickfix %s", quickFix.GetTitle())
	}
	return quickFix
}

func (c *CodeActionsService) getQuickFixGroupablesAndCache(issues []types.Issue) []types.Groupable {
	quickFixGroupables := []types.Groupable{}
	for _, issue := range issues {
		for _, action := range issue.GetCodeActions() {
			if action.GetGroupingType() == types.Quickfix {
				quickFixGroupables = append(quickFixGroupables, action)
			}
			c.cacheCodeAction(action, issue)
		}
	}
	return quickFixGroupables
}

// getQuickFixGroupablesFromAllIssues gets quickfix groupables without caching (for unfiltered count)
func (c *CodeActionsService) getQuickFixGroupablesFromAllIssues(issues []types.Issue) []types.Groupable {
	quickFixGroupables := []types.Groupable{}
	for _, issue := range issues {
		for _, action := range issue.GetCodeActions() {
			if action.GetGroupingType() == types.Quickfix {
				quickFixGroupables = append(quickFixGroupables, action)
			}
		}
	}
	return quickFixGroupables
}

// countIssuesWithQuickfixes counts how many issues have at least one quickfix action
func (c *CodeActionsService) countIssuesWithQuickfixes(issues []types.Issue) int {
	count := 0
	for _, issue := range issues {
		hasQuickfix := false
		for _, action := range issue.GetCodeActions() {
			if action.GetGroupingType() == types.Quickfix {
				hasQuickfix = true
				break
			}
		}
		if hasQuickfix {
			count++
		}
	}
	return count
}

func (c *CodeActionsService) cacheCodeAction(action types.CodeAction, issue types.Issue) {
	if action.GetUuid() != nil {
		cached := cachedAction{
			issue:  issue,
			action: action,
		}
		c.actionsCache[*action.GetUuid()] = cached
	}
}

func (c *CodeActionsService) ResolveCodeAction(action types.LSPCodeAction) (types.LSPCodeAction, error) {
	c.logger.Debug().Msg("Received code action resolve request")
	t := time.Now()

	// If we don't have the data element, our resolution does not work. We then need to return
	// the action we received, so that a potentially included command can be executed.
	if action.Command != nil && action.Data == nil {
		return action, nil
	}

	// we cannot proceed without action data, so now it would be an error
	if action.Data == nil {
		return action, missingKeyError{}
	}

	key := uuid.UUID(*action.Data)
	cached, found := c.actionsCache[key]
	if !found {
		return types.LSPCodeAction{}, errors.New(fmt.Sprint("could not find cached action for uuid ", key))
	}

	// only delete cache entry after it's been resolved
	defer delete(c.actionsCache, key)
	edit := (*cached.action.GetDeferredEdit())()
	resolvedAction := cached.action
	resolvedAction.SetEdit(edit)
	elapsed := time.Since(t)
	elapsedSeconds := int(elapsed.Seconds())
	codeAction := converter.ToCodeAction(cached.issue, resolvedAction)

	c.logger.Debug().Msg(fmt.Sprint("Resolved code action in ", elapsedSeconds, " seconds:\n", codeAction))
	return codeAction, nil
}

type missingKeyError struct{}

func (e missingKeyError) Error() string {
	return "code action lookup key is missing - this is not a deferred code action"
}

func IsMissingKeyError(err error) bool {
	var missingKeyErr missingKeyError
	ok := errors.As(err, &missingKeyErr)
	return ok
}

func (c *CodeActionsService) formatDisplayedIssuesTitle(originalTitle string, fixable, unfixable int) string {
	plural := ""
	if fixable > 1 {
		plural = "s"
	}

	unfixableSuffix := ""
	if unfixable > 0 {
		unfixableSuffix = fmt.Sprintf(" (%d unfixable)", unfixable)
	}

	return fmt.Sprintf("%s and fix %d displayed issue%s%s", originalTitle, fixable, plural, unfixableSuffix)
}

func (c *CodeActionsService) formatAllIssuesTitle(originalTitle string, fixable, unfixable int) string {
	plural := ""
	if fixable > 1 {
		plural = "s"
	}

	unfixableSuffix := ""
	if unfixable > 0 {
		unfixableSuffix = fmt.Sprintf(" (%d unfixable)", unfixable)
	}

	return fmt.Sprintf("%s and fix %d issue%s%s", originalTitle, fixable, plural, unfixableSuffix)
}

// cloneQuickFixAction creates a deep copy of a code action with a new UUID
func (c *CodeActionsService) cloneQuickFixAction(action types.CodeAction) types.CodeAction {
	// Cast to *snyk.CodeAction to access fields for cloning
	snykAction, ok := action.(*snyk.CodeAction)
	if !ok {
		// If it's not a snyk.CodeAction, return as is
		return action
	}

	// Create a new UUID for the cloned action
	newUUID := uuid.New()

	// Create a new action with copied fields
	cloned := &snyk.CodeAction{
		Title:           snykAction.Title,
		OriginalTitle:   snykAction.OriginalTitle,
		IsPreferred:     snykAction.IsPreferred,
		Edit:            snykAction.Edit,
		DeferredEdit:    snykAction.DeferredEdit,
		Command:         snykAction.Command,
		DeferredCommand: snykAction.DeferredCommand,
		Uuid:            &newUUID, // New UUID for the clone
		GroupingKey:     snykAction.GroupingKey,
		GroupingValue:   snykAction.GroupingValue,
		GroupingType:    snykAction.GroupingType,
	}

	return cloned
}
