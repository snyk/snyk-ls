/*
 * © 2023-2026 Snyk Limited
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
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/workflow"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/domain/snyk/remediation"
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

	// actionsCacheMu protects actionsCache. Every read and write of actionsCache
	// must hold this lock. In ResolveCodeAction, the lock is released BEFORE
	// invoking the slow deferred edit so that concurrent codeAction/resolve
	// requests (which run on separate LSP handler goroutines) are not serialized
	// through the potentially multi-minute remediation call.
	actionsCacheMu sync.Mutex
	// actionsCache holds all the issues that were returns by the GetCodeActions method.
	// This is used to resolve the code actions later on in ResolveCodeAction.
	actionsCache        map[uuid.UUID]cachedAction
	engine              workflow.Engine
	logger              zerolog.Logger
	fileWatcher         dirtyFilesWatcher
	notifier            noti.Notifier
	configResolver      types.ConfigResolverInterface
	remediationProvider remediation.RemediationProvider
}

type cachedAction struct {
	issue  types.Issue
	action types.CodeAction
}

func NewService(engine workflow.Engine, provider snyk.IssueProvider, fileWatcher dirtyFilesWatcher, notifier noti.Notifier, featureFlagService featureflag.Service, configResolver types.ConfigResolverInterface, remediationProvider remediation.RemediationProvider) *CodeActionsService {
	return &CodeActionsService{
		IssuesProvider:      provider,
		featureFlagService:  featureFlagService,
		actionsCache:        make(map[uuid.UUID]cachedAction),
		engine:              engine,
		logger:              engine.GetLogger().With().Str("service", "CodeActionsService").Logger(),
		fileWatcher:         fileWatcher,
		notifier:            notifier,
		configResolver:      configResolver,
		remediationProvider: remediationProvider,
	}
}

func (c *CodeActionsService) GetCodeActions(params types.CodeActionParams) []types.LSPCodeAction {
	c.logger.Debug().Msg("Received code action request")
	if c.fileWatcher.IsDirty(params.TextDocument.URI) {
		c.logger.Debug().Msg("File is dirty, skipping code actions")
		return nil
	}
	path := uri.PathFromUri(params.TextDocument.URI)
	folder := config.GetWorkspace(c.engine.GetConfiguration()).GetFolderContaining(path)
	if folder == nil {
		c.logger.Debug().Any("path", path).Msg("file not in workspace folder, skipping code actions")
		return nil
	}

	r := converter.FromRange(params.Range)
	issues := c.IssuesProvider.IssuesForRange(path, r)
	c.logger.Debug().Any("path", path).Any("range", r).Msgf("Found %d issues", len(issues))

	codeConsistentIgnoresEnabled := c.featureFlagService.GetFromFolderConfig(folder.Path(), featureflag.SnykCodeConsistentIgnores)

	var filteredIssues []types.Issue
	if !codeConsistentIgnoresEnabled {
		filteredIssues = issues
	} else {
		// Issue view options can be set per-folder, so use the folderConfig to fetch the effective value.
		folderConfig := config.GetUnenrichedFolderConfigFromEngine(c.engine, c.configResolver, folder.Path(), c.engine.GetLogger())
		issueViewOptions := c.configResolver.IssueViewOptionsForFolder(folderConfig)
		isViewingOpenIssues := issueViewOptions.OpenIssues
		isViewingIgnoredIssues := issueViewOptions.IgnoredIssues
		for _, issue := range issues {
			if !isViewingOpenIssues && !issue.GetIsIgnored() {
				continue
			}
			if !isViewingIgnoredIssues && issue.GetIsIgnored() {
				continue
			}
			filteredIssues = append(filteredIssues, issue)
		}
		c.logger.Debug().Any("path", path).Any("range", r).Msgf("Filtered to %d issues", len(filteredIssues))
	}

	quickFixGroupables := c.getQuickFixGroupablesAndCache(filteredIssues)

	var updatedIssues []types.Issue
	if len(quickFixGroupables) != 0 {
		updatedIssues = c.UpdateIssuesWithQuickFix(quickFixGroupables, filteredIssues)
	} else {
		updatedIssues = filteredIssues
	}

	remediationActions := c.remediationCodeActions(updatedIssues, path, folder.Path(), r)
	actions := converter.ToCodeActions(updatedIssues)
	actions = append(actions, remediationActions...)
	c.logger.Debug().Msg(fmt.Sprint("Returning ", len(actions), " code actions"))
	return actions
}

func (c *CodeActionsService) remediationCodeActions(issues []types.Issue, path types.FilePath, folderPath types.FilePath, r types.Range) []types.LSPCodeAction {
	if c.remediationProvider == nil {
		return nil
	}
	var actions []types.LSPCodeAction
	for i := range issues {
		issue := issues[i]
		findingId := issue.GetFindingId()
		if findingId == "" {
			continue
		}
		issueProduct := issue.GetProduct()

		// Capture loop variables for the closure.
		issueFindingId := findingId
		issueRange := r
		provider := c.remediationProvider
		deferredEdit := func(ctx context.Context) *types.WorkspaceEdit {
			edit, err := provider.Remediate(ctx, remediation.RemediationRequest{
				FindingId:   issueFindingId,
				FilePath:    path,
				ContentRoot: folderPath,
				Range:       issueRange,
				Product:     issueProduct,
			})
			if err != nil {
				c.logger.Error().Err(err).Str("findingId", issueFindingId).Msg("remediation provider returned error")
			}
			return edit
		}
		action, err := snyk.NewDeferredCodeAction(
			"Fix with Snyk Remediation Agent",
			&deferredEdit,
			nil,
			"",
			nil,
		)
		if err == nil {
			action.Kind = types.RemediationAgentQuickFix
			lspAction := converter.ToCodeAction(issue, &action)
			c.cacheCodeAction(&action, issue)
			actions = append(actions, lspAction)
		}
	}
	return actions
}

func (c *CodeActionsService) UpdateIssuesWithQuickFix(quickFixGroupables []types.Groupable, issues []types.Issue) []types.Issue {
	// we only allow one quickfix, so it needs to be grouped
	quickFix := c.getQuickFixAction(quickFixGroupables)
	if quickFix == nil {
		// If no quickfix action found, return issues unchanged
		return issues
	}

	// Get the original title from the action to avoid concatenation issues
	originalTitle := quickFix.GetOriginalTitle()

	fixable := len(quickFixGroupables)
	unfixable := len(issues) - fixable

	// Format the complete title using the original title, not concatenating to existing
	completeTitle := c.formatQuickFixTitle(originalTitle, fixable, unfixable)
	quickFix.SetTitle(completeTitle)

	updatedIssues := make([]types.Issue, 0, len(issues))
	for _, issue := range issues {
		groupedActions := append([]types.CodeAction{}, quickFix)

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

func (c *CodeActionsService) cacheCodeAction(action types.CodeAction, issue types.Issue) {
	if action.GetUuid() != nil {
		cached := cachedAction{
			issue:  issue,
			action: action,
		}
		c.actionsCacheMu.Lock()
		c.actionsCache[*action.GetUuid()] = cached
		c.actionsCacheMu.Unlock()
	}
}

// ResolveCodeAction resolves a cached code action by invoking its deferred edit
// and returning the resulting LSPCodeAction. The cache entry is kept alive for
// the duration of the edit so that a concurrent retry for the same UUID can
// still find it (e.g. a client that timed out and re-sent the request). The
// entry is always removed after the edit — even if the edit panics (the jrpc2
// handler recovers panics, keeping the process alive) — because the delete is
// registered as a deferred call before the edit runs.
//
// Concurrent resolves of the same UUID are not deduplicated at this layer: both
// callers may invoke the deferred edit independently. Providers must be safe for
// concurrent calls; the remy provider serializes per content-root.
func (c *CodeActionsService) ResolveCodeAction(ctx context.Context, action types.LSPCodeAction) (types.LSPCodeAction, error) {
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

	// Read under lock, then release before invoking the slow deferred edit.
	// The entry stays in the cache while the edit runs so that a concurrent
	// retry for the same UUID (e.g. a client that timed out and re-sent the
	// request) can still find it instead of receiving a hard "not found" error.
	c.actionsCacheMu.Lock()
	cached, found := c.actionsCache[key]
	c.actionsCacheMu.Unlock()

	if !found {
		return types.LSPCodeAction{}, errors.New(fmt.Sprint("could not find cached action for uuid ", key))
	}

	// Remove the cache entry once the edit is done, even if it panics.
	// Using defer guarantees cleanup on any exit path — normal return or panic.
	defer func() {
		c.actionsCacheMu.Lock()
		delete(c.actionsCache, key)
		c.actionsCacheMu.Unlock()
	}()

	// Invoke the deferred edit outside the lock. When DeferredEdit is nil the
	// action carries no edit (e.g. a command-only CodeAction); skip the call and
	// leave edit as nil so the resolved action is returned without an Edit field.
	var edit *types.WorkspaceEdit
	if de := cached.action.GetDeferredEdit(); de != nil {
		edit = (*de)(ctx)
	}

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

func (c *CodeActionsService) formatQuickFixTitle(originalTitle string, fixable, unfixable int) string {
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
