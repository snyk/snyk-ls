package codeaction

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/uri"
)

// IssuesProvider is an interface that allows to retrieve issues for a given path and range.
// This is used instead of any concrete dependency to allow for easier testing and more flexibility in implementation.
type issuesProvider interface {
	IssuesFor(path string, r snyk.Range) []snyk.Issue
}

type dirtyFilesWatcher interface {
	IsDirty(path sglsp.DocumentURI) bool
}

// CodeActionsService is an application-layer service for handling code actions.
type CodeActionsService struct {
	IssuesProvider issuesProvider

	// actionsCache holds all the issues that were returns by the GetCodeActions method.
	// This is used to resolve the code actions later on in ResolveCodeAction.
	actionsCache map[uuid.UUID]cachedAction
	logger       zerolog.Logger
	fileWatcher  dirtyFilesWatcher
}

type cachedAction struct {
	issue  snyk.Issue
	action snyk.CodeAction
}

func NewService(provider issuesProvider, fileWatcher dirtyFilesWatcher) *CodeActionsService {
	return &CodeActionsService{
		IssuesProvider: provider,
		actionsCache:   make(map[uuid.UUID]cachedAction),
		logger:         log.With().Str("service", "CodeActionsService").Logger(),
		fileWatcher:    fileWatcher,
	}
}

func (c *CodeActionsService) GetCodeActions(params lsp.CodeActionParams) []lsp.CodeAction {
	c.logger.Info().Msg("Received code action request")
	if c.fileWatcher.IsDirty(params.TextDocument.URI) {
		c.logger.Info().Msg("File is dirty, skipping code actions")
		return nil
	}
	path := uri.PathFromUri(params.TextDocument.URI)
	r := converter.FromRange(params.Range)
	issues := c.IssuesProvider.IssuesFor(path, r)
	logMsg := fmt.Sprint("Found ", len(issues), " issues for path ", path, " and range ", r)
	c.logger.Info().Msg(logMsg)
	actions := converter.ToCodeActions(issues)

	// The cache is cleared every time GetCodeActions is called, because the assumed workflow is:
	// 1. User gets multiple code action options for a given path/range via textDocument/codeAction
	// 2. User selects an action and the action is resolved via codeAction/resolve
	// So there is no reason to store issues for longer than that.
	for key := range c.actionsCache {
		delete(c.actionsCache, key)
	}
	for _, issue := range issues {
		for _, action := range issue.CodeActions {
			if action.Uuid != nil {
				cached := cachedAction{
					issue:  issue,
					action: action,
				}
				c.actionsCache[*action.Uuid] = cached
			}
		}
	}

	c.logger.Info().Msg(fmt.Sprint("Returning ", len(actions), " code actions"))
	return actions
}

func (c *CodeActionsService) ResolveCodeAction(action lsp.CodeAction) (lsp.CodeAction, error) {
	c.logger.Info().Msg("Received code action resolve request")
	t := time.Now()
	cached, found := c.actionsCache[uuid.UUID(*action.Data)]
	if !found {
		return lsp.CodeAction{}, errors.New(fmt.Sprint("could not find cached action for uuid ", *action.Data))
	}
	edit := (*cached.action.DeferredEdit)()
	resolvedAction := cached.action
	resolvedAction.Edit = edit
	elapsed := time.Since(t)
	elapsedSeconds := int(elapsed.Seconds())
	codeAction := converter.ToCodeAction(cached.issue, resolvedAction)

	c.logger.Info().Msg(fmt.Sprint("Resolved code action in ", elapsedSeconds, " seconds:\n", codeAction))
	return codeAction, nil
}
