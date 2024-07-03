package codeaction

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/internal/lsp"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

type dirtyFilesWatcher interface {
	IsDirty(path sglsp.DocumentURI) bool
}

// CodeActionsService is an application-layer service for handling code actions.
type CodeActionsService struct {
	IssuesProvider snyk.IssueProvider

	// actionsCache holds all the issues that were returns by the GetCodeActions method.
	// This is used to resolve the code actions later on in ResolveCodeAction.
	actionsCache  map[uuid.UUID]cachedAction
	logger        zerolog.Logger
	fileWatcher   dirtyFilesWatcher
	notifier      noti.Notifier
	codeApiClient code.SnykCodeClient
}

type cachedAction struct {
	issue  snyk.Issue
	action snyk.CodeAction
}

func NewService(c *config.Config, provider snyk.IssueProvider, fileWatcher dirtyFilesWatcher, notifier noti.Notifier, codeApiClient code.SnykCodeClient) *CodeActionsService {
	return &CodeActionsService{
		IssuesProvider: provider,
		actionsCache:   make(map[uuid.UUID]cachedAction),
		logger:         c.Logger().With().Str("service", "CodeActionsService").Logger(),
		fileWatcher:    fileWatcher,
		notifier:       notifier,
		codeApiClient:  codeApiClient,
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
	issues := c.IssuesProvider.IssuesForRange(path, r)
	logMsg := fmt.Sprint("Found ", len(issues), " issues for path ", path, " and range ", r)
	c.logger.Info().Msg(logMsg)
	actions := converter.ToCodeActions(issues)

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

func (c *CodeActionsService) ResolveCodeAction(action lsp.CodeAction, server lsp.Server) (lsp.CodeAction, error) {
	c.logger.Info().Msg("Received code action resolve request")
	t := time.Now()

	if action.Command != nil {
		codeAction, err := c.handleCommand(action, server)
		return codeAction, err
	}

	if action.Data == nil {
		return lsp.CodeAction{}, missingKeyError{}
	}

	key := uuid.UUID(*action.Data)
	cached, found := c.actionsCache[key]
	// only delete cache entry after it's been resolved
	defer delete(c.actionsCache, key)
	if !found {
		return lsp.CodeAction{}, errors.New(fmt.Sprint("could not find cached action for uuid ", key))
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

func (c *CodeActionsService) handleCommand(action lsp.CodeAction, server lsp.Server) (lsp.CodeAction, error) {
	c.logger.Info().Str("method", "codeaction.handleCommand").Msgf("handling command %s", action.Command.Command)
	cmd := types.CommandData{
		Title:     action.Command.Title,
		CommandId: action.Command.Command,
		Arguments: action.Command.Arguments,
	}
	_, err := command.Service().ExecuteCommandData(context.Background(), cmd, server)
	if err != nil {
		return lsp.CodeAction{}, err
	}
	return lsp.CodeAction{}, nil
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
