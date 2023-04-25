package codeaction

import (
	"context"
	"sync"
	"time"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/internal/lsp"
)

type TextDocumentCodeActionHandler func(context.Context, lsp.CodeActionParams) ([]lsp.CodeAction, error)
type ResolveHandler func(context.Context, lsp.CodeAction) (*lsp.CodeAction, error)

// ResolveCodeActionHandler returns a jrpc2.Handler that can be used to handle the "codeAction/resolve" LSP method
func ResolveCodeActionHandler(
	c *config.Config,
	service *CodeActionsService,
	server lsp.Server,
	authenticationService snyk.AuthenticationService,
	learnService learn.Service,
) ResolveHandler {
	logger := c.Logger().With().Str("method", "ResolveCodeActionHandler").Logger()
	return func(ctx context.Context, params lsp.CodeAction) (*lsp.CodeAction, error) {
		logger := logger.With().Interface("request", params).Logger()
		logger.Info().Msg("RECEIVING")

		action, err := service.ResolveCodeAction(params, server, authenticationService, learnService)
		if err != nil {
			if IsMissingKeyError(err) { // If the key is missing, it means that the code action is not a deferred code action
				logger.Debug().Msg("Skipping code action - missing key")
				return nil, nil
			}
			logger.Error().Err(err).Msg("Failed to resolve code action")
			return nil, err
		}
		logger.Info().Any("response", action).Msg("SENDING")
		return &action, nil
	}
}

// GetCodeActionHandler returns a jrpc2.Handler that can be used to handle the "textDocument/codeAction" LSP method
func GetCodeActionHandler(c *config.Config, service *CodeActionsService) TextDocumentCodeActionHandler {
	const debounceDuration = 50 * time.Millisecond

	// We share a mutex between all the handler calls to prevent concurrent runs.
	var mu = &sync.Mutex{}
	// This "field" is shared between the handlers to allow for cancellation of previous handler
	_, cancel := context.WithCancel(context.Background())
	logger := c.Logger().With().Str("method", "CodeActionHandler").Logger()

	return func(paramCtx context.Context, params lsp.CodeActionParams) ([]lsp.CodeAction, error) {
		// We want to avoid concurrent runs of this handler to prevent race condition.
		var ctx context.Context
		mu.Lock()
		cancel()
		ctx, cancel = context.WithCancel(paramCtx)
		defer cancel()
		mu.Unlock()

		// This handler uses debouncing because it is called very often on mouse/caret moves.
		// The way debouncing is done is by waiting for a short period of time before actually running the handler.
		// If the handler is called again during that time, the context is cancelled.
		select { // Wait debounce duration while listening to cancellations
		case <-ctx.Done():
			logger.Debug().Msg("Cancelled textDocument/codeAction")
			return nil, nil
		case <-time.After(debounceDuration):
			logger.Info().Any("request", params).Msg("RECEIVING")
		}

		// Get code actions
		mu.Lock()
		defer mu.Unlock()
		select { // Checking for cancellation again because it might have happened while waiting for the lock
		case <-ctx.Done():
			logger.Debug().Msg("Cancelled textDocument/codeAction")
			return nil, nil
		default: // Continue execution if no cancellation happened
		}

		// Fetch & return the code actions
		codeActions := service.GetCodeActions(params)
		logger.Info().Any("response", codeActions).Msg("SENDING")
		return codeActions, nil
	}
}
