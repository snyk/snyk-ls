package codeaction

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/server/lsp"
)

type TextDocumentCodeActionHandler func(context.Context, lsp.CodeActionParams) ([]lsp.CodeAction, error)
type CodeActionResolveHandler func(context.Context, lsp.CodeAction) (*lsp.CodeAction, error)

// ResolveCodeActionHandler returns a jrpc2.Handler that can be used to handle the "codeAction/resolve" LSP method
func ResolveCodeActionHandler(service *CodeActionsService) CodeActionResolveHandler {
	logger := log.Logger.With().Str("method", "ResolveCodeActionHandler").Logger()

	return func(ctx context.Context, params lsp.CodeAction) (*lsp.CodeAction, error) {
		logger := logger.With().Interface("request", params).Logger()
		logger.Info().Msg("RECEIVING")

		action, err := service.ResolveCodeAction(params)
		if err != nil {
			logger.Error().Err(err).Msg("Failed to resolve code action")
			return nil, err
		}
		logger.Info().Any("response", action).Msg("SENDING")
		return &action, nil
	}
}

// GetCodeActionHandler returns a jrpc2.Handler that can be used to handle the "textDocument/codeAction" LSP method
func GetCodeActionHandler(service *CodeActionsService) TextDocumentCodeActionHandler {
	const debounceDuration = 50 * time.Millisecond

	// We share a mutex between all the handler calls to prevent concurrent runs.
	var mu = &sync.Mutex{}
	// This "field" is shared between the handlers to allow for cancellation of previous handler
	_, cancel := context.WithCancel(context.Background())
	logger := log.Logger.With().Str("method", "CodeActionHandler").Logger()

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
