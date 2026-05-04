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

package server

import (
	"context"
	"sync"
	"time"

	"github.com/snyk/snyk-ls/application/codeaction"
	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/internal/types"
)

type TextDocumentCodeActionHandler func(context.Context, types.CodeActionParams) ([]types.LSPCodeAction, error)
type ResolveHandler func(context.Context, types.LSPCodeAction) (*types.LSPCodeAction, error)

// ResolveCodeActionHandler returns a jrpc2.Handler that can be used to handle the "codeAction/resolve" LSP method
func ResolveCodeActionHandler(c *config.Config, service *codeaction.CodeActionsService, _ types.Server) ResolveHandler {
	logger := c.Logger().With().Str("method", "ResolveCodeActionHandler").Logger()
	return func(ctx context.Context, params types.LSPCodeAction) (*types.LSPCodeAction, error) {
		logger = logger.With().Interface("request", params).Logger()
		logger.Debug().Msg("RECEIVING")

		action, err := service.ResolveCodeAction(params)
		if err != nil {
			if codeaction.IsMissingKeyError(err) { // If the key is missing, it means that the code action is not a deferred code action
				logger.Debug().Msg("Skipping code action - missing key")
				return nil, nil
			}
			logger.Error().Err(err).Msg("unable to resolve code action")
			return nil, err
		}
		logger.Debug().Any("response", action).Msg("SENDING")
		return &action, nil
	}
}

// GetCodeActionHandler returns a jrpc2.Handler that can be used to handle the "textDocument/codeAction" LSP method
func GetCodeActionHandler(c *config.Config) TextDocumentCodeActionHandler {
	const debounceDuration = 50 * time.Millisecond

	// We share a mutex between all the handler calls to prevent concurrent runs.
	var mu = &sync.Mutex{}
	// This "field" is shared between the handlers to allow for cancellation of previous handler
	_, cancel := context.WithCancel(context.Background())
	logger := c.Logger().With().Str("method", "CodeActionHandler").Logger()

	return func(paramCtx context.Context, params types.CodeActionParams) ([]types.LSPCodeAction, error) {
		// We want to avoid concurrent runs of this handler to prevent race condition.
		var ctx context.Context
		mu.Lock()
		cancel()
		ctx, cancel = context.WithCancel(paramCtx)
		defer cancel()
		mu.Unlock()

		// This handler uses debouncing because it is called very often on mouse/caret moves.
		// The way debouncing is done is by waiting for a short period of time before actually running the handler.
		// If the handler is called again during that time, the context is canceled.
		select { // Wait debounce duration while listening to cancellations
		case <-ctx.Done():
			logger.Debug().Msg("Canceled textDocument/codeAction")
			return nil, nil
		case <-time.After(debounceDuration):
			logger.Debug().Any("request", params).Msg("RECEIVING")
		}

		// Get code actions
		mu.Lock()
		defer mu.Unlock()
		select { // Checking for cancellation again because it might have happened while waiting for the lock
		case <-ctx.Done():
			logger.Debug().Msg("Canceled textDocument/codeAction")
			return nil, nil
		default: // Continue execution if no cancellation happened
		}

		// Fetch & return the code actions
		codeActions := di.CodeActionService().GetCodeActions(params)
		logger.Debug().Any("response", codeActions).Msg("SENDING")
		return codeActions, nil
	}
}
