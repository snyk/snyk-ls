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

	"github.com/rs/zerolog"

	"github.com/snyk/snyk-ls/application/codeaction"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/internal/types"
)

type TextDocumentCodeActionHandler func(context.Context, types.CodeActionParams) ([]types.LSPCodeAction, error)
type ResolveHandler func(context.Context, types.LSPCodeAction) (*types.LSPCodeAction, error)

// ResolveCodeActionHandler returns a jrpc2.Handler that can be used to handle the "codeAction/resolve" LSP method
func ResolveCodeActionHandler(logger *zerolog.Logger, service *codeaction.CodeActionsService, _ types.Server) ResolveHandler {
	l := logger.With().Str("method", "ResolveCodeActionHandler").Logger()
	return func(ctx context.Context, params types.LSPCodeAction) (*types.LSPCodeAction, error) {
		l = l.With().Interface("request", params).Logger()
		l.Debug().Msg("RECEIVING")

		action, err := service.ResolveCodeAction(params)
		if err != nil {
			if codeaction.IsMissingKeyError(err) {
				l.Debug().Msg("Skipping code action - missing key")
				return nil, nil
			}
			l.Error().Err(err).Msg("unable to resolve code action")
			return nil, err
		}
		l.Debug().Any("response", action).Msg("SENDING")
		return &action, nil
	}
}

// GetCodeActionHandler returns a jrpc2.Handler that can be used to handle the "textDocument/codeAction" LSP method
func GetCodeActionHandler(logger *zerolog.Logger) TextDocumentCodeActionHandler {
	const debounceDuration = 50 * time.Millisecond

	var mu = &sync.Mutex{}
	_, cancel := context.WithCancel(context.Background())
	l := logger.With().Str("method", "CodeActionHandler").Logger()

	return func(paramCtx context.Context, params types.CodeActionParams) ([]types.LSPCodeAction, error) {
		var ctx context.Context
		mu.Lock()
		cancel()
		ctx, cancel = context.WithCancel(paramCtx)
		defer cancel()
		mu.Unlock()

		select {
		case <-ctx.Done():
			l.Debug().Msg("Canceled textDocument/codeAction")
			return nil, nil
		case <-time.After(debounceDuration):
			l.Debug().Any("request", params).Msg("RECEIVING")
		}

		mu.Lock()
		defer mu.Unlock()
		select {
		case <-ctx.Done():
			l.Debug().Msg("Canceled textDocument/codeAction")
			return nil, nil
		default:
		}

		codeActions := di.CodeActionService().GetCodeActions(params)
		l.Debug().Any("response", codeActions).Msg("SENDING")
		return codeActions, nil
	}
}
