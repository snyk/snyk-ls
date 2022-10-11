/*
 * Copyright 2022 Snyk Ltd.
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
	"runtime"

	macosClipboard "github.com/atotto/clipboard"
	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/handler"
	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"
	"golang.design/x/clipboard"

	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/notification"
)

func ExecuteCommandHandler(srv *jrpc2.Server) jrpc2.Handler {
	return handler.New(func(ctx context.Context, params sglsp.ExecuteCommandParams) (interface{}, error) {
		// The context provided by the JSON-RPC server is cancelled once a new message is being processed,
		// so we don't want to propagate it to functions that start background operations
		bgCtx := context.Background()

		method := "ExecuteCommandHandler"
		log.Info().Str("method", method).Interface("command", params).Msg("RECEIVING")
		defer log.Info().Str("method", method).Interface("command", params).Msg("SENDING")
		args := params.Arguments
		switch params.Command {
		case snyk.NavigateToRangeCommand:
			if len(args) < 2 {
				log.Warn().Str("method", method).Msg("received NavigateToRangeCommand without range")
			}
			navigateToLocation(srv, args)
		case snyk.WorkspaceScanCommand:
			workspace.Get().ClearIssues(bgCtx)
			workspace.Get().ScanWorkspace(bgCtx)
		case snyk.OpenBrowserCommand:
			command.OpenBrowser(params.Arguments[0].(string))
		case snyk.LoginCommand:
			authenticator := di.Authenticator()
			_, err := authenticator.Authenticate(context.Background())
			if err != nil {
				log.Err(err).Msg("Error on snyk.login command")
				notification.SendError(err)
			}
		case snyk.CopyAuthLinkCommand:
			var err error
			url := di.Authenticator().Provider().AuthURL(bgCtx)

			// We require two clipboard packages due to compatibility issues with OS [ROAD-1185]
			if runtime.GOOS == "darwin" {
				err = macosClipboard.WriteAll(url)
			} else {
				err = clipboard.Init()
				clipboard.Write(clipboard.FmtText, []byte(url))
			}

			if err != nil {
				log.Err(err).Msg("Error on snyk.copyAuthLink command")
				notification.SendError(err)
				break
			}
		case snyk.LogoutCommand:
			di.Authenticator().Logout(bgCtx)
		}
		return nil, nil
	})
}
