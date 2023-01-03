/*
 * © 2022 Snyk Limited All rights reserved.
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

	"github.com/atotto/clipboard"
	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/handler"
	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/notification"
)

func ExecuteCommandHandler(srv *jrpc2.Server) jrpc2.Handler {
	return handler.New(func(ctx context.Context, params sglsp.ExecuteCommandParams) (any, error) {
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
			w := workspace.Get()
			w.ClearIssues(bgCtx)
			w.ScanWorkspace(bgCtx)
			handleUntrustedFolders(bgCtx, srv)

		case snyk.WorkspaceFolderScanCommand:
			w := workspace.Get()
			if len(args) != 1 {
				log.Warn().Str("method", method).Msg("received WorkspaceFolderScanCommand without path")
				return nil, nil
			}
			path := args[0].(string)
			f := w.GetFolderContaining(path)
			if f == nil {
				log.Warn().Str("method", method).Msg("received WorkspaceFolderScanCommand with path not in workspace")
				log.Warn().Interface("folders", w.Folders())
				return nil, nil
			}
			f.ClearScannedStatus()
			f.ClearDiagnosticsFromPathRecursively(path)
			f.ScanFolder(bgCtx)
			handleUntrustedFolders(bgCtx, srv)
		case snyk.OpenBrowserCommand:
			command.OpenBrowser(params.Arguments[0].(string))
		case snyk.TrustWorkspaceFoldersCommand:
			err := TrustWorkspaceFolders()
			if err != nil {
				log.Err(err).Msgf("Error on %s command", snyk.TrustWorkspaceFoldersCommand)
				notification.SendError(err)
			}
		case snyk.LoginCommand:
			authenticator := di.Authenticator()
			_, err := authenticator.Authenticate(context.Background())
			if err != nil {
				log.Err(err).Msg("Error on snyk.login command")
				notification.SendError(err)
			}
		case snyk.CopyAuthLinkCommand:
			url := di.Authenticator().Provider().AuthURL(bgCtx)
			err := clipboard.WriteAll(url)

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

func TrustWorkspaceFolders() error {
	if !config.CurrentConfig().IsTrustedFolderFeatureEnabled() {
		return nil
	}

	trustedFolderPaths := config.CurrentConfig().TrustedFolders()
	_, untrusted := workspace.Get().GetFolderTrust()
	for _, folder := range untrusted {
		trustedFolderPaths = append(trustedFolderPaths, folder.Path())
	}

	config.CurrentConfig().SetTrustedFolders(trustedFolderPaths)
	notification.Send(lsp.SnykTrustedFoldersParams{TrustedFolders: trustedFolderPaths})
	return nil
}
