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
	"fmt"

	"github.com/atotto/clipboard"
	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/handler"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/notification"
)

func executeCommandHandler(srv *jrpc2.Server) jrpc2.Handler {
	return handler.New(func(ctx context.Context, params sglsp.ExecuteCommandParams) (any, error) {
		// The context provided by the JSON-RPC server is cancelled once a new message is being processed,
		// so we don't want to propagate it to functions that start background operations
		bgCtx := context.Background()

		method := "ExecuteCommandHandler"
		log.Info().Str("method", method).Interface("command", params).Msg("RECEIVING")
		defer log.Info().Str("method", method).Interface("command", params).Msg("SENDING")
		commandData := snyk.CommandData{CommandId: params.Command, Arguments: params.Arguments, Title: params.Command}
		cmd, err := command.CreateFromCommandData(commandData, srv)
		// TODO enable after migrating all commands
		//if err != nil {
		//	log.Error().Err(err).Str("method", method).Msg("failed to create command")
		//	return nil, err
		//}
		if err == nil {
			err = di.CommandService().ExecuteCommand(bgCtx, cmd)
			if err == nil {
				return nil, nil //return nil, err
			}
			logError(errors.Wrap(err, fmt.Sprintf("Error executing command %v", commandData)), method)
			return nil, err
		}

		// fallback path starts here
		switch params.Command {
		case snyk.CopyAuthLinkCommand:
			url := di.AuthenticationService().Provider().AuthURL(bgCtx)
			err := clipboard.WriteAll(url)

			if err != nil {
				log.Err(err).Msg("Error on snyk.copyAuthLink command")
				notification.SendError(err)
				break
			}
		case snyk.LogoutCommand:
			di.AuthenticationService().Logout(bgCtx)
		}
		return nil, nil
	})
}
