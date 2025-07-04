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

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/handler"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/internal/types"
)

func executeCommandHandler(srv *jrpc2.Server) jrpc2.Handler {
	return handler.New(func(ctx context.Context, params sglsp.ExecuteCommandParams) (any, error) {
		c := config.CurrentConfig()
		method := "ExecuteCommandHandler"
		c.Logger().Debug().Str("method", method).Interface("command", params).Msg("RECEIVING")
		defer c.Logger().Debug().Str("method", method).Interface("command", params).Msg("SENDING")

		commandData := types.CommandData{CommandId: params.Command, Arguments: params.Arguments, Title: params.Command}

		// The context is passed from JRPC to the commands, if the server shuts down or receives a $/cancelRequest, the context will be canceled.
		// It is on the individual commands to decide if they want to use this context or create their own to not be canceled.
		result, err := command.Service().ExecuteCommandData(ctx, commandData, srv)
		logError(c.Logger(), err, fmt.Sprintf("Error executing command %v", commandData))
		return result, err
	})
}
