/*
 * © 2023-2024 Snyk Limited
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

package command

import (
	"context"
	"errors"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/rs/zerolog"

	"github.com/snyk/snyk-ls/application/config"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/types"
)

type executeMcpCallCommand struct {
	command  types.CommandData
	notifier noti.Notifier
	logger   *zerolog.Logger
	baseURL  string
}

func (cmd *executeMcpCallCommand) Command() types.CommandData {
	return cmd.command
}

func (cmd *executeMcpCallCommand) Execute(ctx context.Context) (any, error) {
	logger := cmd.logger.With().Str("method", "executeMcpCallCommand").Logger()
	if cmd.baseURL == "" {
		logger.Warn().Msg("No base URL set, cannot execute mcp command")
		return nil, nil
	}

	args := cmd.command.Arguments
	if len(args) < 1 {
		return nil, errors.New("invalid number of arguments (>0 expected)")
	}
	mcpCommand, ok := cmd.command.Arguments[0].(string)
	if !ok {
		return nil, errors.New("invalid argument type (string expected)")
	}

	clientEndpoint := cmd.baseURL + "/sse"
	mcpClient, err := client.NewSSEMCPClient(clientEndpoint)
	if err != nil {
		logger.Error().Err(err).Msg("Error creating mcp client")
		return nil, err
	}
	defer func(mcpClient *client.Client) {
		err = mcpClient.Close()
		if err != nil {
			logger.Error().Err(err).Msg("Error closing mcp client")
		}
	}(mcpClient)

	go func() {
		// start
		err = mcpClient.Start(context.Background())
		if err != nil {
			logger.Error().Err(err).Msg("Error starting mcp client")
			return
		}

		// initialize
		initRequest := mcp.InitializeRequest{}
		initRequest.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
		initRequest.Params.ClientInfo = mcp.Implementation{
			Name:    "snyk-lsp-mcp-bridge",
			Version: config.Version,
		}

		_, err = mcpClient.Initialize(ctx, initRequest)
		if err != nil {
			logger.Error().Err(err).Msg("Error initializing mcp client")
			return
		}

		callToolRequest := mcp.CallToolRequest{}
		callToolRequest.Params.Name = mcpCommand

		if len(args) > 1 {
			// currently undefined
			logger.Debug().Msg("got more than one argument, ignoring (this should not happen)")
		}

		logger.Debug().Msgf("Executing mcp command: %s", mcpCommand)
		_, err = mcpClient.CallTool(ctx, callToolRequest)
		if err != nil {
			logger.Error().Err(err).Msg("error executing tool request")
		}
	}()
	return nil, err
}
