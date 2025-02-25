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
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/types"
)

type executeMcpCallCommand struct {
	command     types.CommandData
	authService authentication.AuthenticationService
	notifier    noti.Notifier
	logger      *zerolog.Logger
	baseURL     string
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
	clientEndpoint := cmd.baseURL + "/sse"

	if len(cmd.command.Arguments) != 1 {
		return nil, errors.New("invalid number of arguments (1 expected)")
	}

	mcpCommand, ok := cmd.command.Arguments[0].(string)
	if !ok {
		return nil, errors.New("invalid argument type (string expected)")
	}

	mcpClient, err := client.NewSSEMCPClient(clientEndpoint)
	if err != nil {
		logger.Error().Err(err).Msg("Error creating mcp client")
		return nil, err
	}
	defer func(mcpClient *client.SSEMCPClient) {
		err = mcpClient.Close()
		if err != nil {
			logger.Error().Err(err).Msg("Error closing mcp client")
		}
	}(mcpClient)

	// start
	err = mcpClient.Start(context.Background())
	if err != nil {
		logger.Error().Err(err).Msg("Error starting mcp client")
		return nil, err
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
		return nil, err
	}

	callToolRequest := mcp.CallToolRequest{}
	callToolRequest.Params.Name = mcpCommand

	logger.Debug().Msgf("Executing mcp command: %s", mcpCommand)
	result, err := mcpClient.CallTool(ctx, callToolRequest)
	return result, err
}
