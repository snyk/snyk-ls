/*
 * © 2025 Snyk Limited
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

package mcp_extension

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/mcp_extension/trust"
)

// Tool name constants to maintain backward compatibility
const (
	SnykScaTest    = "snyk_sca_scan"
	SnykCodeTest   = "snyk_code_scan"
	SnykVersion    = "snyk_version"
	SnykAuth       = "snyk_auth"
	SnykAuthStatus = "snyk_auth_status"
	SnykLogout     = "snyk_logout"
	SnykTrust      = "snyk_trust"
)

type SnykMcpToolsDefinition struct {
	Name           string                 `json:"name"`
	Description    string                 `json:"description"`
	Command        []string               `json:"command"`
	StandardParams []string               `json:"standardParams"`
	IgnoreTrust    bool                   `json:"ignoreTrust"`
	Params         []SnykMcpToolParameter `json:"params"`
}

type SnykMcpToolParameter struct {
	Name             string   `json:"name"`
	Type             string   `json:"type"`
	IsRequired       bool     `json:"isRequired"`
	Description      string   `json:"description"`
	SupersedesParams []string `json:"supersedesParams"`
	IsPositional     bool     `json:"isPositional"`
	Position         int      `json:"position"`
}

//go:embed snyk_tools.json
var snykToolsJson string

type SnykMcpTools struct {
	Tools []SnykMcpToolsDefinition `json:"tools"`
}

func loadMcpToolsFromJson() (*SnykMcpTools, error) {
	var config SnykMcpTools
	if err := json.Unmarshal([]byte(snykToolsJson), &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

func (m *McpLLMBinding) addSnykTools(invocationCtx workflow.InvocationContext) error {
	config, err := loadMcpToolsFromJson()

	if err != nil || config == nil {
		m.logger.Err(err).Msg("Failed to load Snyk tools configuration")
		return err
	}

	for _, toolDef := range config.Tools {
		tool := createToolFromDefinition(&toolDef)
		switch toolDef.Name {
		case SnykLogout:
			m.mcpServer.AddTool(tool, m.snykLogoutHandler(invocationCtx, toolDef))
		case SnykTrust:
			m.mcpServer.AddTool(tool, m.snykTrustHandler(invocationCtx, toolDef))
		default:
			m.mcpServer.AddTool(tool, m.defaultHandler(invocationCtx, toolDef))
		}
	}

	return nil
}

// runSnyk runs a Snyk command and returns the result
func (m *McpLLMBinding) runSnyk(ctx context.Context, invocationCtx workflow.InvocationContext, workingDir string, cmd []string) (string, error) {
	logger := m.logger.With().Str("method", "runSnyk").Logger()
	clientInfo := ClientInfoFromContext(ctx)
	logger.Debug().Str("clientName", clientInfo.Name).Str("clientVersion", clientInfo.Version).Msg("Found client info")

	command := exec.CommandContext(ctx, cmd[0], cmd[1:]...)

	if workingDir != "" {
		command.Dir = workingDir
	}
	runtimeInfo := invocationCtx.GetRuntimeInfo()
	if runtimeInfo != nil {
		command.Env = m.expandedEnv(runtimeInfo.GetVersion(), clientInfo.Name, clientInfo.Version)
	} else {
		command.Env = m.expandedEnv("unknown", clientInfo.Name, clientInfo.Version)
	}
	logger.Debug().Strs("args", command.Args).Str("workingDir", command.Dir).Msg("Running Command with")
	logger.Trace().Strs("env", command.Env).Msg("Environment")

	command.Stderr = logger
	res, err := command.Output()
	resAsString := string(res)

	logger.Debug().Str("result", resAsString).Msg("Command run result")

	if err != nil {
		var errorType *exec.ExitError
		if errors.As(err, &errorType) {
			if errorType.ExitCode() > 1 {
				// Exit code > 1 means CLI run didn't work
				logger.Err(err).Msg("Received error running command")
			}
		} else {
			logger.Err(err).Msg("Received error running command")
		}
	}
	return resAsString, nil
}

// defaultHandler creates a generic handler for Snyk commands that applies standard parameters
func (m *McpLLMBinding) defaultHandler(invocationCtx workflow.InvocationContext, toolDef SnykMcpToolsDefinition) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		logger := m.logger.With().Str("method", "defaultHandler").Logger()
		logger.Debug().Str("toolName", toolDef.Name).Msg("Received call for tool")
		if len(toolDef.Command) == 0 {
			return nil, fmt.Errorf("empty command in tool definition for %s", toolDef.Name)
		}

		requestArgs := request.GetArguments()
		params, workingDir, err := prepareCmdArgsForTool(m.logger, toolDef, requestArgs)
		if err != nil {
			return nil, err
		}

		trustDisabled := invocationCtx.GetConfiguration().GetBool(trust.DisableTrustFlag) || toolDef.IgnoreTrust
		if !trustDisabled && !m.folderTrust.IsFolderTrusted(workingDir) {
			trustErr := fmt.Sprintf("folder '%s' is not trusted. Please run 'snyk_trust' first", workingDir)
			logger.Error().Msg(trustErr)
			return mcp.NewToolResultText(trustErr), nil
		}

		args := buildCommand(m.cliPath, toolDef.Command, params)

		// Add working directory if specified
		if workingDir == "" {
			logger.Debug().Msg("Received empty workingDir")
		}

		// Run the command
		output, err := m.runSnyk(ctx, invocationCtx, workingDir, args)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResultText(output), nil
	}
}

func (m *McpLLMBinding) snykLogoutHandler(invocationCtx workflow.InvocationContext, _ SnykMcpToolsDefinition) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		logger := m.logger.With().Str("method", "snykLogoutHandler").Logger()
		logger.Debug().Str("toolName", "snyk_logout").Msg("Received call for tool")
		// Special handling for logout which needs multiple commands
		params := []string{m.cliPath, "config", "unset", "INTERNAL_OAUTH_TOKEN_STORAGE"}
		_, _ = m.runSnyk(ctx, invocationCtx, "", params)

		params = []string{m.cliPath, "config", "unset", "token"}
		_, _ = m.runSnyk(ctx, invocationCtx, "", params)

		return mcp.NewToolResultText("Successfully logged out"), nil
	}
}

func (m *McpLLMBinding) snykTrustHandler(invocationCtx workflow.InvocationContext, toolDef SnykMcpToolsDefinition) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		logger := m.logger.With().Str("method", toolDef.Name).Logger()
		logger.Debug().Str("toolName", toolDef.Name).Msg("Received call for tool")

		if invocationCtx.GetConfiguration().GetBool(trust.DisableTrustFlag) {
			logger.Info().Msg("Folder trust is disabled. Trust mechanism is ignored")
			return mcp.NewToolResultText("Trust mechanism is disabled. Considering Folder to be trusted."), nil
		}

		pathArg := request.GetArguments()["path"]
		if pathArg == nil {
			return nil, fmt.Errorf("argument 'path' is missing for tool %s", toolDef.Name)
		}
		folderPath, ok := pathArg.(string)
		if !ok {
			return nil, fmt.Errorf("argument 'path' is not a string for tool %s", toolDef.Name)
		}
		if folderPath == "" {
			return nil, fmt.Errorf("empty path given to tool %s", toolDef.Name)
		}

		return m.folderTrust.HandleTrust(ctx, folderPath, logger)
	}
}
