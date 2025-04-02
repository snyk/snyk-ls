/*
 * 2025 Snyk Limited
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

package mcp

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// Tool name constants to maintain backward compatibility
const (
	SnykScaTest    = "snyk_sca_test"
	SnykCodeTest   = "snyk_code_test"
	SnykVersion    = "snyk_version"
	SnykAuth       = "snyk_auth"
	SnykAuthStatus = "snyk_auth_status"
	SnykLogout     = "snyk_logout"
)

type SnykMcpToolsDefinition struct {
	Name           string                 `json:"name"`
	Description    string                 `json:"description"`
	Command        []string               `json:"command"`
	StandardParams []string               `json:"standardParams"`
	Params         []SnykMcpToolParameter `json:"params"`
}

type SnykMcpToolParameter struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	IsRequired  bool   `json:"isRequired"`
	Description string `json:"description"`
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
		default:
			m.mcpServer.AddTool(tool, m.defaultHandler(invocationCtx, toolDef))
		}
	}

	return nil
}

// runSnyk runs a Snyk command and returns the result
func (m *McpLLMBinding) runSnyk(ctx context.Context, invocationCtx workflow.InvocationContext, workingDir string, cmd []string) (string, error) {
	command := exec.CommandContext(ctx, cmd[0], cmd[1:]...)

	if workingDir != "" {
		command.Dir = workingDir
	}

	command.Stderr = invocationCtx.GetEnhancedLogger()
	res, err := command.Output()

	resAsString := string(res)
	if err != nil {
		m.logger.Err(err).Msg("Failed to execute command")
	}
	return resAsString, nil
}

// defaultHandler creates a generic handler for Snyk commands that applies standard parameters
func (m *McpLLMBinding) defaultHandler(invocationCtx workflow.InvocationContext, toolDef SnykMcpToolsDefinition) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		params, workingDir := extractParamsFromRequestArgs(toolDef, request.Params.Arguments)

		// Apply standard parameters from tool definition
		// e.g. all_projects and json
		for _, paramName := range toolDef.StandardParams {
			cliParamName := convertToCliParam(paramName)
			params[cliParamName] = true
		}

		// Handle regular commands
		if len(toolDef.Command) == 0 {
			return nil, fmt.Errorf("empty command in tool definition for %s", toolDef.Name)
		}

		args := buildArgs(m.cliPath, toolDef.Command, params)

		// Add working directory if specified
		if workingDir != "" {
			args = append(args, workingDir)
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
		// Special handling for logout which needs multiple commands
		params := []string{m.cliPath, "config", "unset", "INTERNAL_OAUTH_TOKEN_STORAGE"}
		_, _ = m.runSnyk(ctx, invocationCtx, "", params)

		params = []string{m.cliPath, "config", "unset", "token"}
		_, _ = m.runSnyk(ctx, invocationCtx, "", params)

		return mcp.NewToolResultText("Successfully logged out"), nil
	}
}
