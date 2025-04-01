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
	"strings"

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

type SnykToolDefinition struct {
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Command     string              `json:"command"`
	Params      []SnykToolParameter `json:"params"`
}

type SnykToolParameter struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	IsRequired  bool   `json:"isRequired"`
	Description string `json:"description"`
}

//go:embed snyk_tools.json
var snykToolsJson string

type SnykToolsConfig struct {
	Tools []SnykToolDefinition `json:"tools"`
}

func getSnykToolsConfig() (*SnykToolsConfig, error) {
	var config SnykToolsConfig
	if err := json.Unmarshal([]byte(snykToolsJson), &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

// createToolFromDefinition creates an MCP tool from a Snyk tool definition
func createToolFromDefinition(toolDef *SnykToolDefinition) mcp.Tool {
	opts := []mcp.ToolOption{mcp.WithDescription(toolDef.Description)}
	for _, param := range toolDef.Params {
		if param.Type == "string" {
			if param.IsRequired {
				opts = append(opts, mcp.WithString(param.Name, mcp.Required(), mcp.Description(param.Description)))
			} else {
				opts = append(opts, mcp.WithString(param.Name, mcp.Description(param.Description)))
			}
		} else if param.Type == "boolean" {
			if param.IsRequired {
				opts = append(opts, mcp.WithBoolean(param.Name, mcp.Required(), mcp.Description(param.Description)))
			} else {
				opts = append(opts, mcp.WithBoolean(param.Name, mcp.Description(param.Description)))
			}
		}
	}

	return mcp.NewTool(toolDef.Name, opts...)
}

// extractParamsFromRequestArgs extracts parameters from the arguments based on the tool definition
func extractParamsFromRequestArgs(toolDef SnykToolDefinition, arguments map[string]interface{}) (map[string]interface{}, string) {
	params := make(map[string]interface{})
	var workingDir string

	for _, paramDef := range toolDef.Params {
		val, ok := arguments[paramDef.Name]
		if !ok {
			continue
		}

		// Store path separately to use as working directory
		if paramDef.Name == "path" {
			if pathStr, ok := val.(string); ok {
				workingDir = pathStr
			}
		}

		// Convert parameter name from snake_case to kebab-case for CLI arguments
		cliParamName := strings.ReplaceAll(paramDef.Name, "_", "-")

		// Cast the value based on parameter type
		if paramDef.Type == "string" {
			if strVal, ok := val.(string); ok && strVal != "" {
				params[cliParamName] = strVal
			}
		} else if paramDef.Type == "boolean" {
			if boolVal, ok := val.(bool); ok && boolVal {
				params[cliParamName] = true
			}
		}
	}

	return params, workingDir
}

func (m *McpLLMBinding) addSnykTools(invocationCtx workflow.InvocationContext) error {
	config, err := getSnykToolsConfig()
	if err != nil || config == nil {
		m.logger.Err(err).Msg("Failed to load Snyk tools configuration")
		return err
	}

	for _, toolDef := range config.Tools {
		tool := createToolFromDefinition(&toolDef)
		switch toolDef.Name {
		case SnykScaTest:
			m.mcpServer.AddTool(tool, m.snykTestHandler(invocationCtx, toolDef))
		case SnykCodeTest:
			m.mcpServer.AddTool(tool, m.snykCodeTestHandler(invocationCtx, toolDef))
		case SnykVersion:
			m.mcpServer.AddTool(tool, m.snykVersionHandler(invocationCtx, toolDef))
		case SnykAuth:
			m.mcpServer.AddTool(tool, m.snykAuthHandler(invocationCtx, toolDef))
		case SnykAuthStatus:
			m.mcpServer.AddTool(tool, m.snykAuthStatusHandler(invocationCtx, toolDef))
		case SnykLogout:
			m.mcpServer.AddTool(tool, m.snykLogoutHandler(invocationCtx, toolDef))
		default:
			m.logger.Error().Str("tool", toolDef.Name).Msg("Unknown tool name, skipping")
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

// Handler implementations for each Snyk tool
func (m *McpLLMBinding) snykTestHandler(invocationCtx workflow.InvocationContext, toolDef SnykToolDefinition) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Extract parameters based on tool definition
		params, workingDir := extractParamsFromRequestArgs(toolDef, request.Params.Arguments)

		// Add default values for SCA test
		params["all-projects"] = true
		params["json"] = true

		// Build args and run command
		args := buildArgs(m.cliPath, "test", params)
		if workingDir != "" {
			args = append(args, workingDir)
		}

		output, err := m.runSnyk(ctx, invocationCtx, workingDir, args)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResultText(output), nil
	}
}

func (m *McpLLMBinding) snykVersionHandler(invocationCtx workflow.InvocationContext, _ SnykToolDefinition) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// For simple commands without parameters, we can directly execute
		params := []string{m.cliPath, "--version"}
		output, err := m.runSnyk(ctx, invocationCtx, "", params)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResultText(output), nil
	}
}

func (m *McpLLMBinding) snykAuthHandler(invocationCtx workflow.InvocationContext, _ SnykToolDefinition) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Auth command doesn't need parameters from the JSON
		params := []string{m.cliPath, "auth"}
		_, err := m.runSnyk(ctx, invocationCtx, "", params)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResultText("Authenticated Successfully"), nil
	}
}

func (m *McpLLMBinding) snykAuthStatusHandler(invocationCtx workflow.InvocationContext, _ SnykToolDefinition) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Hardcoded whoami command
		params := []string{m.cliPath, "whoami", "--experimental"}
		output, err := m.runSnyk(ctx, invocationCtx, "", params)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResultText(output), nil
	}
}

func (m *McpLLMBinding) snykLogoutHandler(invocationCtx workflow.InvocationContext, _ SnykToolDefinition) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Special handling for logout which needs multiple commands
		params := []string{m.cliPath, "config", "unset", "INTERNAL_OAUTH_TOKEN_STORAGE"}
		_, _ = m.runSnyk(ctx, invocationCtx, "", params)

		params = []string{m.cliPath, "config", "unset", "token"}
		_, _ = m.runSnyk(ctx, invocationCtx, "", params)

		return mcp.NewToolResultText("Successfully logged out"), nil
	}
}

func (m *McpLLMBinding) snykCodeTestHandler(invocationCtx workflow.InvocationContext, toolDef SnykToolDefinition) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		params, workingDir := extractParamsFromRequestArgs(toolDef, request.Params.Arguments)

		params["json"] = true

		args := buildArgs(m.cliPath, "code", params)
		args = append(args, "test")

		// Add working directory if specified
		if workingDir != "" {
			args = append(args, workingDir)
		}

		output, err := m.runSnyk(ctx, invocationCtx, workingDir, args)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResultText(output), nil
	}
}
