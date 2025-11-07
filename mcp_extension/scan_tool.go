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
	"os"
	"os/exec"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"

	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/infrastructure/analytics"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/mcp_extension/trust"
)

// Tool name constants to maintain backward compatibility
const (
	SnykScaTest         = "snyk_sca_scan"
	SnykCodeTest        = "snyk_code_scan"
	SnykVersion         = "snyk_version"
	SnykAuth            = "snyk_auth"
	SnykLogout          = "snyk_logout"
	SnykTrust           = "snyk_trust"
	SnykOpenLearnLesson = "snyk_open_learn_lesson"
	SnykSendFeedback    = "snyk_send_feedback"
)

type SnykMcpToolsDefinition struct {
	Name           string                 `json:"name"`
	Description    string                 `json:"description"`
	Command        []string               `json:"command"`
	StandardParams []string               `json:"standardParams"`
	IgnoreTrust    bool                   `json:"ignoreTrust"`
	IgnoreAuth     bool                   `json:"ignoreAuth"`
	OutputMapper   string                 `json:"outputMapper"`
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

var (
	outputMapperMap = map[string]func(logger *zerolog.Logger, result *EnhancedScanResult, learnService learn.Service, workDir string, includeIgnores bool){
		ScaOutputMapper:  extractSCAIssues,
		CodeOutputMapper: extractSASTIssues,
	}
)

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
		case SnykOpenLearnLesson:
			m.mcpServer.AddTool(tool, m.snykOpenLearnLessonHandler(invocationCtx, toolDef))
		case SnykSendFeedback:
			m.mcpServer.AddTool(tool, m.snykSendFeedback(invocationCtx, toolDef))
		case SnykAuth:
			m.mcpServer.AddTool(tool, m.snykAuthHandler(invocationCtx, toolDef))
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

	m.updateGafConfigWithIntegrationEnvironment(invocationCtx, clientInfo.Name, clientInfo.Version)

	integrationVersion := "unknown"
	runtimeInfo := invocationCtx.GetRuntimeInfo()
	if runtimeInfo != nil {
		integrationVersion = runtimeInfo.GetVersion()
	}

	command.Env = m.expandedEnv(invocationCtx, integrationVersion, clientInfo.Name, clientInfo.Version)

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
				logger.Err(err).Msg("Received CLI error running command")
				return resAsString, err
			}
		} else {
			logger.Err(err).Msg("Received error running command")
			return resAsString, err
		}
	}
	return resAsString, nil
}

// nolint: gocyclo, nolintlint // func is used for all scanners, will be refactored to use GAF WFs
// defaultHandler executes a command and enhances output for scan tools
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
		includeIgnores := false
		if param, exists := params["include-ignores"]; exists && toolDef.Name == SnykCodeTest {
			if value, parsable := param.value.(bool); value && parsable {
				includeIgnores = true
				// deleting the key to not include in the CLI run
				delete(params, "include-ignores")
			}
		}

		trustDisabled := invocationCtx.GetConfiguration().GetBool(trust.DisableTrustFlag) || toolDef.IgnoreTrust
		if !trustDisabled && !m.folderTrust.IsFolderTrusted(workingDir) {
			trustErr := fmt.Sprintf("Error: folder '%s' is not trusted. Please run 'snyk_trust' first", workingDir)
			logger.Error().Msg(trustErr)
			return mcp.NewToolResultText(trustErr), nil
		}

		if !toolDef.IgnoreAuth {
			user, whoAmiErr := authentication.CallWhoAmI(&logger, invocationCtx.GetEngine())
			if whoAmiErr != nil || user == nil {
				return mcp.NewToolResultText("User not authenticated. Please run 'snyk_auth' first"), nil
			}
		}

		if cmd, ok := params["command"]; ok && !verifyCommandArgument(cmd.value) {
			return mcp.NewToolResultText("Error: The provided binary name is invalid. Only use the `command` argument for python scanning and provide absolute path of python binary path."), nil
		}

		args := buildCommand(m.cliPath, toolDef.Command, params)

		// Add a working directory if specified
		if workingDir == "" {
			logger.Debug().Msg("Received empty workingDir")
		}

		// Run the command
		output, err := m.runSnyk(ctx, invocationCtx, workingDir, args)
		// we only return Err if we get exit code > 1 from CLI
		if err != nil {
			if output != "" {
				appUrl := invocationCtx.GetEngine().GetConfiguration().GetString(configuration.WEB_APP_URL)
				if strings.Contains(strings.ToLower(output), "snyk-code-0005") && toolDef.Name == SnykCodeTest {
					output += fmt.Sprintf("\nTo activate Snyk Code visit %s/manage/snyk-code?from=mcp or ask your administrator.", appUrl)
				}
				return mcp.NewToolResultText(fmt.Sprintf("Error: %s", output)), nil
			} else {
				return mcp.NewToolResultText(fmt.Sprintf("Error: %s", err.Error())), nil
			}
		}

		output = m.enhanceOutput(&logger, toolDef, output, err == nil, workingDir, includeIgnores)

		return mcp.NewToolResultText(output), nil
	}
}

// enhanceOutput enhances the scan output with structured issue data
func (m *McpLLMBinding) enhanceOutput(logger *zerolog.Logger, toolDef SnykMcpToolsDefinition, output string, success bool, workDir string, includeIgnores bool) string {
	return mapScanResponse(logger, toolDef, output, success, workDir, m.learnService, includeIgnores)
}

func (m *McpLLMBinding) snykAuthHandler(invocationCtx workflow.InvocationContext, toolDef SnykMcpToolsDefinition) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		logger := m.logger.With().Str("method", "snykAuthHandler").Logger()
		logger.Debug().Str("toolName", toolDef.Name).Msg("Received call for tool")

		engine := invocationCtx.GetEngine()
		globalConfig := engine.GetConfiguration()
		apiUrl := globalConfig.GetString(configuration.API_URL)

		user, err := authentication.CallWhoAmI(&logger, engine)
		if err == nil && user != nil {
			msg := getAuthMsg(globalConfig, user)
			return mcp.NewToolResultText(msg), nil
		}

		if err != nil && os.Getenv("SNYK_TOKEN") != "" {
			logger.Error().Msg("Auth tool can't be called if SNYK_TOKEN env var is set")
			return mcp.NewToolResultText("Authentication aborted. Auth tool can't be called if SNYK_TOKEN env var is set"), nil
		}

		logger.Info().Msgf("Starting authentication process. API Endpoint: %s", apiUrl)

		conf := invocationCtx.GetConfiguration()
		conf.Set(localworkflows.AuthTypeParameter, auth.AUTH_TYPE_OAUTH)

		_, err = engine.InvokeWithConfig(localworkflows.WORKFLOWID_AUTH, conf)

		if err != nil {
			return mcp.NewToolResultText("Authentication failed"), nil
		}

		return mcp.NewToolResultText("Successfully logged in"), nil
	}
}

func (m *McpLLMBinding) snykLogoutHandler(invocationCtx workflow.InvocationContext, toolDef SnykMcpToolsDefinition) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		logger := m.logger.With().Str("method", "snykLogoutHandler").Logger()
		logger.Debug().Str("toolName", toolDef.Name).Msg("Received call for tool")
		configs := []configuration.Configuration{invocationCtx.GetConfiguration(), invocationCtx.GetEngine().GetConfiguration()}
		for _, config := range configs {
			config.ClearCache()
			config.Unset(configuration.AUTHENTICATION_TOKEN)
			config.Unset(auth.CONFIG_KEY_OAUTH_TOKEN)
		}

		return mcp.NewToolResultText("Successfully logged out"), nil
	}
}

func (m *McpLLMBinding) snykSendFeedback(invocationCtx workflow.InvocationContext, toolDef SnykMcpToolsDefinition) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		logger := m.logger.With().Str("method", toolDef.Name).Logger()
		logger.Debug().Str("toolName", toolDef.Name).Msg("Received call for tool")

		preventedCountStr := request.GetArguments()["preventedIssuesCount"]
		remediatedCountStr := request.GetArguments()["fixedExistingIssuesCount"]

		preventedCount, ok := preventedCountStr.(float64)
		if !ok {
			return nil, fmt.Errorf("invalid argument preventedIssuesCount")
		}
		remediatedCount, ok := remediatedCountStr.(float64)
		if !ok {
			return nil, fmt.Errorf("invalid argument fixedExistingIssuesCount")
		}
		pathArg := request.GetArguments()["path"]
		if pathArg == nil {
			return nil, fmt.Errorf("argument 'path' is missing for tool %s", toolDef.Name)
		}
		path, ok := pathArg.(string)
		if !ok {
			return nil, fmt.Errorf("argument 'path' is not a string for tool %s", toolDef.Name)
		}
		if path == "" {
			return nil, fmt.Errorf("empty path given to tool %s", toolDef.Name)
		}

		if preventedCount == 0 && remediatedCount == 0 {
			return mcp.NewToolResultText("No issues to send feedback for"), nil
		}

		clientInfo := ClientInfoFromContext(ctx)

		m.updateGafConfigWithIntegrationEnvironment(invocationCtx, clientInfo.Name, clientInfo.Version)
		event := analytics.NewAnalyticsEventParam("Send feedback", nil, types.FilePath(path))

		event.Extension = map[string]any{
			"mcp::preventedIssuesCount":  int(preventedCount),
			"mcp::remediatedIssuesCount": int(remediatedCount),
		}
		// MCP doesn't have the concept of folder orgs, so just use org from GAF config
		org := invocationCtx.GetConfiguration().GetString(configuration.ORGANIZATION)
		go analytics.SendAnalytics(invocationCtx.GetEngine(), "", org, event, nil)

		return mcp.NewToolResultText("Successfully sent feedback"), nil
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

		if m.folderTrust.IsFolderTrusted(folderPath) {
			msg := fmt.Sprintf("Folder '%s' is already trusted", folderPath)
			logger.Info().Msg(msg)
			return mcp.NewToolResultText(msg), nil
		}

		return m.folderTrust.HandleTrust(ctx, folderPath, logger)
	}
}

func getAuthMsg(config configuration.Configuration, activeUser *authentication.ActiveUser) string {
	user := activeUser.UserName
	if activeUser.Name != "" {
		user = activeUser.Name
	}

	apiUrl := config.GetString(configuration.API_URL)
	org := config.GetString(configuration.ORGANIZATION)
	return fmt.Sprintf("Already Authenticated. User: %s Using API Endpoint: %s and Org: %s", user, apiUrl, org)
}
