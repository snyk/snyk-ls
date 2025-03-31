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
	"encoding/json"
	"os/exec"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	SnykTest          = "snyk_test"
	SnykVersion       = "snyk_version"
	SnykMonitor       = "snyk_monitor"
	SnykAuth          = "snyk_auth"
	SnykAuthStatus    = "snyk_auth_status"
	SnykLogout        = "snyk_logout"
	SnykCodeTest      = "snyk_code_test"
	SnykContainerTest = "snyk_container_test"
	SnykIacTest       = "snyk_iac_test"
	SnykFix           = "snyk_fix"
	SnykIgnore        = "snyk_ignore"
	SnykSbom          = "snyk_sbom"
)

func (m *McpLLMBinding) addSnykTools(invocationCtx workflow.InvocationContext) error {
	// Add snyk_test tool
	testTool := mcp.NewTool(SnykTest,
		mcp.WithDescription("Run Snyk security tests on code"),
		mcp.WithString("path",
			mcp.Description("Path to test (default: current directory)"),
		),
		mcp.WithBoolean("all_projects",
			mcp.Description("Scan all projects in the directory"),
		),
		mcp.WithBoolean("json_output",
			mcp.Description("Output results in JSON format"),
		),
		mcp.WithString("severity_threshold",
			mcp.Description("Only report vulnerabilities of provided level or higher"),
		),
	)
	m.mcpServer.AddTool(testTool, m.snykTestHandler(invocationCtx))

	// Add snyk_version tool
	versionTool := mcp.NewTool(SnykVersion,
		mcp.WithDescription("Get Snyk CLI version"),
	)
	m.mcpServer.AddTool(versionTool, m.snykVersionHandler(invocationCtx))

	// Add snyk_monitor tool
	monitorTool := mcp.NewTool(SnykMonitor,
		mcp.WithDescription("Monitor project for vulnerabilities"),
		mcp.WithString("path",
			mcp.Description("Path to monitor (default: current directory)"),
		),
		mcp.WithBoolean("all_projects",
			mcp.Description("Monitor all projects in the directory"),
		),
		mcp.WithString("org",
			mcp.Description("Specify organization to monitor under"),
		),
	)
	m.mcpServer.AddTool(monitorTool, m.snykMonitorHandler(invocationCtx))

	// Add snyk_auth tool
	authTool := mcp.NewTool(SnykAuth,
		mcp.WithDescription("Authenticate with Snyk using API token"),
	)
	m.mcpServer.AddTool(authTool, m.snykAuthHandler(invocationCtx))

	// Add snyk_auth_status tool
	authStatusTool := mcp.NewTool(SnykAuthStatus,
		mcp.WithDescription("Check Snyk authentication status"),
	)
	m.mcpServer.AddTool(authStatusTool, m.snykAuthStatusHandler(invocationCtx))

	// Add snyk_logout tool
	logoutTool := mcp.NewTool(SnykLogout,
		mcp.WithDescription("Log out from Snyk"),
	)
	m.mcpServer.AddTool(logoutTool, m.snykLogoutHandler(invocationCtx))

	// Add snyk_code_test tool
	codeTestTool := mcp.NewTool(SnykCodeTest,
		mcp.WithDescription("Run Snyk code analysis"),
		mcp.WithString("path",
			mcp.Description("Path to test (default: current directory)"),
		),
		mcp.WithBoolean("json_output",
			mcp.Description("Output results in JSON format"),
		),
	)
	m.mcpServer.AddTool(codeTestTool, m.snykCodeTestHandler(invocationCtx))

	// Add snyk_container_test tool
	containerTestTool := mcp.NewTool(SnykContainerTest,
		mcp.WithDescription("Test container image for vulnerabilities"),
		mcp.WithString("image",
			mcp.Required(),
			mcp.Description("Name of the container image to test"),
		),
		mcp.WithBoolean("json_output",
			mcp.Description("Output results in JSON format"),
		),
		mcp.WithString("file",
			mcp.Description("Path to Dockerfile"),
		),
	)
	m.mcpServer.AddTool(containerTestTool, m.snykContainerTestHandler(invocationCtx))

	// Add snyk_iac_test tool
	iacTestTool := mcp.NewTool(SnykIacTest,
		mcp.WithDescription("Test Infrastructure as Code files"),
		mcp.WithString("path",
			mcp.Description("Path to test (default: current directory)"),
		),
		mcp.WithBoolean("json_output",
			mcp.Description("Output results in JSON format"),
		),
	)
	m.mcpServer.AddTool(iacTestTool, m.snykIacTestHandler(invocationCtx))

	// Add snyk_fix tool
	fixTool := mcp.NewTool(SnykFix,
		mcp.WithDescription("Fix vulnerabilities in project"),
		mcp.WithString("path",
			mcp.Description("Path to fix (default: current directory)"),
		),
		mcp.WithBoolean("all_projects",
			mcp.Description("Fix all projects in the directory"),
		),
		mcp.WithBoolean("dry_run",
			mcp.Description("Don't make any changes, just show what would be done"),
		),
	)
	m.mcpServer.AddTool(fixTool, m.snykFixHandler(invocationCtx))

	// Add snyk_ignore tool
	ignoreTool := mcp.NewTool(SnykIgnore,
		mcp.WithDescription("Ignore a vulnerability"),
		mcp.WithString("id",
			mcp.Required(),
			mcp.Description("ID of the vulnerability to ignore"),
		),
		mcp.WithString("reason",
			mcp.Description("Reason for ignoring"),
		),
		mcp.WithString("expiry",
			mcp.Description("When this ignore should expire"),
		),
	)
	m.mcpServer.AddTool(ignoreTool, m.snykIgnoreHandler(invocationCtx))

	// Add snyk_sbom tool
	sbomTool := mcp.NewTool(SnykSbom,
		mcp.WithDescription("Generate Software Bill of Materials (SBOM)"),
		mcp.WithString("path",
			mcp.Description("Path to generate SBOM for (default: current directory)"),
		),
		mcp.WithString("format",
			mcp.Description("SBOM format"),
		),
		mcp.WithString("file",
			mcp.Description("Output file path"),
		),
	)
	m.mcpServer.AddTool(sbomTool, m.snykSbomHandler(invocationCtx))

	//// Add snyk_config resource
	//configResource := mcp.NewResource(SnykConfig,
	//	mcp.WithDescription("Get Snyk configuration information"),
	//)
	//m.mcpServer.AddResource(configResource, m.snykConfigHandler())

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

// Report progress to the client
func reportProgress() {
	// TODO: Implement progress reporting
}

// Handler implementations for each Snyk tool
func (m *McpLLMBinding) snykTestHandler(invocationCtx workflow.InvocationContext) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Extract parameters
		params := make(map[string]interface{})
		path, _ := request.Params.Arguments["path"].(string)
		severityThreshold, _ := request.Params.Arguments["severity_threshold"].(string)

		params["all-projects"] = true
		params["json"] = true
		if severityThreshold != "" {
			params["severity-threshold"] = severityThreshold
		}

		// Build args and run command
		args := buildArgs(m.cliPath, "test", params)
		if path != "" {
			args = append(args, path)
		}

		// Report progress to the client
		reportProgress()

		// Run the Snyk CLI command
		output, err := m.runSnyk(ctx, invocationCtx, path, args)
		if err != nil {
			return nil, err
		}
		//
		// Attempt to parse and summarize the JSON output
		summary, err := summarizeSnykOutput(output)
		if err == nil {
			jsonSummary, _ := json.Marshal(summary)
			return mcp.NewToolResultText(string(jsonSummary)), nil
		}

		return mcp.NewToolResultText(output), nil
	}
}

func (m *McpLLMBinding) snykVersionHandler(invocationCtx workflow.InvocationContext) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		params := []string{m.cliPath, "--version"}
		output, err := m.runSnyk(ctx, invocationCtx, "", params)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResultText(output), nil
	}
}

func (m *McpLLMBinding) snykMonitorHandler(invocationCtx workflow.InvocationContext) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Extract parameters
		params := make(map[string]interface{})
		path, _ := request.Params.Arguments["path"].(string)
		allProjects, _ := request.Params.Arguments["all_projects"].(bool)
		org, _ := request.Params.Arguments["org"].(string)

		params["all-projects"] = allProjects
		if org != "" {
			params["org"] = org
		}

		// Build args and run command
		args := buildArgs(m.cliPath, "monitor", params)
		if path != "" {
			args = append(args, path)
		}

		output, err := m.runSnyk(ctx, invocationCtx, path, args)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResultText(output), nil
	}
}

func (m *McpLLMBinding) snykAuthHandler(invocationCtx workflow.InvocationContext) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Extract parameters
		params := []string{m.cliPath, "auth", "auth-type=oauth"}
		_, err := m.runSnyk(ctx, invocationCtx, "", params)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResultText("Authenticated Successfully"), nil
	}
}

func (m *McpLLMBinding) snykAuthStatusHandler(invocationCtx workflow.InvocationContext) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		params := []string{m.cliPath, "whoami", "--experimental"}
		output, err := m.runSnyk(ctx, invocationCtx, "", params)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResultText(output), nil
	}
}

func (m *McpLLMBinding) snykLogoutHandler(invocationCtx workflow.InvocationContext) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		params := []string{m.cliPath, "config", "unset", "INTERNAL_OAUTH_TOKEN_STORAGE"}
		output, err := m.runSnyk(ctx, invocationCtx, "", params)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResultText(output), nil
	}
}

func (m *McpLLMBinding) snykCodeTestHandler(invocationCtx workflow.InvocationContext) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Extract parameters
		params := make(map[string]interface{})
		path, _ := request.Params.Arguments["path"].(string)

		params["json"] = true

		// Build args and run command
		args := buildArgs(m.cliPath, "code", params)
		args = append(args, "test")
		if path != "" {
			args = append(args, path)
		}

		output, err := m.runSnyk(ctx, invocationCtx, path, args)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResultText(output), nil
	}
}

func (m *McpLLMBinding) snykContainerTestHandler(invocationCtx workflow.InvocationContext) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Extract parameters
		params := make(map[string]interface{})
		image, _ := request.Params.Arguments["image"].(string)
		file, _ := request.Params.Arguments["file"].(string)

		params["json"] = true
		if file != "" {
			params["file"] = file
		}

		// Build args and run command
		args := buildArgs(m.cliPath, "container", params)
		args = append(args, "test", image)

		output, err := m.runSnyk(ctx, invocationCtx, "", args)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResultText(output), nil
	}
}

func (m *McpLLMBinding) snykIacTestHandler(invocationCtx workflow.InvocationContext) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Extract parameters
		params := make(map[string]interface{})
		path, _ := request.Params.Arguments["path"].(string)

		params["json"] = true

		// Build args and run command
		args := buildArgs(m.cliPath, "iac", params)
		args = append(args, "test")
		if path != "" {
			args = append(args, path)
		}

		output, err := m.runSnyk(ctx, invocationCtx, path, args)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResultText(output), nil
	}
}

func (m *McpLLMBinding) snykFixHandler(invocationCtx workflow.InvocationContext) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Extract parameters
		params := make(map[string]interface{})
		path, _ := request.Params.Arguments["path"].(string)
		dryRun, _ := request.Params.Arguments["dry_run"].(bool)

		params["all-projects"] = true
		params["dry-run"] = dryRun

		// Build args and run command
		args := buildArgs(m.cliPath, "fix", params)
		if path != "" {
			args = append(args, path)
		}

		output, err := m.runSnyk(ctx, invocationCtx, path, args)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResultText(output), nil
	}
}

func (m *McpLLMBinding) snykIgnoreHandler(invocationCtx workflow.InvocationContext) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		params := make(map[string]interface{})
		id, _ := request.Params.Arguments["id"].(string)
		reason, _ := request.Params.Arguments["reason"].(string)
		expiry, _ := request.Params.Arguments["expiry"].(string)

		if reason != "" {
			params["reason"] = reason
		}
		if expiry != "" {
			params["expiry"] = expiry
		}
		if id != "" {
			params["id"] = expiry
		}

		// Build args and run command
		args := buildArgs(m.cliPath, "ignore", params)

		output, err := m.runSnyk(ctx, invocationCtx, "", args)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResultText(output), nil
	}
}

func (m *McpLLMBinding) snykSbomHandler(invocationCtx workflow.InvocationContext) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Extract parameters
		params := make(map[string]interface{})
		path, _ := request.Params.Arguments["path"].(string)
		format, _ := request.Params.Arguments["format"].(string)
		file, _ := request.Params.Arguments["file"].(string)

		if format != "" {
			params["format"] = format
		}
		if file != "" {
			params["file"] = file
		}

		// Build args and run command
		args := buildArgs(m.cliPath, "sbom", params)
		if path != "" {
			args = append(args, path)
		}

		output, err := m.runSnyk(ctx, invocationCtx, path, args)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResultText(output), nil
	}
}
