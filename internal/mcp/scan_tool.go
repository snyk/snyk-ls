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

	"github.com/mark3labs/mcp-go/mcp"

	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/types"
)

const (
	//SnykScanWorkspaceScan = types.WorkspaceScanCommand
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

func (m *McpLLMBinding) addSnykTools() error {
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
	m.mcpServer.AddTool(testTool, m.snykTestHandler())

	// Add snyk_version tool
	versionTool := mcp.NewTool(SnykVersion,
		mcp.WithDescription("Get Snyk CLI version"),
	)
	m.mcpServer.AddTool(versionTool, m.snykVersionHandler())

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
	m.mcpServer.AddTool(monitorTool, m.snykMonitorHandler())

	// Add snyk_auth tool
	authTool := mcp.NewTool(SnykAuth,
		mcp.WithDescription("Authenticate with Snyk using API token"),
	)
	m.mcpServer.AddTool(authTool, m.snykAuthHandler())

	// Add snyk_auth_status tool
	authStatusTool := mcp.NewTool(SnykAuthStatus,
		mcp.WithDescription("Check Snyk authentication status"),
	)
	m.mcpServer.AddTool(authStatusTool, m.snykAuthStatusHandler())

	// Add snyk_logout tool
	logoutTool := mcp.NewTool(SnykLogout,
		mcp.WithDescription("Log out from Snyk"),
	)
	m.mcpServer.AddTool(logoutTool, m.snykLogoutHandler())

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
	m.mcpServer.AddTool(codeTestTool, m.snykCodeTestHandler())

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
	m.mcpServer.AddTool(containerTestTool, m.snykContainerTestHandler())

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
	m.mcpServer.AddTool(iacTestTool, m.snykIacTestHandler())

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
	m.mcpServer.AddTool(fixTool, m.snykFixHandler())

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
	m.mcpServer.AddTool(ignoreTool, m.snykIgnoreHandler())

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
	m.mcpServer.AddTool(sbomTool, m.snykSbomHandler())

	//// Add snyk_config resource
	//configResource := mcp.NewResource(SnykConfig,
	//	mcp.WithDescription("Get Snyk configuration information"),
	//)
	//m.mcpServer.AddResource(configResource, m.snykConfigHandler())

	return nil
}

//func (m *McpLLMBinding) addSnykScanTool() error {
//	//tool := mcp.NewTool(SnykScanWorkspaceScan,
//	//	mcp.WithDescription("Perform Snyk scans on current workspace"),
//	//)
//	//
//	//m.mcpServer.AddTool(tool, m.snykWorkSpaceScanHandler())
//	//
//	//return nil
//}

func (m *McpLLMBinding) snykWorkSpaceScanHandler() func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		w := m.c.Workspace()
		trusted, _ := w.GetFolderTrust()

		callToolResult := &mcp.CallToolResult{
			Content: make([]interface{}, 0),
		}

		resultProcessor := func(ctx context.Context, data types.ScanData) {
			// add the scan results to the call tool response
			// in the future, this could be a rendered markdown/html template
			callToolResult.Content = append(callToolResult.Content, data)
			if data.Err != nil {
				callToolResult.IsError = true
			}

			// standard processing for the folder
			scanResultProcessor := folderScanResultProcessor(w, data.Path)
			if scanResultProcessor != nil {
				scanResultProcessor(ctx, data)
			}

			// forward to forwarding processor
			if m.forwardingResultProcessor != nil {
				m.forwardingResultProcessor(ctx, data)
			}
		}

		enrichedContext := ctx2.NewContextWithScanSource(ctx, ctx2.LLM)
		for _, folder := range trusted {
			m.scanner.Scan(enrichedContext, folder.Path(), resultProcessor, folder.Path())
		}

		return callToolResult, nil
	}
}

func folderScanResultProcessor(w types.Workspace, path types.FilePath) types.ScanResultProcessor {
	folder := w.GetFolderContaining(path)
	if folder == nil {
		return nil
	}
	scanResultProcessor := folder.ScanResultProcessor()
	return scanResultProcessor
}

// runSnyk runs a Snyk command and returns the result
func (m *McpLLMBinding) runSnyk(ctx context.Context, workingDir string, args []string) (string, error) {
	res, err := m.cliExecutor.Execute(ctx, args, types.FilePath(workingDir))
	resAsString := string(res)
	if err != nil {
		m.logger.Err(err).Msg("Failed to execute command")
	}
	return resAsString, nil
}

// Report progress to the client
func reportProgress(ctx context.Context, request mcp.CallToolRequest, percentage int) {
	// TODO: Implement progress reporting
}

// Handler implementations for each Snyk tool
func (m *McpLLMBinding) snykTestHandler() func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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
		args := buildArgs(m.c.CliSettings().Path(), "test", params)
		if path != "" {
			args = append(args, path)
		}

		// Report progress to the client
		reportProgress(ctx, request, 0)

		// Run the Snyk CLI command
		output, err := m.runSnyk(ctx, path, args)
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

func (m *McpLLMBinding) snykVersionHandler() func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		params := []string{m.c.CliSettings().Path(), "--version"}
		output, err := m.runSnyk(ctx, "", params)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResultText(output), nil
	}
}

func (m *McpLLMBinding) snykMonitorHandler() func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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
		args := buildArgs(m.c.CliSettings().Path(), "monitor", params)
		if path != "" {
			args = append(args, path)
		}

		output, err := m.runSnyk(ctx, path, args)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResultText(output), nil
	}
}

func (m *McpLLMBinding) snykAuthHandler() func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Extract parameters
		params := []string{m.c.CliSettings().Path(), "auth", "auth-type=oauth"}
		_, err := m.runSnyk(ctx, "", params)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResultText("Authenticated Successfully"), nil
	}
}

func (m *McpLLMBinding) snykAuthStatusHandler() func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		params := []string{m.c.CliSettings().Path(), "whoami", "--experimental"}
		output, err := m.runSnyk(ctx, "", params)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResultText(output), nil
	}
}

func (m *McpLLMBinding) snykLogoutHandler() func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		params := []string{m.c.CliSettings().Path(), "config", "unset", "token"}
		output, err := m.runSnyk(ctx, "", params)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResultText(output), nil
	}
}

func (m *McpLLMBinding) snykCodeTestHandler() func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Extract parameters
		params := make(map[string]interface{})
		path, _ := request.Params.Arguments["path"].(string)

		params["json"] = true

		// Build args and run command
		args := buildArgs(m.c.CliSettings().Path(), "code", params)
		args = append(args, "test")
		if path != "" {
			args = append(args, path)
		}

		output, err := m.runSnyk(ctx, path, args)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResultText(output), nil
	}
}

func (m *McpLLMBinding) snykContainerTestHandler() func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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
		args := buildArgs(m.c.CliSettings().Path(), "container", params)
		args = append(args, "test", image)

		output, err := m.runSnyk(ctx, "", args)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResultText(output), nil
	}
}

func (m *McpLLMBinding) snykIacTestHandler() func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Extract parameters
		params := make(map[string]interface{})
		path, _ := request.Params.Arguments["path"].(string)

		params["json"] = true

		// Build args and run command
		args := buildArgs(m.c.CliSettings().Path(), "iac", params)
		args = append(args, "test")
		if path != "" {
			args = append(args, path)
		}

		output, err := m.runSnyk(ctx, path, args)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResultText(output), nil
	}
}

func (m *McpLLMBinding) snykFixHandler() func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Extract parameters
		params := make(map[string]interface{})
		path, _ := request.Params.Arguments["path"].(string)
		dryRun, _ := request.Params.Arguments["dry_run"].(bool)

		params["all-projects"] = true
		params["dry-run"] = dryRun

		// Build args and run command
		args := buildArgs(m.c.CliSettings().Path(), "fix", params)
		if path != "" {
			args = append(args, path)
		}

		output, err := m.runSnyk(ctx, path, args)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResultText(output), nil
	}
}

func (m *McpLLMBinding) snykIgnoreHandler() func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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
		args := buildArgs(m.c.CliSettings().Path(), "ignore", params)

		output, err := m.runSnyk(ctx, "", args)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResultText(output), nil
	}
}

func (m *McpLLMBinding) snykSbomHandler() func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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
		args := buildArgs(m.c.CliSettings().Path(), "sbom", params)
		if path != "" {
			args = append(args, path)
		}

		output, err := m.runSnyk(ctx, path, args)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResultText(output), nil
	}
}

//func (m *McpLLMBinding) snykConfigHandler() func(ctx context.Context, request mcp.CallResourceRequest) (*mcp.CallResourceResult, error) {
//	return func(ctx context.Context, request mcp.CallResourceRequest) (*mcp.CallResourceResult, error) {
//		// Get configuration information
//		snykPath := "default" // TODO: Get actual path from configuration
//		workingDir, _ := os.Getwd()
//		workspacePath := "Not specified" // TODO: Get actual workspace path from configuration
//
//		config := map[string]string{
//			"SnykCliPath":      snykPath,
//			"WorkingDirectory": workingDir,
//			"WorkspacePath":    workspacePath,
//		}
//
//		jsonConfig, _ := json.Marshal(config)
//
//		return &mcp.CallResourceResult{
//			Content: string(jsonConfig),
//		}, nil
//	}
//}
