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
	"os/exec"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	SnykScaTest    = "snyk_sca_test"
	SnykCodeTest   = "snyk_code_test"
	SnykVersion    = "snyk_version"
	SnykAuth       = "snyk_auth"
	SnykAuthStatus = "snyk_auth_status"
	SnykLogout     = "snyk_logout"
)

func (m *McpLLMBinding) addSnykTools(invocationCtx workflow.InvocationContext) error {
	// Add snyk_test tool
	testTool := mcp.NewTool(SnykScaTest,
		mcp.WithDescription("Run a SCA test on project dependencies to detect known vulnerabilities. Use this to scan open-source packages in supported ecosystems like npm, Maven, etc. Supports monorepo scanning via `--all-projects`. Outputs vulnerability data in JSON if enabled."),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Path to the project to test (default is the absolute path of the current directory, formatted according to the operating system's conventions)."),
		),
		mcp.WithBoolean("all_projects",
			mcp.Description("Scan all projects in the specified directory. (Default is true)."),
		),
		mcp.WithBoolean("json",
			mcp.Description("Output results in JSON format. (Default is true)."),
		),
		mcp.WithString("severity_threshold",
			mcp.Description("Only report vulnerabilities of the specified level or higher (low, medium, high, critical). (Default is empty)"),
		),
		mcp.WithString("org",
			mcp.Description("Specify the organization under which to run the test. (Default is empty)."),
		),
		mcp.WithBoolean("dev",
			mcp.Description("Include development dependencies. (Default is false)"),
		),
		mcp.WithBoolean("skip_unresolved",
			mcp.Description("Skip testing of unresolved packages. (Default is false)"),
		),
		mcp.WithBoolean("prune_repeated_subdependencies",
			mcp.Description("Prune repeated sub-dependencies. (Default is false)."),
		),
		mcp.WithString("fail_on",
			mcp.Description("Specify the failure criteria (all, upgradable, patchable). (Default is all)."),
		),
		mcp.WithString("file",
			mcp.Description("Specify a package file to test. (Default is empty)"),
		),
		mcp.WithBoolean("fail_fast",
			mcp.Description("Use with --all-projects to interrupt scans when errors occur. (Default is false)"),
		),
		mcp.WithString("detection_depth",
			mcp.Description("Use with --all-projects to indicate how many subdirectories to search. (Default is empty)"),
		),
		mcp.WithString("exclude",
			mcp.Description("Use with --all-projects to exclude directory names and file names. (Default is empty)"),
		),
		mcp.WithBoolean("print_deps",
			mcp.Description("Print the dependency tree before sending it for analysis. (Default is false)"),
		),
		mcp.WithString("remote_repo_url",
			mcp.Description("Set or override the remote URL for the repository to monitor. (Default is empty)"),
		),
		mcp.WithString("package_manager",
			mcp.Description("Specify the name of the package manager when the filename is not standard. (Default is empty)"),
		),
		mcp.WithBoolean("unmanaged",
			mcp.Description("For C++ only, scan all files for known open source dependencies. (Default is false)"),
		),
		mcp.WithBoolean("ignore_policy",
			mcp.Description("Ignore all set policies, the current policy in the .snyk file, Org level ignores, and the project policy. (Default is false)"),
		),
		mcp.WithBoolean("trust_policies",
			mcp.Description("Apply and use ignore rules from the Snyk policies in your dependencies. (Default is false)"),
		),
		mcp.WithString("show_vulnerable_paths",
			mcp.Description("Display the dependency paths (none|some|all). (Default: none)."),
		),
		mcp.WithString("project_name",
			mcp.Description("Specify a custom Snyk project name. (Default is empty)"),
		),
		mcp.WithString("target_reference",
			mcp.Description("Specify a reference that differentiates this project, for example, a branch name. (Default is empty)"),
		),
		mcp.WithString("policy_path",
			mcp.Description("Manually pass a path to a .snyk policy file. (Default is empty)"),
		),
	)
	m.mcpServer.AddTool(testTool, m.snykTestHandler(invocationCtx))

	// Add snyk_code_test tool
	codeTestTool := mcp.NewTool(SnykCodeTest,
		mcp.WithDescription("Run a static application security test (SAST) on your source code to detect security issues like SQL injection, XSS, and hardcoded secrets. Designed to catch issues early in the development cycle."),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Path to the project to test (default is the absolute path of the current directory, formatted according to the operating system's conventions)."),
		),
		mcp.WithString("file",
			mcp.Description("Specific file to scan (default: empty)."),
		),
		mcp.WithBoolean("json",
			mcp.Description("Output results in JSON format. (default: true)"),
		),
		mcp.WithString("severity_threshold",
			mcp.Description("Only report vulnerabilities of the specified level or higher (low, medium, high). (default: empty)"),
		),
		mcp.WithString("org",
			mcp.Description("Specify the organization under which to run the test. (default: empty)"),
		),
	)
	m.mcpServer.AddTool(codeTestTool, m.snykCodeTestHandler(invocationCtx))

	versionTool := mcp.NewTool(SnykVersion,
		mcp.WithDescription("Get Snyk CLI version"),
	)
	m.mcpServer.AddTool(versionTool, m.snykVersionHandler(invocationCtx))

	authTool := mcp.NewTool(SnykAuth,
		mcp.WithDescription("Authenticate with Snyk using API token"),
	)
	m.mcpServer.AddTool(authTool, m.snykAuthHandler(invocationCtx))

	authStatusTool := mcp.NewTool(SnykAuthStatus,
		mcp.WithDescription("Check Snyk authentication status"),
	)
	m.mcpServer.AddTool(authStatusTool, m.snykAuthStatusHandler(invocationCtx))

	logoutTool := mcp.NewTool(SnykLogout,
		mcp.WithDescription("Log out from Snyk"),
	)
	m.mcpServer.AddTool(logoutTool, m.snykLogoutHandler(invocationCtx))

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
func (m *McpLLMBinding) snykTestHandler(invocationCtx workflow.InvocationContext) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Extract parameters
		params := make(map[string]interface{})
		path, _ := request.Params.Arguments["path"].(string)
		severityThreshold, _ := request.Params.Arguments["severity_threshold"].(string)
		org, _ := request.Params.Arguments["org"].(string)
		dev, _ := request.Params.Arguments["dev"].(bool)
		skipUnresolved, _ := request.Params.Arguments["skip_unresolved"].(bool)
		pruneRepeatedSubdependencies, _ := request.Params.Arguments["prune_repeated_subdependencies"].(bool)
		failOn, _ := request.Params.Arguments["fail_on"].(string)
		file, _ := request.Params.Arguments["file"].(string)
		failFast, _ := request.Params.Arguments["fail_fast"].(bool)
		detectionDepth, _ := request.Params.Arguments["detection_depth"].(string)
		exclude, _ := request.Params.Arguments["exclude"].(string)
		remoteRepoUrl, _ := request.Params.Arguments["remote_repo_url"].(string)
		packageManager, _ := request.Params.Arguments["package_manager"].(string)
		unmanaged, _ := request.Params.Arguments["unmanaged"].(bool)
		ignorePolicy, _ := request.Params.Arguments["ignore_policy"].(bool)
		trustPolicies, _ := request.Params.Arguments["trust_policies"].(bool)
		showVulnerablePaths, _ := request.Params.Arguments["show_vulnerable_paths"].(string)
		projectName, _ := request.Params.Arguments["project_name"].(string)
		targetReference, _ := request.Params.Arguments["target_reference"].(string)
		policyPath, _ := request.Params.Arguments["policy_path"].(string)

		params["all-projects"] = true
		params["json"] = true

		if severityThreshold != "" {
			params["severity-threshold"] = severityThreshold
		}
		if org != "" {
			params["org"] = org
		}
		if dev {
			params["dev"] = true
		}
		if skipUnresolved {
			params["skip-unresolved"] = true
		}
		if pruneRepeatedSubdependencies {
			params["prune-repeated-subdependencies"] = true
		}
		if failOn != "" {
			params["fail-on"] = failOn
		}
		if file != "" {
			params["file"] = file
		}
		if failFast {
			params["fail-fast"] = true
		}
		if detectionDepth != "" {
			params["detection-depth"] = detectionDepth
		}
		if exclude != "" {
			params["exclude"] = exclude
		}
		if remoteRepoUrl != "" {
			params["remote-repo-url"] = remoteRepoUrl
		}
		if packageManager != "" {
			params["package-manager"] = packageManager
		}
		if unmanaged {
			params["unmanaged"] = true
		}
		if ignorePolicy {
			params["ignore-policy"] = true
		}
		if trustPolicies {
			params["trust-policies"] = true
		}
		if showVulnerablePaths != "" {
			params["show-vulnerable-paths"] = showVulnerablePaths
		}
		if projectName != "" {
			params["project-name"] = projectName
		}
		if targetReference != "" {
			params["target-reference"] = targetReference
		}
		if policyPath != "" {
			params["policy-path"] = policyPath
		}

		// Build args and run command
		args := buildArgs(m.cliPath, "test", params)
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

func (m *McpLLMBinding) snykAuthHandler(invocationCtx workflow.InvocationContext) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Extract parameters
		params := []string{m.cliPath, "auth"}
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
		_, _ = m.runSnyk(ctx, invocationCtx, "", params)

		params = []string{m.cliPath, "config", "unset", "token"}
		_, _ = m.runSnyk(ctx, invocationCtx, "", params)

		return mcp.NewToolResultText("Successfully logged out"), nil
	}
}

func (m *McpLLMBinding) snykCodeTestHandler(invocationCtx workflow.InvocationContext) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Extract parameters
		params := make(map[string]interface{})
		path, _ := request.Params.Arguments["path"].(string)
		file, _ := request.Params.Arguments["file"].(string)
		severityThreshold, _ := request.Params.Arguments["severity_threshold"].(string)
		org, _ := request.Params.Arguments["org"].(string)

		params["json"] = true

		if severityThreshold != "" {
			params["severity-threshold"] = severityThreshold
		}
		if org != "" {
			params["org"] = org
		}
		if file != "" {
			params["file"] = file
		}

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
