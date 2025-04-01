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
	"github.com/mark3labs/mcp-go/server"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	SnykScaTest           = "snyk_sca_test"
	SnykVersion           = "snyk_version"
	SnykMonitor           = "snyk_monitor"
	SnykAuth              = "snyk_auth"
	SnykAuthStatus        = "snyk_auth_status"
	SnykLogout            = "snyk_logout"
	SnykCodeTest          = "snyk_code_test"
	SnykContainerTest     = "snyk_container_test"
	SnykIacTest           = "snyk_iac_test"
	SnykIgnore            = "snyk_ignore"
	SnykSbom              = "snyk_sbom"
	SnykSbomTest          = "snyk_sbom_test"
	SnykConfig            = "snyk_config"
	SnykConfigEnvironment = "snyk_config_environment"
	SnykPolicy            = "snyk_policy"
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
			mcp.Description("Display the dependency paths (none|some|all). Default: some."),
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

	versionTool := mcp.NewTool(SnykVersion,
		mcp.WithDescription("Get Snyk CLI version"),
	)
	m.mcpServer.AddTool(versionTool, m.snykVersionHandler(invocationCtx))

	// Add snyk_monitor tool
	monitorTool := mcp.NewTool(SnykMonitor,
		mcp.WithDescription("Monitor a project for vulnerabilities continuously."),
		mcp.WithString("path",
			mcp.Description("Path to the project to test (default is the absolute path of the current directory, formatted according to the operating system's conventions)."),
		),
		mcp.WithBoolean("all_projects",
			mcp.Description("Monitor all projects in the specified directory."),
		),
		mcp.WithString("org",
			mcp.Description("Specify the organization under which to monitor the project."),
		),
		mcp.WithBoolean("dev",
			mcp.Description("Include development dependencies."),
		),
		mcp.WithString("remote_repo_url",
			mcp.Description("Specify the remote repository URL for the project."),
		),
		mcp.WithBoolean("prune_repeated_subdependencies",
			mcp.Description("Prune repeated sub-dependencies."),
		),
		mcp.WithBoolean("skip_unresolved",
			mcp.Description("Skip monitoring of unresolved packages."),
		),
		mcp.WithBoolean("fail_fast",
			mcp.Description("Use with --all-projects to interrupt scans when errors occur."),
		),
		mcp.WithString("detection_depth",
			mcp.Description("Use with --all-projects to indicate how many subdirectories to search."),
		),
		mcp.WithString("exclude",
			mcp.Description("Use with --all-projects to exclude directory names and file names."),
		),
		mcp.WithBoolean("print_deps",
			mcp.Description("Print the dependency tree before sending it for analysis."),
		),
		mcp.WithString("file",
			mcp.Description("Specify a package file to monitor."),
		),
		mcp.WithString("package_manager",
			mcp.Description("Specify the name of the package manager when the filename is not standard."),
		),
		mcp.WithBoolean("unmanaged",
			mcp.Description("For C++ only, scan all files for known open source dependencies."),
		),
		mcp.WithBoolean("ignore_policy",
			mcp.Description("Ignore all set policies, the current policy in the .snyk file, Org level ignores, and the project policy."),
		),
		mcp.WithBoolean("trust_policies",
			mcp.Description("Apply and use ignore rules from the Snyk policies in your dependencies."),
		),
		mcp.WithString("project_name",
			mcp.Description("Specify a custom Snyk project name."),
		),
		mcp.WithString("target_reference",
			mcp.Description("Specify a reference that differentiates this project, for example, a branch name."),
		),
		mcp.WithString("policy_path",
			mcp.Description("Manually pass a path to a .snyk policy file."),
		),
		mcp.WithBoolean("json",
			mcp.Description("Print results on the console as a JSON data structure."),
		),
		mcp.WithString("project_environment",
			mcp.Description("Set the project environment to one or more values (comma-separated)."),
		),
		mcp.WithString("project_lifecycle",
			mcp.Description("Set the project lifecycle to one or more values (comma-separated)."),
		),
		mcp.WithString("project_business_criticality",
			mcp.Description("Set the project business criticality to one or more values (comma-separated)."),
		),
		mcp.WithString("project_tags",
			mcp.Description("Set the project tags to one or more values (comma-separated key value pairs)."),
		),
	)
	m.mcpServer.AddTool(monitorTool, m.snykMonitorHandler(invocationCtx))

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

	// Add snyk_container_test tool
	containerTestTool := mcp.NewTool(SnykContainerTest,
		mcp.WithDescription("Scan a container image for known vulnerabilities in both OS-level and application dependencies. Use this before shipping images to production."),
		mcp.WithString("image",
			mcp.Required(),
			mcp.Description("Name of the container image to test (e.g., 'ubuntu:18.04')."),
		),
		mcp.WithBoolean("json",
			mcp.Description("Output results in JSON format (default: true)."),
		),
		mcp.WithString("file",
			mcp.Description("Path to the Dockerfile associated with the image (default: empty)."),
		),
		mcp.WithString("severity_threshold",
			mcp.Description("Only report vulnerabilities of the specified level or higher (low, medium, high, critical) (default: empty)."),
		),
		mcp.WithString("org",
			mcp.Description("Specify the organization under which to run the test (default: empty)."),
		),
		mcp.WithBoolean("exclude_base_image_vulns",
			mcp.Description("Exclude vulnerabilities introduced by the base image(default: false)."),
		),
		mcp.WithBoolean("print_deps",
			mcp.Description("Print the dependency tree before sending it for analysis (default: false)."),
		),
		mcp.WithString("project_name",
			mcp.Description("Specify a custom Snyk project name (default: empty)."),
		),
		mcp.WithString("policy_path",
			mcp.Description("Manually pass a path to a .snyk policy file (default: empty)."),
		),
		mcp.WithString("fail_on",
			mcp.Description("Fail only when there are vulnerabilities that can be fixed (all|upgradable) (default: empty)."),
		),
		mcp.WithBoolean("app_vulns",
			mcp.Description("Allow detection of vulnerabilities in application dependencies from container images (default: false)."),
		),
		mcp.WithBoolean("exclude_app_vulns",
			mcp.Description("Disable scanning for application vulnerabilities (default: false)."),
		),
		mcp.WithBoolean("exclude_node_modules",
			mcp.Description("Disable the scan of node_modules directories inside node.js container images (default: false)."),
		),
		mcp.WithString("nested_jars_depth",
			mcp.Description("Set how many levels of nested jars to unpack when app-vulns is enabled (default: empty)."),
		),
		mcp.WithString("platform",
			mcp.Description("For multi-architecture images, specify the platform to test (default: empty)."),
		),
		mcp.WithString("username",
			mcp.Description("Specify a username to use when connecting to a container registry (default: empty)."),
		),
		mcp.WithString("password",
			mcp.Description("Specify a password to use when connecting to a container registry (default: empty)."),
		),
	)
	m.mcpServer.AddTool(containerTestTool, m.snykContainerTestHandler(invocationCtx))

	// Add snyk_iac_test tool
	iacTestTool := mcp.NewTool(SnykIacTest,
		mcp.WithDescription("Analyze Infrastructure as Code (IaC) files—like Terraform, CloudFormation, or Kubernetes—for misconfigurations and security risks. Ideal for scanning your CI/CD pipeline or IaC repositories."),
		mcp.WithString("path",
			mcp.Description("Path to the project to test (default is the absolute path of the current directory, formatted according to the operating system's conventions)."),
		),
		mcp.WithBoolean("json",
			mcp.Description("Output results in JSON format (default: true)."),
		),
		mcp.WithString("severity_threshold",
			mcp.Description("Only report vulnerabilities of the specified level or higher (low, medium, high, critical) (default: empty)."),
		),
		mcp.WithString("org",
			mcp.Description("Specify the organization under which to run the test (default: empty)."),
		),
		mcp.WithString("detection_depth",
			mcp.Description("Indicate how many subdirectories to search (default: empty)."),
		),
		mcp.WithBoolean("ignore_policy",
			mcp.Description("Ignore all set policies, the current policy in the .snyk file, org level ignores, and the project policy (default: false)."),
		),
		mcp.WithString("policy_path",
			mcp.Description("Manually pass a path to a .snyk policy file (default: empty)."),
		),
		mcp.WithString("remote_repo_url",
			mcp.Description("Set or override the remote URL for the repository (default: empty)."),
		),
		mcp.WithBoolean("report",
			mcp.Description("Share results with the Snyk Web UI (default: false)."),
		),
		mcp.WithString("rules",
			mcp.Description("Path to custom rules bundle for scanning (default: empty)."),
		),
		mcp.WithString("scan",
			mcp.Description("Terraform plan scanning mode (planned-values or resource-changes) (default: empty)."),
		),
		mcp.WithString("target_name",
			mcp.Description("Set or override the project name for the repository (default: empty)."),
		),
		mcp.WithString("target_reference",
			mcp.Description("Specify a reference that differentiates this project, for example, a branch name. (default: empty)"),
		),
		mcp.WithString("var_file",
			mcp.Description("Path to a variable definitions file (default: empty)."),
		),
	)
	m.mcpServer.AddTool(iacTestTool, m.snykIacTestHandler(invocationCtx))

	// Add snyk_ignore tool
	ignoreTool := mcp.NewTool(SnykIgnore,
		mcp.WithDescription("Suppress reporting of a known vulnerability by marking it as ignored, optionally with a reason and expiration. Useful to mute low-priority issues or apply temporary exceptions."),
		mcp.WithString("id",
			mcp.Required(),
			mcp.Description("Identifier of the vulnerability to ignore."),
		),
		mcp.WithString("reason",
			mcp.Description("Justification for ignoring the vulnerability."),
		),
		mcp.WithString("expiry",
			mcp.Description("Expiry date in YYYY-MM-DD format. Default: 30 days."),
		),
		mcp.WithString("policy_path",
			mcp.Description("Path to a .snyk policy file to pass manually (default: empty)."),
		),
		mcp.WithString("path",
			mcp.Description("Path to resource inside the depgraph for which to ignore the issue (default: empty)."),
		),
		mcp.WithString("file_path",
			mcp.Description("Filesystem path for which to exclude directories or files from scanning (default: empty)."),
		),
		mcp.WithString("file_path_group",
			mcp.Description("Grouping used in combination with --file-path (global|code|iac-drift) (default: empty)."),
		),
	)
	m.mcpServer.AddTool(ignoreTool, m.snykIgnoreHandler(invocationCtx))

	// Add snyk_config tool
	configTool := mcp.NewTool(SnykConfig,
		mcp.WithDescription("Manage the Snyk CLI configuration."),
		mcp.WithString("subcommand",
			mcp.Required(),
			mcp.Description("Subcommand to run (get, set, unset, clear)."),
		),
		mcp.WithString("key",
			mcp.Description("Configuration key."),
		),
		mcp.WithString("value",
			mcp.Description("Configuration value."),
		),
	)
	m.mcpServer.AddTool(configTool, m.snykConfigHandler(invocationCtx))

	// Add snyk_config_environment tool
	configEnvironmentTool := mcp.NewTool(SnykConfigEnvironment,
		mcp.WithDescription("Configure the Snyk CLI for a specific environment."),
		mcp.WithString("environment",
			mcp.Required(),
			mcp.Description("Environment to use (e.g., default, SNYK-US-01, SNYK-EU-01)."),
		),
		mcp.WithBoolean("no_check",
			mcp.Description("Skip basic checks for ambiguous or unexpected configuration."),
		),
	)
	m.mcpServer.AddTool(configEnvironmentTool, m.snykConfigEnvironmentHandler(invocationCtx))

	// Add snyk_policy tool
	policyTool := mcp.NewTool(SnykPolicy,
		mcp.WithDescription("Display the .snyk policy file for a package."),
		mcp.WithString("path",
			mcp.Description("Path to the .snyk policy file."),
		),
	)
	m.mcpServer.AddTool(policyTool, m.snykPolicyHandler(invocationCtx))

	sbomTool := mcp.NewTool(SnykSbom,
		mcp.WithDescription("Generate a Software Bill of Materials (SBOM) from your project, listing all dependencies and their versions. Use this to meet compliance or audit requirements."),
		mcp.WithString("path",
			mcp.Description("Path to the project to test (default is the absolute path of the current directory, formatted according to the operating system's conventions)."),
		),
		mcp.WithString("format",
			mcp.Required(),
			mcp.Description("Specify the output format (cyclonedx1.4+json, cyclonedx1.4+xml, cyclonedx1.5+json, cyclonedx1.5+xml, cyclonedx1.6+json, cyclonedx1.6+xml, spdx2.3+json)."),
		),
		mcp.WithString("org",
			mcp.Description("Specify the organization under which to run the command."),
		),
		mcp.WithString("file",
			mcp.Description("Specify the desired manifest file on which the SBOM will be based."),
		),
		mcp.WithBoolean("unmanaged",
			mcp.Description("Generate an SBOM for unmanaged software projects."),
		),
		mcp.WithBoolean("dev",
			mcp.Description("Include development-only dependencies in the SBOM output."),
		),
		mcp.WithBoolean("all_projects",
			mcp.Description("Auto-detect all projects in the working directory and generate a single SBOM based on their contents."),
		),
		mcp.WithString("name",
			mcp.Description("Provide the name of the software which the SBOM describes."),
		),
		mcp.WithString("version",
			mcp.Description("Provide the version of the software that the SBOM describes."),
		),
		mcp.WithString("exclude",
			mcp.Description("Used with --all-projects to indicate directory names and file names to exclude (comma-separated)."),
		),
		mcp.WithString("detection_depth",
			mcp.Description("Use with --all-projects to indicate how many subdirectories to search."),
		),
		mcp.WithBoolean("prune_repeated_subdependencies",
			mcp.Description("Prune dependency trees, removing duplicate sub-dependencies."),
		),
		mcp.WithBoolean("maven_aggregate_project",
			mcp.Description("Use when scanning Maven aggregate projects."),
		),
		mcp.WithBoolean("scan_unmanaged",
			mcp.Description("Scan individual JAR, WAR, or AAR files."),
		),
		mcp.WithBoolean("scan_all_unmanaged",
			mcp.Description("Auto-detect Maven, JAR, WAR, and AAR files recursively from the current folder."),
		),
		mcp.WithString("sub_project",
			mcp.Description("For Gradle multi project configurations, scan a specific sub-project."),
		),
		mcp.WithString("gradle_sub_project",
			mcp.Description("For Gradle multi project configurations, scan a specific sub-project."),
		),
		mcp.WithBoolean("all_sub_projects",
			mcp.Description("For multi project configurations, scan all sub-projects."),
		),
		mcp.WithString("configuration_matching",
			mcp.Description("Resolve dependencies using only configuration(s) that match the specified Java regular expression."),
		),
		mcp.WithString("configuration_attributes",
			mcp.Description("Select certain values of configuration attributes to install and resolve dependencies."),
		),
		mcp.WithString("init_script",
			mcp.Description("Use for projects that contain a Gradle initialization script."),
		),
		mcp.WithBoolean("assets_project_name",
			mcp.Description("When monitoring a .NET project using NuGet PackageReference, use the project name in project.assets.json if found."),
		),
		mcp.WithBoolean("skip_unresolved",
			mcp.Description("Skip packages that cannot be found in the environment."),
		),
	)
	m.mcpServer.AddTool(sbomTool, m.snykSbomHandler(invocationCtx))
	// Add snyk_sbom tool
	sbomTestTool := mcp.NewTool(SnykSbomTest,
		mcp.WithDescription("Test existing Software Bill of Materials (SBOM) files for vulnerabilities. Supports CycloneDX (JSON v1.4, v1.5, v1.6) and SPDX (JSON v2.3) formats."),
		mcp.WithString("file",
			mcp.Required(),
			mcp.Description("Specify the file path of the SBOM document to test."),
		),
		mcp.WithBoolean("experimental",
			mcp.Required(),
			mcp.Description("Use experimental command features (currently required as the command is in experimental phase). (default: true)"),
		),
	)
	m.mcpServer.AddTool(sbomTestTool, m.snykSbomTestHandler(invocationCtx))

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

func (m *McpLLMBinding) snykMonitorHandler(invocationCtx workflow.InvocationContext) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Extract parameters
		params := make(map[string]interface{})
		path, _ := request.Params.Arguments["path"].(string)
		allProjects, _ := request.Params.Arguments["all_projects"].(bool)
		org, _ := request.Params.Arguments["org"].(string)
		dev, _ := request.Params.Arguments["dev"].(bool)
		remoteRepoUrl, _ := request.Params.Arguments["remote_repo_url"].(string)
		pruneRepeatedSubdependencies, _ := request.Params.Arguments["prune_repeated_subdependencies"].(bool)
		skipUnresolved, _ := request.Params.Arguments["skip_unresolved"].(bool)
		failFast, _ := request.Params.Arguments["fail_fast"].(bool)
		detectionDepth, _ := request.Params.Arguments["detection_depth"].(string)
		exclude, _ := request.Params.Arguments["exclude"].(string)
		printDeps, _ := request.Params.Arguments["print_deps"].(bool)
		file, _ := request.Params.Arguments["file"].(string)
		packageManager, _ := request.Params.Arguments["package_manager"].(string)
		unmanaged, _ := request.Params.Arguments["unmanaged"].(bool)
		ignorePolicy, _ := request.Params.Arguments["ignore_policy"].(bool)
		trustPolicies, _ := request.Params.Arguments["trust_policies"].(bool)
		projectName, _ := request.Params.Arguments["project_name"].(string)
		targetReference, _ := request.Params.Arguments["target_reference"].(string)
		policyPath, _ := request.Params.Arguments["policy_path"].(string)
		json, _ := request.Params.Arguments["json"].(bool)
		projectEnvironment, _ := request.Params.Arguments["project_environment"].(string)
		projectLifecycle, _ := request.Params.Arguments["project_lifecycle"].(string)
		projectBusinessCriticality, _ := request.Params.Arguments["project_business_criticality"].(string)
		projectTags, _ := request.Params.Arguments["project_tags"].(string)

		params["all-projects"] = allProjects
		params["json"] = json
		if org != "" {
			params["org"] = org
		}
		if dev {
			params["dev"] = true
		}
		if remoteRepoUrl != "" {
			params["remote-repo-url"] = remoteRepoUrl
		}
		if pruneRepeatedSubdependencies {
			params["prune-repeated-subdependencies"] = true
		}
		if skipUnresolved {
			params["skip-unresolved"] = true
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
		if printDeps {
			params["print-deps"] = true
		}
		if file != "" {
			params["file"] = file
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
		if projectName != "" {
			params["project-name"] = projectName
		}
		if targetReference != "" {
			params["target-reference"] = targetReference
		}
		if policyPath != "" {
			params["policy-path"] = policyPath
		}
		if projectEnvironment != "" {
			params["project-environment"] = projectEnvironment
		}
		if projectLifecycle != "" {
			params["project-lifecycle"] = projectLifecycle
		}
		if projectBusinessCriticality != "" {
			params["project-business-criticality"] = projectBusinessCriticality
		}
		if projectTags != "" {
			params["project-tags"] = projectTags
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

func (m *McpLLMBinding) snykContainerTestHandler(invocationCtx workflow.InvocationContext) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Extract parameters
		params := make(map[string]interface{})
		image, _ := request.Params.Arguments["image"].(string)
		file, _ := request.Params.Arguments["file"].(string)
		json, _ := request.Params.Arguments["json"].(bool)
		severityThreshold, _ := request.Params.Arguments["severity_threshold"].(string)
		org, _ := request.Params.Arguments["org"].(string)
		excludeBaseImageVulns, _ := request.Params.Arguments["exclude_base_image_vulns"].(bool)
		printDeps, _ := request.Params.Arguments["print_deps"].(bool)
		projectName, _ := request.Params.Arguments["project_name"].(string)
		policyPath, _ := request.Params.Arguments["policy_path"].(string)
		failOn, _ := request.Params.Arguments["fail_on"].(string)
		appVulns, _ := request.Params.Arguments["app_vulns"].(bool)
		excludeAppVulns, _ := request.Params.Arguments["exclude_app_vulns"].(bool)
		excludeNodeModules, _ := request.Params.Arguments["exclude_node_modules"].(bool)
		nestedJarsDepth, _ := request.Params.Arguments["nested_jars_depth"].(string)
		platform, _ := request.Params.Arguments["platform"].(string)
		username, _ := request.Params.Arguments["username"].(string)
		password, _ := request.Params.Arguments["password"].(string)

		params["json"] = json
		if severityThreshold != "" {
			params["severity-threshold"] = severityThreshold
		}
		if org != "" {
			params["org"] = org
		}
		if excludeBaseImageVulns {
			params["exclude-base-image-vulns"] = true
		}
		if printDeps {
			params["print-deps"] = true
		}
		if projectName != "" {
			params["project-name"] = projectName
		}
		if policyPath != "" {
			params["policy-path"] = policyPath
		}
		if failOn != "" {
			params["fail-on"] = failOn
		}
		if appVulns {
			params["app-vulns"] = true
		}
		if excludeAppVulns {
			params["exclude-app-vulns"] = true
		}
		if excludeNodeModules {
			params["exclude-node-modules"] = true
		}
		if nestedJarsDepth != "" {
			params["nested-jars-depth"] = nestedJarsDepth
		}
		if platform != "" {
			params["platform"] = platform
		}
		if username != "" {
			params["username"] = username
		}
		if password != "" {
			params["password"] = password
		}
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
		severityThreshold, _ := request.Params.Arguments["severity_threshold"].(string)
		org, _ := request.Params.Arguments["org"].(string)
		detectionDepth, _ := request.Params.Arguments["detection_depth"].(string)
		ignorePolicy, _ := request.Params.Arguments["ignore_policy"].(bool)
		policyPath, _ := request.Params.Arguments["policy_path"].(string)
		projectBusinessCriticality, _ := request.Params.Arguments["project_business_criticality"].(string)
		projectEnvironment, _ := request.Params.Arguments["project_environment"].(string)
		projectLifecycle, _ := request.Params.Arguments["project_lifecycle"].(string)
		remoteRepoUrl, _ := request.Params.Arguments["remote_repo_url"].(string)
		report, _ := request.Params.Arguments["report"].(bool)
		rules, _ := request.Params.Arguments["rules"].(string)
		scan, _ := request.Params.Arguments["scan"].(string)
		targetName, _ := request.Params.Arguments["target_name"].(string)
		targetReference, _ := request.Params.Arguments["target_reference"].(string)
		varFile, _ := request.Params.Arguments["var_file"].(string)

		params["json"] = true
		if severityThreshold != "" {
			params["severity-threshold"] = severityThreshold
		}
		if org != "" {
			params["org"] = org
		}
		if detectionDepth != "" {
			params["detection-depth"] = detectionDepth
		}
		if ignorePolicy {
			params["ignore-policy"] = true
		}
		if policyPath != "" {
			params["policy-path"] = policyPath
		}
		if projectBusinessCriticality != "" {
			params["project-business-criticality"] = projectBusinessCriticality
		}
		if projectEnvironment != "" {
			params["project-environment"] = projectEnvironment
		}
		if projectLifecycle != "" {
			params["project-lifecycle"] = projectLifecycle
		}
		if remoteRepoUrl != "" {
			params["remote-repo-url"] = remoteRepoUrl
		}
		if report {
			params["report"] = true
		}
		if rules != "" {
			params["rules"] = rules
		}
		if scan != "" {
			params["scan"] = scan
		}
		if targetName != "" {
			params["target-name"] = targetName
		}
		if targetReference != "" {
			params["target-reference"] = targetReference
		}
		if varFile != "" {
			params["var-file"] = varFile
		}

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

func (m *McpLLMBinding) snykIgnoreHandler(invocationCtx workflow.InvocationContext) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		params := make(map[string]interface{})
		id, _ := request.Params.Arguments["id"].(string)
		reason, _ := request.Params.Arguments["reason"].(string)
		expiry, _ := request.Params.Arguments["expiry"].(string)
		policyPath, _ := request.Params.Arguments["policy_path"].(string)
		path, _ := request.Params.Arguments["path"].(string)
		filePath, _ := request.Params.Arguments["file_path"].(string)
		filePathGroup, _ := request.Params.Arguments["file_path_group"].(string)

		if reason != "" {
			params["reason"] = reason
		}
		if expiry != "" {
			params["expiry"] = expiry
		}
		if id != "" {
			params["id"] = expiry
		}
		if policyPath != "" {
			params["policy-path"] = policyPath
		}
		if path != "" {
			params["path"] = path
		}
		if filePath != "" {
			params["file-path"] = filePath
		}
		if filePathGroup != "" {
			params["file-path-group"] = filePathGroup
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

func (m *McpLLMBinding) snykSbomTestHandler(invocationCtx workflow.InvocationContext) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Extract parameters
		params := make(map[string]interface{})
		file, _ := request.Params.Arguments["file"].(string)

		params["json"] = true
		params["experimental"] = true
		if file != "" {
			params["file"] = file
		}
		// Build args and run command
		args := buildArgs(m.cliPath, "sbom", params)
		args = append(args, "test")

		output, err := m.runSnyk(ctx, invocationCtx, "", args)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResultText(output), nil
	}
}

func (m *McpLLMBinding) snykConfigHandler(invocationCtx workflow.InvocationContext) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Extract parameters
		params := make(map[string]interface{})
		subcommand, _ := request.Params.Arguments["subcommand"].(string)
		key, _ := request.Params.Arguments["key"].(string)
		value, _ := request.Params.Arguments["value"].(string)

		if key != "" {
			params["key"] = key
		}
		if value != "" {
			params["value"] = value
		}

		// Build args and run command
		args := buildArgs(m.cliPath, "config", params)
		args = append(args, subcommand)

		output, err := m.runSnyk(ctx, invocationCtx, "", args)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResultText(output), nil
	}
}

func (m *McpLLMBinding) snykConfigEnvironmentHandler(invocationCtx workflow.InvocationContext) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Extract parameters
		params := make(map[string]interface{})
		environment, _ := request.Params.Arguments["environment"].(string)
		noCheck, _ := request.Params.Arguments["no_check"].(bool)

		if noCheck {
			params["no-check"] = true
		}

		// Build args and run command
		args := buildArgs(m.cliPath, "config", params)
		args = append(args, "environment", environment)

		output, err := m.runSnyk(ctx, invocationCtx, "", args)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResultText(output), nil
	}
}

func (m *McpLLMBinding) snykPolicyHandler(invocationCtx workflow.InvocationContext) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Extract parameters
		params := make(map[string]interface{})
		path, _ := request.Params.Arguments["path"].(string)

		// Build args and run command
		args := buildArgs(m.cliPath, "policy", params)
		if path != "" {
			args = append(args, path)
		}

		output, err := m.runSnyk(ctx, invocationCtx, "", args)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResultText(output), nil
	}
}
