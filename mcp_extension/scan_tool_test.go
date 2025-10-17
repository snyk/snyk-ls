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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/infrastructure/authentication"

	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/infrastructure/learn/mock_learn"
	"github.com/snyk/snyk-ls/mcp_extension/trust"
)

type testFixture struct {
	t                 *testing.T
	mockEngine        *mocks.MockEngine
	binding           *McpLLMBinding
	snykCliPath       string
	invocationContext *mocks.MockInvocationContext
	tools             *SnykMcpTools
}

func SetupEngineMock(t *testing.T) (*mocks.MockEngine, configuration.Configuration) {
	t.Helper()
	ctrl := gomock.NewController(t)
	mockEngine := mocks.NewMockEngine(ctrl)
	engineConfig := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
	return mockEngine, engineConfig
}

func setupTestFixture(t *testing.T) *testFixture {
	t.Helper()
	engine, engineConfig := SetupEngineMock(t)
	logger := zerolog.New(io.Discard)

	mockctl := gomock.NewController(t)
	storage := mocks.NewMockStorage(mockctl)
	engineConfig.SetStorage(storage)

	invocationCtx := mocks.NewMockInvocationContext(mockctl)
	invocationCtx.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
	invocationCtx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	invocationCtx.EXPECT().GetRuntimeInfo().Return(runtimeinfo.New(runtimeinfo.WithName("hurz"), runtimeinfo.WithVersion("1000.8.3"))).AnyTimes()
	invocationCtx.EXPECT().GetEngine().Return(engine).AnyTimes()
	engine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
	_, expectedUserData := whoamiWorkflowResponse(t)
	engine.EXPECT().InvokeWithConfig(localworkflows.WORKFLOWID_WHOAMI, gomock.Any()).Return(expectedUserData, nil).AnyTimes()
	// Snyk CLI mock
	tempDir := t.TempDir()
	snykCliPath := filepath.Join(tempDir, "snyk")
	if runtime.GOOS == "windows" {
		snykCliPath += ".bat"
	}

	// Create a default mock CLI that just echoes the command
	defaultMockResponse := "{\"ok\": true}"
	createMockSnykCli(t, snykCliPath, defaultMockResponse)

	engineConfig.Set(trust.DisableTrustFlag, true)

	// Create the binding
	binding := NewMcpLLMBinding(WithCliPath(snykCliPath), WithLogger(invocationCtx.GetEnhancedLogger()))
	binding.folderTrust = trust.NewFolderTrust(&logger, invocationCtx.GetConfiguration())
	binding.mcpServer = server.NewMCPServer("Snyk", "1.1.1")

	// Create and set mock learn service
	mockLearnService := mock_learn.NewMockService(mockctl)
	mockLearnService.EXPECT().
		GetLesson(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&learn.Lesson{
			Url: "https://learn.snyk.io/lesson/mock-lesson",
		}, nil).
		AnyTimes()
	binding.learnService = mockLearnService

	tools, err := loadMcpToolsFromJson()
	require.NoError(t, err)
	return &testFixture{
		t:                 t,
		mockEngine:        engine,
		binding:           binding,
		snykCliPath:       snykCliPath,
		invocationContext: invocationCtx,
		tools:             tools,
	}
}

func (f *testFixture) mockCliOutput(output string) {
	createMockSnykCli(f.t, f.snykCliPath, output)
}

func getToolWithName(t *testing.T, tools *SnykMcpTools, toolName string) *SnykMcpToolsDefinition {
	t.Helper()
	for _, tool := range tools.Tools {
		if tool.Name == toolName {
			return &tool
		}
	}
	return nil
}

func TestMcpSnykToolRegistration(t *testing.T) {
	fixture := setupTestFixture(t)
	err := fixture.binding.addSnykTools(fixture.invocationContext)
	require.NoError(t, err)
}

func TestSnykTestHandler(t *testing.T) {
	// Setup
	fixture := setupTestFixture(t)

	// Configure mock CLI to return a specific JSON response
	mockOutput := `[{"ok": false,"vulnerabilities": [{"id": "SNYK-JS-ACORN-559469","title": "Regular Expression Denial of Service (ReDoS)","severity":"high","packageName": "acorn","version": "5.5.3","identifiers": {"CVE": ["CVE-2020-7598"],"CWE": ["CWE-400"]},"fixedIn": ["5.7.4", "6.4.1", "7.1.1"],"isUpgradable": true,"isPatchable": false,"upgradePath": ["my-app@1.0.0", "acorn@7.1.1"],"from": ["my-app@1.0.0", "acorn@5.5.3"],"packageManager": "npm"},{"id": "SNYK-JS-TUNNELAGENT-1572284","title": "Uninitialized Memory Exposure","severity": "medium","packageName": "tunnel-agent","version": "0.6.0","identifiers": {"CVE": [],"CWE": ["CWE-201"]},"fixedIn": [],"isUpgradable": false,"isPatchable": false,"upgradePath": [],"from": ["my-app@1.0.0", "tunnel-agent@0.6.0"],"packageManager": "npm"}],"dependencyCount": 42,"packageManager": "npm"}]`
	fixture.mockCliOutput(mockOutput)
	tool := getToolWithName(t, fixture.tools, SnykScaTest)
	require.NotNil(t, tool)
	// Create the handler
	handler := fixture.binding.defaultHandler(fixture.invocationContext, *tool)

	tmpDir := t.TempDir()
	// Define test cases
	testCases := []struct {
		name string
		args map[string]any
	}{
		{
			name: "Basic SCA Test",
			args: map[string]any{
				"path":         tmpDir,
				"all_projects": true,
				"json":         true,
			},
		},
		{
			name: "Test with PreferredOrg",
			args: map[string]any{
				"path":         tmpDir,
				"all_projects": true,
				"json":         true,
				"org":          "my-snyk-org",
			},
		},
		{
			name: "Test with Severity Threshold",
			args: map[string]any{
				"path":               tmpDir,
				"all_projects":       false,
				"json":               true,
				"severity_threshold": "high",
			},
		},
		{
			name: "Test with Multiple Options",
			args: map[string]any{
				"path":                           tmpDir,
				"all_projects":                   true,
				"json":                           true,
				"severity_threshold":             "medium",
				"dev":                            true,
				"skip_unresolved":                true,
				"prune_repeated_subdependencies": true,
				"fail_on":                        "upgradable",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			requestObj := map[string]any{
				"params": map[string]any{
					"arguments": tc.args,
				},
			}
			requestJSON, err := json.Marshal(requestObj)
			require.NoError(t, err, "Failed to marshal request to JSON")

			// Parse the JSON string to CallToolRequest
			var request mcp.CallToolRequest
			err = json.Unmarshal(requestJSON, &request)
			require.NoError(t, err, "Failed to unmarshal JSON to CallToolRequest")

			result, err := handler(t.Context(), request)

			require.NoError(t, err)
			require.NotNil(t, result)

			textContent, ok := result.Content[0].(mcp.TextContent)
			require.True(t, ok)
			content := strings.TrimSpace(textContent.Text)

			// Parse the enhanced JSON response
			var enhanced EnhancedScanResult
			err = json.Unmarshal([]byte(content), &enhanced)
			require.NoError(t, err, "Failed to parse enhanced scan result")

			// Debug output
			t.Logf("Enhanced result: %+v", enhanced)
			if len(enhanced.Issues) > 0 {
				t.Logf("First issue: %+v", enhanced.Issues[0])
			}

			// Check that we have both original output and issue data
			require.True(t, enhanced.Success)
			require.Equal(t, 2, enhanced.IssueCount)
			require.Len(t, enhanced.Issues, 2)

			// Verify we extracted the issues successfully
			// The actual issue verification is done in the dedicated test
		})
	}
}

func TestSnykCodeTestHandler(t *testing.T) {
	// Setup
	fixture := setupTestFixture(t)

	// Configure mock CLI with SARIF response
	mockJsonResponse := `{"runs":[{"tool":{"driver":{"rules":[{"id":"javascript/DangerousEval","shortDescription":{"text":"Code Injection"},"properties":{"cwe":["CWE-94","CWE-95"],"categories":["Security"]}}]}},"results":[{"ruleId":"javascript/DangerousEval","level":"warning","locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/app.js"},"region":{"startLine":10,"startColumn":5}}}]}]}]}`
	fixture.mockCliOutput(mockJsonResponse)

	// Get the tool definition
	toolDef := getToolWithName(t, fixture.tools, SnykCodeTest)

	// Create the handler
	handler := fixture.binding.defaultHandler(fixture.invocationContext, *toolDef)
	tmpDir := t.TempDir()
	// Test cases with various combinations of convertedToolParams
	testCases := []struct {
		name         string
		args         map[string]any
		requireTrust bool
	}{
		{
			name: "Basic Test",
			args: map[string]any{
				"path": tmpDir,
			},
		},
		{
			name: "Test with Custom File",
			args: map[string]any{
				"path": tmpDir,
				"file": "specific_file.js",
			},
		},
		{
			name: "Test with Severity Threshold",
			args: map[string]any{
				"path":               tmpDir,
				"severity_threshold": "high",
			},
		},
		{
			name: "Test with PreferredOrg",
			args: map[string]any{
				"path": tmpDir,
				"org":  "my-snyk-org",
			},
		},
		{
			name: "Test with All Options",
			args: map[string]any{
				"path":               tmpDir,
				"file":               "specific_file.js",
				"severity_threshold": "high",
				"org":                "my-snyk-org",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			requestObj := map[string]any{
				"params": map[string]any{
					"arguments": tc.args,
				},
			}
			fixture.invocationContext.GetConfiguration().Set(trust.DisableTrustFlag, !tc.requireTrust)
			requestJSON, err := json.Marshal(requestObj)
			require.NoError(t, err, "Failed to marshal request to JSON")

			var request mcp.CallToolRequest
			err = json.Unmarshal(requestJSON, &request)
			require.NoError(t, err, "Failed to unmarshal JSON to CallToolRequest")

			result, err := handler(t.Context(), request)
			require.NoError(t, err)
			require.NotNil(t, result)
			textContent, ok := result.Content[0].(mcp.TextContent)
			require.True(t, ok)
			content := strings.TrimSpace(textContent.Text)

			// Parse the enhanced JSON response
			var enhanced EnhancedScanResult
			err = json.Unmarshal([]byte(content), &enhanced)
			require.NoError(t, err, "Failed to parse enhanced scan result")

			// Check that we have both original output and issue data
			require.True(t, enhanced.Success)
			require.Equal(t, 1, enhanced.IssueCount)
			require.Len(t, enhanced.Issues, 1)

			// Verify we extracted the issues successfully
			// The actual issue verification is done in the dedicated test
		})
	}
}

func TestBasicSnykCommands(t *testing.T) {
	// Setup
	fixture := setupTestFixture(t)

	testCases := []struct {
		name         string
		handlerFunc  func(invocationCtx workflow.InvocationContext, toolDefinition SnykMcpToolsDefinition) func(ctx context.Context, arguments mcp.CallToolRequest) (*mcp.CallToolResult, error)
		mockResponse string
		expectedCmd  string
		command      []string
	}{
		{
			name:         "Version Command",
			handlerFunc:  fixture.binding.defaultHandler,
			command:      []string{"--version"},
			mockResponse: `{"client":{"version":"1.1192.0"}}`,
			expectedCmd:  "version",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Configure mock CLI
			fixture.mockCliOutput(tc.mockResponse)

			// Create the handler
			handler := tc.handlerFunc(fixture.invocationContext, SnykMcpToolsDefinition{Command: tc.command})

			// Create an empty request object as JSON string
			requestObj := map[string]any{
				"params": map[string]any{
					"arguments": map[string]any{},
				},
			}
			requestJSON, err := json.Marshal(requestObj)
			require.NoError(t, err, "Failed to marshal request to JSON")

			// Parse the JSON string to CallToolRequest
			var request mcp.CallToolRequest
			err = json.Unmarshal(requestJSON, &request)
			require.NoError(t, err, "Failed to unmarshal JSON to CallToolRequest")

			// Call the handler
			result, err := handler(t.Context(), request)

			// Assertions
			require.NoError(t, err)
			require.NotNil(t, result)
			textContent, ok := result.Content[0].(mcp.TextContent)
			require.True(t, ok)
			require.Equal(t, tc.mockResponse, strings.TrimSpace(textContent.Text))
		})
	}
}

func TestAuthHandler(t *testing.T) {
	// Setup
	fixture := setupTestFixture(t)

	// Configure mock CLI
	mockAuthResponse := "Authenticated Successfully"
	fixture.mockCliOutput(mockAuthResponse)

	// Create the handler
	handler := fixture.binding.defaultHandler(fixture.invocationContext, SnykMcpToolsDefinition{Command: []string{"auth"}})

	requestObj := map[string]any{
		"params": map[string]any{
			"arguments": map[string]any{},
		},
	}
	requestJSON, err := json.Marshal(requestObj)
	require.NoError(t, err, "Failed to marshal request to JSON")

	var request mcp.CallToolRequest
	err = json.Unmarshal(requestJSON, &request)
	require.NoError(t, err, "Failed to unmarshal JSON to CallToolRequest")

	result, err := handler(t.Context(), request)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	textContent, ok := result.Content[0].(mcp.TextContent)
	require.True(t, ok)
	require.Equal(t, mockAuthResponse, strings.TrimSpace(textContent.Text))
}

func TestGetSnykToolsConfig(t *testing.T) {
	config, err := loadMcpToolsFromJson()

	require.NoError(t, err)
	require.NotNil(t, config)
	require.NotEmpty(t, config.Tools)

	toolNames := map[string]bool{
		SnykScaTest:  false,
		SnykCodeTest: false,
		SnykVersion:  false,
		SnykAuth:     false,
		SnykLogout:   false,
	}

	for _, tool := range config.Tools {
		toolNames[tool.Name] = true
	}

	for name, found := range toolNames {
		require.True(t, found, "Tool %s not found in configuration", name)
	}
}

func TestCreateToolFromDefinition(t *testing.T) {
	testCases := []struct {
		name           string
		toolDefinition SnykMcpToolsDefinition
		expectedName   string
	}{
		{
			name: "Simple Tool",
			toolDefinition: SnykMcpToolsDefinition{
				Name:        "test_tool",
				Description: "Test tool description",
				Command:     []string{"test"},
				Params:      []SnykMcpToolParameter{},
			},
			expectedName: "test_tool",
		},
		{
			name: "Tool with String Params",
			toolDefinition: SnykMcpToolsDefinition{
				Name:        "string_param_tool",
				Description: "Tool with string convertedToolParams",
				Command:     []string{"test"},
				Params: []SnykMcpToolParameter{
					{
						Name:        "param1",
						Type:        "string",
						IsRequired:  true,
						Description: "Required string param",
					},
					{
						Name:        "param2",
						Type:        "string",
						IsRequired:  false,
						Description: "Optional string param",
					},
				},
			},
			expectedName: "string_param_tool",
		},
		{
			name: "Tool with Boolean Params",
			toolDefinition: SnykMcpToolsDefinition{
				Name:        "bool_param_tool",
				Description: "Tool with boolean convertedToolParams",
				Command:     []string{"test"},
				Params: []SnykMcpToolParameter{
					{
						Name:        "flag1",
						Type:        "boolean",
						IsRequired:  true,
						Description: "Required boolean param",
					},
					{
						Name:        "flag2",
						Type:        "boolean",
						IsRequired:  false,
						Description: "Optional boolean param",
					},
				},
			},
			expectedName: "bool_param_tool",
		},
		{
			name: "Tool with Mixed Params",
			toolDefinition: SnykMcpToolsDefinition{
				Name:        "mixed_param_tool",
				Description: "Tool with mixed convertedToolParams",
				Command:     []string{"test"},
				Params: []SnykMcpToolParameter{
					{
						Name:        "str_param",
						Type:        "string",
						IsRequired:  true,
						Description: "Required string param",
					},
					{
						Name:        "bool_flag",
						Type:        "boolean",
						IsRequired:  false,
						Description: "Optional boolean param",
					},
				},
			},
			expectedName: "mixed_param_tool",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tool := createToolFromDefinition(&tc.toolDefinition)

			require.NotNil(t, tool)
			require.Equal(t, tc.expectedName, tool.Name)
		})
	}
}

func TestExtractParamsFromRequest(t *testing.T) {
	dir := t.TempDir()
	testCases := []struct {
		name               string
		toolDef            SnykMcpToolsDefinition
		requestArgs        map[string]any
		expectedParamCount int
		expectedWorkingDir string
		expectedParams     map[string]any
	}{
		{
			name: "Empty Request",
			toolDef: SnykMcpToolsDefinition{
				Name:   "test_tool",
				Params: []SnykMcpToolParameter{},
			},
			requestArgs:        map[string]any{},
			expectedParamCount: 0,
			expectedWorkingDir: "",
			expectedParams:     map[string]any{},
		},
		{
			name: "String Parameters",
			toolDef: SnykMcpToolsDefinition{
				Name: "string_tool",
				Params: []SnykMcpToolParameter{
					{
						Name: "org",
						Type: "string",
					},
					{
						Name: "path",
						Type: "string",
					},
				},
			},
			requestArgs: map[string]any{
				"org":  "my-org",
				"path": dir,
			},
			expectedParamCount: 2,
			expectedWorkingDir: dir,
			expectedParams: map[string]any{
				"org":  "my-org",
				"path": dir,
			},
		},
		{
			name: "Boolean Parameters",
			toolDef: SnykMcpToolsDefinition{
				Name: "bool_tool",
				Params: []SnykMcpToolParameter{
					{
						Name: "json",
						Type: "boolean",
					},
					{
						Name: "all_projects",
						Type: "boolean",
					},
				},
			},
			requestArgs: map[string]any{
				"json":         true,
				"all_projects": true,
			},
			expectedParamCount: 2,
			expectedWorkingDir: "",
			expectedParams: map[string]any{
				"json":         true,
				"all-projects": true,
			},
		},
		{
			name: "Mixed Parameters",
			toolDef: SnykMcpToolsDefinition{
				Name: "mixed_tool",
				Params: []SnykMcpToolParameter{
					{
						Name: "path",
						Type: "string",
					},
					{
						Name: "json",
						Type: "boolean",
					},
					{
						Name: "severity_threshold",
						Type: "string",
					},
				},
			},
			requestArgs: map[string]any{
				"path":               dir,
				"json":               true,
				"severity_threshold": "high",
			},
			expectedParamCount: 3,
			expectedWorkingDir: dir,
			expectedParams: map[string]any{
				"path":               dir,
				"json":               true,
				"severity-threshold": "high",
			},
		},
		{
			name: "Empty String Parameters",
			toolDef: SnykMcpToolsDefinition{
				Name: "empty_string_tool",
				Params: []SnykMcpToolParameter{
					{
						Name: "org",
						Type: "string",
					},
				},
			},
			requestArgs: map[string]any{
				"org": "",
			},
			expectedParamCount: 0,
			expectedWorkingDir: "",
			expectedParams:     map[string]any{},
		},
		{
			name: "False Boolean Parameters",
			toolDef: SnykMcpToolsDefinition{
				Name: "false_bool_tool",
				Params: []SnykMcpToolParameter{
					{
						Name: "all_projects",
						Type: "boolean",
					},
				},
			},
			requestArgs: map[string]any{
				"all-projects": false,
			},
			expectedParamCount: 0,
			expectedWorkingDir: "",
			expectedParams:     map[string]any{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params, workingDir, err := normalizeParamsAndDetermineWorkingDir(tc.toolDef, tc.requestArgs)
			require.NoError(t, err)
			require.Equal(t, tc.expectedWorkingDir, workingDir)

			// assert only empty string parameters are there if we don't expect any - they'll be filtered in buildArgs
			if tc.expectedParamCount == 0 {
				for _, parameter := range params {
					if strings.ToLower(parameter.Type) == "string" {
						require.Equalf(t, "", parameter.value, "Parameter %s should not be set", parameter.Name)
					} else {
						require.Failf(t, "Parameter %s should not be set", parameter.Name)
					}
				}
			}

			// assert each of the expected parameters is set
			for key, value := range tc.expectedParams {
				positional := false
				for _, param := range tc.toolDef.Params {
					if param.Name == key && param.IsPositional {
						positional = true
						break
					}
				}

				if positional {
					continue
				}

				expectedKey := strings.ReplaceAll(key, "_", "-")
				actualValue, ok := params[expectedKey]
				require.True(t, ok, "Parameter %s not found", expectedKey)
				require.Equal(t, value, actualValue.value)
			}
		})
	}
}

func TestBuildCommand(t *testing.T) {
	testCases := []struct {
		name                string
		cliPath             string
		command             []string
		convertedToolParams map[string]convertedToolParameter
		expected            []string
	}{
		{
			name:                "No Parameters",
			cliPath:             "snyk",
			command:             []string{"test"},
			convertedToolParams: map[string]convertedToolParameter{},
			expected:            []string{"snyk", "test"},
		},
		{
			name:    "String Parameters",
			cliPath: "snyk",
			command: []string{"test"},
			convertedToolParams: map[string]convertedToolParameter{
				"org": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "org",
						Type: "string",
					},
					value: "my-org",
				},
				"file": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "file",
						Type: "string",
					},
					value: "package.json",
				},
			},
			expected: []string{"snyk", "test", "--org=my-org", "--file=package.json"},
		},
		{
			name:    "Boolean Parameters",
			cliPath: "snyk",
			command: []string{"test"},
			convertedToolParams: map[string]convertedToolParameter{
				"all-projects": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "all-projects",
						Type: "boolean",
					},
					value: true,
				},
			},
			expected: []string{"snyk", "test", "--all-projects"},
		},
		{
			name:    "Mixed Parameters",
			cliPath: "snyk",
			command: []string{"test"},
			convertedToolParams: map[string]convertedToolParameter{
				"org": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "org",
						Type: "string",
					},
					value: "my-org",
				},
				"all-projects": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "all-projects",
						Type: "boolean",
					},
					value: true,
				},
			},
			expected: []string{"snyk", "test", "--org=my-org", "--all-projects"},
		},
		{
			name:    "Empty String Parameters",
			cliPath: "snyk",
			command: []string{"test"},
			convertedToolParams: map[string]convertedToolParameter{
				"org": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "org",
						Type: "string",
					},
					value: "",
				},
			},
			expected: []string{"snyk", "test"},
		},
		{
			name:    "False Boolean Parameters",
			cliPath: "snyk",
			command: []string{"test"},
			convertedToolParams: map[string]convertedToolParameter{
				"all-projects": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "all-projects",
						Type: "boolean",
					},
					value: false,
				},
			},
			expected: []string{"snyk", "test"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			args := buildCommand(tc.cliPath, tc.command, tc.convertedToolParams)
			for _, arg := range tc.expected {
				require.Contains(t, args, arg)
			}
			require.Len(t, tc.expected, len(args))
		})
	}
}

func TestRunSnyk(t *testing.T) {
	fixture := setupTestFixture(t)

	ctx := t.Context()

	testCases := []struct {
		name        string
		mockOutput  string
		command     []string
		workingDir  string
		expectError bool
	}{
		{
			name:        "Successful Command",
			mockOutput:  "Command executed successfully",
			command:     []string{fixture.snykCliPath, "test"},
			workingDir:  "",
			expectError: false,
		},
		{
			name:        "Command with Working Directory",
			mockOutput:  "Command executed successfully",
			command:     []string{fixture.snykCliPath, "test"},
			workingDir:  t.TempDir(),
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fixture.mockCliOutput(tc.mockOutput)

			output, err := fixture.binding.runSnyk(ctx, fixture.invocationContext, tc.workingDir, tc.command)

			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.mockOutput, strings.TrimSpace(output))
			}
		})
	}
}

func createMockSnykCli(t *testing.T, path, output string) {
	t.Helper()
	createMockSnykCliWithExitCode(t, path, output, 0)
}

func createMockSnykCliWithExitCode(t *testing.T, path, output string, exitCode int) {
	t.Helper()

	var script string

	if runtime.GOOS == "windows" {
		script = fmt.Sprintf(`@echo off
echo %s
exit /b %d
`, output, exitCode)
	} else {
		script = fmt.Sprintf(`#!/bin/sh
echo '%s'
exit %d
`, output, exitCode)
	}

	err := os.WriteFile(path, []byte(script), 0755)
	require.NoError(t, err)
}

func TestPrepareCmdArgsForTool(t *testing.T) {
	dir := t.TempDir()
	tempFile, err := os.CreateTemp(dir, t.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = tempFile.Close()
	})

	nopLogger := zerolog.Nop()

	testCases := []struct {
		name           string
		toolDef        SnykMcpToolsDefinition
		requestArgs    map[string]any
		expectedParams map[string]convertedToolParameter
		expectedWd     string
	}{
		{
			name: "Basic string & bool convertedToolParams, path extraction",
			toolDef: SnykMcpToolsDefinition{
				Params: []SnykMcpToolParameter{
					{Name: "path", Type: "string", IsPositional: true},
					{Name: "all_projects", Type: "boolean"},
					{Name: "org", Type: "string"},
				},
			},
			requestArgs: map[string]any{
				"path":         dir,
				"all_projects": true,
				"org":          "my-org-name",
				"unused_param": "",
			},
			expectedParams: map[string]convertedToolParameter{
				"path": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name:         "path",
						Type:         "string",
						IsPositional: true,
					},
					value: dir,
				},
				"all-projects": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "all-projects",
						Type: "boolean",
					},
					value: true,
				},
				"org": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "org",
						Type: "string",
					},
					value: "my-org-name",
				},
			},
			expectedWd: dir,
		},
		{
			name: "path with file given",
			toolDef: SnykMcpToolsDefinition{
				Params: []SnykMcpToolParameter{
					{Name: "all-projects", Type: "boolean"},
					{Name: "org", Type: "string"},
					{Name: "path", Type: "string", IsPositional: true},
				},
			},
			requestArgs: map[string]any{
				"all-projects": true,
				"org":          "my-org-name",
				"path":         tempFile.Name(),
			},
			expectedParams: map[string]convertedToolParameter{
				"all-projects": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "all-projects",
						Type: "boolean",
					},
					value: true,
				},
				"org": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "org",
						Type: "string",
					},
					value: "my-org-name",
				},
				"path": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name:         "path",
						Type:         "string",
						IsPositional: true,
					},
					value: tempFile.Name(),
				},
			},
			expectedWd: dir,
		},
		{
			name: "no path given",
			toolDef: SnykMcpToolsDefinition{
				Params: []SnykMcpToolParameter{
					{Name: "all_projects", Type: "boolean"},
					{Name: "org", Type: "string"},
				},
			},
			requestArgs: map[string]any{
				"all_projects": true,
				"org":          "my-org-name",
			},
			expectedParams: map[string]convertedToolParameter{
				"all-projects": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "all-projects",
						Type: "boolean",
					},
					value: true,
				},
				"org": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "org",
						Type: "string",
					},
					value: "my-org-name",
				},
			},
			expectedWd: "",
		},
		{
			name: "Standard convertedToolParams addition",
			toolDef: SnykMcpToolsDefinition{
				Params: []SnykMcpToolParameter{
					{Name: "file", Type: "string"},
				},
				StandardParams: []string{"json", "debug_mode"},
			},
			requestArgs: map[string]any{
				"file": "package.json",
			},
			expectedParams: map[string]convertedToolParameter{
				"file": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "file",
						Type: "string",
					},
					value: "package.json",
				},
				"json": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "json",
						Type: "boolean",
					},
					value: true,
				},
				"debug-mode": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "debug-mode",
						Type: "boolean",
					},
					value: true,
				},
			},
			expectedWd: "",
		},
		{
			name: "Supersedence: 'file' supersedes 'all_projects' (both in request)",
			toolDef: SnykMcpToolsDefinition{
				Params: []SnykMcpToolParameter{
					{Name: "file", Type: "string", SupersedesParams: []string{"all_projects"}},
					{Name: "all_projects", Type: "boolean"},
					{Name: "json", Type: "boolean"},
				},
			},
			requestArgs: map[string]any{
				"file":        "pom.xml",
				"allprojects": true,
				"json":        true,
			},
			expectedParams: map[string]convertedToolParameter{
				"file": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name:             "file",
						Type:             "string",
						SupersedesParams: []string{"all_projects"},
					},
					value: "pom.xml",
				},
				"json": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "json",
						Type: "boolean",
					},
					value: true,
				},
			},
			expectedWd: "",
		},
		{
			name: "Supersedence: 'file' (in request) supersedes 'all_projects' (from standard_params)",
			toolDef: SnykMcpToolsDefinition{
				Params: []SnykMcpToolParameter{
					{Name: "file", Type: "string", SupersedesParams: []string{"all_projects"}},
					{Name: "json", Type: "boolean"},
				},
				StandardParams: []string{"all_projects", "debug"}, // all_projects will be added as standard
			},
			requestArgs: map[string]any{
				"file": "pom.xml",
				"json": true,
			},
			expectedParams: map[string]convertedToolParameter{
				"file": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name:             "file",
						Type:             "string",
						SupersedesParams: []string{"all_projects"},
					},
					value: "pom.xml",
				},
				"json": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "json",
						Type: "boolean",
					},
					value: true,
				},
				"debug": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "debug",
						Type: "boolean",
					},
					value: true,
				},
			},
			expectedWd: "",
		},
		{
			name: "No request args, only standard convertedToolParams",
			toolDef: SnykMcpToolsDefinition{
				StandardParams: []string{"json", "all_projects"},
			},
			requestArgs: map[string]any{},
			expectedParams: map[string]convertedToolParameter{
				"all-projects": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "all-projects",
						Type: "boolean",
					},
					value: true,
				},
				"json": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "json",
						Type: "boolean",
					},
					value: true,
				},
			},
			expectedWd: "",
		},
		{
			name: "Path is provided but not a string",
			toolDef: SnykMcpToolsDefinition{
				Params: []SnykMcpToolParameter{
					{Name: "path", Type: "string", IsPositional: true},
				},
			},
			requestArgs: map[string]any{
				"path": 123,
			},
			expectedParams: map[string]convertedToolParameter{
				"path": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name:         "path",
						Type:         "string",
						IsPositional: true,
					},
					value: 123,
				}},
			expectedWd: "", // Path extraction fails if not string
		},
		{
			name: "Boolean param in request is false",
			toolDef: SnykMcpToolsDefinition{
				Params: []SnykMcpToolParameter{
					{Name: "all_projects", Type: "boolean"},
				},
			},
			requestArgs: map[string]any{
				"all-projects": false,
			},
			expectedParams: map[string]convertedToolParameter{}, // False booleans are not added
			expectedWd:     "",
		},
		{
			name: "String param in request is empty string",
			toolDef: SnykMcpToolsDefinition{
				Params: []SnykMcpToolParameter{
					{Name: "org", Type: "string"},
				},
			},
			requestArgs: map[string]any{
				"org": "",
			},
			expectedParams: map[string]convertedToolParameter{
				"org": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "org",
						Type: "string",
					},
					value: "",
				}},
			expectedWd: "",
		},
		{
			name: "Supersedence: multiple convertedToolParams superseded",
			toolDef: SnykMcpToolsDefinition{
				Params: []SnykMcpToolParameter{
					{Name: "package_manager", Type: "string", SupersedesParams: []string{"all_projects", "file"}},
					{Name: "all_projects", Type: "boolean"},
					{Name: "file", Type: "string"},
					{Name: "json", Type: "boolean"},
				},
			},
			requestArgs: map[string]any{
				"package_manager": "npm",
				"all_projects":    true,
				"file":            "package-lock.json",
				"json":            true,
			},
			expectedParams: map[string]convertedToolParameter{
				"package-manager": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name:             "package-manager",
						Type:             "string",
						SupersedesParams: []string{"all_projects", "file"},
					},
					value: "npm",
				},
				"json": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "json",
						Type: "boolean",
					},
					value: true,
				},
			},
			expectedWd: "",
		},
		{
			name: "Supersedence: superseded param not in request, but in standard convertedToolParams",
			toolDef: SnykMcpToolsDefinition{
				Params: []SnykMcpToolParameter{
					{Name: "org", Type: "string", SupersedesParams: []string{"dev"}},
				},
				StandardParams: []string{"dev", "json"},
			},
			requestArgs: map[string]any{
				"org": "my-org",
			},
			expectedParams: map[string]convertedToolParameter{
				//"org":  "my-org",
				//"json": true, // dev is removed
				"org": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name:             "org",
						Type:             "string",
						SupersedesParams: []string{"dev"},
					},
					value: "my-org",
				},
				"json": {
					SnykMcpToolParameter: SnykMcpToolParameter{
						Name: "json",
						Type: "boolean",
					},
					value: true,
				},
			},
			expectedWd: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actualParams, actualWd, err := prepareCmdArgsForTool(&nopLogger, tc.toolDef, tc.requestArgs)
			require.NoError(t, err)
			require.EqualValues(t, tc.expectedParams, actualParams, "Parameter map mismatch")
			require.Equal(t, tc.expectedWd, actualWd, "Working directory mismatch")
		})
	}
}

func TestSnykTrustHandler(t *testing.T) {
	fixture := setupTestFixture(t)
	toolDef := getToolWithName(t, fixture.tools, SnykTrust)
	require.NotNil(t, toolDef, "snyk_trust tool definition not found")
	fixture.invocationContext.GetConfiguration().Set(trust.DisableTrustFlag, false)

	handler := fixture.binding.snykTrustHandler(fixture.invocationContext, *toolDef)

	t.Run("PathMissing", func(t *testing.T) {
		request := mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Arguments: map[string]interface{}{},
			},
		}

		result, err := handler(t.Context(), request)

		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "argument 'path' is missing for tool snyk_trust")
	})

	t.Run("PathEmpty", func(t *testing.T) {
		request := mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Arguments: map[string]interface{}{"path": ""},
			},
		}

		result, err := handler(t.Context(), request)

		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "empty path given to tool snyk_trust")
	})
}

func whoamiWorkflowResponse(t *testing.T) (*authentication.ActiveUser, []workflow.Data) {
	t.Helper()
	expectedUser := authentication.ActiveUser{
		Id:       "id",
		UserName: "username",
	}
	expectedUserJSON, err := json.Marshal(expectedUser)
	require.NoError(t, err)

	expectedUserData := []workflow.Data{
		workflow.NewData(
			workflow.NewTypeIdentifier(localworkflows.WORKFLOWID_WHOAMI, "payload"),
			"application/json",
			expectedUserJSON),
	}
	return &expectedUser, expectedUserData
}

func TestGetCodeEnablementUrl(t *testing.T) {
	tests := []struct {
		name        string
		apiUrl      string
		expectedUrl string
	}{
		{
			name:        "Standard API URL",
			apiUrl:      "https://api.snyk.io",
			expectedUrl: "https://app.snyk.io/manage/snyk-code?from=snyk-ls",
		},
		{
			name:        "API URL with path",
			apiUrl:      "https://api.snyk.io/api",
			expectedUrl: "https://app.snyk.io/manage/snyk-code?from=snyk-ls",
		},
		{
			name:        "Custom endpoint",
			apiUrl:      "https://api.custom.snyk.io",
			expectedUrl: "https://app.custom.snyk.io/manage/snyk-code?from=snyk-ls",
		},
		{
			name:        "Custom endpoint with /api path",
			apiUrl:      "https://custom.endpoint.com/api",
			expectedUrl: "https://app.custom.endpoint.com/manage/snyk-code?from=snyk-ls",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := configuration.NewWithOpts()
			config.Set(configuration.API_URL, tc.apiUrl)

			result := getCodeEnablementUrl(config)
			require.Equal(t, tc.expectedUrl, result)
		})
	}
}

func TestDetectSastNotEnabledError(t *testing.T) {
	tests := []struct {
		name     string
		output   string
		expected bool
	}{
		{
			name:     "Snyk Code is not enabled (lowercase)",
			output:   "Error: snyk code is not enabled for your organization",
			expected: true,
		},
		{
			name:     "Snyk Code is not enabled (capitalized)",
			output:   "Error: Snyk Code is not enabled for your organization",
			expected: true,
		},
		{
			name:     "Snyk Code is not supported for org",
			output:   "Snyk Code is not supported for org test-org-123",
			expected: true,
		},
		{
			name:     "Enable in Settings message",
			output:   "Please enable in Settings > Snyk Code",
			expected: true,
		},
		{
			name:     "SAST is not enabled",
			output:   "SAST is not enabled",
			expected: true,
		},
		{
			name:     "Code analysis is not enabled",
			output:   "Code analysis is not enabled for your account",
			expected: true,
		},
		{
			name:     "Code is not supported",
			output:   "code is not supported for this organization",
			expected: true,
		},
		{
			name:     "Generic is not enabled for pattern",
			output:   "Snyk Code is not enabled for your organization",
			expected: true,
		},
		{
			name:     "Different error - Authentication (should not match)",
			output:   "Error: Authentication failed",
			expected: false,
		},
		{
			name:     "Different error - No vulnerabilities (should not match)",
			output:   "No vulnerabilities found",
			expected: false,
		},
		{
			name:     "Empty output (should not match)",
			output:   "",
			expected: false,
		},
		{
			name:     "Unrelated error message (should not match)",
			output:   "Error: Network timeout occurred",
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := detectSastNotEnabledError(tc.output)
			require.Equal(t, tc.expected, result)
		})
	}
}

func TestSnykCodeTestHandler_SastNotEnabled(t *testing.T) {
	fixture := setupTestFixture(t)
	toolDef := getToolWithName(t, fixture.tools, SnykCodeTest)
	require.NotNil(t, toolDef, "snyk_code_scan tool definition not found")

	// Create a mock CLI that returns realistic SAST not enabled error with exit code 2
	// Note: `snyk code test --sarif` returns plain text errors, not JSON
	sastNotEnabledResponse := "Snyk Code is not supported for org test-org. Please enable in Settings > Snyk Code"
	createMockSnykCliWithExitCode(t, fixture.snykCliPath, sastNotEnabledResponse, 2)

	// Mock browser opening to capture the URL
	browserOpened := false
	var capturedUrl string
	fixture.binding.openBrowserFunc = func(url string) {
		browserOpened = true
		capturedUrl = url
	}

	handler := fixture.binding.snykCodeTestHandler(fixture.invocationContext, *toolDef)

	t.Run("Detects SAST not enabled, opens browser, and returns enhanced error", func(t *testing.T) {
		testPath := t.TempDir()
		request := mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Arguments: map[string]interface{}{
					"path": testPath,
				},
			},
		}

		result, err := handler(t.Context(), request)

		require.NoError(t, err)
		require.NotNil(t, result)

		// Verify browser was opened
		require.True(t, browserOpened, "Browser should have been opened automatically")
		require.Contains(t, capturedUrl, "/manage/snyk-code?from=snyk-ls")

		// Verify enhanced error message
		textContent, ok := result.Content[0].(mcp.TextContent)
		require.True(t, ok)
		require.Contains(t, textContent.Text, "Snyk Code (SAST) is not enabled")
		require.Contains(t, textContent.Text, "I've opened the Snyk Code enablement page")
		require.Contains(t, textContent.Text, "organization admin permissions")
		require.Contains(t, textContent.Text, "/manage/snyk-code?from=snyk-ls")
		require.NotContains(t, textContent.Text, "snyk_enable_code", "Should not mention separate tool anymore")
	})
}

func TestSnykCodeTestHandler_Success(t *testing.T) {
	fixture := setupTestFixture(t)
	toolDef := getToolWithName(t, fixture.tools, SnykCodeTest)
	require.NotNil(t, toolDef, "snyk_code_scan tool definition not found")

	// Create a mock CLI that returns successful SARIF output
	successResponse := `{"runs":[{"tool":{"driver":{"name":"SnykCode"}},"results":[]}]}`
	createMockSnykCli(t, fixture.snykCliPath, successResponse)

	handler := fixture.binding.snykCodeTestHandler(fixture.invocationContext, *toolDef)

	t.Run("Returns success response when SAST is enabled", func(t *testing.T) {
		testPath := t.TempDir()
		request := mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Arguments: map[string]interface{}{
					"path": testPath,
				},
			},
		}

		result, err := handler(t.Context(), request)

		require.NoError(t, err)
		require.NotNil(t, result)

		textContent, ok := result.Content[0].(mcp.TextContent)
		require.True(t, ok)
		// Should not contain error message about SAST not being enabled
		require.NotContains(t, textContent.Text, "SAST is not enabled")
		require.NotContains(t, textContent.Text, "snyk_enable_code")
	})
}
