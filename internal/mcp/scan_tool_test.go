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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	// Snyk CLI mock
	tempDir := t.TempDir()
	snykCliPath := filepath.Join(tempDir, "snyk")
	if os.Getenv("GOOS") == "windows" {
		snykCliPath += ".bat"
	}

	// Create a default mock CLI that just echoes the command
	defaultMockResponse := "{\"ok\": true}"
	createMockSnykCli(t, snykCliPath, defaultMockResponse)

	// Create the binding
	binding := NewMcpLLMBinding(WithCliPath(snykCliPath), WithLogger(invocationCtx.GetEnhancedLogger()))
	binding.mcpServer = server.NewMCPServer("Snyk", "1.1.1")
	tools, err := loadMcpToolsFromJson()
	assert.NoError(t, err)
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
	assert.NoError(t, err)
}

func TestSnykTestHandler(t *testing.T) {
	// Setup
	fixture := setupTestFixture(t)

	// Configure mock CLI to return a specific JSON response
	mockOutput := `{ok": false,"vulnerabilities": [{"id": "SNYK-JS-ACORN-559469","title": "Regular Expression Denial of Service (ReDoS)","severity":"high","packageName": "acorn"},{"id": "SNYK-JS-TUNNELAGENT-1572284","title": "Uninitialized Memory Exposure","severity": "medium","packageName": "tunnel-agent"}],"dependencyCount": 42,"packageManager": "npm"}`
	fixture.mockCliOutput(mockOutput)
	tool := getToolWithName(t, fixture.tools, SnykScaTest)
	assert.NotNil(t, tool)
	// Create the handler
	handler := fixture.binding.snykTestHandler(fixture.invocationContext, *tool)

	tmpDir := t.TempDir()
	// Define test cases
	testCases := []struct {
		name           string
		args           map[string]interface{}
		expectedParams []string
	}{
		{
			name: "Basic SCA Test",
			args: map[string]interface{}{
				"path":         tmpDir,
				"all_projects": true,
				"json":         true,
			},
			expectedParams: []string{"--all-projects", "--json"},
		},
		{
			name: "Test with Organization",
			args: map[string]interface{}{
				"path":         tmpDir,
				"all_projects": true,
				"json":         true,
				"org":          "my-snyk-org",
			},
			expectedParams: []string{"--all-projects", "--json", "--org=my-snyk-org"},
		},
		{
			name: "Test with Severity Threshold",
			args: map[string]interface{}{
				"path":               tmpDir,
				"all_projects":       false,
				"json":               true,
				"severity_threshold": "high",
			},
			expectedParams: []string{"--json", "--severity-threshold=high"},
		},
		{
			name: "Test with Multiple Options",
			args: map[string]interface{}{
				"path":                           tmpDir,
				"all_projects":                   true,
				"json":                           true,
				"severity_threshold":             "medium",
				"dev":                            true,
				"skip_unresolved":                true,
				"prune_repeated_subdependencies": true,
				"fail_on":                        "upgradable",
			},
			expectedParams: []string{
				"--all-projects", "--json", "--severity-threshold=medium",
				"--dev", "--skip-unresolved", "--prune-repeated-subdependencies",
				"--fail-on=upgradable",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			requestObj := map[string]interface{}{
				"params": map[string]interface{}{
					"arguments": tc.args,
				},
			}
			requestJSON, err := json.Marshal(requestObj)
			assert.NoError(t, err, "Failed to marshal request to JSON")

			// Parse the JSON string to CallToolRequest
			var request mcp.CallToolRequest
			err = json.Unmarshal(requestJSON, &request)
			assert.NoError(t, err, "Failed to unmarshal JSON to CallToolRequest")

			result, err := handler(context.Background(), request)

			assert.NoError(t, err)
			assert.NotNil(t, result)

			textContent, ok := result.Content[0].(mcp.TextContent)
			assert.True(t, ok)
			content := strings.TrimSpace(textContent.Text)
			assert.Contains(t, content, "ok")
			assert.Contains(t, content, "vulnerabilities")
			assert.Contains(t, content, "dependencyCount")
			assert.Contains(t, content, "packageManager")
		})
	}
}

func TestSnykCodeTestHandler(t *testing.T) {
	// Setup
	fixture := setupTestFixture(t)

	// Configure mock CLI
	mockJsonResponse := `{"ok":false,"issues":[],"filesAnalyzed":10}`
	fixture.mockCliOutput(mockJsonResponse)

	// Get the tool definition
	toolDef := getToolWithName(t, fixture.tools, SnykCodeTest)

	// Create the handler
	handler := fixture.binding.snykCodeTestHandler(fixture.invocationContext, *toolDef)
	tmpDir := t.TempDir()
	// Test cases with various combinations of arguments
	testCases := []struct {
		name string
		args map[string]interface{}
	}{
		{
			name: "Basic Test",
			args: map[string]interface{}{
				"path": tmpDir,
			},
		},
		{
			name: "Test with Custom File",
			args: map[string]interface{}{
				"path": tmpDir,
				"file": "specific_file.js",
			},
		},
		{
			name: "Test with Severity Threshold",
			args: map[string]interface{}{
				"path":               tmpDir,
				"severity_threshold": "high",
			},
		},
		{
			name: "Test with Organization",
			args: map[string]interface{}{
				"path": tmpDir,
				"org":  "my-snyk-org",
			},
		},
		{
			name: "Test with All Options",
			args: map[string]interface{}{
				"path":               tmpDir,
				"file":               "specific_file.js",
				"severity_threshold": "high",
				"org":                "my-snyk-org",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			requestObj := map[string]interface{}{
				"params": map[string]interface{}{
					"arguments": tc.args,
				},
			}
			requestJSON, err := json.Marshal(requestObj)
			assert.NoError(t, err, "Failed to marshal request to JSON")

			var request mcp.CallToolRequest
			err = json.Unmarshal(requestJSON, &request)
			assert.NoError(t, err, "Failed to unmarshal JSON to CallToolRequest")

			result, err := handler(context.Background(), request)

			assert.NoError(t, err)
			assert.NotNil(t, result)
			textContent, ok := result.Content[0].(mcp.TextContent)
			assert.True(t, ok)
			content := strings.TrimSpace(textContent.Text)
			assert.Contains(t, content, "ok")
			assert.Contains(t, content, "issues")
			assert.Contains(t, content, "filesAnalyzed")
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
	}{
		{
			name:         "Version Command",
			handlerFunc:  fixture.binding.snykVersionHandler,
			mockResponse: `{"client":{"version":"1.1192.0"}}`,
			expectedCmd:  "version",
		},
		{
			name:         "Auth Status Command",
			handlerFunc:  fixture.binding.snykAuthStatusHandler,
			mockResponse: `{"authenticated":true,"username":"user@example.com"}`,
			expectedCmd:  "auth",
		},
		{
			name:         "Logout Command",
			handlerFunc:  fixture.binding.snykLogoutHandler,
			mockResponse: `Successfully logged out`,
			expectedCmd:  "logout",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Configure mock CLI
			fixture.mockCliOutput(tc.mockResponse)

			// Create the handler
			handler := tc.handlerFunc(fixture.invocationContext, SnykMcpToolsDefinition{})

			// Create an empty request object as JSON string
			requestObj := map[string]interface{}{
				"params": map[string]interface{}{
					"arguments": map[string]interface{}{},
				},
			}
			requestJSON, err := json.Marshal(requestObj)
			assert.NoError(t, err, "Failed to marshal request to JSON")

			// Parse the JSON string to CallToolRequest
			var request mcp.CallToolRequest
			err = json.Unmarshal(requestJSON, &request)
			assert.NoError(t, err, "Failed to unmarshal JSON to CallToolRequest")

			// Call the handler
			result, err := handler(context.Background(), request)

			// Assertions
			assert.NoError(t, err)
			assert.NotNil(t, result)
			textContent, ok := result.Content[0].(mcp.TextContent)
			assert.True(t, ok)
			assert.Equal(t, tc.mockResponse, strings.TrimSpace(textContent.Text))
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
	handler := fixture.binding.snykAuthHandler(fixture.invocationContext, SnykMcpToolsDefinition{})

	requestObj := map[string]interface{}{
		"params": map[string]interface{}{
			"arguments": map[string]interface{}{},
		},
	}
	requestJSON, err := json.Marshal(requestObj)
	assert.NoError(t, err, "Failed to marshal request to JSON")

	var request mcp.CallToolRequest
	err = json.Unmarshal(requestJSON, &request)
	assert.NoError(t, err, "Failed to unmarshal JSON to CallToolRequest")

	result, err := handler(context.Background(), request)

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, result)
	textContent, ok := result.Content[0].(mcp.TextContent)
	assert.True(t, ok)
	assert.Equal(t, mockAuthResponse, strings.TrimSpace(textContent.Text))
}

func TestGetSnykToolsConfig(t *testing.T) {
	config, err := loadMcpToolsFromJson()

	assert.NoError(t, err)
	assert.NotNil(t, config)
	assert.NotEmpty(t, config.Tools)

	toolNames := map[string]bool{
		SnykScaTest:    false,
		SnykCodeTest:   false,
		SnykVersion:    false,
		SnykAuth:       false,
		SnykAuthStatus: false,
		SnykLogout:     false,
	}

	for _, tool := range config.Tools {
		toolNames[tool.Name] = true
	}

	for name, found := range toolNames {
		assert.True(t, found, "Tool %s not found in configuration", name)
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
				Command:     "test",
				Params:      []SnykMcpToolParameter{},
			},
			expectedName: "test_tool",
		},
		{
			name: "Tool with String Params",
			toolDefinition: SnykMcpToolsDefinition{
				Name:        "string_param_tool",
				Description: "Tool with string params",
				Command:     "test",
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
				Description: "Tool with boolean params",
				Command:     "test",
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
				Description: "Tool with mixed params",
				Command:     "test",
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

			assert.NotNil(t, tool)
			assert.Equal(t, tc.expectedName, tool.Name)
		})
	}
}

func TestExtractParamsFromRequest(t *testing.T) {
	testCases := []struct {
		name               string
		toolDef            SnykMcpToolsDefinition
		arguments          map[string]interface{}
		expectedParamCount int
		expectedWorkingDir string
		expectedParams     map[string]interface{}
	}{
		{
			name: "Empty Request",
			toolDef: SnykMcpToolsDefinition{
				Name:   "test_tool",
				Params: []SnykMcpToolParameter{},
			},
			arguments:          map[string]interface{}{},
			expectedParamCount: 0,
			expectedWorkingDir: "",
			expectedParams:     map[string]interface{}{},
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
			arguments: map[string]interface{}{
				"org":  "my-org",
				"path": "/test/path",
			},
			expectedParamCount: 2,
			expectedWorkingDir: "/test/path",
			expectedParams: map[string]interface{}{
				"org":  "my-org",
				"path": "/test/path",
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
			arguments: map[string]interface{}{
				"json":         true,
				"all_projects": true,
			},
			expectedParamCount: 2,
			expectedWorkingDir: "",
			expectedParams: map[string]interface{}{
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
			arguments: map[string]interface{}{
				"path":               "/test/path",
				"json":               true,
				"severity_threshold": "high",
			},
			expectedParamCount: 3,
			expectedWorkingDir: "/test/path",
			expectedParams: map[string]interface{}{
				"path":               "/test/path",
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
			arguments: map[string]interface{}{
				"org": "",
			},
			expectedParamCount: 0,
			expectedWorkingDir: "",
			expectedParams:     map[string]interface{}{},
		},
		{
			name: "False Boolean Parameters",
			toolDef: SnykMcpToolsDefinition{
				Name: "false_bool_tool",
				Params: []SnykMcpToolParameter{
					{
						Name: "json",
						Type: "boolean",
					},
				},
			},
			arguments: map[string]interface{}{
				"json": false,
			},
			expectedParamCount: 0,
			expectedWorkingDir: "",
			expectedParams:     map[string]interface{}{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params, workingDir := extractParamsFromRequestArgs(tc.toolDef, tc.arguments)

			assert.Equal(t, tc.expectedWorkingDir, workingDir)

			assert.Equal(t, len(tc.expectedParams), len(params))

			for key, expectedValue := range tc.expectedParams {
				switch key {
				case "path":
					continue
				default:
					expectedKey := strings.ReplaceAll(key, "_", "-")
					actualValue, ok := params[expectedKey]
					assert.True(t, ok, "Parameter %s not found", expectedKey)
					assert.Equal(t, expectedValue, actualValue)
				}
			}
		})
	}
}

func TestBuildArgs(t *testing.T) {
	testCases := []struct {
		name     string
		cliPath  string
		command  string
		params   map[string]interface{}
		expected []string
	}{
		{
			name:     "No Parameters",
			cliPath:  "snyk",
			command:  "test",
			params:   map[string]interface{}{},
			expected: []string{"snyk", "test"},
		},
		{
			name:    "String Parameters",
			cliPath: "snyk",
			command: "test",
			params: map[string]interface{}{
				"org":  "my-org",
				"file": "package.json",
			},
			expected: []string{"snyk", "test", "--org=my-org", "--file=package.json"},
		},
		{
			name:    "Boolean Parameters",
			cliPath: "snyk",
			command: "test",
			params: map[string]interface{}{
				"json":         true,
				"all-projects": true,
			},
			expected: []string{"snyk", "test", "--json", "--all-projects"},
		},
		{
			name:    "Mixed Parameters",
			cliPath: "snyk",
			command: "test",
			params: map[string]interface{}{
				"org":          "my-org",
				"json":         true,
				"all-projects": true,
			},
			expected: []string{"snyk", "test", "--org=my-org", "--all-projects", "--json"},
		},
		{
			name:    "Empty String Parameters",
			cliPath: "snyk",
			command: "test",
			params: map[string]interface{}{
				"org": "",
			},
			expected: []string{"snyk", "test"},
		},
		{
			name:    "False Boolean Parameters",
			cliPath: "snyk",
			command: "test",
			params: map[string]interface{}{
				"json": false,
			},
			expected: []string{"snyk", "test"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			args := buildArgs(tc.cliPath, tc.command, tc.params)
			for _, arg := range args {
				assert.Contains(t, tc.expected, arg)
			}
		})
	}
}

func TestRunSnyk(t *testing.T) {
	fixture := setupTestFixture(t)

	ctx := context.Background()

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
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.mockOutput, strings.TrimSpace(output))
			}
		})
	}
}

func createMockSnykCli(t *testing.T, path, output string) {
	var script string

	if os.Getenv("GOOS") == "windows" {
		script = fmt.Sprintf(`@echo off
echo %s
exit /b 0
`, output)
	} else {
		script = fmt.Sprintf(`#!/bin/sh
echo "%s"
exit 0
`, output)
	}

	err := os.WriteFile(path, []byte(script), 0755)
	require.NoError(t, err)
}
