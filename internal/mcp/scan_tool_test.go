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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/mark3labs/mcp-go/server"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testFixture struct {
	t                 *testing.T
	mockEngine        *mocks.MockEngine
	binding           *McpLLMBinding
	snykCliPath       string
	invocationContext *mocks.MockInvocationContext
	tools             *SnykToolsConfig
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
	tools, err := getSnykToolsConfig()
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

func TestMcpSnykToolRegistration(t *testing.T) {
	fixture := setupTestFixture(t)
	err := fixture.binding.addSnykTools(fixture.invocationContext)
	assert.NoError(t, err)
}

//
//func TestSnykTestHandler(t *testing.T) {
//	// Setup
//	fixture := setupTestFixture(t)
//
//	// Configure mock CLI to return a specific JSON response
//	mockOutput := `{
//		"ok": false,
//		"vulnerabilities": [
//			{
//				"id": "SNYK-JS-ACORN-559469",
//				"title": "Regular Expression Denial of Service (ReDoS)",
//				"severity": "high",
//				"packageName": "acorn"
//			},
//			{
//				"id": "SNYK-JS-TUNNELAGENT-1572284",
//				"title": "Uninitialized Memory Exposure",
//				"severity": "medium",
//				"packageName": "tunnel-agent"
//			}
//		],
//		"dependencyCount": 42,
//		"packageManager": "npm"
//	}`
//	fixture.mockCliOutput(mockOutput)
//	tool := getToolWithName(t, fixture.tools, SnykScaTest)
//	assert.NotNil(t, tool)
//	// Create the handler
//	handler := fixture.binding.snykTestHandler(fixture.invocationContext, *tool)
//
//	// Define test cases
//	testCases := []struct {
//		name           string
//		args           map[string]interface{}
//		expectedParams []string
//	}{
//		{
//			name: "Basic SCA Test",
//			args: map[string]interface{}{
//				"path":         "/test/path",
//				"all_projects": true,
//				"json":         true,
//			},
//			expectedParams: []string{"--all-projects", "--json"},
//		},
//		{
//			name: "Test with Organization",
//			args: map[string]interface{}{
//				"path":         "/test/path",
//				"all_projects": true,
//				"json":         true,
//				"org":          "my-snyk-org",
//			},
//			expectedParams: []string{"--all-projects", "--json", "--org=my-snyk-org"},
//		},
//		{
//			name: "Test with Severity Threshold",
//			args: map[string]interface{}{
//				"path":               "/test/path",
//				"all_projects":       false,
//				"json":               true,
//				"severity_threshold": "high",
//			},
//			expectedParams: []string{"--json", "--severity-threshold=high"},
//		},
//		{
//			name: "Test with Multiple Options",
//			args: map[string]interface{}{
//				"path":                           "/test/path",
//				"all_projects":                   true,
//				"json":                           true,
//				"severity_threshold":             "medium",
//				"dev":                            true,
//				"skip_unresolved":                true,
//				"prune_repeated_subdependencies": true,
//				"fail_on":                        "upgradable",
//			},
//			expectedParams: []string{
//				"--all-projects", "--json", "--severity-threshold=medium",
//				"--dev", "--skip-unresolved", "--prune-repeated-subdependencies",
//				"--fail-on=upgradable",
//			},
//		},
//	}
//
//	for _, tc := range testCases {
//		t.Run(tc.name, func(t *testing.T) {
//			// Call the handler
//			result, err := handler(context.Background(), mcp.CallToolRequest{
//				Params: mcp.ToolRequestParams{
//					Arguments: tc.args,
//				},
//			})
//
//			// Assertions
//			assert.NoError(t, err)
//			assert.NotNil(t, result)
//
//			// Verify the result is valid JSON
//			var jsonResult map[string]interface{}
//			err = json.Unmarshal([]byte(result.Result), &jsonResult)
//			assert.NoError(t, err, "Result is not valid JSON")
//
//			// Check the result has the expected fields
//			assert.Equal(t, false, jsonResult["ok"])
//			assert.Contains(t, jsonResult, "vulnerabilities")
//			assert.Contains(t, jsonResult, "dependencyCount")
//			assert.Contains(t, jsonResult, "packageManager")
//		})
//	}
//}
//
//func TestSnykCodeTestHandler(t *testing.T) {
//	// Setup
//	fixture := setupTestFixture(t)
//
//	// Configure mock CLI to return a specific JSON response for code test
//	mockOutput := `{
//		"ok": false,
//		"issues": [
//			{
//				"id": "javascript/sql-injection",
//				"title": "SQL Injection",
//				"severity": "high",
//				"path": "routes/index.js"
//			},
//			{
//				"id": "javascript/xss",
//				"title": "Cross-site Scripting (XSS)",
//				"severity": "medium",
//				"path": "views/search.jade"
//			}
//		],
//		"filesAnalyzed": 25
//	}`
//	fixture.mockCliOutput(mockOutput)
//
//	// Create the handler
//	handler := fixture.binding.snykCodeTestHandler(fixture.mockEngine)
//
//	// Test cases
//	testCases := []struct {
//		name           string
//		args           map[string]interface{}
//		expectedParams []string
//	}{
//		{
//			name: "Basic Code Test",
//			args: map[string]interface{}{
//				"path": "/test/path",
//				"json": true,
//			},
//			expectedParams: []string{"--json"},
//		},
//		{
//			name: "Code Test with File Parameter",
//			args: map[string]interface{}{
//				"path": "/test/path",
//				"file": "routes/index.js",
//				"json": true,
//			},
//			expectedParams: []string{"--json", "--file=routes/index.js"},
//		},
//		{
//			name: "Code Test with Organization",
//			args: map[string]interface{}{
//				"path": "/test/path",
//				"org":  "my-snyk-org",
//				"json": true,
//			},
//			expectedParams: []string{"--json", "--org=my-snyk-org"},
//		},
//		{
//			name: "Code Test with Multiple Parameters",
//			args: map[string]interface{}{
//				"path":               "/test/path",
//				"file":               "routes/index.js",
//				"json":               true,
//				"severity_threshold": "high",
//				"org":                "my-snyk-org",
//			},
//			expectedParams: []string{
//				"--json", "--file=routes/index.js",
//				"--severity-threshold=high", "--org=my-snyk-org",
//			},
//		},
//	}
//
//	for _, tc := range testCases {
//		t.Run(tc.name, func(t *testing.T) {
//			// Call the handler
//			result, err := handler(context.Background(), mcp.CallToolRequest{
//				Params: mcp.ToolRequestParams{
//					Arguments: tc.args,
//				},
//			})
//
//			// Assertions
//			assert.NoError(t, err)
//			assert.NotNil(t, result)
//
//			// Verify the result is valid JSON
//			var jsonResult map[string]interface{}
//			err = json.Unmarshal([]byte(result.Result), &jsonResult)
//			assert.NoError(t, err, "Result is not valid JSON")
//
//			// Check the result has the expected fields
//			assert.Equal(t, false, jsonResult["ok"])
//			assert.Contains(t, jsonResult, "issues")
//			assert.Contains(t, jsonResult, "filesAnalyzed")
//		})
//	}
//}

//func TestBasicSnykCommands(t *testing.T) {
//	// Setup
//	fixture := setupTestFixture(t)
//
//	// Test simple commands that don't take arguments
//	testCases := []struct {
//		name         string
//		handlerFunc  func(invocationCtx workflow.InvocationContext, toolDefinition SnykToolDefinition) func(ctx context.Context, arguments mcp.CallToolRequest) (*mcp.CallToolResult, error)
//		mockResponse string
//		expectedCmd  string
//	}{
//		{
//			name:         "Version Command",
//			handlerFunc:  fixture.binding.snykVersionHandler,
//			mockResponse: `{"client":{"version":"1.1192.0"}}`,
//			expectedCmd:  "version",
//		},
//		{
//			name:         "Auth Status Command",
//			handlerFunc:  fixture.binding.snykAuthStatusHandler,
//			mockResponse: `{"authenticated":true,"username":"user@example.com"}`,
//			expectedCmd:  "auth",
//		},
//		{
//			name:         "Logout Command",
//			handlerFunc:  fixture.binding.snykLogoutHandler,
//			mockResponse: `Successfully logged out`,
//			expectedCmd:  "logout",
//		},
//	}
//
//	for _, tc := range testCases {
//		t.Run(tc.name, func(t *testing.T) {
//			// Configure mock CLI
//			fixture.mockCliOutput(tc.mockResponse)
//
//			// Create the handler
//			handler := tc.handlerFunc(fixture.mockEngine)
//
//			// Call the handler
//			result, err := handler(context.Background(), mcp.CallToolRequest{
//				Params: mcp.ToolRequestParams{},
//			})
//
//			// Assertions
//			assert.NoError(t, err)
//			assert.NotNil(t, result)
//			assert.Equal(t, tc.mockResponse, result.Result)
//		})
//	}
//}
//
//func TestAuthHandler(t *testing.T) {
//	// Setup
//	fixture := setupTestFixture(t)
//
//	// Configure mock CLI
//	mockAuthResponse := `Your account has been authenticated. Snyk is now ready to be used.`
//	fixture.mockCliOutput(mockAuthResponse)
//
//	// Create the handler
//	handler := fixture.binding.snykAuthHandler(fixture.mockEngine)
//
//	// Call the handler
//	result, err := handler(context.Background(), mcp.CallToolRequest{
//		Params: mcp.ToolRequestParams{},
//	})
//
//	// Assertions
//	assert.NoError(t, err)
//	assert.NotNil(t, result)
//	assert.Equal(t, mockAuthResponse, result.Result)
//}

func TestGetSnykToolsConfig(t *testing.T) {
	config, err := getSnykToolsConfig()

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
		toolDefinition SnykToolDefinition
		expectedName   string
	}{
		{
			name: "Simple Tool",
			toolDefinition: SnykToolDefinition{
				Name:        "test_tool",
				Description: "Test tool description",
				Command:     "test",
				Params:      []SnykToolParameter{},
			},
			expectedName: "test_tool",
		},
		{
			name: "Tool with String Params",
			toolDefinition: SnykToolDefinition{
				Name:        "string_param_tool",
				Description: "Tool with string params",
				Command:     "test",
				Params: []SnykToolParameter{
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
			toolDefinition: SnykToolDefinition{
				Name:        "bool_param_tool",
				Description: "Tool with boolean params",
				Command:     "test",
				Params: []SnykToolParameter{
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
			toolDefinition: SnykToolDefinition{
				Name:        "mixed_param_tool",
				Description: "Tool with mixed params",
				Command:     "test",
				Params: []SnykToolParameter{
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
		toolDef            SnykToolDefinition
		arguments          map[string]interface{}
		expectedParamCount int
		expectedWorkingDir string
		expectedParams     map[string]interface{}
	}{
		{
			name: "Empty Request",
			toolDef: SnykToolDefinition{
				Name:   "test_tool",
				Params: []SnykToolParameter{},
			},
			arguments:          map[string]interface{}{},
			expectedParamCount: 0,
			expectedWorkingDir: "",
			expectedParams:     map[string]interface{}{},
		},
		{
			name: "String Parameters",
			toolDef: SnykToolDefinition{
				Name: "string_tool",
				Params: []SnykToolParameter{
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
			toolDef: SnykToolDefinition{
				Name: "bool_tool",
				Params: []SnykToolParameter{
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
			toolDef: SnykToolDefinition{
				Name: "mixed_tool",
				Params: []SnykToolParameter{
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
			toolDef: SnykToolDefinition{
				Name: "empty_string_tool",
				Params: []SnykToolParameter{
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
			toolDef: SnykToolDefinition{
				Name: "false_bool_tool",
				Params: []SnykToolParameter{
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
			expected: []string{"snyk", "test", "--org=my-org", "--json", "--all-projects"},
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
			assert.Equal(t, tc.expected, args)
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
