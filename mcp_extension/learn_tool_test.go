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
	"testing"
	// Core Go testing package

	"github.com/golang/mock/gomock"
	// Gomock for creating mock objects

	gaf_mocks "github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/stretchr/testify/require"

	// Testify for assertions
	// Mocks from the Go Application Framework, aliased

	"github.com/snyk/snyk-ls/infrastructure/learn/mock_learn"
	// Mock for the learn service

	"io"
	"net/http" // For http.DefaultClient

	"github.com/mark3labs/mcp-go/server" // For mcpServer in McpLLMBinding
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow" // Needed for LearnServiceFactoryFunc

	"github.com/snyk/snyk-ls/mcp_extension/trust" // For folderTrust in McpLLMBinding

	"context"
	"encoding/json"

	"github.com/mark3labs/mcp-go/mcp"

	"strings" // For URL assertions

	"github.com/snyk/snyk-ls/infrastructure/learn"
)

// learnTestFixture defines the test fixture.
// learnTestFixture defines the test fixture.
// Fields will be populated by setupLearnTestFixture.
// This structure is adapted from learnTestFixture in mcp_extension/scan_tool_test.go
type learnTestFixture struct {
	t                *testing.T
	mockCtrl         *gomock.Controller
	mockEngine       *gaf_mocks.MockEngine
	mockInvCtx       *gaf_mocks.MockInvocationContext
	mockLearnService *mock_learn.MockService
	binding          *McpLLMBinding
	loadedTools      *SnykMcpTools // Holds all tools loaded from snyk_tools.json
	capturedOpenURL  string        // To capture the URL passed to the mock open browser function
}

// setupLearnTestFixture initializes a new learnTestFixture for testing.
// It adapts the setup pattern from setupTestFixture in mcp_extension/scan_tool_test.go.
func setupLearnTestFixture(t *testing.T) *learnTestFixture {
	t.Helper()

	mockCtrl := gomock.NewController(t)

	// Mock GAF Engine & Configuration (similar to scan_tool_test.go)
	mockEngine := gaf_mocks.NewMockEngine(mockCtrl)
	mockNetworkAccess := gaf_mocks.NewMockNetworkAccess(mockCtrl) // Create MockNetworkAccess
	engineConfig := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
	mockEngine.EXPECT().GetNetworkAccess().Return(mockNetworkAccess).AnyTimes()                  // Expect GetNetworkAccess call
	mockNetworkAccess.EXPECT().GetUnauthorizedHttpClient().Return(http.DefaultClient).AnyTimes() // Expect GetUnauthorizedHttpClient call

	// Add a mock storage, as it might be accessed via config.SetStorage in McpLLMBinding or its dependencies
	mockStorage := gaf_mocks.NewMockStorage(mockCtrl)
	engineConfig.SetStorage(mockStorage)

	// Mock InvocationContext (similar to scan_tool_test.go)
	logger := zerolog.New(io.Discard) // Discard logs for cleaner test output
	mockInvCtx := gaf_mocks.NewMockInvocationContext(mockCtrl)
	mockInvCtx.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
	mockInvCtx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	mockInvCtx.EXPECT().GetEngine().Return(mockEngine).AnyTimes() // Needed for InitLearnService

	// Mock Learn Service
	mockLearnSvc := mock_learn.NewMockService(mockCtrl)

	// Define a test-specific factory that returns the mockLearnSvc
	testLearnServiceFactory := func(invCtx workflow.InvocationContext, testLogger *zerolog.Logger) learn.Service {
		return mockLearnSvc
	}

	// Initialize McpLLMBinding (as done in scan_tool_test.go for its fixture)
	// We don't need a real CLI path for these tests as learn tools don't directly call CLI.

	// fixtureRefForClosure is used to allow the mockOpenBrowser closure to refer to the fixture instance
	// once it's fully initialized.
	var fixtureRefForClosure **learnTestFixture
	mockOpenBrowser := func(url string) {
		if fixtureRefForClosure != nil && *fixtureRefForClosure != nil {
			(*fixtureRefForClosure).capturedOpenURL = url
		}
	}

	binding := NewMcpLLMBinding(
		WithLogger(&logger),
		WithOpenBrowserFunc(mockOpenBrowser),
		WithLearnServiceFactory(testLearnServiceFactory), // Use the test factory
	)
	binding.mcpServer = server.NewMCPServer("Snyk", "test-version") // Basic server for registration
	// Manually set learnService using the factory, simulating McpLLMBinding.Start() behavior
	// This ensures m.learnService is populated before addSnykTools is called.
	if binding.learnServiceFactory != nil {
		binding.learnService = binding.learnServiceFactory(mockInvCtx, &logger)
	} else {
		// Fallback or error if factory somehow wasn't set (should not happen with current NewMcpLLMBinding)
		t.Fatal("learnServiceFactory was not set on binding")
	}

	// Ensure the learnService on the binding is indeed our mock for sanity
	if _, ok := binding.learnService.(*mock_learn.MockService); !ok {
		t.Fatalf("binding.learnService is not the mock instance, type is %T", binding.learnService)
	}
	binding.folderTrust = trust.NewFolderTrust(&logger, engineConfig) // Initialize folderTrust

	// Load SnykMcpTools (tool definitions from JSON)
	// This function is defined in mcp_extension/scan_tool.go
	loadedTools, err := loadMcpToolsFromJson()
	require.NoError(t, err, "Failed to load SnykMcpTools from JSON")

	currentFixture := &learnTestFixture{
		t:                t,
		mockCtrl:         mockCtrl,
		mockEngine:       mockEngine,
		mockInvCtx:       mockInvCtx,
		mockLearnService: mockLearnSvc,
		binding:          binding,
		loadedTools:      loadedTools,
	}
	// Point fixtureRefForClosure to the address of currentFixture
	fixtureRefForClosure = &currentFixture

	// Call InitLearnService to ensure globalLearnService is set up if any part of the binding relies on it
	// even if we override globalLearnService directly for handler tests.
	// This also starts the cache maintenance goroutine if the real InitLearnService is called.
	// For handler unit tests, directly using the mocked globalLearnService is primary.
	// However, McpLLMBinding.Start calls InitLearnService. If we were testing Start, this would be critical.
	// For now, ensure the mock is in place.
	// The InitLearnService in learn_tool.go will use the globalLearnService we just set if it's called.
	// Let's ensure our mock is used by InitLearnService if it were to be called by the binding logic under test.
	// The most direct way for handler tests is that the handlers *themselves* use the global var.
	// InitLearnService(currentFixture.mockInvCtx, &logger) // This call overwrites the globalLearnService mock. Removing it.

	// Add Snyk tools to the binding's MCP server.
	// This step is crucial for the binding to know about the tools and their handlers.
	// The handlers for learn tools (snykGetAllLearnLessonsHandler, snykOpenLearnLessonHandler)
	// are methods on McpLLMBinding and will be registered here.
	err = currentFixture.binding.addSnykTools(currentFixture.mockInvCtx)
	require.NoError(t, err, "binding.addSnykTools failed")

	return currentFixture
}

func TestSnykGetAllLearnLessonsHandler_SuccessfulRetrieval(t *testing.T) {
	fixture := setupLearnTestFixture(t)
	toolName := SnykGetAllLearnLessons // Constant defined in scan_tool.go
	toolDef := getToolWithName(t, fixture.loadedTools, toolName)
	require.NotNil(t, toolDef, "Tool definition for %s not found", toolName)

	// Prepare mock lessons
	mockLessons := []learn.Lesson{
		{Title: "Lesson 1", Description: "Desc 1", Ecosystems: []string{"js", "ts"}},
		{Title: "Lesson 2", Description: "This course is no longer supported.", Ecosystems: []string{"java"}},
		{Title: "Lesson 3", Description: "Desc 3", Ecosystems: []string{"go"}},
	}
	expectedOutputLessons := []LessonOutput{ // LessonOutput is defined in learn_tool.go
		{Title: "Lesson 1", Description: "Desc 1", Ecosystems: "js & ts"},
		{Title: "Lesson 3", Description: "Desc 3", Ecosystems: "go"},
	}

	fixture.mockLearnService.EXPECT().GetAllLessons().Return(mockLessons, nil).Times(1)

	// Create request (no arguments needed for this tool)
	request := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Arguments: map[string]interface{}{},
		},
	}

	// Get the handler
	handler := fixture.binding.snykGetAllLearnLessonsHandler(fixture.mockInvCtx, *toolDef)

	// Call the handler
	result, err := handler(context.Background(), request)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Content, 1, "Expected one content item in the result")

	textContent, ok := result.Content[0].(mcp.TextContent)
	require.True(t, ok, "Expected result content to be mcp.TextContent")

	var actualOutputLessons []LessonOutput
	err = json.Unmarshal([]byte(textContent.Text), &actualOutputLessons)
	require.NoError(t, err, "Failed to unmarshal result text into []LessonOutput")

	require.Equal(t, expectedOutputLessons, actualOutputLessons, "Output lessons do not match expected lessons")
}

func TestSnykOpenLearnLessonHandler_SuccessfulOpening(t *testing.T) {
	fixture := setupLearnTestFixture(t)
	toolName := SnykOpenLearnLesson // Constant defined in scan_tool.go
	toolDef := getToolWithName(t, fixture.loadedTools, toolName)
	require.NotNil(t, toolDef, "Tool definition for %s not found", toolName)

	lessonTitleToOpen := "Found Lesson"
	lessonURL := "http://example.com/found"
	mockLessons := []learn.Lesson{
		{Title: "Another Lesson", Url: "http://example.com/another"},
		{Title: lessonTitleToOpen, Url: lessonURL, Ecosystems: []string{"js"}},
	}

	fixture.mockLearnService.EXPECT().GetAllLessons().Return(mockLessons, nil).Times(1)

	fixture.capturedOpenURL = "" // Reset before the call

	// Create request
	request := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Arguments: map[string]interface{}{
				"lessonTitle": lessonTitleToOpen,
			},
		},
	}

	// Get the handler
	handler := fixture.binding.snykOpenLearnLessonHandler(fixture.mockInvCtx, *toolDef)

	// Call the handler
	result, err := handler(context.Background(), request)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Content, 1, "Expected one content item in the result")

	textContent, ok := result.Content[0].(mcp.TextContent)
	require.True(t, ok, "Expected result content to be mcp.TextContent")

	expectedMessage := "Successfully requested to open lesson: " + lessonTitleToOpen
	require.Equal(t, expectedMessage, textContent.Text)

	// Assert that the mock open browser function was called with the correct URL
	require.True(t, strings.HasPrefix(fixture.capturedOpenURL, lessonURL), "Opened URL should start with the base lesson URL. Got: %s", fixture.capturedOpenURL)
	require.True(t, strings.Contains(fixture.capturedOpenURL, "loc=ide"), "Opened URL should contain 'loc=ide'. Got: %s", fixture.capturedOpenURL)

	// Test URL construction when original URL has query params
	lessonURLWithQuery := "http://example.com/found?param=true"
	mockLessonsWithQuery := []learn.Lesson{
		{Title: lessonTitleToOpen, Url: lessonURLWithQuery, Ecosystems: []string{"js"}},
	}
	fixture.mockLearnService.EXPECT().GetAllLessons().Return(mockLessonsWithQuery, nil).Times(1)
	fixture.capturedOpenURL = "" // Reset for next call

	_, err = handler(context.Background(), request) // Call handler again with new mock setup
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(fixture.capturedOpenURL, lessonURLWithQuery), "Opened URL should start with the base lesson URL with query. Got: %s", fixture.capturedOpenURL)
	require.True(t, strings.Contains(fixture.capturedOpenURL, "loc=ide"), "Opened URL should contain 'loc=ide'. Got: %s", fixture.capturedOpenURL)
	require.True(t, strings.Contains(fixture.capturedOpenURL, "&loc=ide"), "Opened URL should append with '&loc=ide' when query params exist. Got: %s", fixture.capturedOpenURL)
}
