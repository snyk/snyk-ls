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
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/infrastructure/learn/mock_learn"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestSnykOpenLearnLessonHandler(t *testing.T) {
	t.Run("opens lesson successfully with all parameters", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockLearnService := mock_learn.NewMockService(ctrl)
		logger := zerolog.Nop()
		var openedURL string

		mcpBinding := &McpLLMBinding{
			logger:       &logger,
			learnService: mockLearnService,
			openBrowserFunc: func(url string) {
				openedURL = url
			},
		}

		expectedLesson := &learn.Lesson{
			LessonId: "lesson1",
			Title:    "Test Lesson",
			Url:      "https://learn.snyk.io/lesson1",
		}

		mockLearnService.EXPECT().GetLesson(
			"javascript",
			"SNYK-JS-ASYNC-2441827",
			[]string{"CWE-601"},
			[]string{"CVE-2024-1234"},
			types.DependencyVulnerability,
		).Return(expectedLesson, nil)

		toolDef := SnykMcpToolsDefinition{Name: "test_tool"}
		handler := mcpBinding.snykOpenLearnLessonHandler(nil, toolDef)

		request := createMockRequest(map[string]interface{}{
			"issueType": "sca",
			"cves":      "CVE-2024-1234",
			"cwes":      "CWE-601",
			"rule":      "SNYK-JS-ASYNC-2441827",
			"ecosystem": "javascript",
		})

		result, err := handler(t.Context(), request)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		textContent, ok := result.Content[0].(mcp.TextContent)
		require.True(t, ok)
		assert.Contains(t, textContent.Text, "Successfully requested to open lesson: Test Lesson")
		assert.Equal(t, "https://learn.snyk.io/lesson1?loc=MCP", openedURL)
	})

	t.Run("opens lesson successfully with SAST issue type", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockLearnService := mock_learn.NewMockService(ctrl)
		logger := zerolog.Nop()
		var openedURL string

		mcpBinding := &McpLLMBinding{
			logger:       &logger,
			learnService: mockLearnService,
			openBrowserFunc: func(url string) {
				openedURL = url
			},
		}

		expectedLesson := &learn.Lesson{
			LessonId: "lesson1",
			Title:    "SQL Injection Lesson",
			Url:      "https://learn.snyk.io/lesson1",
		}

		mockLearnService.EXPECT().GetLesson(
			"javascript",
			"javascript/sqlinjection",
			[]string{"CWE-89"},
			[]string{},
			types.CodeSecurityVulnerability,
		).Return(expectedLesson, nil)

		toolDef := SnykMcpToolsDefinition{Name: "test_tool"}
		handler := mcpBinding.snykOpenLearnLessonHandler(nil, toolDef)

		request := createMockRequest(map[string]interface{}{
			"issueType": "sast",
			"cwes":      "CWE-89",
			"rule":      "javascript/sqlinjection",
			"ecosystem": "javascript",
		})

		result, err := handler(t.Context(), request)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		textContent, ok := result.Content[0].(mcp.TextContent)
		require.True(t, ok)
		assert.Contains(t, textContent.Text, "Successfully requested to open lesson: SQL Injection Lesson")
		assert.Equal(t, "https://learn.snyk.io/lesson1?loc=MCP", openedURL)
	})

	t.Run("opens lesson with existing query parameters", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockLearnService := mock_learn.NewMockService(ctrl)
		logger := zerolog.Nop()
		var openedURL string

		mcpBinding := &McpLLMBinding{
			logger:       &logger,
			learnService: mockLearnService,
			openBrowserFunc: func(url string) {
				openedURL = url
			},
		}

		expectedLesson := &learn.Lesson{
			LessonId: "lesson1",
			Title:    "Test Lesson",
			Url:      "https://learn.snyk.io/lesson1?existing=param",
		}

		mockLearnService.EXPECT().GetLesson(
			"javascript",
			"SNYK-JS-ASYNC-2441827",
			[]string{},
			[]string{},
			types.DependencyVulnerability,
		).Return(expectedLesson, nil)

		toolDef := SnykMcpToolsDefinition{Name: "test_tool"}
		handler := mcpBinding.snykOpenLearnLessonHandler(nil, toolDef)

		request := createMockRequest(map[string]interface{}{
			"issueType": "sca",
			"rule":      "SNYK-JS-ASYNC-2441827",
			"ecosystem": "javascript",
		})

		result, err := handler(t.Context(), request)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		textContent, ok := result.Content[0].(mcp.TextContent)
		require.True(t, ok)
		assert.Contains(t, textContent.Text, "Successfully requested to open lesson: Test Lesson")
		assert.Equal(t, "https://learn.snyk.io/lesson1?existing=param&loc=MCP", openedURL)
	})

	t.Run("handles missing optional parameters", func(t *testing.T) {
		testBasicLearnLessonHandler(t, map[string]interface{}{
			"issueType": "sca",
		}, "handles missing optional parameters")
	})

	t.Run("defaults to DependencyVulnerability for unknown issue type", func(t *testing.T) {
		testBasicLearnLessonHandler(t, map[string]interface{}{
			"issueType": "unknown",
		}, "defaults to DependencyVulnerability for unknown issue type")
	})

	t.Run("returns error when GetLesson fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockLearnService := mock_learn.NewMockService(ctrl)
		logger := zerolog.Nop()

		mcpBinding := &McpLLMBinding{
			logger:       &logger,
			learnService: mockLearnService,
		}

		expectedError := errors.New("failed to get lesson")
		mockLearnService.EXPECT().GetLesson(
			"",
			"",
			[]string{},
			[]string{},
			types.DependencyVulnerability,
		).Return(nil, expectedError)

		toolDef := SnykMcpToolsDefinition{Name: "test_tool"}
		handler := mcpBinding.snykOpenLearnLessonHandler(nil, toolDef)

		request := createMockRequest(map[string]interface{}{
			"issueType": "sca",
		})

		result, err := handler(t.Context(), request)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		textContent, ok := result.Content[0].(mcp.TextContent)
		assert.True(t, ok)
		assert.Contains(t, textContent.Text, "failed to retrieve the learn lesson")
	})

	t.Run("returns error when lesson URL is invalid", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockLearnService := mock_learn.NewMockService(ctrl)
		logger := zerolog.Nop()

		mcpBinding := &McpLLMBinding{
			logger:       &logger,
			learnService: mockLearnService,
		}

		expectedLesson := &learn.Lesson{
			LessonId: "lesson1",
			Title:    "Test Lesson",
			Url:      "://invalid-url",
		}

		mockLearnService.EXPECT().GetLesson(
			"",
			"",
			[]string{},
			[]string{},
			types.DependencyVulnerability,
		).Return(expectedLesson, nil)

		toolDef := SnykMcpToolsDefinition{Name: "test_tool"}
		handler := mcpBinding.snykOpenLearnLessonHandler(nil, toolDef)

		request := createMockRequest(map[string]interface{}{
			"issueType": "sca",
		})

		result, err := handler(t.Context(), request)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Contains(t, result.Content[0].(mcp.TextContent).Text, "invalid lesson URL")
	})

	t.Run("parses comma-separated CVEs and CWEs", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockLearnService := mock_learn.NewMockService(ctrl)
		logger := zerolog.Nop()

		mcpBinding := &McpLLMBinding{
			logger:       &logger,
			learnService: mockLearnService,
			openBrowserFunc: func(url string) {
				// do nothing
			},
		}

		expectedLesson := &learn.Lesson{
			LessonId: "lesson1",
			Title:    "Test Lesson",
			Url:      "https://learn.snyk.io/lesson1",
		}

		mockLearnService.EXPECT().GetLesson(
			"",
			"",
			[]string{"CWE-89", "CWE-601"},
			[]string{"CVE-2024-1234", "CVE-2024-5678"},
			types.DependencyVulnerability,
		).Return(expectedLesson, nil)

		toolDef := SnykMcpToolsDefinition{Name: "test_tool"}
		handler := mcpBinding.snykOpenLearnLessonHandler(nil, toolDef)

		request := createMockRequest(map[string]interface{}{
			"issueType": "sca",
			"cves":      "CVE-2024-1234,CVE-2024-5678",
			"cwes":      "CWE-89,CWE-601",
		})

		result, err := handler(t.Context(), request)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		textContent, ok := result.Content[0].(mcp.TextContent)
		require.True(t, ok)
		assert.Contains(t, textContent.Text, "Successfully requested to open lesson: Test Lesson")
	})

	t.Run("returns message when no lesson is found (nil lesson)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockLearnService := mock_learn.NewMockService(ctrl)
		logger := zerolog.Nop()

		mcpBinding := &McpLLMBinding{
			logger:       &logger,
			learnService: mockLearnService,
		}

		// Mock GetLesson to return nil (no lesson found)
		mockLearnService.EXPECT().GetLesson(
			"javascript",
			"nonexistent-rule",
			[]string{},
			[]string{},
			types.DependencyVulnerability,
		).Return(nil, nil)

		toolDef := SnykMcpToolsDefinition{Name: "test_tool"}
		handler := mcpBinding.snykOpenLearnLessonHandler(nil, toolDef)

		request := createMockRequest(map[string]interface{}{
			"issueType": "sca",
			"rule":      "nonexistent-rule",
			"ecosystem": "javascript",
		})

		result, err := handler(t.Context(), request)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		textContent, ok := result.Content[0].(mcp.TextContent)
		require.True(t, ok)
		assert.Equal(t, "No Snyk Learn lesson found for the given parameters.", textContent.Text)
	})
}

func TestLearnServiceIntegration(t *testing.T) {
	t.Run("learn service factory function is stored correctly", func(t *testing.T) {
		factoryCalled := false
		mockFactory := func(invocationContext workflow.InvocationContext, logger *zerolog.Logger) learn.Service {
			factoryCalled = true
			return nil
		}

		binding := NewMcpLLMBinding(WithLearnServiceFactory(mockFactory))
		assert.NotNil(t, binding)
		assert.NotNil(t, binding.learnServiceFactory)

		// Factory should not be called during construction
		assert.False(t, factoryCalled)
	})
}

// Helper function to create a mock request
func createMockRequest(args map[string]interface{}) mcp.CallToolRequest {
	var request mcp.CallToolRequest
	request.Params.Arguments = args
	return request
}

// Helper function to test basic learn lesson handler scenarios with minimal setup
func testBasicLearnLessonHandler(t *testing.T, args map[string]interface{}, testDescription string) {
	t.Helper()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockLearnService := mock_learn.NewMockService(ctrl)
	logger := zerolog.Nop()

	mcpBinding := &McpLLMBinding{
		logger:       &logger,
		learnService: mockLearnService,
		openBrowserFunc: func(url string) {
			// do nothing
		},
	}

	expectedLesson := &learn.Lesson{
		LessonId: "lesson1",
		Title:    "Test Lesson",
		Url:      "https://learn.snyk.io/lesson1",
	}

	mockLearnService.EXPECT().GetLesson(
		"",
		"",
		[]string{},
		[]string{},
		types.DependencyVulnerability,
	).Return(expectedLesson, nil)

	toolDef := SnykMcpToolsDefinition{Name: "test_tool"}
	handler := mcpBinding.snykOpenLearnLessonHandler(nil, toolDef)

	request := createMockRequest(args)
	result, err := handler(t.Context(), request)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	textContent, ok := result.Content[0].(mcp.TextContent)
	require.True(t, ok)
	assert.Contains(t, textContent.Text, "Successfully requested to open lesson: Test Lesson")
}
