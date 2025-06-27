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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/infrastructure/learn"
)

// NewDefaultLearnService creates and returns a new learn.Service instance
// using default production dependencies from the invocation context.
func NewDefaultLearnService(invocationContext workflow.InvocationContext, logger *zerolog.Logger) learn.Service {
	l := logger.With().Str("component", "learn_service_creation").Logger()

	engine := invocationContext.GetEngine()

	serviceInstance := learn.New(engine.GetConfiguration(), &l, engine.GetNetworkAccess().GetUnauthorizedHttpClient)

	if serviceInstance == nil {
		l.Error().Msg("Failed to create learn service instance from learn.New.")
		return nil
	}

	go serviceInstance.MaintainCache()
	l.Debug().Msg("Learn service instance created via default factory and cache maintenance started.")
	return serviceInstance
}

// LessonOutput defines the structure for JSON output
type LessonOutput struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Ecosystems  string `json:"ecosystems"`
}

func (m *McpLLMBinding) snykGetAllLearnLessonsHandler(_ workflow.InvocationContext, toolDef SnykMcpToolsDefinition) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		logger := m.logger.With().Str("method", toolDef.Name).Logger()
		logger.Debug().Str("toolName", toolDef.Name).Msg("Received call for tool")

		if m.learnService == nil {
			logger.Error().Msg("Learn service is not initialized on McpLLMBinding.")
			return nil, fmt.Errorf("learn service not initialized on McpLLMBinding")
		}

		lessons, err := m.learnService.GetAllLessons()
		if err != nil {
			logger.Error().Err(err).Msg("Failed to get all learn lessons.")
			return nil, fmt.Errorf("failed to get learn lessons: %w", err)
		}

		var lessonOutputs []LessonOutput
		for _, lesson := range lessons {
			if strings.HasPrefix(lesson.Description, "This course is no longer supported.") {
				continue
			}
			lessonOutputs = append(lessonOutputs, LessonOutput{
				Title:       lesson.Title,
				Description: lesson.Description,
				Ecosystems:  strings.Join(lesson.Ecosystems, " & "),
			})
		}

		var buf bytes.Buffer
		encoder := json.NewEncoder(&buf)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		err = encoder.Encode(lessonOutputs)
		if err != nil {
			logger.Error().Err(err).Msg("Failed to encode lessons to JSON.")
			return nil, fmt.Errorf("failed to encode lessons to JSON: %w", err)
		}

		return mcp.NewToolResultText(buf.String()), nil
	}
}

func (m *McpLLMBinding) snykOpenLearnLessonHandler(_ workflow.InvocationContext, toolDef SnykMcpToolsDefinition) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		logger := m.logger.With().Str("method", toolDef.Name).Logger()
		logger.Debug().Str("toolName", toolDef.Name).Msg("Received call for tool")

		args := request.GetArguments()
		lessonTitleVal, ok := args["lessonTitle"]
		if !ok {
			err := fmt.Errorf("missing 'lessonTitle' parameter for tool %s", toolDef.Name)
			logger.Error().Err(err).Msg("Parameter error")
			return nil, err
		}

		lessonTitle, ok := lessonTitleVal.(string)
		if !ok {
			err := fmt.Errorf("'lessonTitle' parameter is not a string for tool %s", toolDef.Name)
			logger.Error().Err(err).Interface("value", lessonTitleVal).Msg("Parameter type error")
			return nil, err
		}

		if lessonTitle == "" {
			err := fmt.Errorf("'lessonTitle' parameter cannot be empty for tool %s", toolDef.Name)
			logger.Error().Err(err).Msg("Parameter value error")
			return nil, err
		}

		logger.Info().Str("lessonTitle", lessonTitle).Msg("Parsed parameters for snyk_open_learn_lesson")

		if m.learnService == nil {
			err := fmt.Errorf("learn service not initialized on McpLLMBinding")
			logger.Error().Err(err).Msg("Service error")
			return nil, err
		}

		allLessons, err := m.learnService.GetAllLessons()
		if err != nil {
			logger.Error().Err(err).Msg("Failed to get all learn lessons")
			return nil, fmt.Errorf("failed to retrieve lessons: %w", err)
		}

		var targetLesson *learn.Lesson
		for i := range allLessons {
			// Case-insensitive comparison for robustness
			if strings.EqualFold(allLessons[i].Title, lessonTitle) {
				targetLesson = &allLessons[i]
				break
			}
		}

		if targetLesson == nil {
			errNotFound := fmt.Errorf("lesson with title '%s' not found", lessonTitle)
			logger.Warn().Err(errNotFound).Msg("Lesson not found")
			return nil, errNotFound
		}

		lessonURL := targetLesson.Url
		if !strings.Contains(lessonURL, "loc=ide") {
			if strings.Contains(lessonURL, "?") {
				lessonURL += "&loc=ide"
			} else {
				lessonURL += "?loc=ide"
			}
		}

		logger.Info().Str("lessonURL", lessonURL).Msg("Attempting to open lesson URL in browser")

		m.openBrowserFunc(lessonURL)

		resultText := fmt.Sprintf("Successfully requested to open lesson: %s", lessonTitle)
		logger.Info().Msg(resultText)
		return mcp.NewToolResultText(resultText), nil
	}
}
