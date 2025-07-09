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
	"fmt"
	"net/url"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/internal/types"
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

// parseStringArrayParam extracts a comma-separated string array from request arguments
func parseStringArrayParam(args map[string]interface{}, key string) []string {
	if val, ok := args[key]; ok {
		if strVal, isString := val.(string); isString {
			return strings.Split(strVal, ",")
		}
	}
	return []string{}
}

// parseStringParam extracts a string parameter from request arguments
func parseStringParam(args map[string]interface{}, key string) string {
	if val, ok := args[key]; ok {
		if strVal, isString := val.(string); isString {
			return strVal
		}
	}
	return ""
}

// parseIssueType converts issue type string to types.IssueType
func parseIssueType(issueTypeString string) types.IssueType {
	switch issueTypeString {
	case "sca":
		return types.DependencyVulnerability
	case "sast":
		return types.CodeSecurityVulnerability
	default:
		return types.DependencyVulnerability
	}
}

// buildLessonURL constructs the lesson URL with IDE location parameter
func buildLessonURL(lessonURL string) (string, error) {
	u, err := url.Parse(lessonURL)
	if err != nil {
		return "", fmt.Errorf("invalid lesson URL: %w", err)
	}
	q := u.Query()
	q.Set("loc", "ide")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (m *McpLLMBinding) snykOpenLearnLessonHandler(_ workflow.InvocationContext, toolDef SnykMcpToolsDefinition) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		logger := m.logger.With().Str("method", toolDef.Name).Logger()
		logger.Debug().Str("toolName", toolDef.Name).Msg("Received call for tool")

		args := request.GetArguments()
		cveArray := parseStringArrayParam(args, "cves")
		cweArray := parseStringArrayParam(args, "cwes")
		ruleString := parseStringParam(args, "rule")
		ecosystemString := parseStringParam(args, "ecosystem")
		issueTypeString := parseStringParam(args, "issueType")
		issueType := parseIssueType(issueTypeString)

		if m.learnService == nil {
			return mcp.NewToolResultText("unable to retrieve learn lesson, learn service not initialized"), nil
		}
		targetLesson, err := m.learnService.GetLesson(ecosystemString, ruleString, cweArray, cveArray, issueType)
		if err != nil {
			err = fmt.Errorf("failed to retrieve the learn lessen, error: %w", err)
			logger.Err(err).Send()
			return mcp.NewToolResultText(err.Error()), nil
		}

		if targetLesson == nil {
			resultText := "No Snyk Learn lesson found for the given parameters."
			logger.Debug().Msg(resultText)
			return mcp.NewToolResultText(resultText), nil
		}

		lessonURL, err := buildLessonURL(targetLesson.Url)
		if err != nil {
			err = fmt.Errorf("Failed to parse lesson URL, error: %w", err)
			logger.Err(err).Str("url", targetLesson.Url).Send()
			return mcp.NewToolResultText(err.Error()), nil
		}

		logger.Debug().Str("lessonURL", lessonURL).Msg("Attempting to open lesson URL in browser")
		m.openBrowserFunc(lessonURL)

		resultText := fmt.Sprintf("Successfully requested to open lesson: %s", targetLesson.Title)
		logger.Debug().Msg(resultText)
		return mcp.NewToolResultText(resultText), nil
	}
}
