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

func (m *McpLLMBinding) snykOpenLearnLessonHandler(_ workflow.InvocationContext, toolDef SnykMcpToolsDefinition) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		logger := m.logger.With().Str("method", toolDef.Name).Logger()
		logger.Debug().Str("toolName", toolDef.Name).Msg("Received call for tool")

		args := request.GetArguments()
		cves, ok := args["cves"]
		cveArray := []string{}
		sep := ","
		if ok {
			if cveStr, isString := cves.(string); isString {
				cveArray = strings.Split(cveStr, sep)
			}
		}

		cwes, ok := args["cwes"]
		cweArray := []string{}
		if ok {
			if cweStr, isString := cwes.(string); isString {
				cweArray = strings.Split(cweStr, sep)
			}
		}

		rule, ok := args["rule"]
		ruleString := ""
		if ok {
			if ruleStr, isString := rule.(string); isString {
				ruleString = ruleStr
			}
		}

		ecosystem, ok := args["ecosystem"]
		ecosystemString := ""
		if ok {
			if ecoStr, isString := ecosystem.(string); isString {
				ecosystemString = ecoStr
			}
		}

		issueTypeArg, ok := args["issueType"]
		issueTypeString := ""
		if ok {
			if issueStr, isString := issueTypeArg.(string); isString {
				issueTypeString = issueStr
			}
		}

		var issueType types.IssueType
		switch issueTypeString {
		case "sca":
			issueType = types.DependencyVulnerability
		case "sast":
			issueType = types.CodeSecurityVulnerability
		default:
			issueType = types.DependencyVulnerability
		}

		targetLesson, err := m.learnService.GetLesson(ecosystemString, ruleString, cweArray, cveArray, issueType)
		if err != nil {
			logger.Err(err).Msg("Failed to get lesson.")
			return nil, err
		}

		u, err := url.Parse(targetLesson.Url)
		if err != nil {
			logger.Error().Err(err).Str("url", targetLesson.Url).Msg("Failed to parse lesson URL")
			return nil, fmt.Errorf("invalid lesson URL: %w", err)
		}
		q := u.Query()
		q.Set("loc", "ide")
		u.RawQuery = q.Encode()
		lessonURL := u.String()

		logger.Debug().Str("lessonURL", lessonURL).Msg("Attempting to open lesson URL in browser")

		m.openBrowserFunc(lessonURL)

		resultText := fmt.Sprintf("Successfully requested to open lesson: %s", targetLesson.Title)
		logger.Debug().Msg(resultText)
		return mcp.NewToolResultText(resultText), nil
	}
}
