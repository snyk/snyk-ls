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
	"os"
	"path/filepath"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	mcpServer "github.com/mark3labs/mcp-go/server"
	"github.com/rs/zerolog"
)

var positionalParam = map[string]bool{
	"path":  true,
	"image": true,
}

// buildArgs builds command-line arguments for Snyk CLI based on parameters
func buildArgs(cliPath string, command []string, params map[string]interface{}) []string {
	args := []string{cliPath}
	args = append(args, command...)

	// Add params as command-line flags
	for key, value := range params {
		if positionalParam[strings.ToLower(key)] {
			args = append(args, value.(string))
		} else {
			switch v := value.(type) {
			case bool:
				if v {
					args = append(args, "--"+key)
				}
			case string:
				if v != "" {
					args = append(args, "--"+key+"="+v)
				}
			}
		}
	}

	return args
}

// createToolFromDefinition creates an MCP tool from a Snyk tool definition
func createToolFromDefinition(toolDef *SnykMcpToolsDefinition) mcp.Tool {
	opts := []mcp.ToolOption{mcp.WithDescription(toolDef.Description)}
	for _, param := range toolDef.Params {
		if param.Type == "string" {
			if param.IsRequired {
				opts = append(opts, mcp.WithString(param.Name, mcp.Required(), mcp.Description(param.Description)))
			} else {
				opts = append(opts, mcp.WithString(param.Name, mcp.Description(param.Description)))
			}
		} else if param.Type == "boolean" {
			if param.IsRequired {
				opts = append(opts, mcp.WithBoolean(param.Name, mcp.Required(), mcp.Description(param.Description)))
			} else {
				opts = append(opts, mcp.WithBoolean(param.Name, mcp.Description(param.Description)))
			}
		}
	}

	return mcp.NewTool(toolDef.Name, opts...)
}

func prepareCmdArgsForTool(logger *zerolog.Logger, toolDef SnykMcpToolsDefinition, arguments map[string]interface{}) (map[string]interface{}, string) {
	params, workingDir, _ := extractParamsFromRequestArgs(toolDef, arguments)

	for _, paramName := range toolDef.StandardParams {
		cliParamName := convertToCliParam(paramName)
		params[cliParamName] = true
	}

	// Handle supersedence: if an explicitly provided argument supersedes others, remove the superseded ones.
	for _, paramDef := range toolDef.Params {
		if _, argExistsInRequest := arguments[paramDef.Name]; !argExistsInRequest || len(paramDef.SupersedesParams) == 0 {
			continue
		}
		for _, supersededParamName := range paramDef.SupersedesParams {
			cliSupersededName := convertToCliParam(supersededParamName)
			if _, ok := params[cliSupersededName]; ok {
				logger.Debug().Str("supersedingArg", paramDef.Name).Str("supersededParam", supersededParamName).Msg("Deleting superseded parameter.")
				delete(params, cliSupersededName)
			}
		}
	}
	return params, workingDir
}

// extractParamsFromRequestArgs extracts parameters from the arguments based on the tool definition
func extractParamsFromRequestArgs(toolDef SnykMcpToolsDefinition, arguments map[string]interface{}) (map[string]interface{}, string, error) {
	params := make(map[string]interface{})
	var workingDir string

	for _, paramDef := range toolDef.Params {
		val, ok := arguments[paramDef.Name]
		if !ok {
			continue
		}

		// Store path separately to use as working directory
		if paramDef.Name == "path" {
			if pathStr, ok := val.(string); ok {
				fileInfo, err := os.Stat(pathStr)
				if err != nil {
					return nil, "", fmt.Errorf("file does not exist, path: %s, err: %w", paramDef.Name, err)
				}
				if fileInfo.IsDir() {
					workingDir = pathStr
				} else {
					workingDir = filepath.Dir(pathStr)
				}
			}
		}

		// Convert parameter name from snake_case to kebab-case for CLI arguments
		cliParamName := strings.ReplaceAll(paramDef.Name, "_", "-")

		// Cast the value based on parameter type
		if paramDef.Type == "string" {
			if strVal, ok := val.(string); ok && strVal != "" {
				params[cliParamName] = strVal
			}
		} else if paramDef.Type == "boolean" {
			if boolVal, ok := val.(bool); ok && boolVal {
				params[cliParamName] = true
			}
		}
	}

	return params, workingDir, nil
}

// convertToCliParam Convert parameter name from snake_case to kebab-case for CLI arguments
func convertToCliParam(cliParam string) string {
	return strings.ReplaceAll(cliParam, "_", "-")
}

func ClientInfoFromContext(ctx context.Context) mcp.Implementation {
	retrievedSession := mcpServer.ClientSessionFromContext(ctx)
	sessionWithClientInfo, ok := retrievedSession.(mcpServer.SessionWithClientInfo)
	var clientInfo mcp.Implementation
	if ok {
		clientInfo = sessionWithClientInfo.GetClientInfo()
	}
	return clientInfo
}
