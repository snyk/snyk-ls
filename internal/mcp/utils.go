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

package mcp

import (
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
)

// buildArgs builds command-line arguments for Snyk CLI based on parameters
func buildArgs(cliPath string, command []string, params map[string]interface{}) []string {
	args := []string{cliPath}
	args = append(args, command...)

	// Add params as command-line flags
	for key, value := range params {
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

// extractParamsFromRequestArgs extracts parameters from the arguments based on the tool definition
func extractParamsFromRequestArgs(toolDef SnykMcpToolsDefinition, arguments map[string]interface{}) (map[string]interface{}, string) {
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
				workingDir = pathStr
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

	return params, workingDir
}

// convertToCliParam Convert parameter name from snake_case to kebab-case for CLI arguments
func convertToCliParam(cliParam string) string {
	return strings.ReplaceAll(cliParam, "_", "-")
}
