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
	"context"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/types"
)

const SnykScanWorkspaceScan = types.WorkspaceScanCommand

func (m *McpServer) addSnykScanTool() error {
	tool := mcp.NewTool(SnykScanWorkspaceScan,
		mcp.WithDescription("Perform Snyk scans on current workspace"),
	)

	m.mcpServer.AddTool(tool, m.snykWorkSpaceScanHandler())

	return nil
}

func (m *McpServer) snykWorkSpaceScanHandler() func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		w := m.c.Workspace()
		trusted, _ := w.GetFolderTrust()

		callToolResult := &mcp.CallToolResult{
			Content: make([]interface{}, 0),
		}

		resultProcessor := func(data snyk.ScanData) {
			// add the scan results to the call tool response
			// in the future, this could be a rendered markdown/html template
			callToolResult.Content = append(callToolResult.Content, data)
			if data.Err != nil {
				callToolResult.IsError = true
			}
		}

		for _, folder := range trusted {
			m.scanner.Scan(ctx, folder.Path(), resultProcessor, folder.Path())
		}

		return callToolResult, nil
	}
}
