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
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_WorkspaceScan(t *testing.T) {
	c := testutil.SmokeTest(t, false)
	w := workspace.New(c, nil, nil, nil, nil, nil, nil, nil)
	f := workspace.NewFolder(c, "testPath", "test", nil, nil, nil, nil, nil, nil)
	w.AddFolder(f)

	c.SetWorkspace(w)
	sc := scanner.NewTestScanner()
	server := NewMcpServer(c, WithScanner(sc), WithLogger(c.Logger()))

	go func() {
		_ = server.Start()
	}()

	baseURL := ""
	assert.Eventually(t, func() bool {
		server.mutex.Lock()
		defer server.mutex.Unlock()
		portInUse := isPortInUse(server.baseURL)
		baseURL = server.baseURL.String() + "/sse"
		return portInUse
	}, time.Minute, time.Second)

	mcpClient, err := client.NewSSEMCPClient(baseURL)
	assert.NoError(t, err)
	defer mcpClient.Close()

	// start
	err = mcpClient.Start(context.Background())
	assert.NoError(t, err)

	// initialize
	initRequest := mcp.InitializeRequest{}
	initRequest.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initRequest.Params.ClientInfo = mcp.Implementation{
		Name:    "example-client",
		Version: "1.0.0",
	}

	_, err = mcpClient.Initialize(context.Background(), initRequest)
	assert.NoError(t, err)

	toolsRequest := mcp.ListToolsRequest{}
	tools, err := mcpClient.ListTools(context.Background(), toolsRequest)
	assert.NoError(t, err)
	assert.Len(t, tools.Tools, 1)

	scanRequest := mcp.CallToolRequest{}
	scanRequest.Params.Name = SnykScanWorkspaceScan

	result, err := mcpClient.CallTool(context.Background(), scanRequest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
}
