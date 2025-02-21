//go:build !race
// +build !race

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
	"net/url"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/testutil"
)

// Test_WorkspaceScan does not run in race mode, due to races in the underlying framework
func Test_WorkspaceScan(t *testing.T) {
	c := testutil.SmokeTest(t, false)
	w := workspace.New(c, nil, nil, nil, nil, nil, nil, nil)
	sc := scanner.NewTestScanner()
	scanNotifier := scanner.NewMockScanNotifier()
	hoverService := hover.NewFakeHoverService()
	notifier := noti.NewMockNotifier()
	emitter := scanstates.NewSummaryEmitter(c, notifier)
	scanStateAggregator := scanstates.NewScanStateAggregator(c, emitter)
	scanPersister := persistence.NewNopScanPersister()

	f := workspace.NewFolder(
		c,
		"testPath",
		"test",
		sc,
		hoverService,
		scanNotifier,
		notifier,
		scanPersister,
		scanStateAggregator,
	)

	w.AddFolder(f)

	c.SetWorkspace(w)
	server := NewMcpLLMBinding(c, WithScanner(sc), WithLogger(c.Logger()))

	var baseURL *url.URL
	go func() {
		baseURL, _ = server.Start()
	}()

	assert.Eventually(t, func() bool {
		server.mutex.Lock()
		defer server.mutex.Unlock()
		portInUse := isPortInUse(server.baseURL)
		return portInUse && server.baseURL == baseURL
	}, time.Minute, time.Second)

	clientEndpoint := server.baseURL.String() + "/sse"

	mcpClient, err := client.NewSSEMCPClient(clientEndpoint)
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
