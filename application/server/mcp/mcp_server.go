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
	"fmt"
	"net/url"
	"sync"

	"github.com/mark3labs/mcp-go/server"
	"github.com/rs/zerolog"
	"github.com/snyk/code-client-go/llm"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"
)

// McpServer is an implementation of a mcp server that allows interaction between
// a given SnykLLMBinding and a CommandService.
type McpServer struct {
	c         *config.Config
	binding   llm.SnykLLMBindings
	scanner   scanner.Scanner
	logger    *zerolog.Logger
	mcpServer *server.MCPServer
	sseServer *server.SSEServer
	baseURL   *url.URL
	mutex     sync.Mutex
}

func NewMcpServer(c *config.Config, opts ...McpOption) *McpServer {
	logger := zerolog.Nop()
	mcpServerImpl := &McpServer{
		c:      c,
		logger: &logger,
	}

	for _, opt := range opts {
		opt(mcpServerImpl)
	}

	return mcpServerImpl
}

func defaultURL() *url.URL {
	rawURL := fmt.Sprintf("http://%s:%d", DefaultHost, determineFreePort())
	parse, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return parse
}

// Start starts the MCP server. It blocks until the server is stopped via Shutdown.
func (m *McpServer) Start() error {
	// protect critical assignments with mutex
	m.mutex.Lock()
	m.mcpServer = server.NewMCPServer(
		"Snyk MCP Server",
		config.Version,
		server.WithLogging(),
		server.WithResourceCapabilities(true, true),
		server.WithPromptCapabilities(true),
	)

	err := m.addSnykScanTool()
	if err != nil {
		return err
	}

	// listen on default url/port if none was configured
	if m.baseURL == nil {
		m.baseURL = defaultURL()
	}

	m.sseServer = server.NewSSEServer(m.mcpServer, m.baseURL.String())
	m.mutex.Unlock()

	m.logger.Info().Str("baseURL", m.baseURL.String()).Msg("starting")
	err = m.sseServer.Start(m.baseURL.Host)
	if err != nil {
		m.logger.Error().Err(err).Msg("Error starting MCP SSE server")
		return err
	}
	return nil
}

func (m *McpServer) Shutdown(ctx context.Context) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	err := m.sseServer.Shutdown(ctx)
	if err != nil {
		m.logger.Error().Err(err).Msg("Error shutting down SSE server")
	}
}
