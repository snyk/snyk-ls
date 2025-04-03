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
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/server"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	SseTransportType   string = "sse"
	StdioTransportType string = "stdio"
)

// McpLLMBinding is an implementation of a mcp server that allows interaction between
// a given SnykLLMBinding and a CommandService.
type McpLLMBinding struct {
	logger    *zerolog.Logger
	mcpServer *server.MCPServer
	sseServer *server.SSEServer
	baseURL   *url.URL
	mutex     sync.RWMutex
	started   bool
	cliPath   string
}

func NewMcpLLMBinding(opts ...Option) *McpLLMBinding {
	logger := zerolog.Nop()
	mcpServerImpl := &McpLLMBinding{
		logger: &logger,
	}

	for _, opt := range opts {
		opt(mcpServerImpl)
	}

	return mcpServerImpl
}

func defaultURL() *url.URL {
	rawURL := fmt.Sprintf("http://%s:%d", DefaultHost, determineFreePort())
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return u
}

// Start starts the MCP server. It blocks until the server is stopped via Shutdown.
func (m *McpLLMBinding) Start(invocationContext workflow.InvocationContext) error {
	runTimeInfo := invocationContext.GetRuntimeInfo()
	version := ""
	if runTimeInfo != nil {
		version = runTimeInfo.GetVersion()
	}
	m.mcpServer = server.NewMCPServer(
		"Snyk MCP Server",
		version,
		server.WithLogging(),
		server.WithResourceCapabilities(true, true),
		server.WithPromptCapabilities(true),
	)

	err := m.addSnykTools(invocationContext)
	if err != nil {
		return err
	}

	transportType := invocationContext.GetConfiguration().GetString("transport")
	if transportType == StdioTransportType {
		return m.HandleStdioServer()
	} else if transportType == SseTransportType {
		return m.HandleSseServer()
	} else {
		return fmt.Errorf("invalid transport type: %s", transportType)
	}
}

func (m *McpLLMBinding) HandleStdioServer() error {
	m.mutex.Lock()
	m.started = true
	m.mutex.Unlock()

	err := server.ServeStdio(m.mcpServer)

	if err != nil {
		m.logger.Error().Err(err).Msg("Error starting MCP Stdio server")
		return err
	}

	return nil
}

func (m *McpLLMBinding) HandleSseServer() error {
	// listen on default url/port if none was configured
	if m.baseURL == nil {
		m.baseURL = defaultURL()
	}

	m.sseServer = server.NewSSEServer(m.mcpServer, m.baseURL.String())

	//nolint:forbidigo // stdio stream isn't started yet
	fmt.Printf("Starting with base URL %s\n", m.baseURL.String())

	m.logger.Info().Str("baseURL", m.baseURL.String()).Msg("starting")
	go func() {
		// sleep initially for a few milliseconds so we actually can start the server
		time.Sleep(100 * time.Millisecond)
		for !isPortInUse(m.baseURL) {
			time.Sleep(10 * time.Millisecond)
		}

		m.mutex.Lock()
		m.logger.Info().Str("baseURL", m.baseURL.String()).Msg("started")
		m.started = true
		m.mutex.Unlock()
	}()

	err := m.sseServer.Start(m.baseURL.Host)
	if err != nil {
		// expect http.ErrServerClosed when shutting down
		if !errors.Is(err, http.ErrServerClosed) {
			m.logger.Error().Err(err).Msg("Error starting MCP SSE server")
		}
		return err
	}
	return nil
}

func (m *McpLLMBinding) Shutdown(ctx context.Context) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.sseServer != nil {
		err := m.sseServer.Shutdown(ctx)
		if err != nil {
			m.logger.Error().Err(err).Msg("Error shutting down MCP SSE server")
		}
	}
}

func (m *McpLLMBinding) Started() bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	return m.started
}

func (m *McpLLMBinding) expandedEnv(version string) []string {
	environ := os.Environ()
	var expandedEnv = []string{}
	for _, v := range environ {
		parts := strings.SplitN(v, "=", 2)
		var toAdd string
		switch {
		case parts[0] == configuration.INTEGRATION_NAME:
			fallthrough
		case parts[0] == configuration.INTEGRATION_VERSION:
			// do nothing
		default:
			toAdd = v
			expandedEnv = append(expandedEnv, toAdd)
		}
	}
	expandedEnv = append(expandedEnv, configuration.INTEGRATION_NAME+"=MCP")
	expandedEnv = append(expandedEnv, fmt.Sprintf("%s=%s", configuration.INTEGRATION_VERSION, version))
	return expandedEnv
}
