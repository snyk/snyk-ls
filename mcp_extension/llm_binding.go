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
	"net"
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

	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/mcp_extension/logging"
	"github.com/snyk/snyk-ls/mcp_extension/networking"
	"github.com/snyk/snyk-ls/mcp_extension/trust"
)

const (
	SseTransportType   string = "sse"
	StdioTransportType string = "stdio"
)

// McpLLMBinding is an implementation of a mcp server that allows interaction between
// a given SnykLLMBinding and a CommandService.
type McpLLMBinding struct {
	logger              *zerolog.Logger
	mcpServer           *server.MCPServer
	sseServer           *server.SSEServer
	folderTrust         *trust.FolderTrust
	baseURL             *url.URL
	mutex               sync.RWMutex
	started             bool
	cliPath             string
	openBrowserFunc     types.OpenBrowserFunc
	learnService        learn.Service
	learnServiceFactory LearnServiceFactoryFunc
}

func NewMcpLLMBinding(opts ...Option) *McpLLMBinding {
	logger := zerolog.Nop()
	mcpServerImpl := &McpLLMBinding{
		logger:              &logger,
		openBrowserFunc:     types.DefaultOpenBrowserFunc,
		learnServiceFactory: NewDefaultLearnService,
	}

	for _, opt := range opts {
		opt(mcpServerImpl)
	}

	return mcpServerImpl
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

	m.logger = logging.ConfigureLogging(m.mcpServer)
	invocationContext.GetEngine().SetLogger(m.logger)

	m.learnService = m.learnServiceFactory(invocationContext, m.logger)
	if m.learnService == nil {
		m.logger.Error().Msg("Failed to initialize learn service via factory.")
	}

	m.folderTrust = trust.NewFolderTrust(m.logger, invocationContext.GetConfiguration())

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
	m.logger.Info().Msg("Starting MCP Stdio server")
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
		defaultUrl, err := networking.LoopbackURL()
		if err != nil {
			return err
		}
		m.baseURL = defaultUrl
	}

	m.sseServer = server.NewSSEServer(m.mcpServer, server.WithBaseURL(m.baseURL.String()))

	endpoint := m.baseURL.String() + "/sse"

	m.logger.Info().Str("baseURL", endpoint).Msg("starting")
	go func() {
		// sleep initially for a few milliseconds so we actually can start the server
		time.Sleep(100 * time.Millisecond)
		for !networking.IsPortInUse(m.baseURL) {
			time.Sleep(10 * time.Millisecond)
		}

		m.mutex.Lock()
		m.logger.Info().Str("baseURL", endpoint).Msg("started")
		m.started = true
		m.mutex.Unlock()
	}()

	srv := &http.Server{
		Addr:    m.baseURL.Host,
		Handler: middleware(m.sseServer),
	}

	err := srv.ListenAndServe()

	if err != nil {
		// expect http.ErrServerClosed when shutting down
		if !errors.Is(err, http.ErrServerClosed) {
			m.logger.Error().Err(err).Msg("Error starting MCP SSE server")
		}
		return err
	}
	return nil
}

var allowedHostnames = map[string]bool{
	"localhost": true,
	"127.0.0.1": true,
	"::1":       true,
	"":          true,
}

func middleware(sseServer *server.SSEServer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isValidHttpRequest(r) {
			sseServer.ServeHTTP(w, r)
		} else {
			http.Error(w, "Forbidden: Access restricted to localhost origins", http.StatusForbidden)
		}
	})
}

func isValidHttpRequest(r *http.Request) bool {
	originHeader := r.Header.Get("Origin")
	isValidOrigin := originHeader == ""
	hostHeader := r.Host
	host, _, err := net.SplitHostPort(hostHeader)
	if err != nil {
		// Try to parse without port
		host = hostHeader
	}
	isValidHost := allowedHostnames[host]

	if !isValidOrigin {
		parsedOrigin, err := url.Parse(originHeader)
		if err == nil {
			requestHost := parsedOrigin.Hostname()
			if _, allowed := allowedHostnames[requestHost]; allowed {
				isValidOrigin = true
			}
		}
	}

	return isValidOrigin && isValidHost
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

func (m *McpLLMBinding) updateGafConfigWithIntegrationEnvironment(invocationCtx workflow.InvocationContext, environmentName, environmentVersion string) {
	getConfiguration := invocationCtx.GetConfiguration()
	getConfiguration.Set(configuration.INTEGRATION_NAME, "MCP")

	integrationVersion := "unknown"
	runtimeInfo := invocationCtx.GetRuntimeInfo()
	if runtimeInfo != nil {
		integrationVersion = runtimeInfo.GetVersion()
	}
	getConfiguration.Set(configuration.INTEGRATION_VERSION, integrationVersion)
	getConfiguration.Set(configuration.INTEGRATION_ENVIRONMENT, environmentName)
	getConfiguration.Set(configuration.INTEGRATION_ENVIRONMENT_VERSION, environmentVersion)
}

func (m *McpLLMBinding) expandedEnv(invocationCtx workflow.InvocationContext, environmentName, environmentVersion string) []string {
	environ := os.Environ()
	var expandedEnv = []string{}
	for _, v := range environ {
		if strings.HasPrefix(strings.ToLower(v), strings.ToLower(configuration.INTEGRATION_NAME)) {
			continue
		}
		if strings.HasPrefix(strings.ToLower(v), strings.ToLower(configuration.INTEGRATION_VERSION)) {
			continue
		}
		expandedEnv = append(expandedEnv, v)
	}
	expandedEnv = append(expandedEnv, fmt.Sprintf("%s=%s", strings.ToUpper(configuration.INTEGRATION_NAME), "MCP"))

	integrationVersion := "unknown"
	runtimeInfo := invocationCtx.GetRuntimeInfo()
	if runtimeInfo != nil {
		integrationVersion = runtimeInfo.GetVersion()
	}

	expandedEnv = append(expandedEnv, fmt.Sprintf("%s=%s", strings.ToUpper(configuration.INTEGRATION_VERSION), integrationVersion))
	expandedEnv = append(expandedEnv, fmt.Sprintf("%s=%s", strings.ToUpper(configuration.INTEGRATION_ENVIRONMENT), environmentName))
	expandedEnv = append(expandedEnv, fmt.Sprintf("%s=%s", strings.ToUpper(configuration.INTEGRATION_ENVIRONMENT_VERSION), environmentVersion))
	return expandedEnv
}
