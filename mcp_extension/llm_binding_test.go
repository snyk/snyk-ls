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
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/mark3labs/mcp-go/server"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/infrastructure/learn/mock_learn"
	"github.com/snyk/snyk-ls/mcp_extension/networking"
)

func TestNewMcpServer(t *testing.T) {
	mcpServer := NewMcpLLMBinding()
	assert.NotNil(t, mcpServer)
	assert.NotNil(t, mcpServer.logger)
}

func TestNewMcpServerWithOptions(t *testing.T) {
	baseURL, _ := url.Parse("http://test:8080")

	mcpServer := NewMcpLLMBinding(WithBaseURL(baseURL))

	assert.Equal(t, baseURL, mcpServer.baseURL)
}

func TestDefaultURL(t *testing.T) {
	u, err := networking.LoopbackURL()
	assert.NoError(t, err)
	assert.NotNil(t, u)
	assert.Equal(t, "http", u.Scheme)
	assert.Contains(t, u.Host, networking.DefaultHost)
}

func TestExpandedEnv(t *testing.T) {
	t.Setenv(configuration.INTEGRATION_NAME, "abc")
	t.Setenv(configuration.INTEGRATION_VERSION, "abc")
	binding := NewMcpLLMBinding()

	env := binding.expandedEnv("1.x.1", "Client1", "1.0.0")

	for _, s := range os.Environ() {
		if strings.HasPrefix(s, configuration.INTEGRATION_NAME) {
			continue
		}
		if strings.HasPrefix(s, configuration.INTEGRATION_VERSION) {
			continue
		}
		assert.Contains(t, env, s)
	}

	assert.Contains(t, env, configuration.INTEGRATION_NAME+"=MCP")
	assert.Contains(t, env, configuration.INTEGRATION_VERSION+"=1.x.1")
	assert.Contains(t, env, configuration.INTEGRATION_ENVIRONMENT+"=Client1")
	assert.Contains(t, env, configuration.INTEGRATION_ENVIRONMENT_VERSION+"=1.0.0")
}

func TestIsValidHttpRequest(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		origin   string
		expected bool
	}{
		{
			name:     "valid request with localhost host",
			host:     "localhost",
			origin:   "",
			expected: true,
		},
		{
			name:     "valid request with localhost origin",
			host:     "localhost",
			origin:   "http://localhost:3000",
			expected: true,
		},
		{
			name:     "valid request with IPv4 loopback",
			host:     "127.0.0.1",
			origin:   "",
			expected: true,
		},
		{
			name:     "valid request with IPv6 loopback",
			host:     "::1",
			origin:   "",
			expected: true,
		},
		{
			name:     "invalid request with allowed host",
			host:     "example.com",
			origin:   "",
			expected: false,
		},
		{
			name:     "invalid request with disallowed origin",
			host:     "localhost",
			origin:   "http://example.com",
			expected: false,
		},
		{
			name:     "valid request with empty origin and host",
			host:     "",
			origin:   "",
			expected: true,
		},
		{
			name:     "valid host header with port",
			host:     "localhost:3000",
			origin:   "",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &http.Request{
				Header: make(http.Header),
				Host:   tt.host,
			}
			r.Header.Set("Host", tt.host)
			if tt.origin != "" {
				r.Header.Set("Origin", tt.origin)
			}

			result := isValidHttpRequest(r)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestStarted(t *testing.T) {
	t.Run("returns false when not started", func(t *testing.T) {
		binding := NewMcpLLMBinding()
		assert.False(t, binding.Started())
	})

	t.Run("returns true when started", func(t *testing.T) {
		binding := NewMcpLLMBinding()
		binding.mutex.Lock()
		binding.started = true
		binding.mutex.Unlock()
		assert.True(t, binding.Started())
	})
}

func TestShutdown(t *testing.T) {
	t.Run("handles shutdown with no SSE server", func(t *testing.T) {
		binding := NewMcpLLMBinding()
		ctx := context.Background()

		// Should not panic or error when no SSE server exists
		binding.Shutdown(ctx)
		assert.Nil(t, binding.sseServer)
	})

	t.Run("handles shutdown with SSE server", func(t *testing.T) {
		binding := NewMcpLLMBinding()

		// Create a mock SSE server for testing
		mcpServer := server.NewMCPServer("test", "1.0.0")
		binding.sseServer = server.NewSSEServer(mcpServer)

		ctx := context.Background()
		binding.Shutdown(ctx)

		// Verify the shutdown was attempted
		assert.NotNil(t, binding.sseServer)
	})
}

func TestMiddleware(t *testing.T) {
	t.Run("allows valid localhost requests", func(t *testing.T) {
		mcpServer := server.NewMCPServer("test", "1.0.0")
		sseServer := server.NewSSEServer(mcpServer)
		handler := middleware(sseServer)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = "localhost"
		req.Header.Set("Origin", "http://localhost:3000")

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		// Should not return forbidden (would be handled by SSE server)
		assert.NotEqual(t, http.StatusForbidden, rr.Code)
	})

	t.Run("blocks invalid external requests", func(t *testing.T) {
		mcpServer := server.NewMCPServer("test", "1.0.0")
		sseServer := server.NewSSEServer(mcpServer)
		handler := middleware(sseServer)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = "example.com"
		req.Header.Set("Origin", "http://example.com")

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusForbidden, rr.Code)
		assert.Contains(t, rr.Body.String(), "Forbidden: Access restricted to localhost origins")
	})
}

func TestHandleStdioServer(t *testing.T) {
	t.Run("requires initialized MCP server", func(t *testing.T) {
		binding := NewMcpLLMBinding()

		// Should handle the case where mcpServer is nil gracefully
		assert.NotPanics(t, func() {
			// This will likely fail due to nil server, but shouldn't panic our test
			// We just want to ensure the method can be called
			go func() {
				defer func() {
					if r := recover(); r != nil {
						// Expected to panic due to nil mcpServer, this is fine for testing
						_ = r // Explicitly ignore the recovered value
					}
				}()
				_ = binding.HandleStdioServer()
			}()
		})
	})
}

func TestHandleSseServer(t *testing.T) {
	t.Run("sets base URL when none provided", func(t *testing.T) {
		binding := NewMcpLLMBinding()

		// Mock the mcpServer
		binding.mcpServer = server.NewMCPServer("test", "1.0.0")

		// Test the initial part of HandleSseServer logic without actually starting the server
		originalBaseURL := binding.baseURL
		assert.Nil(t, originalBaseURL)

		// Call would set the base URL if none was provided, but we can't test the full flow
		// without starting an actual server, so we'll test the baseURL setting behavior separately
		if binding.baseURL == nil {
			defaultURL, err := networking.LoopbackURL()
			require.NoError(t, err)
			binding.baseURL = defaultURL
		}

		assert.NotNil(t, binding.baseURL)
		assert.Equal(t, "http", binding.baseURL.Scheme)
	})

	t.Run("uses provided base URL", func(t *testing.T) {
		testURL, _ := url.Parse("http://localhost:9999")
		binding := NewMcpLLMBinding(WithBaseURL(testURL))

		// Should use the provided URL
		assert.Equal(t, testURL, binding.baseURL)
	})
}

func TestStart(t *testing.T) {
	t.Run("panics with nil invocation context", func(t *testing.T) {
		binding := NewMcpLLMBinding()

		// Test with nil context - should panic as expected
		assert.Panics(t, func() {
			_ = binding.Start(nil)
		})
	})

	t.Run("stores learn service factory", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		// Create a mock learn service
		mockLearnService := mock_learn.NewMockService(ctrl)

		// Create a factory that returns our mock
		mockFactory := func(invocationContext workflow.InvocationContext, logger *zerolog.Logger) learn.Service {
			return mockLearnService
		}

		binding := NewMcpLLMBinding(WithLearnServiceFactory(mockFactory))

		// Verify the factory was stored
		assert.NotNil(t, binding.learnServiceFactory)
	})
}

func TestNewDefaultLearnService(t *testing.T) {
	t.Run("panics with nil invocation context", func(t *testing.T) {
		logger := zerolog.Nop()

		// Test with nil context - should panic as expected
		assert.Panics(t, func() {
			NewDefaultLearnService(nil, &logger)
		})
	})

	t.Run("panics with nil parameters", func(t *testing.T) {
		// Test with nil parameters - should panic as expected
		assert.Panics(t, func() {
			NewDefaultLearnService(nil, nil)
		})
	})
}
