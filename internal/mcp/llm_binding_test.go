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
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
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
	u := defaultURL()
	assert.NotNil(t, u)
	assert.Equal(t, "http", u.Scheme)
	assert.Contains(t, u.Host, DefaultHost)
}

func TestExpandedEnv(t *testing.T) {
	t.Setenv(configuration.INTEGRATION_NAME, "abc")
	t.Setenv(configuration.INTEGRATION_VERSION, "abc")
	binding := NewMcpLLMBinding()

	env := binding.expandedEnv("1.x.1")

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
