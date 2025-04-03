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
