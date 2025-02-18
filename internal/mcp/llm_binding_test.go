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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/domain/snyk/scanner"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestNewMcpServer(t *testing.T) {
	c := testutil.UnitTest(t)
	mcpServer := NewMcpServer(c)
	assert.NotNil(t, mcpServer)
	assert.NotNil(t, mcpServer.logger)
}

func TestNewMcpServerWithOptions(t *testing.T) {
	c := testutil.UnitTest(t)
	baseURL, _ := url.Parse("http://test:8080")

	s := scanner.NewTestScanner()
	mcpServer := NewMcpServer(c, WithScanner(s), WithBaseURL(baseURL))

	assert.Equal(t, s, mcpServer.scanner)
	assert.Equal(t, baseURL, mcpServer.baseURL)
}

func TestDefaultURL(t *testing.T) {
	u := defaultURL()
	assert.NotNil(t, u)
	assert.Equal(t, "http", u.Scheme)
	assert.Contains(t, u.Host, DefaultHost)
}
