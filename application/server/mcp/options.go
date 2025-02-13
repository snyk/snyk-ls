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

	"github.com/rs/zerolog"
	"github.com/snyk/code-client-go/llm"

	"github.com/snyk/snyk-ls/domain/snyk/scanner"
)

type McpOption func(server *McpServer)

func WithScanner(scanner scanner.Scanner) McpOption {
	return func(server *McpServer) {
		server.scanner = scanner
	}
}

func WithLogger(logger *zerolog.Logger) McpOption {
	return func(server *McpServer) {
		l := logger.With().Str("component", "mcp").Logger()
		server.logger = &l
	}
}

func WithBinding(binding llm.SnykLLMBindings) McpOption {
	return func(server *McpServer) {
		server.binding = binding
	}
}

func WithBaseURL(baseURL *url.URL) func(server *McpServer) {
	return func(server *McpServer) {
		server.baseURL = baseURL
	}
}
