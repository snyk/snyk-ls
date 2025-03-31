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
)

type Option func(server *McpLLMBinding)

func WithLogger(logger *zerolog.Logger) Option {
	return func(server *McpLLMBinding) {
		l := logger.With().Str("component", "mcp").Logger()
		server.logger = &l
	}
}

func WithCliPath(cliPath string) Option {
	return func(server *McpLLMBinding) {
		server.cliPath = cliPath
	}
}

func WithBaseURL(baseURL *url.URL) func(server *McpLLMBinding) {
	return func(server *McpLLMBinding) {
		server.baseURL = baseURL
	}
}
