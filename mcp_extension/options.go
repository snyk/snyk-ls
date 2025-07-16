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
	"net/url"

	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/internal/types"
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

func WithOpenBrowserFunc(fn types.OpenBrowserFunc) Option {
	return func(server *McpLLMBinding) {
		server.openBrowserFunc = fn
	}
}

// LearnServiceFactoryFunc defines the signature for a function that can create a learn.Service.
type LearnServiceFactoryFunc func(invocationContext workflow.InvocationContext, logger *zerolog.Logger) learn.Service

// WithLearnServiceFactory provides an option to set a custom factory for creating the learn.Service.
func WithLearnServiceFactory(factory LearnServiceFactoryFunc) Option {
	return func(server *McpLLMBinding) {
		if factory != nil {
			server.learnServiceFactory = factory
		}
	}
}
