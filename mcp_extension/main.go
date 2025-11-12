/*
 * © 2023 Snyk Limited All rights reserved.
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

// Package mcp_extension implements the MCP extension
package mcp_extension

import (
	"context"
	"os"
	"path/filepath"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"

	storage2 "github.com/snyk/snyk-ls/internal/storage"
	"github.com/snyk/snyk-ls/internal/storedconfig"

	"github.com/spf13/pflag"

	"github.com/snyk/snyk-ls/application/entrypoint"
	"github.com/snyk/snyk-ls/mcp_extension/trust"

	"github.com/snyk/go-application-framework/pkg/workflow"
)

var WORKFLOWID_MCP = workflow.NewWorkflowIdentifier("mcp")

func Init(engine workflow.Engine) error {
	flags := pflag.NewFlagSet("mcp", pflag.ContinueOnError)
	flags.StringP("transport", "t", "sse", "sets transport to <sse|stdio>")

	flags.Bool(configuration.FLAG_EXPERIMENTAL, false, "enable experimental mcp command")
	_ = flags.MarkDeprecated(configuration.FLAG_EXPERIMENTAL, "This is feature is in early access.")

	flags.Bool(trust.DisableTrustFlag, false, "disable folder trust")

	cfg := workflow.ConfigurationOptionsFromFlagset(flags)
	entry, _ := engine.Register(WORKFLOWID_MCP, cfg, mcpWorkflow)
	entry.SetVisibility(false)

	return nil
}

func mcpWorkflow(
	invocation workflow.InvocationContext,
	_ []workflow.Data,
) (output []workflow.Data, err error) {
	defer entrypoint.OnPanicRecover()

	config := invocation.GetConfiguration()
	logger := invocation.GetEnhancedLogger()

	ideConfigPath := os.Getenv("IDE_CONFIG_PATH")
	if ideConfigPath != "" {
		storageErr := useIdeStorage(invocation, ideConfigPath)
		if storageErr != nil {
			logger.Err(storageErr).Msgf("Failed to use IDE storage specified in path %s", ideConfigPath)
		}
	}

	config.Set(configuration.INTEGRATION_NAME, "MCP")

	runtimeInfo := invocation.GetRuntimeInfo()
	if runtimeInfo != nil {
		config.Set(configuration.INTEGRATION_VERSION, runtimeInfo.GetVersion())
	} else {
		config.Set(configuration.INTEGRATION_VERSION, "unknown")
	}

	output = []workflow.Data{}

	cliPath, err := getCliPath(invocation)
	if err != nil {
		logger.Err(err).Msg("Failed to set cli path")
		return output, err
	}
	logger.Trace().Interface("environment", os.Environ()).Msg("start environment")
	config.PersistInStorage(trust.TrustedFoldersConfigKey)
	config.PersistInStorage(auth.CONFIG_KEY_OAUTH_TOKEN)
	config.PersistInStorage(configuration.AUTHENTICATION_TOKEN)

	mcpStart(invocation, cliPath)

	return output, nil
}

func useIdeStorage(invocationCtx workflow.InvocationContext, ideConfigPath string) error {
	logger := invocationCtx.GetEnhancedLogger()
	file, err := storedconfig.ConfigFile(ideConfigPath)
	if err != nil {
		return err
	}

	// The config file must exist and MCP server shouldn't create it.
	if _, err = os.Stat(file); err != nil {
		return err
	}

	storage, err := storage2.NewStorageWithCallbacks(
		storage2.WithStorageFile(file),
		storage2.WithLogger(invocationCtx.GetEnhancedLogger()),
	)
	if err != nil {
		return err
	}

	config := invocationCtx.GetConfiguration()
	config.SetStorage(storage)
	globalConfig := invocationCtx.GetEngine().GetConfiguration()
	globalConfig.SetStorage(storage)

	// Force refresh of in-memory values
	err = storage.Refresh(config, auth.CONFIG_KEY_OAUTH_TOKEN)
	if err != nil {
		logger.Err(err).Msg("Failed to refresh oauth token for local config")
	}
	err = storage.Refresh(config, configuration.AUTHENTICATION_TOKEN)
	if err != nil {
		logger.Err(err).Msg("Failed to refresh authentication token local config")
	}
	err = storage.Refresh(globalConfig, auth.CONFIG_KEY_OAUTH_TOKEN)
	if err != nil {
		logger.Err(err).Msg("Failed to refresh oauth token for global config")
	}
	err = storage.Refresh(globalConfig, configuration.AUTHENTICATION_TOKEN)
	if err != nil {
		logger.Err(err).Msg("Failed to refresh authentication token for global config")
	}

	return nil
}

func mcpStart(invocationContext workflow.InvocationContext, cliPath string) {
	logger := invocationContext.GetEnhancedLogger()
	mcpServer := NewMcpLLMBinding(WithLogger(invocationContext.GetEnhancedLogger()), WithCliPath(cliPath))

	// start mcp server
	err := mcpServer.Start(invocationContext)

	if err != nil {
		logger.Err(err).Msg("failed to start mcp server")
	}
	defer func() {
		logger.Info().Msg("Shutting down MCP Server...")
		mcpServer.Shutdown(context.Background())
	}()
}

func getCliPath(ctx workflow.InvocationContext) (string, error) {
	logger := ctx.GetEnhancedLogger()
	exePath, err := os.Executable()
	if err != nil {
		logger.Err(err).Msg("Failed to get executable path")
		return "", err
	}

	resolvedPath, err := filepath.EvalSymlinks(exePath)
	if err != nil {
		logger.Err(err).Msg("Failed to eval symlink from path")
		resolvedPath = exePath
	}
	return resolvedPath, nil
}
