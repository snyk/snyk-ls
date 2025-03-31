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

package mcp_extension

import (
	"os"
	"path/filepath"

	"github.com/snyk/snyk-ls/application/entrypoint"
	"github.com/snyk/snyk-ls/application/server"

	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/pkg/workflow"
)

var WORKFLOWID_MCP = workflow.NewWorkflowIdentifier("mcp")

func Init(engine workflow.Engine) error {
	flags := pflag.NewFlagSet("mcp", pflag.ContinueOnError)

	flags.StringP("transport", "t", "sse", "sets transport to <sse|stdio>")

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

	output = []workflow.Data{}

	logger := invocation.GetEnhancedLogger()

	cliPath, err := GetCliPath(invocation)
	if err != nil {
		logger.Err(err).Msg("Failed to set cli path")
		return output, err
	}
	logger.Trace().Interface("environment", os.Environ()).Msg("start environment")
	server.McpStart(invocation, cliPath)

	return output, nil
}

func GetCliPath(ctx workflow.InvocationContext) (string, error) {
	logger := ctx.GetEnhancedLogger()
	exePath, err := os.Executable()
	if err != nil {
		logger.Err(err).Msg("Failed to get executable path")
		return "", err
	}
	resolvedPath, err := filepath.EvalSymlinks(exePath)

	if err != nil {
		logger.Err(err).Msg("Failed to eval symlink from path")
		return "", err
	} else {
		// Set Cli path to current process path
		return resolvedPath, nil
	}
}
