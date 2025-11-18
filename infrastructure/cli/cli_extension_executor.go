/*
 * © 2022 Snyk Limited All rights reserved.
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

package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/envvars"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/types"
)

type ExtensionExecutor struct {
	semaphore  chan int
	cliTimeout time.Duration
	c          *config.Config
}

func NewExtensionExecutor(c *config.Config) Executor {
	concurrencyLimit := 2

	return &ExtensionExecutor{
		make(chan int, concurrencyLimit),
		90 * time.Minute, // TODO: add preference to make this configurable [ROAD-1184]
		c,
	}
}

func (c ExtensionExecutor) Execute(ctx context.Context, cmd []string, workingDir types.FilePath) (resp []byte, err error) {
	method := "ExtensionExecutor.Execute"
	c.c.Logger().Debug().Str("method", method).Interface("cmd", cmd[1:]).Str("workingDir", string(workingDir)).Msg("calling legacycli extension")

	// set deadline to handle CLI hanging when obtaining semaphore
	ctx, cancel := context.WithDeadline(ctx, time.Now().Add(c.cliTimeout))
	defer cancel()

	// handle concurrency limit, and when context is canceled
	select {
	case c.semaphore <- 1:
		defer func() { <-c.semaphore }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	output, err := c.doExecute(ctx, cmd, workingDir)
	c.c.Logger().Trace().Str("method", method).Str("response", string(output))
	return output, err
}

func (c ExtensionExecutor) doExecute(ctx context.Context, cmd []string, workingDir types.FilePath) ([]byte, error) {
	method := "ExtensionExecutor.doExecute"
	err := c.c.WaitForDefaultEnv(ctx)
	if err != nil {
		return []byte{}, err
	}

	engine := c.c.Engine()
	engine.GetConfiguration().Set(configuration.TIMEOUT, c.cliTimeout.Seconds())

	legacyCLI := workflow.NewWorkflowIdentifier("legacycli")
	legacyCLIConfig := engine.GetConfiguration().Clone()
	legacyCLIConfig.Set(configuration.WORKING_DIRECTORY, string(workingDir))
	legacyCLIConfig.Set(configuration.WORKFLOW_USE_STDIO, false)
	// Use folder-level organization if we are executing from within a project folder.
	// If no folder-specific org is configured, fall back to global organization.
	if workingDir != "" {
		folderOrg := c.c.FolderOrganization(workingDir)
		if folderOrg != "" {
            resolvedFolderOrg, err := c.c.ResolveOrgToUUID(folderOrg)
			if err != nil {
				c.c.Logger().Warn().Err(err).Str("method", method).Str("folderOrg", folderOrg).Msg("failed to resolve folder organization to UUID, falling back to global organization")
				legacyCLIConfig.Set(configuration.ORGANIZATION, c.c.Organization())
			} else {
				legacyCLIConfig.Set(configuration.ORGANIZATION, resolvedFolderOrg)
				cmd = getArgsWithOrgSubstitution(cmd, resolvedFolderOrg)
			}
		} else {
			// Fall back to global organization if no folder-specific org is configured
			legacyCLIConfig.Set(configuration.ORGANIZATION, c.c.Organization())
		}
	} else {
		// If no working directory, use global organization
		legacyCLIConfig.Set(configuration.ORGANIZATION, c.c.Organization())
	}
	legacyCLIConfig.Set(configuration.RAW_CMD_ARGS, cmd[1:])

	envvars.LoadConfiguredEnvironment(legacyCLIConfig.GetStringSlice(configuration.CUSTOM_CONFIG_FILES), string(workingDir))
	envvars.UpdatePath(c.c.GetUserSettingsPath(), true) // prioritize the user specified PATH over their SHELL's

	data, err := engine.InvokeWithConfig(legacyCLI, legacyCLIConfig)
	if len(data) > 0 {
		output, ok := data[0].GetPayload().([]byte)
		if !ok {
			return nil, fmt.Errorf("invalid response from extension executor")
		}
		return output, err
	}
	return []byte{}, err
}

func (c ExtensionExecutor) ExpandParametersFromConfig(base []string) []string {
	return expandParametersFromConfig(base)
}

func (c ExtensionExecutor) CliVersion() string {
	cmd := []string{"version"}
	output, err := c.Execute(context.Background(), cmd, "")
	if err != nil {
		c.c.Logger().Error().Err(err).Msg("failed to run version command")
		return ""
	}

	return strings.Trim(string(output), "\n")
}
