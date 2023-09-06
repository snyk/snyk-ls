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
	"io"
	"strings"
	"time"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
)

type ExtensionExecutor struct {
	semaphore  chan int
	cliTimeout time.Duration
}

func (e ExtensionExecutor) ExecuteWithFunc(ctx context.Context, cmd []string, workingDir string, f func(reader *io.PipeReader, writer *io.PipeWriter)) error {
	//TODO implement me
	panic("implement me")
}

func NewExtensionExecutor() Executor {
	concurrencyLimit := 2

	return &ExtensionExecutor{
		make(chan int, concurrencyLimit),
		90 * time.Minute, // TODO: add preference to make this configurable [ROAD-1184]
	}
}

func (e ExtensionExecutor) Execute(ctx context.Context, cmd []string, workingDir string) (resp []byte, err error) {
	method := "ExtensionExecutor.Execute"
	log.Debug().Str("method", method).Interface("cmd", cmd[1:]).Str("workingDir", workingDir).Msg("calling legacycli extension")

	// set deadline to handle CLI hanging when obtaining semaphore
	ctx, cancel := context.WithDeadline(ctx, time.Now().Add(e.cliTimeout))
	defer cancel()

	// handle concurrency limit, and when context is cancelled
	select {
	case e.semaphore <- 1:
		defer func() { <-e.semaphore }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	output, err := e.doExecute(ctx, cmd, workingDir)
	log.Trace().Str("method", method).Str("response", string(output))
	return output, err
}

func (e ExtensionExecutor) doExecute(ctx context.Context, cmd []string, workingDir string) ([]byte, error) {
	output := []byte{}

	engine := config.CurrentConfig().Engine()
	legacyCLI := workflow.NewWorkflowIdentifier("legacycli")
	legacyCLIConfig := config.CurrentConfig().Engine().GetConfiguration().Clone()
	legacyCLIConfig.Set(configuration.RAW_CMD_ARGS, cmd[1:])
	legacyCLIConfig.Set(configuration.WORKFLOW_USE_STDIO, false)
	legacyCLIConfig.Set(configuration.WORKING_DIRECTORY, workingDir)

	data, err := engine.InvokeWithConfig(legacyCLI, legacyCLIConfig)
	if len(data) > 0 {
		output = data[0].GetPayload().([]byte)
	}

	return output, err
}

func (e ExtensionExecutor) ExpandParametersFromConfig(base []string) []string {
	return expandParametersFromConfig(base)
}

func (e ExtensionExecutor) CliVersion() string {
	cmd := []string{"version"}
	output, err := e.Execute(context.Background(), cmd, "")
	if err != nil {
		log.Error().Err(err).Msg("failed to run version command")
		return ""
	}

	return strings.Trim(string(output), "\n")
}
