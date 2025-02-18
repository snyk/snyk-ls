/*
 * © 2023-2024 Snyk Limited
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

package command

import (
	"context"
	"errors"
	"fmt"
	"os/exec"

	"github.com/rs/zerolog"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/types"
)

type executeCLICommand struct {
	command     types.CommandData
	authService authentication.AuthenticationService
	notifier    noti.Notifier
	logger      *zerolog.Logger
	cli         cli.Executor
}

type cliScanResult struct {
	ExitCode int    `json:"exitCode"`
	StdOut   string `json:"stdOut"`
}

func (cmd *executeCLICommand) Command() types.CommandData {
	return cmd.command
}

func (cmd *executeCLICommand) Execute(ctx context.Context) (any, error) {
	if len(cmd.command.Arguments) < 2 {
		return nil, fmt.Errorf("invalid usage of executeCLICommand. First arg needs to be the workDir, then CLI arguments without binary path")
	}
	workDir, ok := cmd.command.Arguments[0].(string)
	if !ok {
		return nil, fmt.Errorf("workDir needs to be a string")
	}

	args := []string{config.CurrentConfig().CliSettings().Path()}
	for _, argument := range cmd.command.Arguments[1:] {
		elems, ok := argument.(string)
		if !ok {
			return nil, fmt.Errorf("argument needs to be a string")
		}
		args = append(args, elems)
	}

	args = cmd.cli.ExpandParametersFromConfig(args)
	var exitCode int
	resp, err := cmd.cli.Execute(ctx, args, types.FilePath(workDir))
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			exitCode = exitError.ExitCode()
		}
	}
	return cliScanResult{
		ExitCode: exitCode,
		StdOut:   string(resp),
	}, nil
}
