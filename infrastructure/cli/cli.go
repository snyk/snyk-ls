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
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/snyk/snyk-ls/application/config"
	noti "github.com/snyk/snyk-ls/domain/ide/notification"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
)

type SnykCli struct {
	authenticationService snyk.AuthenticationService
	errorReporter         error_reporting.ErrorReporter
	analytics             ux.Analytics
	semaphore             chan int
	cliTimeout            time.Duration
	notifier              noti.Notifier
	c                     *config.Config
}

var Mutex = &sync.Mutex{}

func NewExecutor(c *config.Config, authenticationService snyk.AuthenticationService, errorReporter error_reporting.ErrorReporter, analytics ux.Analytics, notifier noti.Notifier) Executor {
	concurrencyLimit := 2

	return &SnykCli{
		authenticationService,
		errorReporter,
		analytics,
		make(chan int, concurrencyLimit),
		90 * time.Minute, // TODO: add preference to make this configurable [ROAD-1184]
		notifier,
		c,
	}
}

type Executor interface {
	Execute(ctx context.Context, cmd []string, workingDir string) (resp []byte, err error)
	ExpandParametersFromConfig(base []string) []string
}

func (c SnykCli) Execute(ctx context.Context, cmd []string, workingDir string) (resp []byte, err error) {
	method := "SnykCli.Execute"
	c.c.Logger().Debug().Str("method", method).Interface("cmd", cmd).Str("workingDir", workingDir).Msg("calling Snyk CLI")

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

func (c SnykCli) doExecute(ctx context.Context, cmd []string, workingDir string) ([]byte, error) {
	command := c.getCommand(cmd, workingDir, ctx)
	command.Stderr = c.c.Logger()
	output, err := command.Output()
	return output, err
}

func (c SnykCli) getCommand(cmd []string, workingDir string, ctx context.Context) *exec.Cmd {
	if c.c.Logger().GetLevel() < zerolog.InfoLevel {
		cmd = append(cmd, "-d")
	}
	command := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	command.Dir = workingDir
	cliEnv := AppendCliEnvironmentVariables(os.Environ(), true)
	command.Env = cliEnv
	c.c.Logger().Trace().Str("method", "getCommand").Interface("command.Args", command.Args).Send()
	c.c.Logger().Trace().Str("method", "getCommand").Interface("command.Env", command.Env).Send()
	c.c.Logger().Trace().Str("method", "getCommand").Interface("command.Dir", command.Dir).Send()
	return command
}

func expandParametersFromConfig(base []string) []string {
	var expandedParams = base
	conf := config.CurrentConfig()

	settings := conf.CliSettings()
	if settings.Insecure {
		expandedParams = append(expandedParams, "--insecure")
	}

	org := conf.Organization()
	if org != "" {
		expandedParams = append(expandedParams, "--org="+org)
	}

	return expandedParams
}

// ExpandParametersFromConfig adds configuration parameters to the base command
// todo no need to export that, we could have a simpler interface that looks more like an actual CLI
func (c SnykCli) ExpandParametersFromConfig(base []string) []string {
	return expandParametersFromConfig(base)
}

func (c SnykCli) CliVersion() string {
	cmd := []string{"version"}
	output, err := c.Execute(context.Background(), cmd, "")
	if err != nil {
		c.c.Logger().Error().Err(err).Msg("failed to run version command")
		return ""
	}

	return strings.Trim(string(output), "\n")
}
