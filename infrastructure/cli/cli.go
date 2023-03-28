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

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/notification"
)

type SnykCli struct {
	authenticator snyk.AuthenticationService
	errorReporter error_reporting.ErrorReporter
	analytics     ux.Analytics
	semaphore     chan int
	cliTimeout    time.Duration
}

var Mutex = &sync.Mutex{}

func NewExecutor(authenticator snyk.AuthenticationService, errorReporter error_reporting.ErrorReporter, analytics ux.Analytics) Executor {
	concurrencyLimit := 2

	return &SnykCli{
		authenticator,
		errorReporter,
		analytics,
		make(chan int, concurrencyLimit),
		90 * time.Minute, // TODO: add preference to make this configurable [ROAD-1184]
	}
}

type Executor interface {
	Execute(ctx context.Context, cmd []string, workingDir string) (resp []byte, err error)
	ExpandParametersFromConfig(base []string) []string
	HandleErrors(ctx context.Context, output string) (fail bool)
}

func (c SnykCli) Execute(ctx context.Context, cmd []string, workingDir string) (resp []byte, err error) {
	method := "SnykCli.Execute"
	log.Debug().Str("method", method).Interface("cmd", cmd).Str("workingDir", workingDir).Msg("calling Snyk CLI")

	// set deadline to handle CLI hanging when obtaining semaphore
	ctx, cancel := context.WithDeadline(ctx, time.Now().Add(c.cliTimeout))
	defer cancel()

	// handle concurrency limit, and when context is cancelled
	select {
	case c.semaphore <- 1:
		defer func() { <-c.semaphore }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	output, err := c.doExecute(ctx, cmd, workingDir, true)
	log.Trace().Str("method", method).Str("response", string(output))
	return output, err
}

func (c SnykCli) doExecute(ctx context.Context, cmd []string, workingDir string, firstAttempt bool) ([]byte, error) {
	command := c.getCommand(cmd, workingDir, ctx)
	output, err := command.Output()
	noCancellation := ctx.Err() == nil
	if err != nil && noCancellation {
		ctx := context.Background()
		shouldRetry := c.HandleErrors(ctx, string(output))
		if firstAttempt && shouldRetry {
			output, err = c.doExecute(ctx, cmd, workingDir, false)
		}
	}
	return output, err
}

func (c SnykCli) getCommand(cmd []string, workingDir string, ctx context.Context) *exec.Cmd {
	command := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	command.Dir = workingDir
	cliEnv := AppendCliEnvironmentVariables(os.Environ(), true)
	command.Env = cliEnv
	log.Debug().Str("method", "getCommand").Interface("command", command).Send()
	return command
}

// todo no need to export that, we could have a simpler interface that looks more like an actual CLI
func (c SnykCli) ExpandParametersFromConfig(base []string) []string {
	var expandedParams = base
	settings := config.CurrentConfig().CliSettings()
	if settings.Insecure {
		expandedParams = append(expandedParams, "--insecure")
	}

	return expandedParams
}

func (c SnykCli) HandleErrors(ctx context.Context, output string) (fail bool) {
	if strings.Contains(output, "`snyk` requires an authenticated account. Please run `snyk auth` and try again.") {
		log.Info().Msg("Snyk failed to obtain authentication information. Trying to authenticate again...")
		notification.SendShowMessage(sglsp.Info, "Snyk failed to obtain authentication information, trying to authenticate again. This could open a browser window.")

		token, err := c.authenticator.Provider().Authenticate(ctx)
		if token == "" || err != nil {
			log.Error().Err(err).Msg("Failed to authenticate.")
			c.errorReporter.CaptureError(err)
			return true
		}

		c.authenticator.UpdateCredentials(token, true)
		return true
	}
	return false
}
