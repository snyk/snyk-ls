/*
 * © 2022-2024 Snyk Limited
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

package authentication

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

type CliAuthenticationProvider struct {
	authURL        string
	errorReporter  error_reporting.ErrorReporter
	engine         workflow.Engine
	configResolver types.ConfigResolverInterface
}

func (a *CliAuthenticationProvider) GetCheckAuthenticationFunction() AuthenticationFunction {
	return AuthenticationCheck
}

func NewCliAuthenticationProvider(engine workflow.Engine, errorReporter error_reporting.ErrorReporter, configResolver types.ConfigResolverInterface) *CliAuthenticationProvider {
	return &CliAuthenticationProvider{"", errorReporter, engine, configResolver}
}

func (a *CliAuthenticationProvider) setAuthUrl(url string) {
	a.authURL = url
}

func (a *CliAuthenticationProvider) Authenticate(ctx context.Context) (string, error) {
	logger := a.engine.GetLogger()
	err := a.authenticate(ctx)
	if err != nil {
		// A canceled authentication (e.g. the IDE canceled the login via $/cancelRequest) is an
		// expected outcome, not a failure: log at debug and don't report it.
		if util.IsCancellation(err) {
			logger.Debug().Str("method", "Authenticate").Msg("authentication canceled")
			return "", err
		}
		logger.Err(err).Str("method", "Authenticate").Msg("error while authenticating")
		a.errorReporter.CaptureError(err)
	}
	token, err := a.getToken(ctx)
	logger.Debug().Str("method", "Authenticate").Int("length", len(token)).Msg("got creds")
	if err != nil {
		if util.IsCancellation(err) {
			logger.Debug().Str("method", "Authenticate").Msg("get creds canceled")
			return "", err
		}
		logger.Err(err).Str("method", "Authenticate").Msg("error getting creds after authenticating")
		a.errorReporter.CaptureError(err)
	}

	return token, err
}

func (a *CliAuthenticationProvider) ClearAuthentication(ctx context.Context) error {
	cmd, err := a.configUnsetAPICmd(ctx)
	if err != nil {
		return err
	}

	var out strings.Builder
	cmd.Stdout = &out

	err = a.runCLICmd(ctx, cmd)

	str := out.String()
	a.engine.GetLogger().Info().Str("output", str).Msg("unset Snyk CLI API creds")

	if err != nil {
		return err
	}

	return err
}

func (a *CliAuthenticationProvider) AuthURL(_ context.Context) string {
	return a.authURL
}

// Auth represents the `snyk auth` command.
func (a *CliAuthenticationProvider) authenticate(ctx context.Context) error {
	a.authURL = ""

	cmd, err := a.authCmd(ctx)
	if err != nil {
		return err
	}

	reader, writer := io.Pipe()
	go func() {
		defer func(writer *io.PipeWriter) { _ = writer.Close() }(writer)

		out := &strings.Builder{}
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			text := scanner.Text()
			url := a.getAuthURL(text)
			out.Write(scanner.Bytes())
			a.engine.GetLogger().Debug().Str("method", "authenticate").Msgf("current auth url line: %s", text)

			if url != "" {
				a.authURL = url
				a.engine.GetLogger().Debug().Str("method", "authenticate").Msgf("found URL: %s", url)
			}
		}

		a.engine.GetLogger().Info().Str("method", "authenticate").Str("output", out.String()).Msg("auth Snyk CLI")
	}()

	// by assigning the writer to stdout, we pipe the cmd output to the go routine that parses it
	cmd.Stdout = writer
	return a.runCLICmd(ctx, cmd)
}

func (a *CliAuthenticationProvider) getAuthURL(str string) string {
	url := ""

	hasToken := strings.Contains(str, "/login?token=")
	index := strings.Index(str, "https://")

	if index != -1 && hasToken {
		url = str[index:]

		// trim the line ending
		url = strings.TrimRight(url, "\r")
		url = strings.TrimRight(url, "\n")
	}

	return url
}

func (a *CliAuthenticationProvider) getToken(ctx context.Context) (string, error) {
	cmd, err := a.configGetAPICmd(ctx)
	if err != nil {
		return "", err
	}

	var out strings.Builder
	cmd.Stdout = &out

	err = a.runCLICmd(ctx, cmd)
	if err != nil {
		return "", errors.Wrap(err, fmt.Sprintf("error getting creds with %v", cmd))
	}

	token := out.String()
	token = strings.TrimSuffix(token, "\r")
	token = strings.TrimSuffix(token, "\n")

	if token == "" {
		return "", ErrEmptyAPIToken
	}

	return token, nil
}

func (a *CliAuthenticationProvider) authCmd(ctx context.Context) (*exec.Cmd, error) {
	a.engine.GetLogger().Info().Msg("authenticate Snyk CLI with a Snyk account")
	args := []string{"auth"}
	return a.buildCLICmd(ctx, args...), nil
}

// GetToken represents the `snyk config get api` command.
func (a *CliAuthenticationProvider) configGetAPICmd(ctx context.Context) (*exec.Cmd, error) {
	a.engine.GetLogger().Info().Msg("get Snyk API creds")
	args := []string{"config", "get", "api"}
	return a.buildCLICmd(ctx, args...), nil
}

func (a *CliAuthenticationProvider) configUnsetAPICmd(ctx context.Context) (*exec.Cmd, error) {
	a.engine.GetLogger().Info().Msg("unset Snyk CLI API creds")
	args := []string{"config", "unset", "api"}
	return a.buildCLICmd(ctx, args...), nil
}

func (a *CliAuthenticationProvider) buildCLICmd(ctx context.Context, args ...string) *exec.Cmd {
	if a.configResolver.GetBool(types.SettingProxyInsecure, nil) {
		args = append(args, "--insecure")
	}
	cliPath := a.configResolver.GetString(types.SettingCliPath, nil)
	if cliPath != "" {
		cliPath = filepath.Clean(cliPath)
	}
	cmd := exec.CommandContext(ctx, cliPath, args...)
	cmd.Env = cli.AppendCliEnvironmentVariables(a.engine, a.configResolver, os.Environ(), false)

	a.engine.GetLogger().Info().Str("command", cmd.String()).Msg("running Snyk CLI command")
	return cmd
}

func (a *CliAuthenticationProvider) runCLICmd(ctx context.Context, cmd *exec.Cmd) error {
	// check for early cancellation
	select {
	case <-ctx.Done():
		return ctx.Err()
	default: // If no cancellation requested, do nothing
	}

	err := cmd.Run()
	// When the context is done (the IDE cancels the login via $/cancelRequest, or a deadline fires),
	// exec kills the CLI subprocess and cmd.Run() returns "signal: killed". Normalize that to the
	// context error so callers can detect it with errors.Is and treat it as expected rather than a
	// failure. The underlying cmd.Run() error is logged at debug (not discarded silently) for
	// diagnosability when a real CLI failure races the cancellation/timeout.
	if ctxErr := ctx.Err(); ctxErr != nil {
		a.engine.GetLogger().Debug().Err(err).Str("method", "runCLICmd").Msgf("Snyk CLI command aborted (%v); discarding subprocess error", ctxErr)
		return ctxErr
	}
	if err != nil {
		a.engine.GetLogger().Err(err).Msg("error while calling Snyk CLI command")
	}

	return err
}

func (a *CliAuthenticationProvider) AuthenticationMethod() types.AuthenticationMethod {
	return types.TokenAuthentication
}
