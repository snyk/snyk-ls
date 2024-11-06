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
	"strings"

	"github.com/pkg/errors"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
)

type CliAuthenticationProvider struct {
	authURL       string
	errorReporter error_reporting.ErrorReporter
	c             *config.Config
}

func (a *CliAuthenticationProvider) GetCheckAuthenticationFunction() AuthenticationFunction {
	return AuthenticationCheck
}

func NewCliAuthenticationProvider(c *config.Config, errorReporter error_reporting.ErrorReporter) *CliAuthenticationProvider {
	return &CliAuthenticationProvider{"", errorReporter, c}
}

func (a *CliAuthenticationProvider) setAuthUrl(url string) {
	a.authURL = url
}

func (a *CliAuthenticationProvider) Authenticate(ctx context.Context) (string, error) {
	err := a.authenticate(ctx)
	if err != nil {
		a.c.Logger().Err(err).Str("method", "Authenticate").Msg("error while authenticating")
		a.errorReporter.CaptureError(err)
	}
	token, err := a.getToken(ctx)
	a.c.Logger().Debug().Str("method", "Authenticate").Int("length", len(token)).Msg("got creds")
	if err != nil {
		a.c.Logger().Err(err).Str("method", "Authenticate").Msg("error getting creds after authenticating")
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
	a.c.Logger().Info().Str("output", str).Msg("unset Snyk CLI API creds")

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
			a.c.Logger().Debug().Str("method", "authenticate").Msgf("current auth url line: %s", text)

			if url != "" {
				a.authURL = url
				a.c.Logger().Debug().Str("method", "authenticate").Msgf("found URL: %s", url)
			}
		}

		a.c.Logger().Info().Str("method", "authenticate").Str("output", out.String()).Msg("auth Snyk CLI")
	}()

	// by assigning the writer to stdout, we pipe the cmd output to the go routine that parses it
	cmd.Stdout = writer
	err = a.runCLICmd(ctx, cmd)
	return err
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
	a.c.Logger().Info().Msg("authenticate Snyk CLI with a Snyk account")
	args := []string{"auth"}
	return a.buildCLICmd(ctx, args...), nil
}

// GetToken represents the `snyk config get api` command.
func (a *CliAuthenticationProvider) configGetAPICmd(ctx context.Context) (*exec.Cmd, error) {
	a.c.Logger().Info().Msg("get Snyk API creds")
	args := []string{"config", "get", "api"}
	return a.buildCLICmd(ctx, args...), nil
}

func (a *CliAuthenticationProvider) configUnsetAPICmd(ctx context.Context) (*exec.Cmd, error) {
	a.c.Logger().Info().Msg("unset Snyk CLI API creds")
	args := []string{"config", "unset", "api"}
	return a.buildCLICmd(ctx, args...), nil
}

func (a *CliAuthenticationProvider) buildCLICmd(ctx context.Context, args ...string) *exec.Cmd {
	if config.CurrentConfig().CliSettings().Insecure {
		args = append(args, "--insecure")
	}
	cmd := exec.CommandContext(ctx, config.CurrentConfig().CliSettings().Path(), args...)
	cmd.Env = cli.AppendCliEnvironmentVariables(os.Environ(), false)

	a.c.Logger().Info().Str("command", cmd.String()).Interface("env", cmd.Env).Msg("running Snyk CLI command")
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
	if err == nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		a.c.Logger().Err(err).Msg("error while calling Snyk CLI command")
	}

	return err
}
