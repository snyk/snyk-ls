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

package auth

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/cli"
)

type CliAuthenticationProvider struct {
	authURL       string
	cli           cli.Executor
	errorReporter error_reporting.ErrorReporter
}

func (a *CliAuthenticationProvider) GetCheckAuthenticationFunction() snyk.AuthenticationFunction {
	return snyk.AuthenticationCheck
}

func NewCliAuthenticationProvider(errorReporter error_reporting.ErrorReporter, cli cli.Executor) snyk.AuthenticationProvider {
	return &CliAuthenticationProvider{"", cli, errorReporter}
}

func (a *CliAuthenticationProvider) SetAuthURL(url string) {
	a.authURL = url
}

func (a *CliAuthenticationProvider) Authenticate(ctx context.Context) (string, error) {
	err := a.authenticate(ctx)
	if err != nil {
		log.Err(err).Str("method", "Authenticate").Msg("error while authenticating")
		a.errorReporter.CaptureError(err)
	}
	token, err := a.getToken(ctx)
	log.Debug().Str("method", "Authenticate").Int("token length", len(token)).Msg("got token")
	if err != nil {
		log.Err(err).Str("method", "Authenticate").Msg("error getting token after azuthenticating")
		a.errorReporter.CaptureError(err)
	}

	return token, err
}

func (a *CliAuthenticationProvider) ClearAuthentication(ctx context.Context) error {
	cmd := a.configUnsetAPICmd()

	err := a.runCLICmd(ctx, cmd)
	if err != nil {
		return err
	}

	log.Info().Msg("unset Snyk CLI API token")

	return err
}

func (a *CliAuthenticationProvider) AuthURL(_ context.Context) string {
	return a.authURL
}

// Auth represents the `snyk auth` command.
func (a *CliAuthenticationProvider) authenticate(ctx context.Context) error { //
	a.authURL = ""

	cmd := a.authCmd()

	stdoutReaderFunc := func(reader *io.PipeReader, writer *io.PipeWriter) {
		defer func(writer *io.PipeWriter) { _ = writer.Close() }(writer)

		out := &strings.Builder{}
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			text := scanner.Text()
			url := a.getAuthURL(text)
			out.Write(scanner.Bytes())
			log.Debug().Str("method", "authenticate").Msgf("current auth url line: %s", text)

			if url != "" {
				a.authURL = url
				log.Debug().Str("method", "authenticate").Msgf("found URL: %s", url)
			}
		}

		log.Info().Str("method", "authenticate").Str("output", out.String()).Msg("auth Snyk CLI")
	}

	// by assigning the writer to stdout, we pipe the cmd output to the go routine that parses it
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	// reader, writer := io.Pipe()
	err = a.cli.ExecuteWithFunc(ctx, cmd, dir, stdoutReaderFunc)
	if err != nil {
		return err
	}

	// cmd.Stdout = writer
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
	cmd := a.configGetAPICmd()

	var out strings.Builder

	err := a.runCLICmd(ctx, cmd)
	if err != nil {
		return "", errors.Wrap(err, fmt.Sprintf("error getting token with %v", cmd))
	}

	token := out.String()
	token = strings.TrimSuffix(token, "\r")
	token = strings.TrimSuffix(token, "\n")

	if token == "" {
		return "", snyk.ErrEmptyAPIToken
	}

	return token, nil
}

func (a *CliAuthenticationProvider) authCmd() []string {
	log.Info().Msg("authenticate Snyk CLI with a Snyk account")
	args := []string{"auth"}
	return args
}

// GetToken represents the `snyk config get api` command.
func (a *CliAuthenticationProvider) configGetAPICmd() []string {
	log.Info().Msg("get Snyk API token")
	args := []string{"config", "get", "api"}
	return args
}

func (a *CliAuthenticationProvider) configUnsetAPICmd() []string {
	log.Info().Msg("unset Snyk CLI API token")
	args := []string{"config", "unset", "api"}
	return args
}

func (a *CliAuthenticationProvider) runCLICmd(ctx context.Context, args []string) error {
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	_, err = a.cli.Execute(ctx, args, dir)

	if err != nil {
		return err
	}
	return nil
}
