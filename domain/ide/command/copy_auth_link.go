/*
 * © 2023 Snyk Limited
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

	"github.com/atotto/clipboard"
	"github.com/rs/zerolog"

	noti "github.com/snyk/snyk-ls/domain/ide/notification"
	"github.com/snyk/snyk-ls/domain/snyk"
)

type copyAuthLinkCommand struct {
	command     snyk.CommandData
	authService snyk.AuthenticationService
	notifier    noti.Notifier
	logger      *zerolog.Logger
}

func (cmd *copyAuthLinkCommand) Command() snyk.CommandData {
	return cmd.command
}

func (cmd *copyAuthLinkCommand) Execute(ctx context.Context) (any, error) {
	url := cmd.authService.Provider().AuthURL(ctx)
	cmd.logger.Debug().Str("method", "copyAuthLinkCommand.Execute").
		Str("url", url).
		Msgf("copying auth link to clipboard")
	err := clipboard.WriteAll(url)

	if err != nil {
		cmd.logger.Err(err).Msg("Error on snyk.copyAuthLink command")
		cmd.notifier.SendError(err)
	}
	return url, err
}
