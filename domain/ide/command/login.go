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

	"github.com/rs/zerolog"

	"github.com/snyk/snyk-ls/infrastructure/authentication"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

type loginCommand struct {
	command     types.CommandData
	authService authentication.AuthenticationService
	notifier    noti.Notifier
	logger      *zerolog.Logger
}

func (cmd *loginCommand) Command() types.CommandData {
	return cmd.command
}

func (cmd *loginCommand) Execute(ctx context.Context) (any, error) {
	cmd.logger.Debug().Str("method", "loginCommand.Execute").Msgf("logging in")
	token, err := cmd.authService.Authenticate(ctx)
	if err != nil {
		cmd.logger.Err(err).Msg("Error on snyk.login command")
		cmd.notifier.SendError(err)
	}
	if err == nil && token != "" {
		cmd.logger.Debug().Str("method", "loginCommand.Execute").
			Str("hashed token", util.Hash([]byte(token))[0:16]).
			Msgf("authentication successful, received token")
	}
	return nil, err
}
