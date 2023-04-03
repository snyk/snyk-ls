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

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/notification"
)

type loginCommand struct {
	command     snyk.CommandData
	authService snyk.AuthenticationService
}

func (cmd *loginCommand) Command() snyk.CommandData {
	return cmd.command
}

func (cmd *loginCommand) Execute(ctx context.Context) error {
	_, err := cmd.authService.Authenticate(ctx)
	if err != nil {
		log.Err(err).Msg("Error on snyk.login command")
		notification.SendError(err)
	}
	return err
}
