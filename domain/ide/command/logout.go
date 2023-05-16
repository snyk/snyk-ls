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

	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/snyk"
)

type logoutCommand struct {
	command     snyk.CommandData
	authService snyk.AuthenticationService
}

func (cmd *logoutCommand) Command() snyk.CommandData {
	return cmd.command
}

func (cmd *logoutCommand) Execute(ctx context.Context) (any, error) {
	log.Debug().Str("method", "logoutCommand.Execute").Msgf("logging out")
	cmd.authService.Logout(ctx)
	workspace.Get().ClearIssues(ctx)
	return nil, nil
}
