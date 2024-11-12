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

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/internal/types"
)

type logoutCommand struct {
	command     types.CommandData
	authService authentication.AuthenticationService
	c           *config.Config
}

func (cmd *logoutCommand) Command() types.CommandData {
	return cmd.command
}

func (cmd *logoutCommand) Execute(ctx context.Context) (any, error) {
	cmd.c.Logger().Debug().Str("method", "logoutCommand.Execute").Msgf("logging out")
	cmd.authService.Logout(ctx)
	cmd.c.Workspace().Clear()
	return nil, nil
}
