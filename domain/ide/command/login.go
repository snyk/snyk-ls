/*
 * © 2023-2026 Snyk Limited
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
	"fmt"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

type loginCommand struct {
	command     types.CommandData
	authService authentication.AuthenticationService
	notifier    noti.Notifier
	c           *config.Config
}

func (cmd *loginCommand) Command() types.CommandData {
	return cmd.command
}

func (cmd *loginCommand) Execute(ctx context.Context) (any, error) {
	cmd.c.Logger().Debug().Str("method", "loginCommand.Execute").Msgf("logging in")

	args := cmd.command.Arguments
	if len(args) < 3 {
		return nil, fmt.Errorf("login command requires 3 arguments: authMethod, endpoint, insecure; got %d", len(args))
	}

	authMethod, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("login command argument 0 (authMethod) must be a string")
	}
	endpoint, ok := args[1].(string)
	if !ok {
		return nil, fmt.Errorf("login command argument 1 (endpoint) must be a string")
	}
	insecure, ok := args[2].(bool)
	if !ok {
		return nil, fmt.Errorf("login command argument 2 (insecure) must be a bool")
	}

	token, err := cmd.authService.Authenticate(ctx, authMethod, endpoint, insecure)
	if err != nil {
		cmd.c.Logger().Err(err).Msg("Error on snyk.login command")
		cmd.notifier.SendError(err)
		return nil, err
	}

	cmd.c.Logger().Debug().Str("method", "loginCommand.Execute").
		Str("hashed token", util.Hash([]byte(token))[0:16]).
		Msgf("authentication successful, received token")

	// Token is NOT stored on config here — the IDE will persist it and send it back via didChangeConfiguration.
	// LDX-Sync refresh and folder config propagation happen when creds are actually applied via didChangeConfiguration.
	return token, nil
}
