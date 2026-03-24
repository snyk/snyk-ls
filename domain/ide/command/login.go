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
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

type loginCommand struct {
	command            types.CommandData
	authService        authentication.AuthenticationService
	featureFlagService featureflag.Service
	notifier           noti.Notifier
	c                  *config.Config
	ldxSyncService     LdxSyncService
	configResolver     types.ConfigResolverInterface
}

func (cmd *loginCommand) Command() types.CommandData {
	return cmd.command
}

// applyAuthConfig applies auth settings from command arguments to the config before authentication.
// Arguments must be in the order: authMethod (string), endpoint (string), insecure (bool or string).
// The order mirrors the order in writeSettings() in application/server/configuration.go.
func (cmd *loginCommand) applyAuthConfig(ctx context.Context) error {
	args := cmd.command.Arguments

	authMethodStr, ok := args[0].(string)
	if !ok {
		return fmt.Errorf("expected string for authMethod argument, got %T", args[0])
	}

	endpoint, ok := args[1].(string)
	if !ok {
		return fmt.Errorf("expected string for endpoint argument, got %T", args[1])
	}

	insecure, err := util.ParseBoolArg(args[2])
	if err != nil {
		return fmt.Errorf("expected bool for insecure argument: %w", err)
	}

	ApplyEndpointChange(ctx, cmd.c, cmd.authService, endpoint)
	ApplyInsecureSetting(cmd.c, insecure)
	ApplyAuthMethodChange(ctx, cmd.c, cmd.authService, types.AuthenticationMethod(authMethodStr))

	return nil
}

func (cmd *loginCommand) Execute(ctx context.Context) (any, error) {
	// The login command accepts either 0 arguments (use current config) or exactly 3
	// (authMethod, endpoint, insecure). Any other count is a caller error.
	n := len(cmd.command.Arguments)
	if n != 0 && n != 3 {
		err := fmt.Errorf("login command expects 0 or 3 arguments, got %d", n)
		cmd.c.Logger().Err(err).Msg("Invalid argument count for login command")
		cmd.notifier.SendError(err)
		return nil, err
	}

	if n == 3 {
		if err := cmd.applyAuthConfig(ctx); err != nil {
			cmd.c.Logger().Err(err).Msg("Error applying auth config from login command arguments")
			cmd.notifier.SendError(err)
			return nil, err
		}
	}

	token, err := cmd.authService.Authenticate(ctx)
	if err != nil {
		cmd.c.Logger().Err(err).Msg("Error on snyk.login command")
		cmd.notifier.SendError(err)
	}
	if err == nil && token != "" {
		cmd.c.Logger().Debug().Str("method", "loginCommand.Execute").
			Str("hashed token", util.Hash([]byte(token))[0:16]).
			Msgf("authentication successful, received token")

		// Refresh LDX-Sync configuration after successful authentication.
		// Use context.Background() so this is not canceled if the LSP request context is
		// canceled (e.g. when the IDE cancels the snyk.login request after auth completes).
		cmd.ldxSyncService.RefreshConfigFromLdxSync(context.Background(), cmd.c, cmd.c.Workspace().Folders(), cmd.notifier)
		go sendFolderConfigs(cmd.c, cmd.notifier, cmd.featureFlagService, cmd.configResolver)

		return token, nil
	}
	return nil, err
}
