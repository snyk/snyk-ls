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

	gafConfig "github.com/snyk/go-application-framework/pkg/configuration"

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
//
// All three settings are applied before calling ConfigureProviders, so the provider is
// initialized exactly once with the fully-consistent final state.
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

	// 1. Apply endpoint. If changed and LSP is initialized, log out and clear workspace.
	endpointChanged := cmd.c.UpdateApiEndpoints(endpoint)
	if endpointChanged && cmd.c.IsLSPInitialized() {
		cmd.authService.Logout(ctx)
		if ws := cmd.c.Workspace(); ws != nil {
			ws.Clear()
		}
	}

	// 2. Apply insecure setting.
	cmd.c.Engine().GetConfiguration().Set(gafConfig.INSECURE_HTTPS, insecure)

	// 3. Apply auth method after endpoint. The token must also be cleared before setting the
	// new auth method (see below) to eliminate the race window where the new method is set
	// but the old token is still present.
	authMethod := types.AuthenticationMethod(authMethodStr)
	actualMethodChanged := false
	if authMethod != types.EmptyAuthenticationMethod {
		previousMethod := cmd.c.AuthenticationMethod()
		// Clear the stored token BEFORE setting the new auth method. This mirrors
		// writeSettings() which calls updateToken("") before updateAuthenticationMethod().
		// The token must be cleared first to eliminate the race window where the new method
		// is already set but the old token is still present. In that window, a concurrent
		// IsAuthenticated() call can detect a credential mismatch and call logout() →
		// ClearAuthentication() on the CLI provider, which spawns a slow subprocess.
		if authMethod != previousMethod {
			actualMethodChanged = true
			cmd.authService.UpdateCredentials("", false, false)
		}
		cmd.c.SetAuthenticationMethod(authMethod)
	}

	// 4. Reconfigure providers once, after all settings are applied, so the provider
	// is initialized with the complete final state (endpoint + insecure + auth method).
	if endpointChanged || actualMethodChanged {
		cmd.authService.ConfigureProviders(cmd.c)
	}

	return nil
}

func (cmd *loginCommand) Execute(ctx context.Context) (any, error) {
	if len(cmd.command.Arguments) >= 3 {
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
