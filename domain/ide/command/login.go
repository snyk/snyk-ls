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

	gafconfiguration "github.com/snyk/go-application-framework/pkg/configuration"

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

func (cmd *loginCommand) Execute(ctx context.Context) (any, error) {
	cmd.c.Logger().Debug().Str("method", "loginCommand.Execute").Msgf("logging in")

	args := cmd.command.Arguments

	switch len(args) {
	case 0:
		return cmd.executePanelLogin(ctx)
	case 3:
		return cmd.executeSettingsPageLogin(ctx, args)
	default:
		return nil, fmt.Errorf("login command requires 0 or 3 arguments; got %d", len(args))
	}
}

// executePanelLogin handles login triggered from the Snyk panel (no args).
// It authenticates using the configured provider and sends $/snyk.hasAuthenticated via UpdateCredentials.
func (cmd *loginCommand) executePanelLogin(ctx context.Context) (any, error) {
	token, err := cmd.authService.Authenticate(ctx)
	if err != nil {
		return cmd.handleAuthError(err, "from panel")
	}
	if token == "" {
		return nil, nil
	}

	cmd.c.Logger().Debug().Str("method", "loginCommand.executePanelLogin").
		Str("hashed token", util.Hash([]byte(token))[0:16]).
		Msgf("authentication successful, persisting token")

	cmd.ldxSyncService.RefreshConfigFromLdxSync(ctx, cmd.c, cmd.c.Workspace().Folders(), cmd.notifier)
	go sendFolderConfigs(cmd.c, cmd.notifier, cmd.featureFlagService, cmd.configResolver)
	cmd.authService.UpdateCredentials(token, true, true)
	return nil, nil
}

func (cmd *loginCommand) handleAuthError(err error, source string) (any, error) {
	cmd.c.Logger().Err(err).Msgf("Error on snyk.login command (%s)", source)
	cmd.notifier.SendError(err)
	return nil, err
}

// executeSettingsPageLogin handles login triggered from the HTML settings page (3 args: method, endpoint, insecure).
// It applies the provided config values to LS, authenticates with the configured provider,
// and sends $/snyk.hasAuthenticated via UpdateCredentials so the IDE updates its webview.
func (cmd *loginCommand) executeSettingsPageLogin(ctx context.Context, args []any) (any, error) {
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

	cmd.applyAuthConfig(authMethod, endpoint, insecure)

	token, err := cmd.authService.Authenticate(ctx)
	if err != nil {
		return cmd.handleAuthError(err, "from html settings page")
	}
	if token == "" {
		return nil, nil
	}

	cmd.c.Logger().Debug().Str("method", "loginCommand.executeSettingsPageLogin").
		Str("hashed token", util.Hash([]byte(token))[0:16]).
		Msgf("authentication successful, sending hasAuthenticated notification")

	cmd.ldxSyncService.RefreshConfigFromLdxSync(ctx, cmd.c, cmd.c.Workspace().Folders(), cmd.notifier)
	go sendFolderConfigs(cmd.c, cmd.notifier, cmd.featureFlagService, cmd.configResolver)
	cmd.authService.UpdateCredentials(token, true, true)
	return nil, nil
}

// applyAuthConfig applies the provided endpoint, insecure, and auth method values to the LS config
// before authentication. This mirrors the logic from writeSettings so the auth flow uses the same
// settings the user specified on the settings page.
func (cmd *loginCommand) applyAuthConfig(authMethod string, endpoint string, insecure bool) {
	c := cmd.c
	authService := cmd.authService

	c.Engine().GetConfiguration().ClearCache()

	// Apply endpoint: if changed and LSP is initialized, logout + reconfigure + clear workspace.
	endpointsUpdated := c.UpdateApiEndpoints(endpoint)
	if endpointsUpdated && c.IsLSPInitialized() {
		authService.Logout(context.Background())
		authService.ConfigureProviders(c)
		if c.Workspace() != nil {
			c.Workspace().Clear()
		}
	}

	// Apply insecure setting.
	cliSettings := c.CliSettings()
	if cliSettings.Insecure != insecure {
		cliSettings.Insecure = insecure
		c.Engine().GetConfiguration().Set(gafconfiguration.INSECURE_HTTPS, insecure)
		c.SetCliSettings(cliSettings)
	}

	// Apply auth method: always configure providers to ensure the provider matches the method.
	if authMethod != "" {
		c.SetAuthenticationMethod(types.AuthenticationMethod(authMethod))
		authService.ConfigureProviders(c)
	}
}
