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
// It authenticates using the stored LS defaults, persists the token immediately,
// and sends $/snyk.hasAuthenticated so the IDE also persists and updates the webview.
func (cmd *loginCommand) executePanelLogin(ctx context.Context) (any, error) {
	authMethod := string(cmd.c.AuthenticationMethod())
	endpoint := cmd.c.SnykApi()
	insecure := cmd.c.CliSettings().Insecure

	result, err := cmd.authService.Authenticate(ctx, authMethod, endpoint, insecure)
	if err != nil {
		return cmd.handleAuthError(err, "panel")
	}

	cmd.c.Logger().Debug().Str("method", "loginCommand.executePanelLogin").
		Str("hashed token", util.Hash([]byte(result.Token))[0:16]).
		Msgf("authentication successful, persisting token")

	// Persist token in LS config and notify IDE to also persist and update webview.
	if result.ApiUrl != "" {
		cmd.c.UpdateApiEndpoints(result.ApiUrl)
	}
	cmd.authService.UpdateCredentials(result.Token, false, false)
	cmd.notifier.Send(types.AuthenticationParams{Token: result.Token, ApiUrl: result.ApiUrl, Persist: true})
	return nil, nil
}

func (cmd *loginCommand) handleAuthError(err error, source string) (any, error) {
	cmd.c.Logger().Err(err).Msgf("Error on snyk.login command (%s)", source)
	cmd.notifier.SendError(err)
	return nil, err
}

// executeSettingsPageLogin handles login triggered from the HTML settings page (3 args).
// It authenticates with a temporary provider and sends $/snyk.hasAuthenticated so the IDE
// injects the token into the webview via window.setAuthToken. The token is NOT persisted here —
// the user decides via Save (persists via didChangeConfiguration) or Cancel (discards).
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

	result, err := cmd.authService.Authenticate(ctx, authMethod, endpoint, insecure)
	if err != nil {
		return cmd.handleAuthError(err, "settings page")
	}

	cmd.c.Logger().Debug().Str("method", "loginCommand.executeSettingsPageLogin").
		Str("hashed token", util.Hash([]byte(result.Token))[0:16]).
		Msgf("authentication successful, sending hasAuthenticated notification")

	// Send $/snyk.hasAuthenticated so the IDE injects the token into the webview via window.setAuthToken.
	// The token is NOT stored here — the user controls persistence via Save/Cancel.
	cmd.notifier.Send(types.AuthenticationParams{Token: result.Token, ApiUrl: result.ApiUrl, Persist: false})
	return nil, nil
}
