/*
 * © 2026 Snyk Limited
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
	gafConfig "github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/internal/types"
)

// ApplyEndpointChange updates API endpoints. If changed and the LSP handshake has been
// acknowledged, logs out and clears workspace. Returns true if endpoints changed.
// Logout internally calls configureProviders, so no explicit ConfigureProviders call is needed.
//
// Requires a non-nil authService, so that logout can be called.
func ApplyEndpointChange(ctx context.Context, conf gafConfig.Configuration, authService authentication.AuthenticationService, logger *zerolog.Logger, endpoint string) bool {
	oldEndpoint := types.GetGlobalString(conf, types.SettingApiEndpoint)
	// Once the LSP handshake is acknowledged, an endpoint switch requires logout to clear
	// credentials. Mutating config without logout would leave the system with new-endpoint
	// config but old-environment credentials — a session leakage risk. This gates on the
	// early handshake-ack signal (not scanner readiness) so the safety clear still runs
	// while background scanner init is in flight (IDE-2181).
	handshakeAcknowledged := types.IsLspHandshakeAcknowledged(conf)
	if handshakeAcknowledged && authService == nil {
		logger.Error().
			Str("old_endpoint", oldEndpoint).
			Str("new_endpoint", endpoint).
			Msg("authService is nil; skipping endpoint switch to prevent session leakage")
		return false
	}
	changed := config.UpdateApiEndpointsOnConfig(conf, endpoint)
	if changed && handshakeAcknowledged {
		logger.Info().
			Str("old_endpoint", oldEndpoint).
			Str("new_endpoint", endpoint).
			Msg("auth endpoint changed after LSP handshake acknowledged; clearing credentials")
		authService.Logout(ctx)
		ws := config.GetWorkspace(conf)
		if ws != nil {
			ws.Clear()
		}
	}
	return changed
}

// ApplyInsecureSetting updates the INSECURE_HTTPS engine config flag.
func ApplyInsecureSetting(conf gafConfig.Configuration, insecure bool) {
	conf.Set(gafConfig.INSECURE_HTTPS, insecure)
}

// ApplyAuthMethodChange sets the auth method and calls ConfigureProviders.
// Returns true if the method actually changed.
// authService is guaranteed non-nil by the caller's mandatory-dependency validation
// (validateMandatoryDeps in application/server/server.go, run before any handler), so unlike
// ApplyEndpointChange this function dereferences it without a nil guard.
func ApplyAuthMethodChange(conf gafConfig.Configuration, authService authentication.AuthenticationService, logger *zerolog.Logger, authMethod types.AuthenticationMethod) bool {
	if authMethod == types.EmptyAuthenticationMethod {
		return false
	}

	previousMethod := config.GetAuthenticationMethodFromConfig(conf)
	changed := authMethod != previousMethod
	logger.Info().
		Str("old_auth_method", string(previousMethod)).
		Str("new_auth_method", string(authMethod)).
		Msg("auth method change requested")

	// When the method actually changes, cancel any login still in flight for the previous method so a
	// stuck auth is aborted immediately and its now-stale result is discarded: canceling the auth
	// context here is what makes the ctx.Err() guard in Authenticate drop the result rather than apply
	// it against the newly reconfigured provider. CancelOngoingAuth uses a separate mutex and is safe
	// to call when nothing is in flight. Both providers return promptly on cancellation — the CLI
	// provider's subprocess is killed via exec.CommandContext, and the OAuth provider's
	// CancelableAuthenticate honors the context.
	//
	// Guarded on `changed` so a config re-push that does not change the method (the settings-change
	// caller, applyAuthenticationMethod) never cancels a freshly started login. The login command
	// path handles the unchanged-method case with its own unconditional cancel (see login.go), since
	// there a login always supersedes in-flight auth.
	if changed {
		authService.CancelOngoingAuth()
	}

	types.SetGlobalUser(conf, types.SettingAuthenticationMethod, string(authMethod))
	authService.ConfigureProviders(conf, logger)

	return changed
}
