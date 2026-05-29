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

// ApplyEndpointChange updates API endpoints. If changed and LSP is initialized,
// logs out and clears workspace. Returns true if endpoints changed.
// Logout internally calls configureProviders, so no explicit ConfigureProviders call is needed.
func ApplyEndpointChange(ctx context.Context, conf gafConfig.Configuration, authService authentication.AuthenticationService, logger *zerolog.Logger, endpoint string) bool {
	oldEndpoint := types.GetGlobalString(conf, types.SettingApiEndpoint)
	changed := config.UpdateApiEndpointsOnConfig(conf, endpoint)
	if changed && conf.GetBool(types.SettingIsLspInitialized) {
		if authService == nil {
			logger.Error().
				Str("old_endpoint", oldEndpoint).
				Str("new_endpoint", endpoint).
				Msg("authService is nil; skipping logout on endpoint change — credentials may persist against wrong endpoint")
			return changed
		}
		logger.Info().
			Str("old_endpoint", oldEndpoint).
			Str("new_endpoint", endpoint).
			Msg("auth endpoint changed after LSP initialization; clearing credentials")
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
// SetGlobalUser is called unconditionally so the new method persists across restarts even
// when authService is nil. ConfigureProviders is skipped when authService is nil.
func ApplyAuthMethodChange(conf gafConfig.Configuration, authService authentication.AuthenticationService, logger *zerolog.Logger, authMethod types.AuthenticationMethod) bool {
	if authMethod == types.EmptyAuthenticationMethod {
		return false
	}

	previousMethod := config.GetAuthenticationMethodFromConfig(conf)
	logger.Info().
		Str("old_auth_method", string(previousMethod)).
		Str("new_auth_method", string(authMethod)).
		Msg("auth method change requested")
	types.SetGlobalUser(conf, types.SettingAuthenticationMethod, string(authMethod))
	if authService == nil {
		logger.Warn().
			Str("auth_method", string(authMethod)).
			Msg("authService is nil; auth method persisted but ConfigureProviders skipped")
		return false
	}
	authService.ConfigureProviders(conf, logger)

	return authMethod != previousMethod
}
