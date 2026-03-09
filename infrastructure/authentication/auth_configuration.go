/*
 * © 2024 Snyk Limited
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

// Package authentication implements authentication functionality
package authentication

import (
	"context"

	"golang.org/x/oauth2"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/storage"
	"github.com/snyk/snyk-ls/internal/types"
)

// Token authentication configures token only authentication
func Token(engine workflow.Engine, errorReporter error_reporting.ErrorReporter) AuthenticationProvider {
	unsetOauthTokenConfig(engine)
	return NewCliAuthenticationProvider(engine, errorReporter)
}

func Pat(engine workflow.Engine, authenticationService AuthenticationService) AuthenticationProvider {
	unsetOauthTokenConfig(engine)

	openBrowserFunc := func(url string) {
		authenticationService.provider().setAuthUrl(url)
		types.DefaultOpenBrowserFunc(url)
	}

	return NewPatProvider(engine, openBrowserFunc)
}

func unsetOauthTokenConfig(engine workflow.Engine) {
	conf := engine.GetConfiguration()
	if s := conf.GetStorage(); s != nil {
		if storageWithCallbacks, ok := s.(storage.StorageWithCallbacks); ok {
			storageWithCallbacks.UnRegisterCallback(auth.CONFIG_KEY_OAUTH_TOKEN)
		}
	}

	conf.Unset(configuration.AUTHENTICATION_BEARER_TOKEN)
	conf.Unset(auth.CONFIG_KEY_OAUTH_TOKEN)
}

// Default authentication configures an OAuth2 authenticator,
// the auth service parameter is needed, as the oauth2 provider needs a callback function
func Default(engine workflow.Engine, authenticationService AuthenticationService) AuthenticationProvider {
	conf := engine.GetConfiguration()
	conf.Unset(configuration.AUTHENTICATION_TOKEN)
	credentialsUpdateCallback := func(_ string, value any) {
		// an empty struct marks an empty token, so we stay with empty string if the cast fails
		newToken, _ := value.(string)
		go authenticationService.updateCredentials(newToken, true, false)
	}

	openBrowserFunc := func(url string) {
		authenticationService.provider().setAuthUrl(url)
		types.DefaultOpenBrowserFunc(url)
	}

	// this doesn't have any effect
	refresherFunc := func(ctx context.Context, oauthConfig *oauth2.Config, token *oauth2.Token) (*oauth2.Token, error) {
		logger := engine.GetLogger().With().Str("method", "oauth.refresherFunc").Logger()
		logger.Info().Msg("refreshing oauth2 token")
		logger.Info().Msgf("used truncated refresh token: %s", token.RefreshToken[len(token.RefreshToken)-8:])
		refreshToken, err := auth.RefreshToken(ctx, oauthConfig, token)
		if err != nil {
			logger.Err(err).Msg("failed to refresh oauth2 token")
			// call authservice to handle notifications and such
			// we don't need the returned values, as we know it will either return false, nil or false, err
			_ = authenticationService.IsAuthenticated()
		}
		return refreshToken, err
	}
	authProvider := NewOAuthProvider(
		engine,
		refresherFunc,
		credentialsUpdateCallback,
		openBrowserFunc,
	)
	return authProvider
}

func NewOAuthProvider(
	engine workflow.Engine,
	customTokenRefresherFunc func(ctx context.Context, oauthConfig *oauth2.Config, token *oauth2.Token) (*oauth2.Token, error),
	credentialsUpdateCallback storage.StorageCallbackFunc,
	openBrowserFunc func(string),
) *OAuth2Provider {
	conf := engine.GetConfiguration()

	conf.Set(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, true)

	if s := conf.GetStorage(); s != nil {
		if storageWithCallbacks, ok := s.(storage.StorageWithCallbacks); ok {
			storageWithCallbacks.RegisterCallback(auth.CONFIG_KEY_OAUTH_TOKEN, credentialsUpdateCallback)
		}
	}

	authenticator := auth.NewOAuth2AuthenticatorWithOpts(
		conf,
		auth.WithOpenBrowserFunc(openBrowserFunc),
		auth.WithTokenRefresherFunc(customTokenRefresherFunc),
		auth.WithLogger(engine.GetLogger()),
		auth.WithHttpClient(engine.GetNetworkAccess().GetUnauthorizedHttpClient()),
	)
	return newOAuthProvider(conf, authenticator, engine.GetLogger())
}

func NewPatProvider(engine workflow.Engine, openBrowserFunc func(string)) *PatAuthenticationProvider {
	conf := engine.GetConfiguration()
	return newPatAuthenticationProvider(conf, openBrowserFunc, engine.GetLogger())
}
