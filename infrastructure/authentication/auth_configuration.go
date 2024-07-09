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

package authentication

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/oauth2"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/lsp"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/storage"
	"github.com/snyk/snyk-ls/internal/types"
)

func (a *AuthenticationServiceImpl) ConfigureProviders(c *config.Config) {
	var as []AuthenticationProvider
	switch c.AuthenticationMethod() {
	case lsp.FakeAuthentication:
		a.setProviders([]AuthenticationProvider{NewFakeCliAuthenticationProvider(c)})
	case lsp.TokenAuthentication:
		as = Token(c, a.errorReporter)
		a.setProviders(as)
	case "":
		// don't do anything
	default:
		as = Default(c, a.errorReporter, a)
		a.setProviders(as)
	}
}

// Token authentication configures token only authentication
func Token(c *config.Config, errorReporter error_reporting.ErrorReporter) []AuthenticationProvider {
	return []AuthenticationProvider{NewCliAuthenticationProvider(c, errorReporter)}
}

// Default authentication configures two authenticators, the first OAuth2,
// the second, as fallback, CLI Token auth
// the auth service parameter is needed, as the oauth2 provider needs a callback function
func Default(c *config.Config, errorReporter error_reporting.ErrorReporter, authenticationService AuthenticationService) []AuthenticationProvider {
	authProviders := []AuthenticationProvider{}

	credentialsUpdateCallback := func(_ string, value any) {
		newToken, ok := value.(string)
		if !ok {
			msg := fmt.Sprintf("Failed to cast creds of type %T to string", value)
			errorReporter.CaptureError(errors.New(msg))
			return
		}
		go authenticationService.UpdateCredentials(newToken, true)
	}

	openBrowserFunc := func(url string) {
		for _, provider := range authenticationService.Providers() {
			provider.SetAuthURL(url)
		}
		types.DefaultOpenBrowserFunc(url)
	}

	// add both OAuth2 and CLI, with preference to OAuth2
	authProviders = append(authProviders,
		NewOAuthProvider(
			c,
			auth.RefreshToken,
			credentialsUpdateCallback,
			openBrowserFunc,
		),
	)
	authProviders = append(authProviders, NewCliAuthenticationProvider(c, errorReporter))
	return authProviders
}

func NewOAuthProvider(
	c *config.Config,
	customTokenRefresherFunc func(ctx context.Context, oauthConfig *oauth2.Config, token *oauth2.Token) (*oauth2.Token, error),
	credentialsUpdateCallback storage.StorageCallbackFunc,
	openBrowserFunc func(string),
) *OAuth2Provider {
	engine := c.Engine()
	conf := engine.GetConfiguration()

	conf.Set(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, true)

	c.Storage().RegisterCallback(auth.CONFIG_KEY_OAUTH_TOKEN, credentialsUpdateCallback)

	authenticator := auth.NewOAuth2AuthenticatorWithOpts(
		conf,
		auth.WithOpenBrowserFunc(openBrowserFunc),
		auth.WithTokenRefresherFunc(customTokenRefresherFunc),
	)
	return newOAuthProvider(conf, authenticator, c.Logger())
}
