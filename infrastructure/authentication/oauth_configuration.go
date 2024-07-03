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

	"golang.org/x/oauth2"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/storage"
)

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
