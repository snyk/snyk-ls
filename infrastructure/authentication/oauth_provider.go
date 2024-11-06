/*
 * © 2023 Snyk Limited
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
	"sync"

	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

type OAuth2Provider struct {
	authenticator auth.Authenticator
	config        configuration.Configuration
	authURL       string
	logger        *zerolog.Logger
	m             sync.Mutex
}

func (p *OAuth2Provider) GetCheckAuthenticationFunction() AuthenticationFunction {
	return AuthenticationCheck
}

func newOAuthProvider(config configuration.Configuration, authenticator auth.Authenticator, logger *zerolog.Logger) *OAuth2Provider {
	logger.Debug().Msg("creating new OAuth provider")
	return &OAuth2Provider{authenticator: authenticator, config: config, logger: logger}
}

func (p *OAuth2Provider) Authenticate(_ context.Context) (string, error) {
	p.m.Lock()
	defer p.m.Unlock()
	err := p.authenticator.Authenticate()
	p.logger.Debug().Msg("authenticated with OAuth")
	return p.config.GetString(auth.CONFIG_KEY_OAUTH_TOKEN), err
}

func (p *OAuth2Provider) setAuthUrl(url string) {
	p.authURL = url
}

func (p *OAuth2Provider) ClearAuthentication(_ context.Context) error {
	p.m.Lock()
	defer p.m.Unlock()
	p.logger.Debug().Msg("clearing authentication")
	p.config.Set(auth.CONFIG_KEY_OAUTH_TOKEN, "")
	p.config.Set(configuration.AUTHENTICATION_TOKEN, "")
	p.config.Set(configuration.AUTHENTICATION_BEARER_TOKEN, "")
	return nil
}

func (p *OAuth2Provider) AuthURL(_ context.Context) string {
	p.m.Lock()
	defer p.m.Unlock()
	return p.authURL
}

func (p *OAuth2Provider) Authenticator() auth.Authenticator {
	p.m.Lock()
	defer p.m.Unlock()
	return p.authenticator
}
