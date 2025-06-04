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
	"errors"
	"sync"

	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

type OAuth2Provider struct {
	authenticator auth.CancelableAuthenticator
	config        configuration.Configuration
	authURL       string
	logger        *zerolog.Logger
	m             sync.Mutex
}

func (p *OAuth2Provider) GetCheckAuthenticationFunction() AuthenticationFunction {
	return AuthenticationCheck
}

func newOAuthProvider(config configuration.Configuration, authenticator auth.CancelableAuthenticator, logger *zerolog.Logger) *OAuth2Provider {
	logger.Debug().Msg("creating new OAuth provider")
	return &OAuth2Provider{authenticator: authenticator, config: config, logger: logger}
}

func (p *OAuth2Provider) Authenticate(ctx context.Context) (string, error) {
	p.m.Lock()
	defer p.m.Unlock()
	err := p.authenticator.CancelableAuthenticate(ctx)
	switch {
	case errors.Is(err, auth.ErrAuthCanceled):
		p.logger.Info().Msg("authentication canceled")
		return "", nil // Consume the error, the user knows they canceled.
	case err != nil:
		return "", err
	}
	p.logger.Debug().Msg("authenticated with OAuth")
	return p.config.GetString(auth.CONFIG_KEY_OAUTH_TOKEN), nil
}

func (p *OAuth2Provider) setAuthUrl(url string) {
	p.authURL = url
}

func (p *OAuth2Provider) ClearAuthentication(_ context.Context) error {
	p.m.Lock()
	defer p.m.Unlock()
	p.logger.Debug().Msg("clearing authentication")
	p.config.Unset(auth.CONFIG_KEY_OAUTH_TOKEN)
	p.config.Unset(configuration.AUTHENTICATION_TOKEN)
	p.config.Unset(configuration.AUTHENTICATION_BEARER_TOKEN)
	return nil
}

func (p *OAuth2Provider) AuthURL(_ context.Context) string {
	// no lock should be used here, as this is usually called during authentication flow, which write-locks the mutex
	return p.authURL
}

func (p *OAuth2Provider) Authenticator() auth.Authenticator {
	p.m.Lock()
	defer p.m.Unlock()
	return p.authenticator
}
