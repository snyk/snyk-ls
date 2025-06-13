/*
 * © 2022-2025 Snyk Limited
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

type PatAuthenticationProvider struct {
	config          configuration.Configuration
	openBrowserFunc func(string)
	authURL         string
	logger          *zerolog.Logger
	m               sync.Mutex
}

func (p *PatAuthenticationProvider) GetCheckAuthenticationFunction() AuthenticationFunction {
	return AuthenticationCheck
}

func newPatAuthenticationProvider(config configuration.Configuration, openBrowserFunc func(string), logger *zerolog.Logger) *PatAuthenticationProvider {
	logger.Debug().Msg("creating new PAT provider")
	return &PatAuthenticationProvider{openBrowserFunc: openBrowserFunc, config: config, logger: logger}
}

// Authenticate opens the browser so the user can generate a PAT. This is the function that gets called when a user
// clicks the "Connect IDE to Snyk" button. It does NOT authenticate the PAT; that is done by GAF when the PAT is first
// used.
func (p *PatAuthenticationProvider) Authenticate(_ context.Context) (string, error) {
	p.m.Lock()
	defer p.m.Unlock()

	url := p.config.GetString(configuration.WEB_APP_URL) + "/account/personal-access-tokens"
	p.logger.Debug().Msg("PAT URL: " + url)

	p.openBrowserFunc(url)
	p.logger.Debug().Msg("Opened browser to generate PAT")
	return "", nil
}

func (p *PatAuthenticationProvider) setAuthUrl(url string) {
	p.authURL = url
}

func (p *PatAuthenticationProvider) ClearAuthentication(_ context.Context) error {
	p.m.Lock()
	defer p.m.Unlock()
	p.logger.Debug().Msg("clearing authentication")
	p.config.Unset(auth.CONFIG_KEY_OAUTH_TOKEN)
	p.config.Unset(configuration.AUTHENTICATION_TOKEN)
	p.config.Unset(configuration.AUTHENTICATION_BEARER_TOKEN)
	return nil
}

func (p *PatAuthenticationProvider) AuthURL(_ context.Context) string {
	// no lock should be used here, as this is usually called during authentication flow, which write-locks the mutex
	return p.authURL
}
