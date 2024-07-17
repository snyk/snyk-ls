/*
 * © 2022-2024 Snyk Limited
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
	"reflect"
	"sync"
	"time"

	"github.com/erni27/imcache"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/data_structure"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/types"
)

type AuthenticationServiceImpl struct {
	providers     []AuthenticationProvider
	errorReporter error_reporting.ErrorReporter
	notifier      noti.Notifier
	c             *config.Config
	// key = token, value = isAuthenticated
	authCache *imcache.Cache[string, bool]
	m         sync.Mutex
}

func NewAuthenticationService(c *config.Config, authProviders []AuthenticationProvider, errorReporter error_reporting.ErrorReporter, notifier noti.Notifier) AuthenticationService {
	cache := imcache.New[string, bool]()
	return &AuthenticationServiceImpl{
		providers:     authProviders,
		errorReporter: errorReporter,
		notifier:      notifier,
		c:             c,
		authCache:     cache,
	}
}

func (a *AuthenticationServiceImpl) Providers() []AuthenticationProvider {
	return a.providers
}

func (a *AuthenticationServiceImpl) Authenticate(ctx context.Context) (token string, err error) {
	for _, provider := range a.providers {
		token, err = provider.Authenticate(ctx)
		if token == "" || err != nil {
			a.c.Logger().Warn().Err(err).Msgf("Failed to authenticate using auth provider %v", reflect.TypeOf(provider))
			continue
		}
		a.UpdateCredentials(token, true)
		return token, err
	}
	return token, err
}

func (a *AuthenticationServiceImpl) UpdateCredentials(newToken string, sendNotification bool) {
	c := config.CurrentConfig()
	oldToken := c.Token()
	if oldToken == newToken {
		return
	}

	// remove old token from cache, but don't add new token, as we want the entry only when
	// checks are performed - e.g. in IsAuthenticated or Authenticate which call the API to check for real
	a.m.Lock()
	a.authCache.Remove(oldToken)
	c.SetToken(newToken)
	a.m.Unlock()

	if sendNotification {
		a.notifier.Send(types.AuthenticationParams{Token: newToken})
	}
}

func (a *AuthenticationServiceImpl) Logout(ctx context.Context) {
	for _, provider := range a.providers {
		err := provider.ClearAuthentication(ctx)
		if err != nil {
			a.c.Logger().Warn().Err(err).Str("method", "Logout").Msg("Failed to log out.")
			a.errorReporter.CaptureError(err)
		}
	}
	a.UpdateCredentials("", true)
}

// IsAuthenticated returns true if the token is verified
// If the token is set, but not valid IsAuthenticated returns false and the reported error
func (a *AuthenticationServiceImpl) IsAuthenticated() (bool, error) {
	logger := a.c.Logger().With().Str("method", "AuthenticationService.IsAuthenticated").Logger()
	a.m.Lock()

	_, found := a.authCache.Get(a.c.Token())
	if found {
		a.c.Logger().Debug().Msg("IsAuthenticated (found in cache)")
		a.m.Unlock()
		return true, nil
	}

	noToken := !a.c.NonEmptyToken()
	if noToken {
		logger.Info().Str("method", "IsAuthenticated").Msg("no credentials found")
		a.m.Unlock()
		return false, nil
	}

	var user string
	var err error
	for _, provider := range a.providers {
		providerType := reflect.TypeOf(provider).String()

		user, err = provider.GetCheckAuthenticationFunction()()
		if user == "" || err != nil {
			a.c.Logger().
				Err(err).
				Str("method", "AuthenticationService.IsAuthenticated").
				Str("authProvider", providerType).
				Msg("Failed to get active user")
		} else {
			break
		}
	}

	if user == "" {
		a.m.Unlock()
		logger.Debug().Msg("logging out")
		a.Logout(context.Background())
		a.HandleInvalidCredentials()
		return false, err
	}

	// we cache the API auth ok for up to 1 minutes after last access. Afterwards, a new check is performed.
	a.authCache.Set(a.c.Token(), true, imcache.WithSlidingExpiration(time.Minute))
	a.c.Logger().Debug().Msg("IsAuthenticated: " + user + ", adding to cache.")
	a.m.Unlock()
	return true, nil
}

func (a *AuthenticationServiceImpl) AddProvider(provider AuthenticationProvider) {
	a.providers = append(a.providers, provider)
}

func (a *AuthenticationServiceImpl) setProviders(providers []AuthenticationProvider) {
	a.providers = providers
}

func (a *AuthenticationServiceImpl) ConfigureProviders(c *config.Config) {
	var as []AuthenticationProvider
	switch c.AuthenticationMethod() {
	case types.FakeAuthentication:
		a.setProviders([]AuthenticationProvider{NewFakeCliAuthenticationProvider(c)})
	case types.TokenAuthentication:
		as = Token(c, a.errorReporter)
		a.setProviders(as)
	case "":
		// don't do anything
	default:
		as = Default(c, a.errorReporter, a)
		a.setProviders(as)
	}
}

func (a *AuthenticationServiceImpl) HandleInvalidCredentials() {
	msg := "Your authentication credentials cannot be validated. Automatically clearing credentials. You need to re-authenticate to use Snyk."

	actions := data_structure.OrderedMap[types.MessageAction, types.CommandData]{}
	actions.Add("Authenticate", types.CommandData{
		Title:     "Authenticate",
		CommandId: types.LoginCommand,
	})
	actions.Add("Cancel", types.CommandData{})

	a.notifier.Send(types.ShowMessageRequest{
		Message: msg,
		Type:    types.Warning,
		Actions: &actions,
	})
}
