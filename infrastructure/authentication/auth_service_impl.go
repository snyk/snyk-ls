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

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/data_structure"
	"github.com/snyk/snyk-ls/internal/lsp"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/observability/ux"
	"github.com/snyk/snyk-ls/internal/types"
)

type AuthenticationServiceImpl struct {
	providers     []AuthenticationProvider
	analytics     ux.Analytics
	errorReporter error_reporting.ErrorReporter
	notifier      noti.Notifier
	c             *config.Config
}

func NewAuthenticationService(c *config.Config, authProviders []AuthenticationProvider, analytics ux.Analytics, errorReporter error_reporting.ErrorReporter, notifier noti.Notifier) AuthenticationService {
	return &AuthenticationServiceImpl{authProviders, analytics, errorReporter, notifier, c}
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
		a.analytics.Identify()
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

	c.SetToken(newToken)

	if sendNotification {
		a.notifier.Send(lsp.AuthenticationParams{Token: newToken})
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
	if !a.c.NonEmptyToken() {
		logger.Info().Str("method", "IsAuthenticated").Msg("no credentials found")
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
		a.HandleInvalidCredentials(a.c)
		return false, err
	}

	a.c.Logger().Debug().Msg("IsAuthenticated: " + user)
	return true, nil
}

func (a *AuthenticationServiceImpl) AddProvider(provider AuthenticationProvider) {
	a.providers = append(a.providers, provider)
}

func (a *AuthenticationServiceImpl) setProviders(providers []AuthenticationProvider) {
	a.providers = providers
}

func (a *AuthenticationServiceImpl) HandleInvalidCredentials(c *config.Config) {
	logger := c.Logger().With().Str("method", "AuthenticationServiceImpl.HandleInvalidCredentials").Logger()
	msg := "Your authentication credentials cannot be validated. Automatically clearing credentials. You need to re-authenticate to use Snyk."
	logger.Debug().Msg("logging out")
	a.Logout(context.Background())

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
