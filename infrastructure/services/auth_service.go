/*
 * © 2022 Snyk Limited All rights reserved.
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

package services

import (
	"context"
	"errors"
	"reflect"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
	noti "github.com/snyk/snyk-ls/domain/ide/notification"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/lsp"
)

type AuthenticationService struct {
	apiClient     snyk_api.SnykApiClient
	authenticator snyk.AuthenticationProvider
	analytics     ux.Analytics
	errorReporter error_reporting.ErrorReporter
	notifier      noti.Notifier
}

func NewAuthenticationService(
	apiProvider snyk_api.SnykApiClient,
	authenticator snyk.AuthenticationProvider,
	analytics ux.Analytics,
	errorReporter error_reporting.ErrorReporter,
	notifier noti.Notifier,
) *AuthenticationService {
	return &AuthenticationService{apiProvider, authenticator, analytics, errorReporter, notifier}
}

func (a *AuthenticationService) Provider() snyk.AuthenticationProvider {
	return a.authenticator
}

func (a *AuthenticationService) Authenticate(ctx context.Context) (string, error) {
	token, err := a.Provider().Authenticate(ctx)
	if token == "" || err != nil {
		log.Error().Err(err).Msgf("Failed to authenticate using auth provider %v", reflect.TypeOf(a.Provider()))
		return "", err
	}
	a.UpdateCredentials(token, true)

	return token, err
}

func (a *AuthenticationService) UpdateCredentials(newToken string, sendNotification bool) {
	c := config.CurrentConfig()
	oldToken := c.Token()
	c.SetToken(newToken)

	if sendNotification {
		a.notifier.Send(lsp.AuthenticationParams{Token: newToken})
	}

	if oldToken != newToken {
		a.analytics.Identify()
	}
}

func (a *AuthenticationService) Logout(ctx context.Context) {
	err := a.Provider().ClearAuthentication(ctx)
	if err != nil {
		log.Error().Err(err).Str("method", "Logout").Msg("Failed to log out.")
		a.errorReporter.CaptureError(err)
		return
	}

	a.notifier.Send(lsp.AuthenticationParams{Token: ""})

	workspace.Get().ClearIssues(ctx)
}

func (a *AuthenticationService) IsAuthenticated() (bool, error) {
	_, getActiveUserErr := a.apiClient.GetActiveUser()
	isAuthenticated := getActiveUserErr == nil

	if !isAuthenticated {
		switch getActiveUserErr.(*snyk_api.SnykApiError).StatusCode() {
		//goland:noinspection GoErrorStringFormat
		case 401:
			return false, errors.New("Authentication failed. Please update your token.")
		default:
			return false, getActiveUserErr
		}
	}

	return isAuthenticated, nil
}

func (a *AuthenticationService) SetProvider(provider snyk.AuthenticationProvider) {
	a.authenticator = provider
}
