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
	"reflect"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
	noti "github.com/snyk/snyk-ls/domain/ide/notification"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/lsp"
)

type ActiveUser struct {
	Id       string `json:"id"`
	UserName string `json:"username,omitempty"`
	Orgs     []struct {
		Name  string `json:"name,omitempty"`
		Id    string `json:"id,omitempty"`
		Group struct {
			Name string `json:"name,omitempty"`
			Id   string `json:"id,omitempty"`
		} `json:"group,omitempty"`
	} `json:"orgs,omitempty"`
}

type authenticationService struct {
	authenticationProvider snyk.AuthenticationProvider
	analytics              ux.Analytics
	errorReporter          error_reporting.ErrorReporter
	notifier               noti.Notifier
}

func NewAuthenticationService(
	authenticationProvider snyk.AuthenticationProvider,
	analytics ux.Analytics,
	errorReporter error_reporting.ErrorReporter,
	notifier noti.Notifier,
) snyk.AuthenticationService {
	return &authenticationService{authenticationProvider, analytics, errorReporter, notifier}
}

func (a *authenticationService) Provider() snyk.AuthenticationProvider {
	return a.authenticationProvider
}

func (a *authenticationService) Authenticate(ctx context.Context) (string, error) {
	token, err := a.authenticationProvider.Authenticate(ctx)
	if token == "" || err != nil {
		log.Error().Err(err).Msgf("Failed to authenticate using auth provider %v", reflect.TypeOf(a.Provider()))
		return "", err
	}
	a.UpdateCredentials(token, true)

	return token, err
}

func (a *authenticationService) UpdateCredentials(newToken string, sendNotification bool) {
	c := config.CurrentConfig()
	oldToken := c.Token()
	if oldToken == newToken {
		return
	}

	c.SetToken(newToken)

	if sendNotification {
		a.notifier.Send(lsp.AuthenticationParams{Token: newToken})
	}

	a.analytics.Identify()
}

func (a *authenticationService) Logout(ctx context.Context) {
	err := a.authenticationProvider.ClearAuthentication(ctx)
	if err != nil {
		log.Error().Err(err).Str("method", "Logout").Msg("Failed to log out.")
		a.errorReporter.CaptureError(err)
		return
	}

	config.CurrentConfig().SetToken("")

	a.notifier.Send(lsp.AuthenticationParams{Token: ""})

	workspace.Get().ClearIssues(ctx)
}

// IsAuthenticated returns true if the token is verified
// If the token is set, but not valid IsAuthenticated returns false and the reported error
func (a *authenticationService) IsAuthenticated() (bool, error) {
	if !config.CurrentConfig().NonEmptyToken() {
		return false, nil
	}

	authenticationFunction := a.authenticationProvider.GetCheckAuthenticationFunction()
	user, getActiveUserErr := authenticationFunction()
	isAuthenticated := getActiveUserErr == nil

	if !isAuthenticated {
		return false, getActiveUserErr
	}

	log.Debug().Msg("IsAuthenticated: " + user)
	return isAuthenticated, nil
}

func (a *authenticationService) SetProvider(provider snyk.AuthenticationProvider) {
	a.authenticationProvider = provider
}
