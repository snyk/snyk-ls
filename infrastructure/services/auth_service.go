/*
 * Copyright 2022 Snyk Ltd.
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

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/notification"
)

type AuthenticationService struct {
	authenticator snyk.AuthenticationProvider
	analytics     ux.Analytics
	errorReporter error_reporting.ErrorReporter
}

func NewAuthenticationService(authenticator snyk.AuthenticationProvider, analytics ux.Analytics, errorReporter error_reporting.ErrorReporter) *AuthenticationService {
	return &AuthenticationService{authenticator, analytics, errorReporter}
}

func (a AuthenticationService) Provider() snyk.AuthenticationProvider {
	return a.authenticator
}

func (a *AuthenticationService) Authenticate(ctx context.Context) (string, error) {
	token, err := a.Provider().Authenticate(ctx)
	if token == "" || err != nil {
		log.Error().Err(err).Msg("Failed to authenticate")
		return "", err
	}
	a.UpdateToken(token, true)

	return token, err
}

func (a AuthenticationService) UpdateToken(newToken string, sendNotification bool) {
	oldToken := config.CurrentConfig().Token()
	config.CurrentConfig().SetToken(newToken)

	if sendNotification {
		notification.Send(lsp.AuthenticationParams{Token: newToken})
	}

	if oldToken != newToken {
		a.analytics.Identify()
	}
}

func (a AuthenticationService) Logout(ctx context.Context) {
	err := a.Provider().ClearAuthentication(ctx)
	if err != nil {
		log.Error().Err(err).Str("method", "Logout").Msg("Failed to log out.")
		a.errorReporter.CaptureError(err)
		return
	}

	notification.Send(lsp.AuthenticationParams{Token: ""})

	workspace.Get().ClearIssues(ctx)
}

func (a AuthenticationService) IsAuthenticated() (bool, error) {
	token := config.CurrentConfig().Token()
	err := a.authenticator.AuthenticateToken(token)
	isAuthenticated := err == nil

	return isAuthenticated, err
}
