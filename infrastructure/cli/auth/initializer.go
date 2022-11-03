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

package auth

import (
	"context"

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/internal/notification"
)

type Initializer struct {
	authenticator snyk.AuthenticationService
	errorReporter error_reporting.ErrorReporter
	analytics     ux.Analytics
}

func NewInitializer(authenticator snyk.AuthenticationService, errorReporter error_reporting.ErrorReporter, analytics ux.Analytics) *Initializer {
	return &Initializer{
		authenticator,
		errorReporter,
		analytics,
	}
}

func (i *Initializer) Init() error {
	const errorMessage = "CLI Initializer failed to authenticate."

	cli.Mutex.Lock()
	defer cli.Mutex.Unlock()

	authenticator := i.authenticator
	currentConfig := config.CurrentConfig()
	isAuthenticated, _ := authenticator.IsAuthenticated()
	if currentConfig.NonEmptyToken() && isAuthenticated {
		log.Info().Msg("Skipping authentication - user is already authenticated")
		return nil
	}
	if !currentConfig.AutomaticAuthentication() {
		if currentConfig.NonEmptyToken() { // Only send notification when the token is invalid
			err := &AuthenticationFailedError{manualAuthentication: true}
			notification.SendError(err)
		}
		log.Info().Msg("Skipping scan - user is not authenticated and automatic authentication is disabled")

		// If the user is not authenticated and auto-authentication is disabled, return an error to indicate the user
		// could not be authenticated and the scan cannot start
		return errors.New(errorMessage)
	}

	notification.SendShowMessage(sglsp.Info, "Authenticating to Snyk. This could open a browser window.")

	token, err := authenticator.Provider().Authenticate(context.Background())
	if token == "" || err != nil {
		if err == nil {
			err = &AuthenticationFailedError{}
		}
		notification.SendError(err)
		err = errors.Wrap(err, errorMessage)
		log.Error().Err(err).Msg(errorMessage)
		i.errorReporter.CaptureError(err)
		return err
	}

	authenticator.UpdateToken(token, true)
	isAuthenticated, err = authenticator.IsAuthenticated()

	if !isAuthenticated {
		err = errors.Wrap(err, errorMessage)
		log.Err(err).Msg(errorMessage)
		notification.SendError(err)
		i.errorReporter.CaptureError(err)
		return err
	}

	return nil
}
