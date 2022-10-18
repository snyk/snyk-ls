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
	if currentConfig.Authenticated() && isAuthenticated {
		log.Info().Msg("Skipping authentication - user is already authenticated")
		return nil
	}
	if !currentConfig.AutomaticAuthentication() {
		notification.Send(sglsp.ShowMessageParams{Message: "Please authenticate your Snyk user in order to start scanning"})
		log.Info().Msg("Skipping authentication - automatic authentication is disabled")
		return errors.New(errorMessage)
	}

	notification.Send(sglsp.ShowMessageParams{Type: sglsp.Info, Message: "Authenticating to Snyk. This could open a browser window."})

	token, err := authenticator.Provider().Authenticate(context.Background())
	if token == "" || err != nil {
		if err == nil {
			err = &AuthenticationFailedError{}
		}
		err = errors.Wrap(err, errorMessage)
		log.Error().Err(err).Msg(errorMessage)
		notification.SendError(err)
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
