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
	"os"

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

func (i *Initializer) Init() {
	cli.Mutex.Lock()
	defer cli.Mutex.Unlock()

	currentConfig := config.CurrentConfig()
	if currentConfig.Authenticated() {
		log.Info().Msg("Skipping authentication - user is already authenticated")
		return
	}
	if !currentConfig.AutomaticAuthentication() {
		log.Info().Msg("Skipping authentication - automatic authentication is disabled")
		return
	}

	notification.Send(sglsp.ShowMessageParams{Type: sglsp.Info, Message: "Authenticating to Snyk. This could open a browser window."})

	token, err := i.authenticator.Provider().Authenticate(context.Background())
	if token == "" || err != nil {
		log.Error().Err(err).Msg("Failed to authenticate. Terminating server.")
		i.errorReporter.CaptureError(err)
		os.Exit(1) // terminate server since unrecoverable from authentication error
	}

	i.authenticator.UpdateToken(token, true)
}
