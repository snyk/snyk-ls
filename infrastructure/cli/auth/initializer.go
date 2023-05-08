/*
 * © 2022-2023 Snyk Limited
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
	"sync"

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/command"
	noti "github.com/snyk/snyk-ls/domain/ide/notification"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
)

type Initializer struct {
	authenticationService snyk.AuthenticationService
	errorReporter         error_reporting.ErrorReporter
	analytics             ux.Analytics
	notifier              noti.Notifier
	mutex                 sync.Mutex
}

func NewInitializer(
	authenticator snyk.AuthenticationService,
	errorReporter error_reporting.ErrorReporter,
	analytics ux.Analytics,
	notifier noti.Notifier,
) *Initializer {
	return &Initializer{
		authenticationService: authenticator,
		errorReporter:         errorReporter,
		analytics:             analytics,
		notifier:              notifier,
	}
}

func (i *Initializer) Init() error {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	const errorMessage = "Auth Initializer failed to authenticate."
	currentConfig := config.CurrentConfig()
	if currentConfig.NonEmptyToken() {
		cmd, _ := command.CreateFromCommandData(snyk.CommandData{CommandId: snyk.GetActiveUserCommand}, nil, i.authenticationService, nil, i.notifier)
		user, _ := cmd.Execute(context.Background())
		if user != nil {
			log.Info().Str("method", "auth.initializer.init").Msg("Skipping authentication - user is already authenticated")
			return nil
		}

		return nil
	}
	if !currentConfig.AutomaticAuthentication() {
		err := i.handleNotAuthenticatedAndManualAuthActive()
		if err != nil {
			return err
		}
		return nil
	}

	err := i.authenticate(i.authenticationService, errorMessage)
	if err != nil {
		log.Err(err).Str("method", "auth.initializer.init").Msg("failed to authenticate")
		i.notifier.SendError(err)
		i.errorReporter.CaptureError(err)
		return err
	}
	return nil
}

func (i *Initializer) authenticate(authenticationService snyk.AuthenticationService, errorMessage string) error {
	i.notifier.SendShowMessage(sglsp.Info, "Authenticating to Snyk. This could open a browser window.")

	token, err := authenticationService.Authenticate(context.Background())
	if token == "" || err != nil {
		if err == nil {
			err = &snyk.AuthenticationFailedError{}
		}
		i.notifier.SendError(err)
		err = errors.Wrap(err, errorMessage)
		log.Err(err).Msg(errorMessage)
		i.errorReporter.CaptureError(err)
		return err
	}
	return nil
}

func (i *Initializer) handleNotAuthenticatedAndManualAuthActive() error {
	err := &snyk.AuthenticationFailedError{ManualAuthentication: true}
	i.notifier.SendError(err)
	msg := "Skipping scan - user is not authenticated and automatic authentication is disabled"
	log.Info().Msg(msg)

	// If the user is not authenticated and auto-authentication is disabled, return an error to indicate the user
	// could not be authenticated and the scan cannot start
	return errors.New(msg)
}
