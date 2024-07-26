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
	"sync"

	"github.com/pkg/errors"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
)

type Initializer struct {
	authenticationService AuthenticationService
	errorReporter         error_reporting.ErrorReporter
	notifier              noti.Notifier
	mutex                 sync.Mutex
	c                     *config.Config
}

func NewInitializer(c *config.Config, authenticator AuthenticationService, errorReporter error_reporting.ErrorReporter, notifier noti.Notifier) *Initializer {
	return &Initializer{
		authenticationService: authenticator,
		errorReporter:         errorReporter,
		notifier:              notifier,
		c:                     c,
	}
}

func (i *Initializer) Init() error {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	const errorMessage = "Auth Initializer failed to authenticate."
	c := config.CurrentConfig()
	if c.NonEmptyToken() {
		authenticated := i.authenticationService.IsAuthenticated()
		if authenticated {
			c.Logger().Info().Str("method", "auth.initializer.init").Msg("Skipping authentication - user is already authenticated")
			return nil
		}
	}

	if !c.AutomaticAuthentication() {
		return nil
	}

	// automatic authentication enabled && token is empty
	err := i.authenticate(i.authenticationService, errorMessage)
	if err != nil {
		c.Logger().Err(err).Str("method", "auth.initializer.init").Msg("failed to authenticate")
		i.notifier.SendError(err)
		i.errorReporter.CaptureError(err)
		return err
	}
	return nil
}

func (i *Initializer) authenticate(authenticationService AuthenticationService, errorMessage string) error {
	i.notifier.SendShowMessage(sglsp.Info, "Authenticating to Snyk. This could open a browser window.")

	token, err := authenticationService.Authenticate(context.Background())
	if token == "" || err != nil {
		if err == nil {
			err = &AuthenticationFailedError{}
		}
		i.notifier.SendError(err)
		err = errors.Wrap(err, errorMessage)
		i.c.Logger().Err(err).Msg(errorMessage)
		i.errorReporter.CaptureError(err)
		return err
	}
	return nil
}
