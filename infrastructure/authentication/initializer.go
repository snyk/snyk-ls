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
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/types"
)

type Initializer struct {
	authenticationService AuthenticationService
	errorReporter         error_reporting.ErrorReporter
	notifier              noti.Notifier
	mutex                 sync.Mutex
	conf                  configuration.Configuration
	logger                *zerolog.Logger
	configResolver        types.ConfigResolverInterface
}

func NewInitializer(conf configuration.Configuration, logger *zerolog.Logger, authenticator AuthenticationService, errorReporter error_reporting.ErrorReporter, notifier noti.Notifier, configResolver types.ConfigResolverInterface) *Initializer {
	return &Initializer{
		authenticationService: authenticator,
		errorReporter:         errorReporter,
		notifier:              notifier,
		conf:                  conf,
		logger:                logger,
		configResolver:        configResolver,
	}
}

func (i *Initializer) Init() error {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	const errorMessage = "Auth Initializer failed to authenticate."
	if config.GetToken(i.conf) != "" {
		authenticated := i.authenticationService.IsAuthenticated()
		if authenticated {
			i.logger.Info().Str("method", "auth.initializer.init").Msg("Skipping authentication - user is already authenticated")
			return nil
		}
	}

	if !i.configResolver.GetBool(types.SettingAutomaticAuthentication, nil) {
		return nil
	}

	// automatic authentication enabled && token is empty
	return i.authenticate(i.authenticationService, errorMessage)
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
		i.logger.Err(err).Str("method", "auth.initializer.init").Msg("failed to authenticate")
		i.errorReporter.CaptureError(err)
		return err
	}
	return nil
}
