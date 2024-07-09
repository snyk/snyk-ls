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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/notification"
	errorreporting "github.com/snyk/snyk-ls/internal/observability/error_reporting"
	ux2 "github.com/snyk/snyk-ls/internal/observability/ux"
)

func Test_autoAuthenticationDisabled_doesNotAuthenticate(t *testing.T) {
	t.Run("Does not authenticate when auto-auth is disabled", getAutoAuthenticationTest(false, true))
	t.Run("Authenticates when auto-auth is enabled", getAutoAuthenticationTest(true, false))
}

func getAutoAuthenticationTest(autoAuthentication bool, expectError bool) func(t *testing.T) {
	return func(t *testing.T) {
		// Arrange
		c := config.CurrentConfig()
		c.SetToken("")
		c.SetAutomaticAuthentication(autoAuthentication)
		analytics := ux2.NewTestAnalytics(c)

		provider := NewFakeCliAuthenticationProvider(c)
		providers := []AuthenticationProvider{provider}
		notifier := notification.NewNotifier()
		authenticator := NewAuthenticationService(c, providers, analytics, errorreporting.NewTestErrorReporter(), notifier)
		initializer := NewInitializer(c, authenticator, errorreporting.NewTestErrorReporter(), analytics, notifier)

		// Act
		err := initializer.Init()

		// Assert
		//assert.Equal(t, expectError, err != nil)
		if expectError {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
		assert.Equal(t, autoAuthentication, provider.IsAuthenticated)
	}
}
