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

	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/notification"
	errorreporting "github.com/snyk/snyk-ls/internal/observability/error_reporting"
)

func Test_autoAuthenticationDisabled_doesNotAuthenticate(t *testing.T) {
	t.Run("Does not authenticate when auto-auth is disabled", getAutoAuthenticationTest(false))
	t.Run("Authenticates when auto-auth is enabled", getAutoAuthenticationTest(true))
}

func getAutoAuthenticationTest(autoAuthentication bool) func(t *testing.T) {
	return func(t *testing.T) {
		// Arrange
		t.Helper()
		c := config.CurrentConfig()
		c.SetToken("")
		c.SetAutomaticAuthentication(autoAuthentication)

		provider := NewFakeCliAuthenticationProvider(c)
		notifier := notification.NewNotifier()
		authenticator := NewAuthenticationService(c, provider, errorreporting.NewTestErrorReporter(), notifier)
		initializer := NewInitializer(c, authenticator, errorreporting.NewTestErrorReporter(), notifier)

		// Act
		err := initializer.Init()
		require.NoError(t, err)

		require.True(t, provider.IsAuthenticated == autoAuthentication)
	}
}
