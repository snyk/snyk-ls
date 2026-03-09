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

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/notification"
	errorreporting "github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_autoAuthenticationDisabled_doesNotAuthenticate(t *testing.T) {
	testCases := []struct {
		name               string
		autoAuthentication bool
	}{
		{
			name:               "Does not authenticate when auto-auth is disabled",
			autoAuthentication: false,
		},
		{
			name:               "Authenticates when auto-auth is enabled",
			autoAuthentication: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			engine, ts := testutil.UnitTestWithEngine(t)
			// Arrange
			ts.SetToken(engine.GetConfiguration(), "")
			engine.GetConfiguration().Set(configuration.UserGlobalKey(types.SettingAutomaticAuthentication), tc.autoAuthentication)

			provider := NewFakeCliAuthenticationProvider(engine)
			notifier := notification.NewNotifier()
			authenticator := NewAuthenticationService(engine, ts, provider, errorreporting.NewTestErrorReporter(engine), notifier)
			initializer := NewInitializer(engine.GetConfiguration(), engine.GetLogger(), authenticator, errorreporting.NewTestErrorReporter(engine), notifier)

			// Act
			err := initializer.Init()
			require.NoError(t, err)

			// Verify
			assert.Equal(t, tc.autoAuthentication, provider.IsAuthenticated)
		})
	}
}
