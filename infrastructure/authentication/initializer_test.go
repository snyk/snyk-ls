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
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/notification"
	errorreporting "github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/testutil"
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
			name:               "Does not authenticate when auto-auth is enabled",
			autoAuthentication: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := testutil.UnitTest(t)
			// Arrange
			c.SetToken("")
			c.SetAutomaticAuthentication(tc.autoAuthentication)

			provider := NewFakeCliAuthenticationProvider(c)
			notifier := notification.NewNotifier()
			authenticator := NewAuthenticationService(c, provider, errorreporting.NewTestErrorReporter(), notifier)
			initializer := NewInitializer(c, authenticator, errorreporting.NewTestErrorReporter(), notifier)

			// Act
			err := initializer.Init()
			require.NoError(t, err)

			// Verify
			assert.Equal(t, tc.autoAuthentication, provider.IsAuthenticated)
		})
	}
}
