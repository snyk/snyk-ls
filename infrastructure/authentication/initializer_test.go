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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/notification"
	errorreporting "github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/testutil"
)

// authServiceWithFixedResult wraps a real AuthenticationServiceImpl but returns a caller-supplied
// AuthenticateResult from Authenticate(). All other interface methods are delegated to the embedded impl.
type authServiceWithFixedResult struct {
	*AuthenticationServiceImpl
	fixedResult AuthenticateResult
}

func (a *authServiceWithFixedResult) Authenticate(_ context.Context, _, _ string, _ bool) (AuthenticateResult, error) {
	return a.fixedResult, nil
}

func newAuthServiceWithFixedResult(c *config.Config, result AuthenticateResult) *authServiceWithFixedResult {
	impl := NewAuthenticationService(c, NewFakeCliAuthenticationProvider(c), errorreporting.NewTestErrorReporter(), notification.NewMockNotifier()).(*AuthenticationServiceImpl)
	return &authServiceWithFixedResult{AuthenticationServiceImpl: impl, fixedResult: result}
}

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
			c := testutil.UnitTest(t)
			// Arrange
			c.SetToken("")
			c.SetAutomaticAuthentication(tc.autoAuthentication)

			provider := NewFakeCliAuthenticationProvider(c)
			notifier := notification.NewNotifier()
			authService := NewAuthenticationService(c, provider, errorreporting.NewTestErrorReporter(), notifier)
			initializer := NewInitializer(c, authService, errorreporting.NewTestErrorReporter(), notifier)

			// Act
			err := initializer.Init()
			require.NoError(t, err)

			// Verify via service state: if auto-auth was enabled, a token should be present
			assert.Equal(t, tc.autoAuthentication, authService.IsAuthenticated())
		})
	}
}

// Test_initializer_authenticate_updatesApiEndpoints verifies that when Authenticate returns a non-empty
// ApiUrl (e.g. the URL derived from an OAuth token's audience), the initializer applies it via
// UpdateApiEndpoints so the LS is talking to the correct API endpoint before didChangeConfiguration arrives.
func Test_initializer_authenticate_updatesApiEndpoints(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetToken("")
	c.SetAutomaticAuthentication(true)

	const expectedApiUrl = "https://api.eu.snyk.io"
	authService := newAuthServiceWithFixedResult(c, AuthenticateResult{
		Token:  "test-token",
		ApiUrl: expectedApiUrl,
	})
	notifier := notification.NewNotifier()
	initializer := NewInitializer(c, authService, errorreporting.NewTestErrorReporter(), notifier)

	err := initializer.Init()

	require.NoError(t, err)
	assert.Equal(t, expectedApiUrl, c.SnykApi(), "initializer must update the API endpoint from the auth result")
}
