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
	"fmt"
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
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
			engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingAutomaticAuthentication), tc.autoAuthentication)

			provider := NewFakeCliAuthenticationProvider(engine)
			notifier := notification.NewNotifier()
			configResolver := testutil.DefaultConfigResolver(engine)
			authenticator := NewAuthenticationService(engine, ts, provider, errorreporting.NewTestErrorReporter(engine), notifier, configResolver)
			initializer := NewInitializer(engine.GetConfiguration(), engine.GetLogger(), authenticator, errorreporting.NewTestErrorReporter(engine), notifier, configResolver)

			// Act
			err := initializer.Init(t.Context())
			require.NoError(t, err)

			// Verify
			assert.Equal(t, tc.autoAuthentication, provider.IsAuthenticated)
		})
	}
}

func Test_autoAuthentication_TimedOut_NotSurfacedOrAborting(t *testing.T) {
	// A startup auto-auth that times out (the user ignored the browser window) is the same
	// user-abandoned outcome as a login-command timeout: it must not be reported to Sentry and must
	// not abort the init chain. Handled silently here since auto-auth is a background, best-effort step.
	engine, ts := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	ts.SetToken(conf, "")
	conf.Set(configresolver.UserGlobalKey(types.SettingAutomaticAuthentication), true)

	provider := NewFakeCliAuthenticationProvider(engine)
	provider.AuthenticateErr = fmt.Errorf("oauth authentication timed out: %w", context.DeadlineExceeded)

	notifier := notification.NewMockNotifier()
	configResolver := testutil.DefaultConfigResolver(engine)
	authService := NewAuthenticationService(engine, ts, provider, errorreporting.NewTestErrorReporter(engine), notifier, configResolver)
	initializer := NewInitializer(conf, engine.GetLogger(), authService, errorreporting.NewTestErrorReporter(engine), notifier, configResolver)

	err := initializer.Init(t.Context())

	require.NoError(t, err, "a timed-out auto-auth must not abort initialization")
	assert.Zero(t, notifier.SendErrorCount(), "a background auto-auth timeout must not be surfaced to the user")
}

func Test_autoAuthentication_CanceledOAuth_NotSurfacedToUser(t *testing.T) {
	// A canceled startup auto-auth (OAuth returns ErrAuthCanceled, normalized to context.Canceled)
	// must not notify the user and must not abort the init chain. The service wraps the initializer's
	// context.Background() in a cancelable child, so CancelOngoingAuth — triggered by a superseding
	// login or an auth-method change during startup — can cancel this in-flight auth.
	engine, ts := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	ts.SetToken(conf, "")
	conf.Set(configresolver.UserGlobalKey(types.SettingAutomaticAuthentication), true)

	authenticator := NewFakeOauthAuthenticator(defaultExpiry, true, conf, true)
	authenticator.canceled = true
	provider := newOAuthProvider(conf, authenticator, engine.GetLogger())

	notifier := notification.NewMockNotifier()
	configResolver := testutil.DefaultConfigResolver(engine)
	authService := NewAuthenticationService(engine, ts, provider, errorreporting.NewTestErrorReporter(engine), notifier, configResolver)
	initializer := NewInitializer(conf, engine.GetLogger(), authService, errorreporting.NewTestErrorReporter(engine), notifier, configResolver)

	err := initializer.Init(t.Context())

	require.NoError(t, err, "a canceled auto-auth must not abort initialization")
	assert.Zero(t, notifier.SendErrorCount(), "a canceled auto-auth must not be surfaced to the user")
}
