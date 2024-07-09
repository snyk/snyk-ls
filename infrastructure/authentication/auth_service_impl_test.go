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
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/lsp"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/observability/ux"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_UpdateCredentials(t *testing.T) {
	t.Run("CLI Authentication", func(t *testing.T) {
		c := testutil.UnitTest(t)
		analytics := ux.NewTestAnalytics(c)
		service := NewAuthenticationService(
			c,
			nil,
			analytics,
			error_reporting.NewTestErrorReporter(),
			notification.NewNotifier(),
		)

		service.UpdateCredentials("new-token", false)

		assert.Equal(t, "new-token", config.CurrentConfig().Token())
	})

	t.Run("OAuth Authentication Authentication", func(t *testing.T) {
		c := testutil.UnitTest(t)
		analytics := ux.NewTestAnalytics(c)
		service := NewAuthenticationService(c, nil, analytics, error_reporting.NewTestErrorReporter(),
			notification.NewNotifier())
		oauthCred := oauth2.Token{
			AccessToken:  t.Name(),
			TokenType:    "b",
			RefreshToken: "c",
			Expiry:       time.Time{},
		}
		tokenBytes, err := json.Marshal(oauthCred)
		assert.NoError(t, err)
		token := string(tokenBytes)

		service.UpdateCredentials(token, false)

		assert.Equal(t, token, config.CurrentConfig().Token())
	})
}

func Test_IsAuthenticated(t *testing.T) {
	t.Run("User is authenticated", func(t *testing.T) {
		c := testutil.UnitTest(t)
		analytics := ux.NewTestAnalytics(c)

		provider := FakeAuthenticationProvider{IsAuthenticated: true, C: c}
		providers := []AuthenticationProvider{&provider}
		service := NewAuthenticationService(c,
			providers,
			analytics,
			error_reporting.NewTestErrorReporter(),
			notification.NewNotifier(),
		)

		isAuthenticated, err := service.IsAuthenticated()

		assert.True(t, isAuthenticated)
		assert.NoError(t, err)
	})

	t.Run("User is not authenticated", func(t *testing.T) {
		c := testutil.UnitTest(t)
		analytics := ux.NewTestAnalytics(c)
		provider := FakeAuthenticationProvider{IsAuthenticated: false, C: c}
		providers := []AuthenticationProvider{&provider}
		service := NewAuthenticationService(
			c,
			providers,
			analytics,
			error_reporting.NewTestErrorReporter(),
			notification.NewNotifier(),
		)

		isAuthenticated, err := service.IsAuthenticated()

		assert.False(t, isAuthenticated)
		assert.Equal(t, err.Error(), "Authentication failed. Please update your token.")
	})
}

func Test_Logout(t *testing.T) {
	c := testutil.IntegTest(t)
	provider := FakeAuthenticationProvider{IsAuthenticated: true}
	service := NewAuthenticationService(
		c,
		[]AuthenticationProvider{&provider},
		ux.NewTestAnalytics(c),
		error_reporting.NewTestErrorReporter(),
		notification.NewNotifier(),
	)

	// act
	service.Logout(context.Background())

	// assert
	assert.False(t, provider.IsAuthenticated)
}

func TestHandleInvalidCredentials(t *testing.T) {
	t.Run("should send request to client", func(t *testing.T) {
		c := testutil.UnitTest(t)
		analytics := ux.NewTestAnalytics(c)
		errorReporter := error_reporting.NewTestErrorReporter()
		notifier := notification.NewNotifier()
		provider := NewFakeCliAuthenticationProvider(c)
		provider.IsAuthenticated = false
		providers := []AuthenticationProvider{provider}
		c.SetToken("invalidCreds")
		cut := NewAuthenticationService(c, providers, analytics, errorReporter, notifier).(*AuthenticationServiceImpl)
		messageRequestReceived := false
		tokenResetReceived := false
		callback := func(params any) {
			switch p := params.(type) {
			case types.ShowMessageRequest:
				actions := p.Actions
				keys := actions.Keys()
				loginAction, ok := actions.Get(keys[0])
				require.True(t, ok)
				require.Equal(t, types.LoginCommand, loginAction.CommandId)
				cancelAction, ok := actions.Get(keys[1])
				require.True(t, ok)
				require.Empty(t, cancelAction.CommandId)
				messageRequestReceived = true
			case lsp.AuthenticationParams:
				require.Empty(t, p.Token)
				tokenResetReceived = true
			}
		}
		go notifier.CreateListener(callback)

		cut.HandleInvalidCredentials(c)

		maxWait := time.Second * 10
		assert.Eventuallyf(t, func() bool {
			return messageRequestReceived
		}, maxWait, time.Millisecond, "didn't receive show message request to re-authenticate")

		assert.Eventuallyf(t, func() bool {
			return tokenResetReceived
		}, maxWait, time.Millisecond, "didn't receive token reset")
	})
}

func TestHandleInvalidCredentials(t *testing.T) {
	t.Run("should send request to client", func(t *testing.T) {
		c := testutil.UnitTest(t)
		analytics := ux.NewTestAnalytics(c)
		errorReporter := error_reporting.NewTestErrorReporter()
		notifier := notification.NewNotifier()
		provider := snyk.NewFakeCliAuthenticationProvider(c)
		provider.IsAuthenticated = false
		c.SetToken("invalidCreds")
		cut := snyk.NewAuthenticationService(c, provider, analytics, errorReporter, notifier).(*snyk.AuthenticationServiceImpl)
		messageRequestReceived := false
		tokenResetReceived := false
		callback := func(params any) {
			switch p := params.(type) {
			case snyk.ShowMessageRequest:
				actions := p.Actions
				keys := actions.Keys()
				loginAction, ok := actions.Get(keys[0])
				require.True(t, ok)
				require.Equal(t, snyk.LoginCommand, loginAction.CommandId)
				cancelAction, ok := actions.Get(keys[1])
				require.True(t, ok)
				require.Empty(t, cancelAction.CommandId)
				messageRequestReceived = true
			case lsp.AuthenticationParams:
				require.Empty(t, p.Token)
				tokenResetReceived = true
			}
		}
		go notifier.CreateListener(callback)

		cut.HandleInvalidCredentials(c)

		maxWait := time.Second * 10
		assert.Eventuallyf(t, func() bool {
			return messageRequestReceived
		}, maxWait, time.Millisecond, "didn't receive show message request to re-authenticate")

		assert.Eventuallyf(t, func() bool {
			return tokenResetReceived
		}, maxWait, time.Millisecond, "didn't receive token reset")
	})
}
