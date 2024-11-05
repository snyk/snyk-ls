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
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/configuration"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestAuthenticateSendsAuthenticationEventOnSuccess(t *testing.T) {
	c := testutil.UnitTest(t)

	err := runAuthEventTest(t, c, analytics.Success)

	assert.NoError(t, err)
}

func TestAuthenticateSendsAuthenticationEventOnFailure(t *testing.T) {
	c := testutil.UnitTest(t)

	err := runAuthEventTest(t, c, analytics.Failure)

	assert.Error(t, err)
}

func runAuthEventTest(t *testing.T, c *config.Config, status analytics.Status) error {
	t.Helper()
	gafConfig := configuration.New()
	authenticator := NewFakeOauthAuthenticator(defaultExpiry, true, gafConfig, status == analytics.Success).(*fakeOauthAuthenticator)
	mockEngine, engineConfig := testutil.SetUpEngineMock(t, c)
	mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()

	mockEngine.EXPECT().InvokeWithInputAndConfig(
		localworkflows.WORKFLOWID_REPORT_ANALYTICS,
		mock.MatchedBy(func(i interface{}) bool {
			inputData, ok := i.([]workflow.Data)
			require.Truef(t, ok, "input should be workflow data")
			require.Lenf(t, inputData, 1, "should only have one input")

			payload := string(inputData[0].GetPayload().([]byte))

			require.Contains(t, payload, "authenticated")
			require.Contains(t, payload, "auth")
			require.Contains(t, payload, status)
			return true
		}),
		gomock.Any(),
	).Return(nil, nil)

	provider := newOAuthProvider(gafConfig, authenticator, c.Logger())
	service := NewAuthenticationService(c, provider, error_reporting.NewTestErrorReporter(), notification.NewMockNotifier())

	_, err := service.Authenticate(context.Background())
	return err
}

func Test_UpdateCredentials(t *testing.T) {
	t.Run("CLI Authentication", func(t *testing.T) {
		c := testutil.UnitTest(t)
		service := NewAuthenticationService(c, nil, error_reporting.NewTestErrorReporter(), notification.NewNotifier())

		service.UpdateCredentials("new-token", false)

		assert.Equal(t, "new-token", config.CurrentConfig().Token())
	})

	t.Run("OAuth Authentication Authentication", func(t *testing.T) {
		c := testutil.UnitTest(t)
		service := NewAuthenticationService(c, nil, error_reporting.NewTestErrorReporter(), notification.NewNotifier())
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

func Test_Authenticate(t *testing.T) {
	t.Run("Get endpoint from GAF config and set in snyk-ls configuration ", func(t *testing.T) {
		apiEndpoint := "https://api.eu.snyk.io"
		c := testutil.UnitTest(t)
		c.Engine().GetConfiguration().Set(configuration.API_URL, apiEndpoint)

		provider := FakeAuthenticationProvider{C: c}
		service := NewAuthenticationService(c, &provider, error_reporting.NewTestErrorReporter(), notification.NewNotifier())

		_, err := service.Authenticate(context.Background())
		if err != nil {
			return
		}

		uiEndpoint := c.SnykUI()
		assert.Equal(t, "https://app.eu.snyk.io", uiEndpoint)
	})
}

func Test_IsAuthenticated(t *testing.T) {
	t.Run("User is authenticated", func(t *testing.T) {
		c := testutil.UnitTest(t)

		provider := FakeAuthenticationProvider{IsAuthenticated: true, C: c}
		service := NewAuthenticationService(c, &provider, error_reporting.NewTestErrorReporter(), notification.NewNotifier())

		isAuthenticated := service.IsAuthenticated()

		assert.True(t, isAuthenticated)
	})

	t.Run("User is not authenticated", func(t *testing.T) {
		c := testutil.UnitTest(t)
		provider := FakeAuthenticationProvider{IsAuthenticated: false, C: c}
		service := NewAuthenticationService(c, &provider, error_reporting.NewTestErrorReporter(), notification.NewNotifier())

		isAuthenticated := service.IsAuthenticated()

		assert.False(t, isAuthenticated)
	})
}

func Test_Logout(t *testing.T) {
	c := testutil.IntegTest(t)
	provider := FakeAuthenticationProvider{IsAuthenticated: true}
	notifier := notification.NewNotifier()
	service := NewAuthenticationService(c, &provider, error_reporting.NewTestErrorReporter(), notifier)

	// act
	service.Logout(context.Background())
	mu := sync.RWMutex{}
	tokenResetReceived := false
	callback := func(params any) {
		switch p := params.(type) {
		case types.AuthenticationParams:
			require.Empty(t, p.Token)
			mu.Lock()
			tokenResetReceived = true
			mu.Unlock()
		}
	}
	go notifier.CreateListener(callback)

	// assert
	assert.False(t, provider.IsAuthenticated)
	assert.Eventuallyf(t, func() bool {
		mu.RLock()
		defer mu.RUnlock()
		return tokenResetReceived
	}, time.Second*10, time.Millisecond, "did not receive a token reset")
}

func TestHandleInvalidCredentials(t *testing.T) {
	t.Run("should send request to client", func(t *testing.T) {
		c := testutil.UnitTest(t)
		errorReporter := error_reporting.NewTestErrorReporter()
		notifier := notification.NewNotifier()
		provider := NewFakeCliAuthenticationProvider(c)
		provider.IsAuthenticated = false
		c.SetToken("invalidCreds")
		cut := NewAuthenticationService(c, provider, errorReporter, notifier).(*AuthenticationServiceImpl)
		mu := sync.RWMutex{}
		messageRequestReceived := false
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
				mu.Lock()
				messageRequestReceived = true
				mu.Unlock()
			}
		}
		go notifier.CreateListener(callback)

		cut.handleInvalidCredentials()

		maxWait := time.Second * 10
		assert.Eventuallyf(t, func() bool {
			mu.RLock()
			defer mu.RUnlock()
			return messageRequestReceived
		}, maxWait, time.Millisecond, "didn't receive show message request to re-authenticate")
	})
}

func TestGetApiUrl(t *testing.T) {
	defaultUrl := config.DefaultSnykApiUrl
	customUrl := "https://custom.snyk.io"
	engineUrl := "https://engine.snyk.io"

	tests := []struct {
		name           string
		customUrl      string
		engineUrl      string
		expectedResult string
	}{
		{
			name:           "Default URL when custom and engine URLs are not set",
			customUrl:      defaultUrl,
			engineUrl:      "",
			expectedResult: defaultUrl,
		},
		{
			name:           "Engine URL when custom URL is default and engine URL is set",
			customUrl:      defaultUrl,
			engineUrl:      engineUrl,
			expectedResult: engineUrl,
		},
		{
			name:           "Custom URL when it's different from default and engine URL",
			customUrl:      customUrl,
			engineUrl:      engineUrl,
			expectedResult: customUrl,
		},
		{
			name:           "Custom URL when custom URL equals engine URL",
			customUrl:      customUrl,
			engineUrl:      customUrl,
			expectedResult: customUrl,
		},
		{
			name:           "Custom URL when engine URL is empty",
			customUrl:      customUrl,
			engineUrl:      "",
			expectedResult: customUrl,
		},
		{
			name:           "Custom URL when engine URL is empty",
			customUrl:      "",
			engineUrl:      engineUrl,
			expectedResult: engineUrl,
		},
		{
			name:           "Custom URL when it's different from default and engine URL is empty",
			customUrl:      customUrl,
			engineUrl:      "",
			expectedResult: customUrl,
		},
		{
			name:           "Custom URL with trailing slash",
			customUrl:      "https://custom.snyk.io/",
			engineUrl:      "",
			expectedResult: customUrl,
		},
		{
			name:           "Custom URL with trailing spaces",
			customUrl:      "https://custom.snyk.io   ",
			engineUrl:      "",
			expectedResult: customUrl,
		},
		{
			name:           "Custom URL with trailing slashes and spaces",
			customUrl:      "https://custom.snyk.io///   ",
			engineUrl:      "",
			expectedResult: customUrl,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getPrioritizedApiUrl(tt.customUrl, tt.engineUrl)
			assert.Equal(t, tt.expectedResult, result, "getApiUrl(%v, %v) = %v; want %v",
				tt.customUrl, tt.engineUrl, result, tt.expectedResult)
		})
	}
}
