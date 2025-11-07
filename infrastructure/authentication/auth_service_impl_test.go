/*
 * © 2022-2025 Snyk Limited
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
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/configuration"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
)

func TestAuthenticateSendsAuthenticationEventOnSuccess(t *testing.T) {
	c := testutil.UnitTest(t)
	gafConfig := c.Engine().GetConfiguration()

	authenticator := NewFakeOauthAuthenticator(defaultExpiry, true, gafConfig, true).(*fakeOauthAuthenticator)
	mockEngine, _ := testutil.SetUpEngineMock(t, c)

	// Expect analytics to be sent exactly once (to first folder's org, or empty org if no folders)
	mockEngine.EXPECT().InvokeWithInputAndConfig(
		localworkflows.WORKFLOWID_REPORT_ANALYTICS,
		mock.MatchedBy(func(i any) bool {
			inputData, ok := i.([]workflow.Data)
			require.Truef(t, ok, "input should be workflow data")
			require.Lenf(t, inputData, 1, "should only have one input")

			payload := string(inputData[0].GetPayload().([]byte))

			require.Contains(t, payload, "authenticated")
			require.Contains(t, payload, "auth")
			require.Contains(t, payload, analytics.Success)
			return true
		}),
		gomock.Any(),
	).Times(1).Return(nil, nil)

	provider := newOAuthProvider(gafConfig, authenticator, c.Logger())
	service := NewAuthenticationService(c, provider, error_reporting.NewTestErrorReporter(), notification.NewMockNotifier())

	_, err := service.Authenticate(t.Context())

	assert.NoError(t, err)
}

func TestAuthenticationAnalytics_OrgSelection(t *testing.T) {
	// Shared test constants
	const (
		firstFolderOrg  = "first-folder-org"
		secondFolderOrg = "second-folder-org"
		globalOrg       = "global-org"
	)

	testCases := []struct {
		name        string
		setupWs     func(t *testing.T, ctrl *gomock.Controller, c *config.Config) types.Workspace
		expectedOrg string
	}{
		{
			name: "uses first folder specific org",
			setupWs: func(t *testing.T, ctrl *gomock.Controller, c *config.Config) types.Workspace {
				t.Helper()

				folder1Path := types.FilePath("/fake/folder1")
				folder2Path := types.FilePath("/fake/folder2")

				folder1Config := &types.FolderConfig{
					FolderPath:   folder1Path,
					PreferredOrg: firstFolderOrg,
					OrgSetByUser: true,
				}
				folder2Config := &types.FolderConfig{
					FolderPath:   folder2Path,
					PreferredOrg: secondFolderOrg,
					OrgSetByUser: true,
				}

				err := storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), folder1Config, c.Logger())
				require.NoError(t, err, "failed to configure first folder org")
				err = storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), folder2Config, c.Logger())
				require.NoError(t, err, "failed to configure second folder org")

				// Set a different global org to ensure folder-specific org takes precedence
				c.SetOrganization(globalOrg)

				// Setup mock workspace with the 2 folders
				mockFolder1 := mock_types.NewMockFolder(ctrl)
				mockFolder1.EXPECT().Path().Return(folder1Path).AnyTimes()

				mockFolder2 := mock_types.NewMockFolder(ctrl)
				mockFolder2.EXPECT().Path().Return(folder2Path).AnyTimes()

				mockWorkspace := mock_types.NewMockWorkspace(ctrl)
				mockWorkspace.EXPECT().Folders().Return([]types.Folder{mockFolder1, mockFolder2}).AnyTimes()

				return mockWorkspace
			},
			expectedOrg: firstFolderOrg,
		},
		{
			name: "falls back to global org when no folders",
			setupWs: func(t *testing.T, ctrl *gomock.Controller, c *config.Config) types.Workspace {
				t.Helper()
				// Set a global org
				c.SetOrganization(globalOrg)

				// Setup workspace with NO folders (empty slice)
				mockWorkspace := mock_types.NewMockWorkspace(ctrl)
				mockWorkspace.EXPECT().Folders().Return([]types.Folder{}).AnyTimes()

				return mockWorkspace
			},
			expectedOrg: globalOrg,
		},
		{
			name: "falls back to global org when nil workspace",
			setupWs: func(t *testing.T, ctrl *gomock.Controller, c *config.Config) types.Workspace {
				t.Helper()
				// Set a global org
				c.SetOrganization(globalOrg)

				// Return nil workspace
				return nil
			},
			expectedOrg: globalOrg,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange: Setup test environment
			ctrl := gomock.NewController(t)
			t.Cleanup(ctrl.Finish)

			c := testutil.UnitTest(t)
			gafConfig := c.Engine().GetConfiguration()
			authenticator := NewFakeOauthAuthenticator(defaultExpiry, true, gafConfig, true).(*fakeOauthAuthenticator)
			mockEngine, _ := testutil.SetUpEngineMock(t, c)

			// Setup workspace (test case specific) and set it on config
			ws := tc.setupWs(t, ctrl, c)
			c.SetWorkspace(ws)

			// Capture analytics WF's data and config to verify folder org
			capturedCh := testutil.MockAndCaptureWorkflowInvocation(t, mockEngine, localworkflows.WORKFLOWID_REPORT_ANALYTICS, 1)

			provider := newOAuthProvider(gafConfig, authenticator, c.Logger())
			service := NewAuthenticationService(c, provider, error_reporting.NewTestErrorReporter(), notification.NewMockNotifier())

			// Act: Authenticate (which triggers analytics)
			_, err := service.Authenticate(t.Context())

			// Assert: Verify authentication succeeded
			assert.NoError(t, err, "authentication should succeed")

			// Assert: Verify analytics were sent with correct org
			captured := testsupport.RequireEventuallyReceive(t, capturedCh, time.Second, 10*time.Millisecond, "analytics should have been sent")
			actualOrg := captured.Config.Get(configuration.ORGANIZATION)
			assert.Equal(t, tc.expectedOrg, actualOrg)
		})
	}
}

func Test_AuthURL(t *testing.T) {
	expectedURL := "https://app.snyk.io/login?token=test"

	c := testutil.UnitTest(t)
	provider := &FakeAuthenticationProvider{ExpectedAuthURL: expectedURL, C: c}
	service := NewAuthenticationService(c, provider, error_reporting.NewTestErrorReporter(), notification.NewNotifier())

	// this would cause a timeout of the test, if auth url tries to obtain a lock
	impl := service.(*AuthenticationServiceImpl)
	impl.m.Lock()
	t.Cleanup(func() { impl.m.Unlock() })

	// Call the AuthURL function
	actualURL := service.AuthURL(t.Context())

	// Verify that the correct URL is returned from the provider
	assert.Equal(t, expectedURL, actualURL)
}

func Test_UpdateCredentials(t *testing.T) {
	t.Run("CLI Authentication", func(t *testing.T) {
		c := testutil.UnitTest(t)
		service := NewAuthenticationService(c, nil, error_reporting.NewTestErrorReporter(), notification.NewNotifier())

		service.UpdateCredentials("new-token", false, false)

		assert.Equal(t, "new-token", c.Token())
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

		service.UpdateCredentials(token, false, false)

		assert.Equal(t, token, c.Token())
	})

	t.Run("Send notification with no URL", func(t *testing.T) {
		c := testutil.UnitTest(t)
		mockNotifier := notification.NewMockNotifier()
		service := NewAuthenticationService(c, nil, error_reporting.NewTestErrorReporter(), mockNotifier)

		token := "some_token"
		service.UpdateCredentials(token, true, false)

		expectedNotification := types.AuthenticationParams{Token: token, ApiUrl: ""}
		assert.Equal(t, expectedNotification, mockNotifier.SentMessages()[0])
	})

	t.Run("Send notification with URL", func(t *testing.T) {
		c := testutil.UnitTest(t)
		mockNotifier := notification.NewMockNotifier()
		service := NewAuthenticationService(c, nil, error_reporting.NewTestErrorReporter(), mockNotifier)

		token := "some_other_token"
		service.UpdateCredentials(token, true, true)

		expectedNotification := types.AuthenticationParams{Token: token, ApiUrl: config.DefaultSnykApiUrl}
		assert.Equal(t, expectedNotification, mockNotifier.SentMessages()[0])
	})

	t.Run("Don't send notification", func(t *testing.T) {
		c := testutil.UnitTest(t)
		mockNotifier := notification.NewMockNotifier()
		service := NewAuthenticationService(c, nil, error_reporting.NewTestErrorReporter(), mockNotifier)

		token := "some_other_token"
		service.UpdateCredentials(token, false, false)
		assert.Empty(t, mockNotifier.SentMessages())

		service.UpdateCredentials(token, false, true)
		assert.Empty(t, mockNotifier.SentMessages())
	})
}

func Test_Authenticate(t *testing.T) {
	t.Run("Get endpoint from GAF config and set in snyk-ls configuration ", func(t *testing.T) {
		apiEndpoint := "https://api.eu.snyk.io"
		c := testutil.UnitTest(t)
		c.Engine().GetConfiguration().Set(configuration.API_URL, apiEndpoint)

		provider := FakeAuthenticationProvider{C: c}
		service := NewAuthenticationService(c, &provider, error_reporting.NewTestErrorReporter(), notification.NewNotifier())

		_, err := service.Authenticate(t.Context())
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
		c.SetAuthenticationMethod(types.FakeAuthentication)

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
	service.Logout(t.Context())
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
