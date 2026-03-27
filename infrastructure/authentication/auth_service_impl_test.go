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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	pkgerrors "github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
)

func TestAuthenticateSendsAuthenticationEventOnSuccess(t *testing.T) {
	engine, ts := testutil.UnitTestWithEngine(t)
	engineConfig := engine.GetConfiguration()

	authenticator := NewFakeOauthAuthenticator(defaultExpiry, true, engineConfig, true).(*fakeOauthAuthenticator)
	mockEngine, _ := testutil.SetUpEngineMock(t, engine)

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

	provider := newOAuthProvider(engineConfig, authenticator, engine.GetLogger())
	service := NewAuthenticationService(mockEngine, ts, provider, error_reporting.NewTestErrorReporter(mockEngine), notification.NewMockNotifier(), testutil.DefaultConfigResolver(mockEngine))

	_, err := service.Authenticate(t.Context())

	assert.NoError(t, err)
}

func TestAuthenticationAnalytics_OrgSelection(t *testing.T) {
	// Shared test constants
	const (
		testFolderOrg = "test-folder-org"
		globalOrg     = "global-org"
	)

	testCases := []struct {
		name        string
		setupWs     func(t *testing.T, ctrl *gomock.Controller, engine workflow.Engine, engineConfig configuration.Configuration) types.Workspace
		expectedOrg string
	}{
		{
			name: "uses any folder specific org",
			setupWs: func(t *testing.T, ctrl *gomock.Controller, engine workflow.Engine, engineConfig configuration.Configuration) types.Workspace {
				t.Helper()

				folder1Path := types.FilePath("/fake/folder1")
				folder2Path := types.FilePath("/fake/folder2")

				types.SetPreferredOrgAndOrgSetByUser(engineConfig, folder1Path, testFolderOrg, true)
				types.SetPreferredOrgAndOrgSetByUser(engineConfig, folder2Path, testFolderOrg, true)

				// Set a different global org to ensure folder-specific org takes precedence
				config.SetOrganization(engineConfig, globalOrg)

				// Setup mock workspace with the 2 folders
				mockFolder1 := mock_types.NewMockFolder(ctrl)
				mockFolder1.EXPECT().Path().Return(folder1Path).AnyTimes()

				mockFolder2 := mock_types.NewMockFolder(ctrl)
				mockFolder2.EXPECT().Path().Return(folder2Path).AnyTimes()

				mockWorkspace := mock_types.NewMockWorkspace(ctrl)
				// FYI, mock returns deterministic slice order, but real Workspace.Folders() returns the slice in a random order
				mockWorkspace.EXPECT().Folders().Return([]types.Folder{mockFolder1, mockFolder2}).AnyTimes()

				return mockWorkspace
			},
			expectedOrg: testFolderOrg,
		},
		{
			name: "falls back to global org when no folders",
			setupWs: func(t *testing.T, ctrl *gomock.Controller, engine workflow.Engine, engineConfig configuration.Configuration) types.Workspace {
				t.Helper()
				// Set a global org
				config.SetOrganization(engineConfig, globalOrg)

				// Setup workspace with NO folders (empty slice)
				mockWorkspace := mock_types.NewMockWorkspace(ctrl)
				mockWorkspace.EXPECT().Folders().Return([]types.Folder{}).AnyTimes()

				return mockWorkspace
			},
			expectedOrg: globalOrg,
		},
		{
			name: "falls back to global org when nil workspace",
			setupWs: func(t *testing.T, ctrl *gomock.Controller, engine workflow.Engine, engineConfig configuration.Configuration) types.Workspace {
				t.Helper()
				// Set a global org
				config.SetOrganization(engineConfig, globalOrg)

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

			engine, ts := testutil.UnitTestWithEngine(t)
			engineConfig := engine.GetConfiguration()
			authenticator := NewFakeOauthAuthenticator(defaultExpiry, true, engineConfig, true).(*fakeOauthAuthenticator)
			mockEngine, mockEngineConfig := testutil.SetUpEngineMock(t, engine)

			// Setup workspace (test case specific) and set it on the mock's config
			ws := tc.setupWs(t, ctrl, engine, mockEngineConfig)
			config.SetWorkspace(mockEngineConfig, ws)

			// Capture analytics WF's data and config to verify folder org
			capturedCh := testutil.MockAndCaptureWorkflowInvocation(t, mockEngine, localworkflows.WORKFLOWID_REPORT_ANALYTICS, 1)

			provider := newOAuthProvider(engineConfig, authenticator, engine.GetLogger())
			service := NewAuthenticationService(mockEngine, ts, provider, error_reporting.NewTestErrorReporter(mockEngine), notification.NewMockNotifier(), testutil.DefaultConfigResolver(mockEngine))

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

	engine, ts := testutil.UnitTestWithEngine(t)
	provider := &FakeAuthenticationProvider{ExpectedAuthURL: expectedURL, Engine: engine}
	service := NewAuthenticationService(engine, ts, provider, error_reporting.NewTestErrorReporter(engine), notification.NewNotifier(), testutil.DefaultConfigResolver(engine))

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
		engine, ts := testutil.UnitTestWithEngine(t)
		service := NewAuthenticationService(engine, ts, nil, error_reporting.NewTestErrorReporter(engine), notification.NewNotifier(), testutil.DefaultConfigResolver(engine))

		service.UpdateCredentials("new-token", false, false)

		assert.Equal(t, "new-token", config.GetToken(engine.GetConfiguration()))
	})

	t.Run("OAuth Authentication Authentication", func(t *testing.T) {
		engine, ts := testutil.UnitTestWithEngine(t)
		service := NewAuthenticationService(engine, ts, nil, error_reporting.NewTestErrorReporter(engine), notification.NewNotifier(), testutil.DefaultConfigResolver(engine))
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

		assert.Equal(t, token, config.GetToken(engine.GetConfiguration()))
	})

	t.Run("Send notification with no URL", func(t *testing.T) {
		engine, ts := testutil.UnitTestWithEngine(t)
		mockNotifier := notification.NewMockNotifier()
		service := NewAuthenticationService(engine, ts, nil, error_reporting.NewTestErrorReporter(engine), mockNotifier, testutil.DefaultConfigResolver(engine))

		token := "some_token"
		service.UpdateCredentials(token, true, false)

		expectedNotification := types.AuthenticationParams{Token: token, ApiUrl: ""}
		assert.Equal(t, expectedNotification, mockNotifier.SentMessages()[0])
	})

	t.Run("Send notification with URL", func(t *testing.T) {
		engine, ts := testutil.UnitTestWithEngine(t)
		mockNotifier := notification.NewMockNotifier()
		service := NewAuthenticationService(engine, ts, nil, error_reporting.NewTestErrorReporter(engine), mockNotifier, testutil.DefaultConfigResolver(engine))

		token := "some_other_token"
		service.UpdateCredentials(token, true, true)

		expectedNotification := types.AuthenticationParams{Token: token, ApiUrl: config.DefaultSnykApiUrl}
		assert.Equal(t, expectedNotification, mockNotifier.SentMessages()[0])
	})

	t.Run("Don't send notification", func(t *testing.T) {
		engine, ts := testutil.UnitTestWithEngine(t)
		mockNotifier := notification.NewMockNotifier()
		service := NewAuthenticationService(engine, ts, nil, error_reporting.NewTestErrorReporter(engine), mockNotifier, testutil.DefaultConfigResolver(engine))

		token := "some_other_token"
		service.UpdateCredentials(token, false, false)
		assert.Empty(t, mockNotifier.SentMessages())

		service.UpdateCredentials(token, false, true)
		assert.Empty(t, mockNotifier.SentMessages())
	})
}

func Test_Authenticate(t *testing.T) {
	t.Run("Get endpoint from config and set in snyk-ls configuration ", func(t *testing.T) {
		apiEndpoint := "https://api.eu.snyk.io"
		engine, ts := testutil.UnitTestWithEngine(t)
		engine.GetConfiguration().Set(configuration.API_URL, apiEndpoint)

		provider := FakeAuthenticationProvider{Engine: engine}
		service := NewAuthenticationService(engine, ts, &provider, error_reporting.NewTestErrorReporter(engine), notification.NewNotifier(), testutil.DefaultConfigResolver(engine))

		_, err := service.Authenticate(t.Context())
		if err != nil {
			return
		}

		uiEndpoint := config.GetSnykUI(engine.GetConfiguration())
		assert.Equal(t, "https://app.eu.snyk.io", uiEndpoint)
	})
}

func TestIsAuthenticated_ConcurrentCallsSendOnlyOneNotification(t *testing.T) {
	engine, ts := testutil.UnitTestWithEngine(t)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingAuthenticationMethod), string(types.FakeAuthentication))

	// Set a non-empty token so the slow (API-check) path is taken instead of the early "no token" return.
	ts.SetToken(engine.GetConfiguration(), "some-test-token")

	// Provider with a delay so concurrent goroutines are all in-flight at the same time.
	// The 50ms delay is load-bearing: it ensures all goroutines overlap during the auth check,
	// guaranteeing concurrent execution. Without the time-based notification dedup, all three
	// goroutines independently call the auth provider and each sends a balloon notification.
	provider := &FakeAuthenticationProvider{
		IsAuthenticated: false,
		Engine:          engine,
		CheckAuthDelay:  50 * time.Millisecond,
	}
	mockNotifier := notification.NewMockNotifier()
	service := NewAuthenticationService(engine, ts, provider, error_reporting.NewTestErrorReporter(engine), mockNotifier, testutil.DefaultConfigResolver(engine))

	const concurrency = 3
	ready := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(concurrency)
	for range concurrency {
		go func() {
			defer wg.Done()
			<-ready // wait for all goroutines to be ready
			service.IsAuthenticated()
		}()
	}
	close(ready) // release all goroutines simultaneously
	wg.Wait()

	assert.Equal(t, 1, mockNotifier.SendShowMessageCount(),
		"concurrent IsAuthenticated() calls with a transient error should send exactly one balloon notification, not one per caller")
	assert.Equal(t, 1, int(atomic.LoadInt32(&provider.AuthCallCount)),
		"concurrent IsAuthenticated() calls should make exactly one auth API call via singleflight, not one per caller")
}

func Test_IsAuthenticated(t *testing.T) {
	t.Run("User is authenticated", func(t *testing.T) {
		engine, ts := testutil.UnitTestWithEngine(t)
		engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingAuthenticationMethod), string(types.FakeAuthentication))

		provider := FakeAuthenticationProvider{IsAuthenticated: true, Engine: engine}
		service := NewAuthenticationService(engine, ts, &provider, error_reporting.NewTestErrorReporter(engine), notification.NewNotifier(), testutil.DefaultConfigResolver(engine))

		isAuthenticated := service.IsAuthenticated()

		assert.True(t, isAuthenticated)
	})

	t.Run("User is not authenticated", func(t *testing.T) {
		engine, ts := testutil.UnitTestWithEngine(t)
		provider := FakeAuthenticationProvider{IsAuthenticated: false, Engine: engine}
		service := NewAuthenticationService(engine, ts, &provider, error_reporting.NewTestErrorReporter(engine), notification.NewNotifier(), testutil.DefaultConfigResolver(engine))

		isAuthenticated := service.IsAuthenticated()

		assert.False(t, isAuthenticated)
	})
}

// buildWhoamiErr simulates the real production error wrapping chain:
// http.Client.Get returns *url.Error → wrapped by GAF whoami workflow →
// pkgerrors.Wrap("failed to invoke whoami workflow") → pkgerrors.Wrap("failed to get active user")
func buildWhoamiErr(inner error) error {
	return pkgerrors.Wrap(pkgerrors.Wrap(inner, "failed to invoke whoami workflow"), "failed to get active user")
}

func Test_shouldCauseLogout(t *testing.T) {
	logger := zerolog.Nop()

	t.Run("DNS error via url.Error does not cause logout", func(t *testing.T) {
		// Mirrors what http.Client.Get returns on DNS failure
		dnsErr := &net.DNSError{Err: "no such host", Name: "api.snyk.io", IsNotFound: true}
		urlErr := &url.Error{Op: "Get", URL: "https://api.snyk.io/rest/self", Err: dnsErr}
		assert.False(t, shouldCauseLogout(buildWhoamiErr(urlErr), &logger))
	})

	t.Run("net.OpError does not cause logout", func(t *testing.T) {
		netErr := &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Err: "no such host"}}
		urlErr := &url.Error{Op: "Get", URL: "https://api.snyk.io/rest/self", Err: netErr}
		assert.False(t, shouldCauseLogout(buildWhoamiErr(urlErr), &logger))
	})

	t.Run("context deadline exceeded does not cause logout", func(t *testing.T) {
		urlErr := &url.Error{Op: "Get", URL: "https://api.snyk.io/rest/self", Err: context.DeadlineExceeded}
		assert.False(t, shouldCauseLogout(buildWhoamiErr(urlErr), &logger))
	})

	t.Run("context canceled does not cause logout", func(t *testing.T) {
		urlErr := &url.Error{Op: "Get", URL: "https://api.snyk.io/rest/self", Err: context.Canceled}
		assert.False(t, shouldCauseLogout(buildWhoamiErr(urlErr), &logger))
	})

	t.Run("io.EOF does not cause logout", func(t *testing.T) {
		urlErr := &url.Error{Op: "Get", URL: "https://api.snyk.io/rest/self", Err: io.EOF}
		assert.False(t, shouldCauseLogout(buildWhoamiErr(urlErr), &logger))
	})

	t.Run("503 server error does not cause logout", func(t *testing.T) {
		err := buildWhoamiErr(fmt.Errorf("API request failed (status: 503)"))
		assert.False(t, shouldCauseLogout(err, &logger))
	})

	t.Run("502 server error does not cause logout", func(t *testing.T) {
		err := buildWhoamiErr(fmt.Errorf("API request failed (status: 502)"))
		assert.False(t, shouldCauseLogout(err, &logger))
	})

	t.Run("401 status causes logout", func(t *testing.T) {
		err := buildWhoamiErr(fmt.Errorf("API request failed (status: 401)"))
		assert.True(t, shouldCauseLogout(err, &logger))
	})

	t.Run("oauth2 error causes logout", func(t *testing.T) {
		err := buildWhoamiErr(fmt.Errorf("oauth2: token expired"))
		assert.True(t, shouldCauseLogout(err, &logger))
	})

	t.Run("json syntax error causes logout", func(t *testing.T) {
		err := buildWhoamiErr(fmt.Errorf("%w", &json.SyntaxError{}))
		assert.True(t, shouldCauseLogout(err, &logger))
	})

	t.Run("oauth2 invalid_grant wrapped in url.Error chain causes logout", func(t *testing.T) {
		// Mirrors the real production error: POST /oauth2/token returns 400 invalid_grant,
		// which the SDK turns into "authentication failed", wrapped in two url.Errors.
		// Previously the outer url.Error check returned false before reaching string matching.
		oauthErr := fmt.Errorf("Client request cannot be processed\nauthentication failed")
		tokenURLErr := &url.Error{Op: "Post", URL: "https://api.snyk.io/oauth2/token", Err: oauthErr}
		selfURLErr := &url.Error{Op: "Get", URL: "https://api.snyk.io/rest/self", Err: tokenURLErr}
		assert.True(t, shouldCauseLogout(buildWhoamiErr(selfURLErr), &logger))
	})

	t.Run("transient network error via nested url.Error does not cause logout", func(t *testing.T) {
		// A genuine connection reset to the oauth endpoint must not trigger logout.
		netErr := &net.OpError{Op: "read", Net: "tcp", Err: fmt.Errorf("connection reset by peer")}
		tokenURLErr := &url.Error{Op: "Post", URL: "https://api.snyk.io/oauth2/token", Err: netErr}
		selfURLErr := &url.Error{Op: "Get", URL: "https://api.snyk.io/rest/self", Err: tokenURLErr}
		assert.False(t, shouldCauseLogout(buildWhoamiErr(selfURLErr), &logger))
	})
}

func Test_Logout(t *testing.T) {
	engine, ts := testutil.IntegTestWithEngine(t)
	// Ensure a token is set so that Logout will trigger a notification when clearing it
	ts.SetToken(engine.GetConfiguration(), "test-token-for-logout")
	provider := FakeAuthenticationProvider{IsAuthenticated: true, Engine: engine}
	notifier := notification.NewNotifier()
	service := NewAuthenticationService(engine, ts, &provider, error_reporting.NewTestErrorReporter(engine), notifier, testutil.DefaultConfigResolver(engine))

	// Set up listener BEFORE calling Logout to ensure we catch the notification
	// CreateListener spawns its own goroutine internally, no need for `go`
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
	notifier.CreateListener(callback)
	t.Cleanup(func() { notifier.DisposeListener() })

	// act
	service.Logout(t.Context())

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
		engine, ts := testutil.UnitTestWithEngine(t)
		errorReporter := error_reporting.NewTestErrorReporter(engine)
		notifier := notification.NewNotifier()
		provider := NewFakeCliAuthenticationProvider(engine)
		provider.IsAuthenticated = false
		ts.SetToken(engine.GetConfiguration(), "invalidCreds")
		cut := NewAuthenticationService(engine, ts, provider, errorReporter, notifier, testutil.DefaultConfigResolver(engine)).(*AuthenticationServiceImpl)
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
