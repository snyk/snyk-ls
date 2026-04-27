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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	pkgerrors "github.com/pkg/errors"
	"github.com/rs/zerolog"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/auth"
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

	authenticator := NewFakeOauthAuthenticator(defaultExpiry, true, engineConfig, true)
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
			authenticator := NewFakeOauthAuthenticator(defaultExpiry, true, engineConfig, true)
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

func Test_PostCredentialUpdateHook_CalledBeforeNotification(t *testing.T) {
	engine, ts := testutil.UnitTestWithEngine(t)
	mockNotifier := notification.NewMockNotifier()

	provider := NewFakeCliAuthenticationProvider(engine)
	service := NewAuthenticationService(engine, ts, provider, error_reporting.NewTestErrorReporter(engine), mockNotifier, testutil.DefaultConfigResolver(engine))

	hookCalled := false
	var messagesAtHookTime []any
	service.SetPostCredentialUpdateHook(func() {
		hookCalled = true
		messagesAtHookTime = append([]any{}, mockNotifier.SentMessages()...)
	})

	_, err := service.Authenticate(t.Context())
	require.NoError(t, err)

	assert.True(t, hookCalled, "hook must be called during authentication")
	assert.Empty(t, messagesAtHookTime, "hook must run before the auth notification is sent")
	assert.NotEmpty(t, mockNotifier.SentMessages(), "auth notification must be sent after the hook")
}

func TestIsAuthenticated_ConcurrentCallsSendOnlyOneNotification(t *testing.T) {
	engine, ts := testutil.UnitTestWithEngine(t)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingAuthenticationMethod), string(types.FakeAuthentication))

	ts.SetToken(engine.GetConfiguration(), "some-test-token")

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
			<-ready
			service.IsAuthenticated()
		}()
	}
	close(ready)
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
		oauthErr := fmt.Errorf("Client request cannot be processed\nauthentication failed")
		tokenURLErr := &url.Error{Op: "Post", URL: "https://api.snyk.io/oauth2/token", Err: oauthErr}
		selfURLErr := &url.Error{Op: "Get", URL: "https://api.snyk.io/rest/self", Err: tokenURLErr}
		assert.True(t, shouldCauseLogout(buildWhoamiErr(selfURLErr), &logger))
	})

	t.Run("transient network error via nested url.Error does not cause logout", func(t *testing.T) {
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

func Test_Logout_NilProvider_DoesNotPanic(t *testing.T) {
	engine, ts := testutil.UnitTestWithEngine(t)
	service := NewAuthenticationService(engine, ts, nil, error_reporting.NewTestErrorReporter(engine), notification.NewMockNotifier(), testutil.DefaultConfigResolver(engine))

	assert.NotPanics(t, func() {
		service.Logout(t.Context())
	})
}

func Test_Logout_CallsClearAuthentication(t *testing.T) {
	engine, ts := testutil.UnitTestWithEngine(t)
	provider := &FakeAuthenticationProvider{IsAuthenticated: true, Engine: engine}
	service := NewAuthenticationService(engine, ts, provider, error_reporting.NewTestErrorReporter(engine), notification.NewMockNotifier(), testutil.DefaultConfigResolver(engine))

	service.Logout(t.Context())

	assert.True(t, provider.ClearAuthenticationCalled, "Logout() must call ClearAuthentication on the provider")
}

func Test_ConfigureProviders_CredentialMismatch_CallsClearAuthentication(t *testing.T) {
	// When configureProviders detects a credential mismatch it must call ClearAuthentication
	// to remove stale credentials from provider-specific storage (e.g. CLI config file).
	// The race condition that previously caused this to fire spuriously is fixed by clearing
	// the token before setting the new auth method in applyAuthConfig.
	engine, ts := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	conf.Set(configresolver.UserGlobalKey(types.SettingAuthenticationMethod), string(types.OAuthAuthentication))
	// A UUID token maps to TokenAuthentication, which is incompatible with OAuthAuthentication, triggering the mismatch path.
	ts.SetToken(conf, "00000000-0000-0000-0000-000000000002")

	// Provider method matches config method so the provider is not replaced before logout runs.
	provider := &FakeAuthenticationProvider{IsAuthenticated: true, Engine: engine, Method: types.OAuthAuthentication}
	service := NewAuthenticationService(engine, ts, provider, error_reporting.NewTestErrorReporter(engine), notification.NewMockNotifier(), testutil.DefaultConfigResolver(engine))

	service.ConfigureProviders(conf, engine.GetLogger())

	assert.True(t, provider.ClearAuthenticationCalled, "configureProviders must call ClearAuthentication on credential mismatch")
	assert.Empty(t, config.GetToken(conf), "mismatched token must be cleared from memory")
}

func TestAuthenticate_CancellationPreservesExistingToken(t *testing.T) {
	engine, ts := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	existingToken := "existing-token"
	ts.SetToken(conf, existingToken)

	blocking := make(chan struct{})
	firstStarted := make(chan struct{})
	provider := &slowFakeAuthProvider{block: blocking, started: firstStarted}
	service := NewAuthenticationService(engine, ts, provider, error_reporting.NewTestErrorReporter(engine), notification.NewMockNotifier(), testutil.DefaultConfigResolver(engine))

	// Start first auth (will block until canceled)
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		_, _ = service.Authenticate(t.Context())
	}()

	// Wait for first to actually start before issuing the second auth
	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first Authenticate did not start")
	}

	// Issue a second auth — this cancels the first via previousAuthCtxCancelFunc.
	// Switch to a fast provider so the second call completes without blocking.
	service.(*AuthenticationServiceImpl).setProvider(&FakeAuthenticationProvider{Engine: engine})
	go func() { _, _ = service.Authenticate(t.Context()) }()

	// First auth should return quickly once canceled
	select {
	case <-firstDone:
	case <-time.After(2 * time.Second):
		t.Fatal("first Authenticate was not canceled by second call")
	}

	// Token should not have been cleared to empty by the cancellation
	assert.NotEmpty(t, config.GetToken(conf), "cancellation should not clear an existing token")
}

func TestAuthenticate_ConcurrentCalls_SecondCancelsFirst(t *testing.T) {
	engine, ts := testutil.UnitTestWithEngine(t)
	blocking := make(chan struct{})
	firstStarted := make(chan struct{})
	firstProvider := &slowFakeAuthProvider{
		block:   blocking,
		started: firstStarted,
	}
	service := NewAuthenticationService(engine, ts, firstProvider, error_reporting.NewTestErrorReporter(engine), notification.NewMockNotifier(), testutil.DefaultConfigResolver(engine))

	// First call — will block
	first := make(chan error, 1)
	go func() {
		_, err := service.Authenticate(t.Context())
		first <- err
	}()

	// Wait for first to start, then issue second call which should cancel first
	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first Authenticate did not start")
	}

	secondProvider := &FakeAuthenticationProvider{Engine: engine}
	service.(*AuthenticationServiceImpl).setProvider(secondProvider)
	go func() { _, _ = service.Authenticate(t.Context()) }()

	// First call should return (canceled) reasonably quickly
	select {
	case <-first:
		// success
	case <-time.After(2 * time.Second):
		t.Fatal("first Authenticate was not canceled by second call")
	}
}

// slowFakeAuthProvider blocks in Authenticate until the block channel is closed.
type slowFakeAuthProvider struct {
	block   chan struct{}
	started chan struct{}
}

func (p *slowFakeAuthProvider) Authenticate(ctx context.Context) (string, error) {
	if p.started != nil {
		select {
		case <-p.started:
		default:
			close(p.started)
		}
	}
	select {
	case <-p.block:
		return "slow-token", nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (p *slowFakeAuthProvider) ClearAuthentication(_ context.Context) error { return nil }
func (p *slowFakeAuthProvider) AuthURL(_ context.Context) string            { return "" }
func (p *slowFakeAuthProvider) setAuthUrl(_ string)                         {}
func (p *slowFakeAuthProvider) AuthenticationMethod() types.AuthenticationMethod {
	return types.FakeAuthentication
}
func (p *slowFakeAuthProvider) GetCheckAuthenticationFunction() AuthenticationFunction {
	return func(_ workflow.Engine) (string, error) { return "", nil }
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

// oauthTokenWithAud builds the JSON-marshaled oauth2.Token wrapper that
// OAuth2Provider.Authenticate returns to AuthenticationServiceImpl.authenticate.
// audClaim may be a string (single-aud JWT form, decoded by jws.ClaimSet) or a
// []string (array-aud form, decoded by GAF's arrayClaimSet).
//
// The returned string is suitable as the input to extractAudUrl.
func oauthTokenWithAud(t *testing.T, audClaim any) string {
	t.Helper()
	tok := &oauth2.Token{
		AccessToken: testutil.BuildJWTWithAud(audClaim),
		TokenType:   "Bearer",
	}
	b, err := json.Marshal(tok)
	require.NoError(t, err)
	return string(b)
}

// Table-driven coverage for the private extractAudHost helper.
func Test_extractAudHost(t *testing.T) {
	logger := zerolog.Nop()

	type tc struct {
		name         string
		token        string
		overrideRgx  bool
		regexValue   string
		expectedHost string
	}

	cases := []tc{
		{name: "bare-host aud", token: oauthTokenWithAud(t, "api.eu.snyk.io"), expectedHost: "api.eu.snyk.io"},
		{name: "full-URL aud", token: oauthTokenWithAud(t, "https://api.snyk.io"), expectedHost: "api.snyk.io"},
		{name: "array aud", token: oauthTokenWithAud(t, []string{"https://api.snyk.io"}), expectedHost: "api.snyk.io"},
		{name: "empty token", token: "", expectedHost: ""},
		{name: "opaque token", token: "opaque-pat-style", expectedHost: ""},
		{name: "empty aud", token: oauthTokenWithAud(t, ""), expectedHost: ""},
		{name: "invalid host", token: oauthTokenWithAud(t, "api.malicious.io"), expectedHost: ""},
		{name: "regex unset", token: oauthTokenWithAud(t, "api.eu.snyk.io"), overrideRgx: true, regexValue: "", expectedHost: ""},
		{name: "FedRAMP", token: oauthTokenWithAud(t, "api.fedramp.snykgov.io"), expectedHost: "api.fedramp.snykgov.io"},
		{name: "ftp scheme", token: oauthTokenWithAud(t, "ftp://api.snyk.io"), expectedHost: ""},
		{name: "http scheme", token: oauthTokenWithAud(t, "http://api.snyk.io"), expectedHost: "api.snyk.io"},
		{name: "null aud", token: oauthTokenWithAud(t, nil), expectedHost: ""},
		{name: "regex compile error", token: oauthTokenWithAud(t, "api.snyk.io"), overrideRgx: true, regexValue: "[invalid", expectedHost: ""},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			engine := testutil.UnitTest(t)
			conf := engine.GetConfiguration()

			require.NotEmpty(t, conf.GetString(auth.CONFIG_KEY_ALLOWED_HOST_REGEXP),
				"GAF default CONFIG_KEY_ALLOWED_HOST_REGEXP must be present in test engine")

			if tt.overrideRgx {
				conf.Set(auth.CONFIG_KEY_ALLOWED_HOST_REGEXP, tt.regexValue)
			}

			actual := extractAudHost(tt.token, conf, &logger)
			assert.Equal(t, tt.expectedHost, actual)
		})
	}
}

// When the freshly returned OAuth token's `aud` claim names a different (valid)
// Snyk host than the configured custom endpoint, the post-auth path must
// override the prioritized URL with the aud-derived host, persist it via
// UpdateApiEndpointsOnConfig, send the "API Endpoint has been updated" Info
// notification exactly once, and emit AuthenticationParams whose ApiUrl
// carries the aud-derived host.
//
// Note on aud format: real Snyk OAuth tokens carry full-URL aud claims
// (e.g. "https://api.snyk.io"). GAF's defaultFuncApiUrl callback also
// re-derives configuration.API_URL from this aud as a side effect of the
// token being persisted, which is why these integration-style tests use a
// full-URL aud rather than the bare-host form (the bare-host form is still
// covered by the Test_extractAudUrl table-driven unit cases).
func Test_authenticate_PropagatesEndpointWhenTokenAudDiffers(t *testing.T) {
	engine, ts := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	require.True(t, config.UpdateApiEndpointsOnConfig(conf, "https://api.eu.snyk.io"))

	authenticator := NewFakeOauthAuthenticator(defaultExpiry, true, conf, true).WithJWTAud("https://api.snyk.io")
	provider := newOAuthProvider(conf, authenticator, engine.GetLogger())

	mockNotifier := notification.NewMockNotifier()
	service := NewAuthenticationService(engine, ts, provider, error_reporting.NewTestErrorReporter(engine), mockNotifier, testutil.DefaultConfigResolver(engine))

	token, err := service.Authenticate(t.Context())
	require.NoError(t, err)
	require.NotEmpty(t, token, "Authenticate must return the OAuth-token JSON")

	assert.Equal(t, "https://api.snyk.io", conf.GetString(configuration.API_URL))
	assert.Equal(t, "https://api.snyk.io", conf.GetString(configresolver.UserGlobalKey(types.SettingApiEndpoint)))
	assert.Equal(t, "https://app.snyk.io", conf.GetString(configuration.WEB_APP_URL))

	var authParamsCount int
	var capturedAuthParams types.AuthenticationParams
	var endpointUpdateMsgCount int
	for _, m := range mockNotifier.SentMessages() {
		switch p := m.(type) {
		case types.AuthenticationParams:
			authParamsCount++
			capturedAuthParams = p
		case sglsp.ShowMessageParams:
			if p.Type == sglsp.Info && strings.Contains(p.Message, "The Snyk API Endpoint has been updated to https://api.snyk.io") {
				endpointUpdateMsgCount++
			}
		}
	}
	assert.Equal(t, 1, authParamsCount, "exactly one AuthenticationParams must be emitted")
	assert.Equal(t, "https://api.snyk.io", capturedAuthParams.ApiUrl, "AuthenticationParams.ApiUrl must carry the aud-derived host")
	assert.Equal(t, token, capturedAuthParams.Token)
	assert.Equal(t, 1, endpointUpdateMsgCount, "exactly one endpoint-update Info message must be sent")
}

// When the new OAuth token's `aud` matches the configured custom endpoint,
// the discovery branch is a no-op: no endpoint mutation, no "API Endpoint has
// been updated" notification, AuthenticationParams carries an empty ApiUrl.
func Test_authenticate_DiscoveryNoOp_WhenAudMatches(t *testing.T) {
	engine, ts := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	require.True(t, config.UpdateApiEndpointsOnConfig(conf, "https://api.eu.snyk.io"))

	authenticator := NewFakeOauthAuthenticator(defaultExpiry, true, conf, true).WithJWTAud("https://api.eu.snyk.io")
	provider := newOAuthProvider(conf, authenticator, engine.GetLogger())

	mockNotifier := notification.NewMockNotifier()
	service := NewAuthenticationService(engine, ts, provider, error_reporting.NewTestErrorReporter(engine), mockNotifier, testutil.DefaultConfigResolver(engine))

	_, err := service.Authenticate(t.Context())
	require.NoError(t, err)

	assert.Equal(t, "https://api.eu.snyk.io", conf.GetString(configuration.API_URL))
	assert.Equal(t, "https://api.eu.snyk.io", conf.GetString(configresolver.UserGlobalKey(types.SettingApiEndpoint)))

	var authParamsApiUrl string
	var endpointUpdateCount int
	for _, m := range mockNotifier.SentMessages() {
		switch p := m.(type) {
		case types.AuthenticationParams:
			authParamsApiUrl = p.ApiUrl
		case sglsp.ShowMessageParams:
			if strings.Contains(p.Message, "API Endpoint has been updated") {
				endpointUpdateCount++
			}
		}
	}
	assert.Empty(t, authParamsApiUrl, "AuthenticationParams.ApiUrl must be empty when aud matches customUrl")
	assert.Equal(t, 0, endpointUpdateCount, "no endpoint-update notification must be sent")
}

// A malicious / non-Snyk `aud` claim must be rejected by the allowed-host
// regex check inside extractAudUrl. Authenticate still succeeds (returning
// the token) but the override branch must NOT trigger: no "API Endpoint has
// been updated" notification is sent, the user's pre-configured
// SettingApiEndpoint is not overwritten by the new (rejected) host, and
// AuthenticationParams.ApiUrl carries no propagated value.
//
// (configuration.API_URL itself is owned by GAF's defaultFuncApiUrl callback,
// which re-derives it from the persisted OAuth token's aud claim regardless
// of whether snyk-ls validates the host. We therefore assert on snyk-ls's
// user-global SettingApiEndpoint and on the absence of the
// snyk-ls-emitted endpoint-update notification.)
func Test_authenticate_DiscoveryRejectsMaliciousHost(t *testing.T) {
	engine, ts := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	require.True(t, config.UpdateApiEndpointsOnConfig(conf, "https://api.eu.snyk.io"))
	endpointBefore := conf.GetString(configresolver.UserGlobalKey(types.SettingApiEndpoint))

	authenticator := NewFakeOauthAuthenticator(defaultExpiry, true, conf, true).WithJWTAud("https://api.malicious.io")
	provider := newOAuthProvider(conf, authenticator, engine.GetLogger())

	mockNotifier := notification.NewMockNotifier()
	service := NewAuthenticationService(engine, ts, provider, error_reporting.NewTestErrorReporter(engine), mockNotifier, testutil.DefaultConfigResolver(engine))

	token, err := service.Authenticate(t.Context())
	require.NoError(t, err)
	require.NotEmpty(t, token, "Authenticate must still succeed and return the token")

	assert.Equal(t, endpointBefore, conf.GetString(configresolver.UserGlobalKey(types.SettingApiEndpoint)),
		"snyk-ls's user-global SettingApiEndpoint must not be overwritten when the aud host is rejected")

	for _, m := range mockNotifier.SentMessages() {
		if p, ok := m.(sglsp.ShowMessageParams); ok {
			assert.NotContains(t, p.Message, "API Endpoint has been updated",
				"no endpoint-update notification must be sent for rejected hosts")
		}
		if ap, ok := m.(types.AuthenticationParams); ok {
			assert.Empty(t, ap.ApiUrl, "AuthenticationParams.ApiUrl must be empty when aud is rejected")
		}
	}
}

// The override branch must NOT trigger a logout. Logout would clear the token
// via updateCredentials("",...) — assert the post-auth token is intact.
// Confirms the override goes via UpdateApiEndpointsOnConfig directly (not via
// ApplyEndpointChange, which calls Logout).
func Test_authenticate_DiscoveryDoesNotTriggerLogoutLoop(t *testing.T) {
	engine, ts := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	require.True(t, config.UpdateApiEndpointsOnConfig(conf, "https://api.eu.snyk.io"))

	authenticator := NewFakeOauthAuthenticator(defaultExpiry, true, conf, true).WithJWTAud("https://api.snyk.io")
	provider := newOAuthProvider(conf, authenticator, engine.GetLogger())

	mockNotifier := notification.NewMockNotifier()
	service := NewAuthenticationService(engine, ts, provider, error_reporting.NewTestErrorReporter(engine), mockNotifier, testutil.DefaultConfigResolver(engine))

	token, err := service.Authenticate(t.Context())
	require.NoError(t, err)
	require.NotEmpty(t, token, "token must be returned even after API URL discovery")

	storedToken := config.GetToken(conf)
	assert.NotEmpty(t, storedToken, "Logout must NOT be invoked as a side effect of API URL discovery (token would be cleared)")
	assert.Equal(t, token, storedToken)

	assert.Equal(t, "https://api.snyk.io", conf.GetString(configuration.API_URL),
		"sanity: endpoint mutation must have happened (otherwise the no-logout assertion is vacuous)")
}

// When customUrl carries a path (single-tenant pattern, e.g.
// "https://api.snyk.io/api/v1") and the new token's aud claim names the SAME
// host, the override branch must be a no-op: no UpdateApiEndpointsOnConfig
// mutation, no "API Endpoint has been updated" notification, and
// SettingApiEndpoint is preserved verbatim with its path intact.
func Test_authenticate_PreservesCustomUrlPathOnOverride_SameHost(t *testing.T) {
	engine, ts := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	require.True(t, config.UpdateApiEndpointsOnConfig(conf, "https://api.snyk.io/api/v1"))

	authenticator := NewFakeOauthAuthenticator(defaultExpiry, true, conf, true).WithJWTAud("https://api.snyk.io")
	provider := newOAuthProvider(conf, authenticator, engine.GetLogger())

	mockNotifier := notification.NewMockNotifier()
	service := NewAuthenticationService(engine, ts, provider, error_reporting.NewTestErrorReporter(engine), mockNotifier, testutil.DefaultConfigResolver(engine))

	_, err := service.Authenticate(t.Context())
	require.NoError(t, err)

	assert.Equal(t, "https://api.snyk.io/api/v1",
		conf.GetString(configresolver.UserGlobalKey(types.SettingApiEndpoint)),
		"customUrl path must be preserved when aud names the same host")

	for _, m := range mockNotifier.SentMessages() {
		if p, ok := m.(sglsp.ShowMessageParams); ok {
			assert.NotContains(t, p.Message, "API Endpoint has been updated",
				"no endpoint-update notification must be sent when aud host matches customUrl host")
		}
	}
}

// When customUrl carries a path (single-tenant pattern) and the new token's
// aud claim names a DIFFERENT (allowed) host, the override must swap only the
// host portion and preserve the path/query/fragment.
func Test_authenticate_PreservesCustomUrlPathOnOverride_DifferentHost(t *testing.T) {
	engine, ts := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	require.True(t, config.UpdateApiEndpointsOnConfig(conf, "https://api.eu.snyk.io/api/v1"))

	authenticator := NewFakeOauthAuthenticator(defaultExpiry, true, conf, true).WithJWTAud("https://api.snyk.io")
	provider := newOAuthProvider(conf, authenticator, engine.GetLogger())

	mockNotifier := notification.NewMockNotifier()
	service := NewAuthenticationService(engine, ts, provider, error_reporting.NewTestErrorReporter(engine), mockNotifier, testutil.DefaultConfigResolver(engine))

	_, err := service.Authenticate(t.Context())
	require.NoError(t, err)

	assert.Equal(t, "https://api.snyk.io/api/v1",
		conf.GetString(configresolver.UserGlobalKey(types.SettingApiEndpoint)),
		"override must swap the host only and preserve the path")

	var endpointUpdateCount int
	var lastUpdateMsg string
	for _, m := range mockNotifier.SentMessages() {
		if p, ok := m.(sglsp.ShowMessageParams); ok {
			if strings.Contains(p.Message, "API Endpoint has been updated") {
				endpointUpdateCount++
				lastUpdateMsg = p.Message
			}
		}
	}
	assert.Equal(t, 1, endpointUpdateCount, "exactly one endpoint-update notification must be sent")
	assert.Contains(t, lastUpdateMsg, "https://api.snyk.io/api/v1",
		"endpoint-update notification must carry the host-swapped, path-preserved customUrl")
}

// When customUrl has leading/trailing whitespace and aud names the same host,
// the host comparison must be whitespace-tolerant: no override fires.
func Test_authenticate_HostComparisonIgnoresCustomUrlWhitespace(t *testing.T) {
	engine, ts := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	// Persist the customUrl directly with leading whitespace; UpdateApiEndpointsOnConfig
	// trims/normalises, so we set the user-global key directly to exercise the
	// whitespace path through authenticate().
	conf.Set(configresolver.UserGlobalKey(types.SettingApiEndpoint), " https://api.snyk.io")

	authenticator := NewFakeOauthAuthenticator(defaultExpiry, true, conf, true).WithJWTAud("https://api.snyk.io")
	provider := newOAuthProvider(conf, authenticator, engine.GetLogger())

	mockNotifier := notification.NewMockNotifier()
	service := NewAuthenticationService(engine, ts, provider, error_reporting.NewTestErrorReporter(engine), mockNotifier, testutil.DefaultConfigResolver(engine))

	_, err := service.Authenticate(t.Context())
	require.NoError(t, err)

	for _, m := range mockNotifier.SentMessages() {
		if p, ok := m.(sglsp.ShowMessageParams); ok {
			assert.NotContains(t, p.Message, "API Endpoint has been updated",
				"whitespace-only difference between customUrl and aud must not trigger an override")
		}
	}
}

// Regression guard that pins the existing semantics of getPrioritizedApiUrl,
// which the aud-claim discovery work explicitly leaves unchanged. Any future
// "improvement" that breaks these rows should fail this test.
func Test_getPrioritizedApiUrl_RegressionGuards(t *testing.T) {
	defaultUrl := config.DefaultSnykApiUrl
	cases := []struct {
		name      string
		customUrl string
		engineUrl string
		expected  string
	}{
		{name: "defaultUrl + empty engineUrl", customUrl: defaultUrl, engineUrl: "", expected: defaultUrl},
		{name: "defaultUrl + EU engineUrl", customUrl: defaultUrl, engineUrl: "https://api.eu.snyk.io", expected: "https://api.eu.snyk.io"},
		{name: "EU customUrl + empty engineUrl", customUrl: "https://api.eu.snyk.io", engineUrl: "", expected: "https://api.eu.snyk.io"},
		{name: "empty customUrl + EU engineUrl", customUrl: "", engineUrl: "https://api.eu.snyk.io", expected: "https://api.eu.snyk.io"},
		{name: "FedRAMP customUrl + EU engineUrl", customUrl: "https://api.fedramp.snykgov.io", engineUrl: "https://api.eu.snyk.io", expected: "https://api.fedramp.snykgov.io"},
		{name: "customUrl with trailing slash", customUrl: "https://api.snyk.io/", engineUrl: "", expected: "https://api.snyk.io"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, getPrioritizedApiUrl(tt.customUrl, tt.engineUrl))
		})
	}
}
