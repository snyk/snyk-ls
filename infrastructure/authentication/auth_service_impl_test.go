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

func TestIsAuthenticatedSendsAuthenticationEventOnSuccess(t *testing.T) {
	// Analytics are sent in IsAuthenticated() on first successful check, not in Authenticate().
	c := testutil.UnitTest(t)
	// FakeAuthentication matches FakeAuthenticationProvider so handleProviderInconsistencies won't reset it.
	c.SetAuthenticationMethod(types.FakeAuthentication)

	mockEngine, _ := testutil.SetUpEngineMock(t, c)

	// Expect analytics to be sent exactly once on the first successful IsAuthenticated() call
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

	provider := &FakeAuthenticationProvider{IsAuthenticated: true, C: c}
	service := NewAuthenticationService(c, provider, error_reporting.NewTestErrorReporter(), notification.NewMockNotifier())

	// Simulate the token being stored (as would happen via didChangeConfiguration)
	fakeToken := "e448dc1a-26c6-11ed-a261-0242ac120002"
	c.SetToken(fakeToken)

	// First IsAuthenticated() call triggers analytics for the new token
	assert.True(t, service.IsAuthenticated())
}

func TestAuthenticationAnalytics_OrgSelection(t *testing.T) {
	// Shared test constants
	const (
		testFolderOrg = "test-folder-org"
		globalOrg     = "global-org"
	)

	testCases := []struct {
		name        string
		setupWs     func(t *testing.T, ctrl *gomock.Controller, c *config.Config) types.Workspace
		expectedOrg string
	}{
		{
			name: "uses any folder specific org",
			setupWs: func(t *testing.T, ctrl *gomock.Controller, c *config.Config) types.Workspace {
				t.Helper()

				folder1Path := types.FilePath("/fake/folder1")
				folder2Path := types.FilePath("/fake/folder2")

				folder1Config := &types.FolderConfig{
					FolderPath:   folder1Path,
					PreferredOrg: testFolderOrg,
					OrgSetByUser: true,
				}
				folder2Config := &types.FolderConfig{
					FolderPath:   folder2Path,
					PreferredOrg: testFolderOrg,
					OrgSetByUser: true,
				}

				err := storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), folder1Config, c.Logger())
				require.NoError(t, err, "failed to configure first folder's org")
				err = storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), folder2Config, c.Logger())
				require.NoError(t, err, "failed to configure second folder's org")

				// Set a different global org to ensure folder-specific org takes precedence
				c.SetOrganization(globalOrg)

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
			// FakeAuthentication matches FakeAuthenticationProvider so handleProviderInconsistencies won't reset it.
			c.SetAuthenticationMethod(types.FakeAuthentication)
			mockEngine, _ := testutil.SetUpEngineMock(t, c)

			// Setup workspace (test case specific) and set it on config
			ws := tc.setupWs(t, ctrl, c)
			c.SetWorkspace(ws)

			// Capture analytics WF's data and config to verify folder org
			capturedCh := testutil.MockAndCaptureWorkflowInvocation(t, mockEngine, localworkflows.WORKFLOWID_REPORT_ANALYTICS, 1)

			// Analytics fire in IsAuthenticated() on the first successful check.
			fakeToken := "e448dc1a-26c6-11ed-a261-0242ac120002"
			c.SetToken(fakeToken)
			provider := &FakeAuthenticationProvider{IsAuthenticated: true, C: c}
			service := NewAuthenticationService(c, provider, error_reporting.NewTestErrorReporter(), notification.NewMockNotifier())

			// Act: IsAuthenticated triggers analytics for the new token
			assert.True(t, service.IsAuthenticated(), "authentication should succeed")

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

	t.Run("Send notification without ApiUrl when updateApiUrl=false", func(t *testing.T) {
		c := testutil.UnitTest(t)
		mockNotifier := notification.NewMockNotifier()
		service := NewAuthenticationService(c, nil, error_reporting.NewTestErrorReporter(), mockNotifier)

		token := "some_token"
		service.UpdateCredentials(token, true, false)

		expectedNotification := types.AuthenticationParams{Token: token}
		assert.Equal(t, expectedNotification, mockNotifier.SentMessages()[0])
	})

	t.Run("Send notification with ApiUrl when updateApiUrl=true", func(t *testing.T) {
		c := testutil.UnitTest(t)
		mockNotifier := notification.NewMockNotifier()
		service := NewAuthenticationService(c, nil, error_reporting.NewTestErrorReporter(), mockNotifier)

		token := "some_other_token"
		service.UpdateCredentials(token, true, true)

		expectedNotification := types.AuthenticationParams{Token: token, ApiUrl: c.SnykApi()}
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

func TestConfigSave_UpdateCredentials_SendsNotification(t *testing.T) {
	t.Run("sends hasAuthenticated with token and ApiUrl on new token", func(t *testing.T) {
		c := testutil.UnitTest(t)
		mockNotifier := notification.NewMockNotifier()
		service := NewAuthenticationService(c, nil, error_reporting.NewTestErrorReporter(), mockNotifier)

		token := "settings-save-token"
		service.UpdateCredentials(token, true, true)

		require.Len(t, mockNotifier.SentMessages(), 1)
		assert.Equal(t, types.AuthenticationParams{Token: token, ApiUrl: c.SnykApi()}, mockNotifier.SentMessages()[0])
	})

	t.Run("no duplicate notification when called again with the same token", func(t *testing.T) {
		c := testutil.UnitTest(t)
		mockNotifier := notification.NewMockNotifier()
		service := NewAuthenticationService(c, nil, error_reporting.NewTestErrorReporter(), mockNotifier)

		token := "settings-save-token"
		service.UpdateCredentials(token, true, true)
		require.Len(t, mockNotifier.SentMessages(), 1, "first call should send notification")

		service.UpdateCredentials(token, true, true)
		assert.Len(t, mockNotifier.SentMessages(), 1, "second call with same token must not send another notification")
	})
}

func Test_Authenticate(t *testing.T) {
	t.Run("Authenticate uses configured provider and returns token without sending notification", func(t *testing.T) {
		c := testutil.UnitTest(t)
		c.UpdateApiEndpoints(config.DefaultSnykApiUrl)

		originalProvider := &FakeAuthenticationProvider{C: c}
		mockNotifier := notification.NewMockNotifier()
		service := NewAuthenticationService(c, originalProvider, error_reporting.NewTestErrorReporter(), mockNotifier)

		token, err := service.Authenticate(t.Context())
		require.NoError(t, err)
		assert.NotEmpty(t, token, "token must be returned on successful authentication")

		// The service's provider must NOT be replaced during the login flow
		assert.Same(t, originalProvider, service.Provider(), "service provider must not be replaced during login")

		// No notification is sent — callers decide what to do with the token via UpdateCredentials
		assert.Empty(t, mockNotifier.SentMessages(), "Authenticate must not send any notifications")
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
	c.SetToken("test-token-for-logout")
	provider := FakeAuthenticationProvider{IsAuthenticated: true}
	mockNotifier := notification.NewMockNotifier()
	service := NewAuthenticationService(c, &provider, error_reporting.NewTestErrorReporter(), mockNotifier)

	service.Logout(t.Context())

	assert.False(t, provider.IsAuthenticated)
	assert.Empty(t, c.Token(), "token must be cleared after logout")
	assert.Empty(t, mockNotifier.SentMessages(), "Logout must not send any notifications")
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

func TestAuthenticate_ServiceProviderNeverReplacedDuringLogin(t *testing.T) {
	c := testutil.UnitTest(t)
	original := &FakeAuthenticationProvider{C: c}
	service := NewAuthenticationService(c, original, error_reporting.NewTestErrorReporter(), notification.NewMockNotifier())

	_, err := service.Authenticate(t.Context())

	assert.NoError(t, err)
	// The service's provider must never be replaced during the login flow
	assert.Same(t, original, service.Provider(), "service provider must not be replaced during login")
}

func TestAuthenticate_SuccessfulAuthDoesNotStoreTokenOrSendNotification(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetToken("old-token")
	provider := &FakeAuthenticationProvider{C: c}
	mockNotifier := notification.NewMockNotifier()
	service := NewAuthenticationService(c, provider, error_reporting.NewTestErrorReporter(), mockNotifier)

	token, err := service.Authenticate(t.Context())

	assert.NoError(t, err)
	assert.Equal(t, "e448dc1a-26c6-11ed-a261-0242ac120002", token)
	// Token is returned but NOT stored — callers decide what to do with it via UpdateCredentials
	assert.Equal(t, "old-token", c.Token(), "config token must remain unchanged until UpdateCredentials is called")
	// No notification is sent — that is the caller's responsibility
	assert.Empty(t, mockNotifier.SentMessages(), "Authenticate must not send any notifications")
}

func TestConfigSave_EndpointChange_ClearsThenRestoresToken(t *testing.T) {
	// Simulates the writeSettings flow: updateApiEndpoints (logout) → updateToken (set new token)
	// The endpoint change clears the old token, but the new token from settings replaces it.
	c := testutil.UnitTest(t)
	c.SetToken("old-token")
	c.SetAuthenticationMethod(types.FakeAuthentication)

	provider := &FakeAuthenticationProvider{C: c}
	service := NewAuthenticationService(c, provider, error_reporting.NewTestErrorReporter(), notification.NewMockNotifier())

	// Step 1: endpoint change triggers logout (clears token)
	service.Logout(t.Context())
	assert.Empty(t, c.Token(), "token should be cleared after endpoint-change logout")

	// Step 2: updateToken sets the new token received from the IDE
	newToken := "new-token-from-auth"
	service.UpdateCredentials(newToken, false, false)
	assert.Equal(t, newToken, c.Token(), "new token should be set after updateToken")
}

func TestConfigSave_AuthMethodMismatch_LogsOutAndPromptsReAuth(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetToken("my-valid-token")
	c.SetAuthenticationMethod(types.FakeAuthentication)

	provider := &FakeAuthenticationProvider{C: c}
	service := NewAuthenticationService(c, provider, error_reporting.NewTestErrorReporter(), notification.NewMockNotifier())

	// Change auth method to one that doesn't match the token format
	c.SetAuthenticationMethod(types.TokenAuthentication)
	service.ConfigureProviders(c)

	// Token should be cleared because the method doesn't match credentials
	assert.Empty(t, c.Token(), "token should be cleared when auth method mismatches credentials")
}

func TestAuthenticate_LogoutCompletelyClearsToken(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetToken("valid-token")
	c.SetAuthenticationMethod(types.FakeAuthentication)

	provider := &FakeAuthenticationProvider{IsAuthenticated: true, C: c}
	mockNotifier := notification.NewMockNotifier()
	service := NewAuthenticationService(c, provider, error_reporting.NewTestErrorReporter(), mockNotifier)

	service.Logout(t.Context())

	// Token should be completely cleared
	assert.Empty(t, c.Token(), "token should be empty after logout")
	// No notification is sent — the IDE initiated the logout and already knows
	assert.Empty(t, mockNotifier.SentMessages(), "Logout must not send any notifications")
	// Service should report not authenticated
	assert.False(t, service.IsAuthenticated())
}

// slowAuthProvider simulates an OAuth provider waiting for browser interaction.
// The first Authenticate call blocks until its context is canceled.
// Subsequent calls return immediately (simulating a fresh, quick auth attempt).
type slowAuthProvider struct {
	FakeAuthenticationProvider
	startedCh chan struct{} // closed when the first Authenticate call starts blocking
	mu        sync.Mutex
	called    bool
}

func newSlowAuthProvider(c *config.Config) *slowAuthProvider {
	return &slowAuthProvider{
		FakeAuthenticationProvider: FakeAuthenticationProvider{C: c},
		startedCh:                  make(chan struct{}),
	}
}

func (s *slowAuthProvider) Authenticate(ctx context.Context) (string, error) {
	s.mu.Lock()
	firstCall := !s.called
	s.called = true
	s.mu.Unlock()

	if firstCall {
		close(s.startedCh)
		<-ctx.Done()
		return "", ctx.Err()
	}
	return "token-from-second-call", nil
}

// TestAuthenticate_ConcurrentCalls_SecondCancelsFirst verifies AC#2 and AC#3:
// when a second Authenticate call arrives while the first is in-flight, the first
// flow is canceled and the second succeeds using the newly provided parameters.
func TestAuthenticate_ConcurrentCalls_SecondCancelsFirst(t *testing.T) {
	c := testutil.UnitTest(t)
	slow := newSlowAuthProvider(c)
	service := NewAuthenticationService(c, slow, error_reporting.NewTestErrorReporter(), notification.NewMockNotifier())

	// Start first auth — blocks inside the slow provider until its context is canceled.
	firstResult := make(chan error, 1)
	go func() {
		_, err := service.Authenticate(t.Context())
		firstResult <- err
	}()

	// Wait for the slow provider to signal it is blocking.
	<-slow.startedCh

	// Second call should cancel the first and succeed via the fast path (called=true).
	_, err := service.Authenticate(t.Context())
	require.NoError(t, err, "second authenticate call should succeed")

	// First auth should have been canceled and returned an error.
	select {
	case firstErr := <-firstResult:
		assert.Error(t, firstErr, "first authenticate call should have been canceled")
	case <-time.After(time.Second):
		t.Fatal("first authenticate goroutine did not return within 1 second after being canceled")
	}
}

// TestAuthenticate_IsAuthenticatedNotBlockedDuringAuth verifies AC#4:
// the main mutex is not held during the auth flow so that IsAuthenticated()
// can run concurrently without being blocked.
func TestAuthenticate_IsAuthenticatedNotBlockedDuringAuth(t *testing.T) {
	c := testutil.UnitTest(t)
	slow := newSlowAuthProvider(c)
	service := NewAuthenticationService(c, slow, error_reporting.NewTestErrorReporter(), notification.NewMockNotifier())

	// Start the slow auth in the background.
	go func() {
		_, _ = service.Authenticate(t.Context())
	}()
	// Cancel the running auth after the test completes to avoid goroutine leaks.
	t.Cleanup(func() {
		_, _ = service.Authenticate(t.Context())
	})

	// Wait for the slow provider to signal it is blocking.
	<-slow.startedCh

	// IsAuthenticated must return within 100ms — it must not block on the main mutex.
	result := make(chan bool, 1)
	go func() { result <- service.IsAuthenticated() }()

	select {
	case <-result:
		// Returned quickly — mutex was not held during the auth flow.
	case <-time.After(100 * time.Millisecond):
		t.Fatal("IsAuthenticated() blocked while Authenticate() was in progress (main mutex held during auth flow)")
	}
}

// TestAuthenticate_CancellationPreservesExistingToken verifies AC#5:
// canceling an in-flight auth flow via a second Authenticate call must not
// clear the existing valid token stored in the config.
func TestAuthenticate_CancellationPreservesExistingToken(t *testing.T) {
	c := testutil.UnitTest(t)
	existingToken := "existing-valid-token"
	c.SetToken(existingToken)

	slow := newSlowAuthProvider(c)
	service := NewAuthenticationService(c, slow, error_reporting.NewTestErrorReporter(), notification.NewMockNotifier())

	// Start slow auth in background.
	firstResult := make(chan error, 1)
	go func() {
		_, err := service.Authenticate(t.Context())
		firstResult <- err
	}()

	// Wait for the slow provider to signal it is blocking.
	<-slow.startedCh

	// Cancel via a second Authenticate call.
	_, err := service.Authenticate(t.Context())
	require.NoError(t, err, "second authenticate call should succeed")

	// Wait for first auth goroutine to complete.
	select {
	case <-firstResult:
	case <-time.After(time.Second):
		t.Fatal("first auth goroutine did not return within 1 second")
	}

	// The original token must still be present — cancellation must never clear the token.
	assert.Equal(t, existingToken, c.Token(), "cancellation should not clear the existing token")
}

// TestAuthenticate_AfterCancellation_SystemReadyForNewAuth verifies AC#1 and AC#2:
// after a canceled auth flow the system is immediately ready to handle a new
// Authenticate call without any stuck state or errors.
func TestAuthenticate_AfterCancellation_SystemReadyForNewAuth(t *testing.T) {
	c := testutil.UnitTest(t)
	slow := newSlowAuthProvider(c)
	service := NewAuthenticationService(c, slow, error_reporting.NewTestErrorReporter(), notification.NewMockNotifier())

	// Start slow auth in background.
	firstResult := make(chan error, 1)
	go func() {
		_, err := service.Authenticate(t.Context())
		firstResult <- err
	}()

	// Wait for the slow provider to signal it is blocking.
	<-slow.startedCh

	// Cancel first auth via a second call (also exercises cancel-and-restart).
	_, err := service.Authenticate(t.Context())
	require.NoError(t, err, "second auth should succeed after canceling first")

	// Wait for first auth goroutine to complete.
	select {
	case firstErr := <-firstResult:
		require.Error(t, firstErr, "first auth should have been canceled")
	case <-time.After(time.Second):
		t.Fatal("first auth goroutine did not return within 1 second")
	}

	// Third auth: the system must be immediately ready — no stuck state after cancellation.
	// slow provider returns quickly now (called=true), so this verifies readiness.
	_, err = service.Authenticate(t.Context())
	assert.NoError(t, err, "system should be ready for a new auth attempt after a canceled flow")
}

