/*
 * © 2024 Snyk Limited
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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	storage2 "github.com/snyk/snyk-ls/internal/storage"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_NewOAuthProvider_registersStorageCallback(t *testing.T) {
	c := testutil.UnitTest(t)
	storageWithCallbacks, err2 := storage2.NewStorageWithCallbacks(storage2.WithStorageFile(t.TempDir() + "testStorage"))
	assert.NoError(t, err2)
	c.SetStorage(storageWithCallbacks)

	// a token that's set into the configuration
	token := oauth2.Token{
		AccessToken:  t.Name(),
		RefreshToken: t.Name(),
		Expiry:       time.Now().Add(1 * time.Hour),
	}

	tokenReceived := make(chan bool, 1)
	credentialsUpdateCallback := func(_ string, newToken any) {
		tokenReceived <- true
	}

	NewOAuthProvider(c, auth.RefreshToken, credentialsUpdateCallback, nil)

	marshal, err := json.Marshal(token)
	assert.NoError(t, err)
	err = c.Storage().Set(auth.CONFIG_KEY_OAUTH_TOKEN, string(marshal))
	assert.NoError(t, err)
	assert.Eventuallyf(t, func() bool {
		return <-tokenReceived
	}, 5*time.Second, 100*time.Millisecond, "token should have been received")
}

func Test_NewOauthProvider_oauthProvider_created_with_injected_refreshMethod(t *testing.T) {
	c := testutil.UnitTest(t)
	storageWithCallbacks, err2 := storage2.NewStorageWithCallbacks(storage2.WithStorageFile(t.TempDir() + "testStorage"))
	assert.NoError(t, err2)
	c.SetStorage(storageWithCallbacks)
	c.SetAuthenticationMethod(types.OAuthAuthentication)

	// an expired token that's set into the configuration
	token := oauth2.Token{
		AccessToken:  t.Name(),
		RefreshToken: t.Name(),
		Expiry:       time.Now().Add(-1 * time.Hour),
	}

	tokenBytes, err := json.Marshal(token)
	assert.NoError(t, err)

	c.SetToken(string(tokenBytes))

	// refresh func is replaced with func that sends true into a channel when called
	triggeredChan := make(chan bool, 1)
	testFunc := func(ctx context.Context, oauthConfig *oauth2.Config, token *oauth2.Token) (*oauth2.Token, error) {
		triggeredChan <- true
		token.Expiry = time.Now().Add(1 * time.Hour)
		return token, nil
	}

	provider := NewOAuthProvider(c, testFunc, nil, nil)

	// AddAuthenticationHeader will trigger the refresh method
	_ = provider.Authenticator().AddAuthenticationHeader(httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Eventuallyf(t, func() bool {
		return <-triggeredChan
	}, 5*time.Second, 100*time.Millisecond, "refresh should have been triggered")
}

// Test_Default_EmptyTokenFromStorage_SendsNoNotification verifies that when storage fires the
// credentials callback with an empty value (e.g. ClearAuthentication calls Unset, which writes
// an empty value through to shared storage), no $/snyk.hasAuthenticated notification is sent.
func Test_Default_EmptyTokenFromStorage_SendsNoNotification(t *testing.T) {
	c := testutil.UnitTest(t)
	storageWithCallbacks, err := storage2.NewStorageWithCallbacks(storage2.WithStorageFile(t.TempDir() + "/testStorage"))
	require.NoError(t, err)
	c.SetStorage(storageWithCallbacks)

	mockNotifier := notification.NewMockNotifier()
	provider := &FakeAuthenticationProvider{C: c}
	authService := NewAuthenticationService(c, provider, error_reporting.NewTestErrorReporter(), mockNotifier)

	_ = Default(c, authService)

	// Simulate what ClearAuthentication does: write an empty value to storage for the OAuth token key.
	// This triggers the credentialsUpdateCallback with an empty value.
	err = c.Storage().Set(auth.CONFIG_KEY_OAUTH_TOKEN, "")
	require.NoError(t, err)

	// Give any goroutine time to run if the guard is absent.
	time.Sleep(50 * time.Millisecond)

	for _, msg := range mockNotifier.SentMessages() {
		if p, ok := msg.(types.AuthenticationParams); ok {
			assert.NotEmpty(t, p.Token, "hasAuthenticated must never be sent with an empty token")
		}
	}
}

// Test_Default_TokenRefresh_SendsNotificationWithApiUrl verifies that when GAF
// refreshes an OAuth token (triggering the credentialsUpdateCallback registered by Default()),
// a $/snyk.hasAuthenticated notification is sent with the token and current ApiUrl.
func Test_Default_TokenRefresh_SendsNotificationWithApiUrl(t *testing.T) {
	c := testutil.UnitTest(t)
	storageWithCallbacks, err := storage2.NewStorageWithCallbacks(storage2.WithStorageFile(t.TempDir() + "/testStorage"))
	require.NoError(t, err)
	c.SetStorage(storageWithCallbacks)

	mockNotifier := notification.NewMockNotifier()
	provider := &FakeAuthenticationProvider{C: c}
	authService := NewAuthenticationService(c, provider, error_reporting.NewTestErrorReporter(), mockNotifier)

	// Default() registers the credentialsUpdateCallback that calls updateCredentials(token, true, true)
	// when a token is written to storage.
	_ = Default(c, authService)

	// Simulate a token refresh by writing a new OAuth token to storage.
	// In production this is done by GAF's token refresher.
	newOAuthToken := `{"access_token":"refreshed-access","token_type":"Bearer","refresh_token":"refresh-tok","expiry":"2099-01-01T00:00:00Z"}`
	err = c.Storage().Set(auth.CONFIG_KEY_OAUTH_TOKEN, newOAuthToken)
	require.NoError(t, err)

	expectedApiUrl := c.SnykApi()
	assert.Eventually(t, func() bool {
		for _, msg := range mockNotifier.SentMessages() {
			p, ok := msg.(types.AuthenticationParams)
			if ok && p.Token != "" && p.ApiUrl == expectedApiUrl {
				return true
			}
		}
		return false
	}, 3*time.Second, 10*time.Millisecond, "refresh must send $/snyk.hasAuthenticated with token and ApiUrl")
}
