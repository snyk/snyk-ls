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
	"path/filepath"
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

// Test_RegisterOAuthStorageBridge_PropagatesTokenToAuthService verifies that the
// pre-init bridge wires GAF storage updates into the auth service even before the
// OAuth provider is configured via Default().
func Test_RegisterOAuthStorageBridge_PropagatesTokenToAuthService(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetAuthenticationMethod(types.OAuthAuthentication)
	storageWithCallbacks, err := storage2.NewStorageWithCallbacks(storage2.WithStorageFile(filepath.Join(t.TempDir(), "testStorage")))
	require.NoError(t, err)
	c.SetStorage(storageWithCallbacks)

	notifier := notification.NewNotifier()
	authParamsChan := make(chan types.AuthenticationParams, 4)
	notifier.CreateListener(func(params any) {
		if authParams, ok := params.(types.AuthenticationParams); ok {
			authParamsChan <- authParams
		}
	})
	t.Cleanup(notifier.DisposeListener)

	service := NewAuthenticationService(c, nil, error_reporting.NewTestErrorReporter(), notifier)
	t.Cleanup(service.Shutdown)

	// Register the bridge BEFORE Default() runs (mirrors initializeHandler order).
	RegisterOAuthStorageBridge(storageWithCallbacks, service)

	rotatedTokenBytes, err := json.Marshal(oauth2.Token{
		AccessToken:  "rotated-access",
		RefreshToken: "rotated-refresh",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour),
	})
	require.NoError(t, err)
	rotatedToken := string(rotatedTokenBytes)

	// Simulate GAF persisting a rotated OAuth token during a pre-init API call.
	require.NoError(t, storageWithCallbacks.Set(auth.CONFIG_KEY_OAUTH_TOKEN, rotatedToken))

	// Wait for the auth service to apply the rotated token.
	require.Eventuallyf(t, func() bool {
		return c.Token() == rotatedToken
	}, 5*time.Second, 25*time.Millisecond, "rotated token must reach auth service via bridge")

	// And the corresponding IDE notification must have been queued.
	select {
	case authParams := <-authParamsChan:
		assert.Equal(t, rotatedToken, authParams.Token)
	case <-time.After(2 * time.Second):
		t.Fatal("expected IDE notification for rotated OAuth token via bridge")
	}
}

// Test_RegisterOAuthStorageBridge_NoOpOnNilArgs verifies the defensive nil-guards
// so initializeHandler can call this even before storage / auth service are ready.
func Test_RegisterOAuthStorageBridge_NoOpOnNilArgs(t *testing.T) {
	c := testutil.UnitTest(t)
	storageWithCallbacks, err := storage2.NewStorageWithCallbacks(storage2.WithStorageFile(filepath.Join(t.TempDir(), "testStorage")))
	require.NoError(t, err)
	service := NewAuthenticationService(c, nil, error_reporting.NewTestErrorReporter(), notification.NewNotifier())
	t.Cleanup(service.Shutdown)

	// Should not panic with either nil
	RegisterOAuthStorageBridge(nil, service)
	RegisterOAuthStorageBridge(storageWithCallbacks, nil)
}

// Test_RegisterOAuthStorageBridge_SerializesRapidTokenRotations verifies that the
// bridge's queued-update worker preserves order during rapid token rotations: the
// final in-memory token must equal the last token written to storage.
func Test_RegisterOAuthStorageBridge_SerializesRapidTokenRotations(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetAuthenticationMethod(types.OAuthAuthentication)
	storageWithCallbacks, err := storage2.NewStorageWithCallbacks(storage2.WithStorageFile(filepath.Join(t.TempDir(), "testStorage")))
	require.NoError(t, err)
	c.SetStorage(storageWithCallbacks)

	notifier := notification.NewNotifier()
	authParamsChan := make(chan types.AuthenticationParams, 16)
	notifier.CreateListener(func(params any) {
		if authParams, ok := params.(types.AuthenticationParams); ok {
			authParamsChan <- authParams
		}
	})
	t.Cleanup(notifier.DisposeListener)

	service := NewAuthenticationService(c, nil, error_reporting.NewTestErrorReporter(), notifier)
	t.Cleanup(service.Shutdown)

	RegisterOAuthStorageBridge(storageWithCallbacks, service)

	// Build tokens with strictly increasing expiry so each newer one is accepted by
	// shouldUpdateOAuth2Token (otherwise SetToken silently rejects out-of-order writes).
	tokenJSONs := make([]string, 5)
	base := time.Now().Add(time.Hour)
	for i := range tokenJSONs {
		tokenBytes, err := json.Marshal(oauth2.Token{
			AccessToken:  "access",
			RefreshToken: "refresh",
			TokenType:    "Bearer",
			Expiry:       base.Add(time.Duration(i) * time.Minute),
		})
		require.NoError(t, err)
		tokenJSONs[i] = string(tokenBytes)
	}

	for _, tokenJSON := range tokenJSONs {
		require.NoError(t, storageWithCallbacks.Set(auth.CONFIG_KEY_OAUTH_TOKEN, tokenJSON))
	}

	final := tokenJSONs[len(tokenJSONs)-1]
	require.Eventuallyf(t, func() bool {
		return c.Token() == final
	}, 5*time.Second, 25*time.Millisecond, "final token in must equal last token written to storage")
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
