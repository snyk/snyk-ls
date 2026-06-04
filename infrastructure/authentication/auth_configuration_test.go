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
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	storage2 "github.com/snyk/snyk-ls/internal/storage"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_NewOAuthProvider_registersStorageCallback(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()
	storageWithCallbacks, err2 := storage2.NewStorageWithCallbacks(storage2.WithStorageFile(t.TempDir() + "testStorage"))
	assert.NoError(t, err2)
	conf.SetStorage(storageWithCallbacks)

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

	NewOAuthProvider(engine, auth.RefreshToken, credentialsUpdateCallback, nil)

	marshal, err := json.Marshal(token)
	assert.NoError(t, err)
	err = storageWithCallbacks.Set(auth.CONFIG_KEY_OAUTH_TOKEN, string(marshal))
	assert.NoError(t, err)
	assert.Eventuallyf(t, func() bool {
		return <-tokenReceived
	}, 5*time.Second, 100*time.Millisecond, "token should have been received")
}

func Test_DefaultOAuthProvider_storageCallbackUpdatesCredentialsAndNotifies(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	storageWithCallbacks, err := storage2.NewStorageWithCallbacks(storage2.WithStorageFile(t.TempDir() + "testStorage"))
	require.NoError(t, err)
	conf.SetStorage(storageWithCallbacks)
	conf.Set(configresolver.UserGlobalKey(types.SettingAuthenticationMethod), string(types.OAuthAuthentication))

	refreshedToken := oauth2.Token{
		AccessToken:  "refreshed-access",
		RefreshToken: "refreshed-refresh",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour),
	}
	tokenBytes, err := json.Marshal(refreshedToken)
	require.NoError(t, err)
	refreshedTokenJSON := string(tokenBytes)

	notifier := notification.NewNotifier()
	authParamsChan := make(chan types.AuthenticationParams, 1)
	notifier.CreateListener(func(params any) {
		if authParams, ok := params.(types.AuthenticationParams); ok {
			authParamsChan <- authParams
		}
	})
	t.Cleanup(func() { notifier.DisposeListener() })

	service := NewAuthenticationService(
		engine,
		tokenService,
		nil,
		error_reporting.NewTestErrorReporter(engine),
		notifier,
		testutil.DefaultConfigResolver(engine),
	)

	Default(engine, service)

	require.NoError(t, storageWithCallbacks.Set(auth.CONFIG_KEY_OAUTH_TOKEN, refreshedTokenJSON))
	var receivedAuthParams types.AuthenticationParams
	require.Eventually(t, func() bool {
		if receivedAuthParams.Token == "" {
			select {
			case receivedAuthParams = <-authParamsChan:
			default:
			}
		}
		return config.GetToken(conf) == refreshedTokenJSON && receivedAuthParams.Token == refreshedTokenJSON
	}, 5*time.Second, 100*time.Millisecond)
	assert.Empty(t, receivedAuthParams.ApiUrl)
}

func Test_RegisterOAuthStorageBridge_UsesDefaultUnlockedCallback(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	storageWithCallbacks, err := storage2.NewStorageWithCallbacks(storage2.WithStorageFile(filepath.Join(t.TempDir(), "testStorage")))
	require.NoError(t, err)
	conf.SetStorage(storageWithCallbacks)
	conf.Set(configresolver.UserGlobalKey(types.SettingAuthenticationMethod), string(types.OAuthAuthentication))

	service := NewAuthenticationService(
		engine,
		tokenService,
		nil,
		error_reporting.NewTestErrorReporter(engine),
		notification.NewNotifier(),
		testutil.DefaultConfigResolver(engine),
	)
	serviceImpl, ok := service.(*AuthenticationServiceImpl)
	require.True(t, ok)

	RegisterOAuthStorageBridge(storageWithCallbacks, service)

	rotatedTokenBytes, err := json.Marshal(oauth2.Token{
		AccessToken:  "rotated-access",
		RefreshToken: "rotated-refresh",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour),
	})
	require.NoError(t, err)
	rotatedToken := string(rotatedTokenBytes)

	serviceImpl.m.Lock()
	defer serviceImpl.m.Unlock()

	require.NoError(t, storageWithCallbacks.Set(auth.CONFIG_KEY_OAUTH_TOKEN, rotatedToken))
	require.Eventually(t, func() bool {
		return config.GetToken(conf) == rotatedToken
	}, 2*time.Second, time.Millisecond)
}

func Test_RegisterOAuthStorageBridge_EmitsSecretSafeLogMarkers(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	var logOutput bytes.Buffer
	logger := zerolog.New(&logOutput).Level(zerolog.DebugLevel)
	engine.SetLogger(&logger)

	conf := engine.GetConfiguration()
	storageWithCallbacks, err := storage2.NewStorageWithCallbacks(storage2.WithStorageFile(filepath.Join(t.TempDir(), "testStorage")))
	require.NoError(t, err)
	conf.SetStorage(storageWithCallbacks)
	conf.Set(configresolver.UserGlobalKey(types.SettingAuthenticationMethod), string(types.OAuthAuthentication))

	notifier := notification.NewNotifier()
	authParamsChan := make(chan types.AuthenticationParams, 1)
	notifier.CreateListener(func(params any) {
		if authParams, ok := params.(types.AuthenticationParams); ok {
			authParamsChan <- authParams
		}
	})
	t.Cleanup(func() { notifier.DisposeListener() })

	service := NewAuthenticationService(
		engine,
		tokenService,
		nil,
		error_reporting.NewTestErrorReporter(engine),
		notifier,
		testutil.DefaultConfigResolver(engine),
	)

	RegisterOAuthStorageBridge(storageWithCallbacks, service)

	rotatedTokenBytes, err := json.Marshal(oauth2.Token{
		AccessToken:  "access-token-must-not-be-logged",
		RefreshToken: "refresh-token-must-not-be-logged",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour),
	})
	require.NoError(t, err)
	rotatedToken := string(rotatedTokenBytes)

	require.NoError(t, storageWithCallbacks.Set(auth.CONFIG_KEY_OAUTH_TOKEN, rotatedToken))

	// Wait for the notification to be sent, which indicates the async callback has completed
	var receivedAuthParams types.AuthenticationParams
	require.Eventually(t, func() bool {
		select {
		case receivedAuthParams = <-authParamsChan:
			return true
		default:
			return false
		}
	}, 2*time.Second, 10*time.Millisecond)

	require.Equal(t, rotatedToken, receivedAuthParams.Token)

	logs := logOutput.String()
	assert.Contains(t, logs, "registered oauth storage bridge")
	assert.Contains(t, logs, "oauth storage bridge received token update")
	assert.Contains(t, logs, `"oauth_storage_key":"INTERNAL_OAUTH_TOKEN_STORAGE"`)
	assert.Contains(t, logs, `"token_empty":false`)
	assert.NotContains(t, logs, rotatedToken)
	assert.NotContains(t, logs, "access-token-must-not-be-logged")
	assert.NotContains(t, logs, "refresh-token-must-not-be-logged")
	assert.False(t, strings.Contains(logs, "eyJ"), "logs should not contain JWT-like token fragments")
}

func Test_RegisterOAuthStorageBridge_SerializesRapidTokenRotations(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	storageWithCallbacks, err := storage2.NewStorageWithCallbacks(storage2.WithStorageFile(filepath.Join(t.TempDir(), "testStorage")))
	require.NoError(t, err)
	conf.SetStorage(storageWithCallbacks)
	conf.Set(configresolver.UserGlobalKey(types.SettingAuthenticationMethod), string(types.OAuthAuthentication))

	notifier := notification.NewNotifier()
	authParamsChan := make(chan types.AuthenticationParams, 10)
	notifier.CreateListener(func(params any) {
		if authParams, ok := params.(types.AuthenticationParams); ok {
			authParamsChan <- authParams
		}
	})
	t.Cleanup(func() { notifier.DisposeListener() })

	service := NewAuthenticationService(
		engine,
		tokenService,
		nil,
		error_reporting.NewTestErrorReporter(engine),
		notifier,
		testutil.DefaultConfigResolver(engine),
	)
	t.Cleanup(func() { service.Shutdown() })

	RegisterOAuthStorageBridge(storageWithCallbacks, service)

	// Simulate rapid token rotations by setting multiple tokens in quick succession
	tokens := []string{"token-1", "token-2", "token-3"}
	tokenJSONs := make([]string, len(tokens))
	for i, token := range tokens {
		tokenBytes, _ := json.Marshal(oauth2.Token{
			AccessToken:  token,
			RefreshToken: token + "-refresh",
			TokenType:    "Bearer",
			Expiry:       time.Now().Add(time.Hour),
		})
		tokenJSONs[i] = string(tokenBytes)
		storageWithCallbacks.Set(auth.CONFIG_KEY_OAUTH_TOKEN, tokenJSONs[i])
	}

	// Wait for all notifications to be delivered
	receivedTokens := make([]string, 0, len(tokens))
	timeout := time.After(5 * time.Second)
	for len(receivedTokens) < len(tokens) {
		select {
		case authParams := <-authParamsChan:
			receivedTokens = append(receivedTokens, authParams.Token)
		case <-timeout:
			t.Fatalf("timeout waiting for notifications, received %d/%d", len(receivedTokens), len(tokens))
		}
	}

	// Verify that the final token in the configuration is the last one set
	finalToken := config.GetToken(conf)
	require.Equal(t, tokenJSONs[len(tokenJSONs)-1], finalToken, "final token should be the last one set")
}

func Test_RegisterOAuthStorageBridge_PreInitRefreshIsBufferedForIde(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()

	storageFile := filepath.Join(t.TempDir(), "ls-config.json")
	storageWithCallbacks, err := storage2.NewStorageWithCallbacks(storage2.WithStorageFile(storageFile))
	require.NoError(t, err)
	conf.SetStorage(storageWithCallbacks)
	conf.PersistInStorage(auth.CONFIG_KEY_OAUTH_TOKEN)
	conf.Set(configresolver.UserGlobalKey(types.SettingAuthenticationMethod), string(types.OAuthAuthentication))

	notifier := notification.NewNotifier()
	service := NewAuthenticationService(
		engine,
		tokenService,
		nil,
		error_reporting.NewTestErrorReporter(engine),
		notifier,
		testutil.DefaultConfigResolver(engine),
	)

	// Register the bridge before any provider is configured (mirrors initializeHandler).
	RegisterOAuthStorageBridge(storageWithCallbacks, service)

	rotatedTokenBytes, err := json.Marshal(oauth2.Token{
		AccessToken:  "fresh-access",
		RefreshToken: "fresh-refresh",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour),
	})
	require.NoError(t, err)
	rotatedToken := string(rotatedTokenBytes)

	// Simulate GAF persisting a rotated OAuth token during a pre-init API call.
	require.NoError(t, storageWithCallbacks.Set(auth.CONFIG_KEY_OAUTH_TOKEN, rotatedToken))

	// Canonical LS token reflects the rotated value almost immediately.
	require.Eventuallyf(t, func() bool {
		return config.GetToken(conf) == rotatedToken
	}, 2*time.Second, time.Millisecond, "rotated token must be applied to user:global:token")

	receivedCh := make(chan types.AuthenticationParams, 4)
	notifier.CreateListener(func(p any) {
		// Mirror application/server.registerNotifier: do not dispatch anything to
		// the IDE before SettingIsLspInitialized turns true.
		for !conf.GetBool(types.SettingIsLspInitialized) {
			time.Sleep(time.Millisecond)
		}
		if authParams, ok := p.(types.AuthenticationParams); ok {
			receivedCh <- authParams
		}
	})
	t.Cleanup(notifier.DisposeListener)

	// No notification reaches the IDE while LSP initialization is in progress.
	select {
	case authParams := <-receivedCh:
		t.Fatalf("notification delivered before LSP initialized: %+v", authParams)
	case <-time.After(50 * time.Millisecond):
	}

	conf.Set(types.SettingIsLspInitialized, true)

	select {
	case authParams := <-receivedCh:
		assert.Equal(t, rotatedToken, authParams.Token)
	case <-time.After(2 * time.Second):
		t.Fatal("expected rotated OAuth token to be delivered after LSP initialization")
	}
}

func Test_NewOauthProvider_oauthProvider_created_with_injected_refreshMethod(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()
	storageWithCallbacks, err2 := storage2.NewStorageWithCallbacks(storage2.WithStorageFile(t.TempDir() + "testStorage"))
	assert.NoError(t, err2)
	conf.SetStorage(storageWithCallbacks)
	conf.Set(configresolver.UserGlobalKey(types.SettingAuthenticationMethod), string(types.OAuthAuthentication))

	// an expired token that's set into the configuration
	token := oauth2.Token{
		AccessToken:  t.Name(),
		RefreshToken: t.Name(),
		Expiry:       time.Now().Add(-1 * time.Hour),
	}

	tokenBytes, err := json.Marshal(token)
	assert.NoError(t, err)

	conf.Set(auth.CONFIG_KEY_OAUTH_TOKEN, string(tokenBytes))

	// refresh func is replaced with func that sends true into a channel when called
	triggeredChan := make(chan bool, 1)
	testFunc := func(ctx context.Context, oauthConfig *oauth2.Config, token *oauth2.Token) (*oauth2.Token, error) {
		triggeredChan <- true
		token.Expiry = time.Now().Add(1 * time.Hour)
		return token, nil
	}

	provider := NewOAuthProvider(engine, testFunc, nil, nil)

	// AddAuthenticationHeader will trigger the refresh method
	_, _ = provider.Authenticator().AddAuthenticationHeader(httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Eventuallyf(t, func() bool {
		return <-triggeredChan
	}, 5*time.Second, 100*time.Millisecond, "refresh should have been triggered")
}
