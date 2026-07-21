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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// Test_IsAuthenticated_DoesNotUseOAuth2ProviderCustomRefresherFunc pins down a
// non-obvious architectural fact (IDE-2178): OAuth2Provider.GetCheckAuthenticationFunction()
// returns the free function AuthenticationCheck, which ignores its receiver and always
// calls the whoami workflow via engine.GetNetworkAccess() - a separate authenticator GAF
// builds internally, with no custom token refresher wired in. Default()'s own refresherFunc
// closure (auth_configuration.go) is only ever used by the explicit login flow
// (Authenticate -> CancelableAuthenticate), never by IsAuthenticated()/scan/whoami traffic.
//
// This drives the real production entry point with an expired token and asserts a real
// refresh attempt and a real whoami call both happen (proven via hit counters) and that
// the stale token is cleared from storage afterward.
func Test_IsAuthenticated_DoesNotUseOAuth2ProviderCustomRefresherFunc(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	conf.Set(configresolver.UserGlobalKey(types.SettingAuthenticationMethod), string(types.OAuthAuthentication))

	var tokenEndpointHits, selfEndpointHits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/oauth2/token"):
			atomic.AddInt32(&tokenEndpointHits, 1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		case strings.Contains(r.URL.Path, "/rest/self"):
			atomic.AddInt32(&selfEndpointHits, 1)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"errors":[{"status":"401","detail":"unauthorized"}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	// Must be set before the OAuth authenticator is constructed - the refresh token URL is
	// captured at construction time.
	conf.Set(configuration.API_URL, server.URL)

	expiredToken := oauth2.Token{
		AccessToken:  testutil.BuildJWTWithAud(t, server.URL),
		RefreshToken: "expired-refresh",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(-1 * time.Hour),
	}
	tokenBytes, err := json.Marshal(expiredToken)
	require.NoError(t, err)
	conf.Set(auth.CONFIG_KEY_OAUTH_TOKEN, string(tokenBytes))

	mockNotifier := notification.NewMockNotifier()
	service := NewAuthenticationService(
		engine,
		tokenService,
		nil,
		error_reporting.NewTestErrorReporter(engine),
		mockNotifier,
		testutil.DefaultConfigResolver(engine),
	)
	t.Cleanup(func() { service.Shutdown() })
	// Pre-wire the same provider production wiring produces (configureProviders() -> Default())
	// so handleProviderInconsistencies() doesn't reconfigure and clear the token before the
	// refresh/whoami path under test ever runs.
	service.SetProvider(Default(engine, service))

	result := service.IsAuthenticated()

	assert.False(t, result, "expired token with failing whoami/refresh must not report authenticated")
	assert.Greater(t, int(atomic.LoadInt32(&tokenEndpointHits)), 0,
		"expected the expired-token real-traffic path to attempt a token refresh against /oauth2/token")
	assert.Greater(t, int(atomic.LoadInt32(&selfEndpointHits)), 0,
		"expected the real whoami workflow to hit /rest/self")
	// IDE-2178's actual symptom is the stale token surviving in storage, not merely
	// IsAuthenticated() returning false for one call - assert the token was cleared.
	assert.Empty(t, conf.GetString(auth.CONFIG_KEY_OAUTH_TOKEN),
		"invalid_grant refresh failure must clear the stale token from storage, not just report not-authenticated")
}
