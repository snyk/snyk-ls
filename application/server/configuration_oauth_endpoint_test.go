/*
 * © 2026 Snyk Limited
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

package server

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// Integration tests for the OAuth-token-aud-driven API URL discovery flow.
// These exercise the public AuthenticationService.Authenticate path wired
// through the production DI container (so the same notifier, configResolver
// and engine that the LSP server uses in production are involved). The aud
// claim is fed in via FakeAuthenticationProvider.TokenToReturn — a JSON-
// marshaled oauth2.Token whose AccessToken is a JWT-shaped string carrying
// the aud claim — which AuthenticationServiceImpl.authenticate then decodes
// via extractAudUrl.

// buildJWTWithAud returns a header.payload.signature string whose payload
// base64url-encodes {"aud": <aud>}. aud may be a string for the single-aud
// JWT form or a []string for the array-aud form. The signature segment is a
// stub since GAF's GetAudienceClaimFromOauthToken does not verify it.
func buildJWTWithAud(aud any) string {
	const header = `{"alg":"HS256","typ":"JWT"}`
	payload, _ := json.Marshal(map[string]any{"aud": aud})
	h := base64.RawURLEncoding.EncodeToString([]byte(header))
	p := base64.RawURLEncoding.EncodeToString(payload)
	return h + "." + p + ".sig"
}

// oauthTokenJSONWithAud wraps a JWT-shaped access token in the
// oauth2.Token-as-JSON envelope that snyk-ls' OAuth2Provider.Authenticate
// would persist in production.
func oauthTokenJSONWithAud(t *testing.T, aud any) string {
	t.Helper()
	tok := &oauth2.Token{
		AccessToken: buildJWTWithAud(aud),
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Hour),
	}
	b, err := json.Marshal(tok)
	require.NoError(t, err)
	return string(b)
}

// oauthEndpointNotifications is a thread-safe collector for notifications
// emitted on di.Notifier() during an Authenticate call.
type oauthEndpointNotifications struct {
	mu                   sync.Mutex
	authParams           []types.AuthenticationParams
	endpointUpdateCount  int
	endpointUpdateLast   string
	allShowMessageParams []sglsp.ShowMessageParams
}

func (c *oauthEndpointNotifications) record(p any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch v := p.(type) {
	case types.AuthenticationParams:
		c.authParams = append(c.authParams, v)
	case sglsp.ShowMessageParams:
		c.allShowMessageParams = append(c.allShowMessageParams, v)
		if v.Type == sglsp.Info && strings.Contains(v.Message, "The Snyk API Endpoint has been updated to ") {
			c.endpointUpdateCount++
			c.endpointUpdateLast = v.Message
		}
	}
}

// oauthEndpointSnapshot is the immutable view returned by snapshot(). It
// avoids dogsled lints in tests that only care about a subset of fields.
type oauthEndpointSnapshot struct {
	authParams      []types.AuthenticationParams
	updateMsgs      int
	lastUpdate      string
	allShowMessages []sglsp.ShowMessageParams
}

func (c *oauthEndpointNotifications) snapshot() oauthEndpointSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return oauthEndpointSnapshot{
		authParams:      append([]types.AuthenticationParams(nil), c.authParams...),
		updateMsgs:      c.endpointUpdateCount,
		lastUpdate:      c.endpointUpdateLast,
		allShowMessages: append([]sglsp.ShowMessageParams(nil), c.allShowMessageParams...),
	}
}

// setupOAuthEndpointTest boots the standard test DI container, attaches a
// notifier listener that captures notifications into the returned collector,
// swaps the authentication provider to a FakeAuthenticationProvider that
// returns the supplied (already-marshaled oauth2.Token) JSON string from
// Authenticate(), and seeds the user's customUrl via UpdateApiEndpointsOnConfig.
func setupOAuthEndpointTest(t *testing.T, customUrl string, tokenToReturn string) (*oauthEndpointNotifications, *authentication.FakeAuthenticationProvider) {
	t.Helper()

	engine, tokenService := testutil.UnitTestWithEngine(t)
	di.TestInit(t, engine, tokenService)
	conf := engine.GetConfiguration()

	conf.Set(configresolver.UserGlobalKey(types.SettingAuthenticationMethod), string(types.FakeAuthentication))

	require.True(t, config.UpdateApiEndpointsOnConfig(conf, customUrl), "seed customUrl precondition")

	notes := &oauthEndpointNotifications{}
	di.Notifier().CreateListener(notes.record)
	t.Cleanup(func() { di.Notifier().DisposeListener() })

	provider := &authentication.FakeAuthenticationProvider{
		Engine:        engine,
		TokenToReturn: tokenToReturn,
	}
	di.AuthenticationService().SetProvider(provider)

	return notes, provider
}

// When the freshly-issued OAuth token's `aud` claim differs from the
// configured custom endpoint, the discovery branch wins: SettingApiEndpoint,
// configuration.API_URL and configuration.WEB_APP_URL all reflect the
// aud-derived host, exactly one $/snyk.hasAuthenticated notification is
// emitted with ApiUrl=<new endpoint>, and exactly one
// "API Endpoint has been updated" Info window/showMessage is sent.
func Test_OAuthCallback_TokenAudDiffersFromConfigured_UpdatesEndpoint(t *testing.T) {
	notes, _ := setupOAuthEndpointTest(t, "https://api.eu.snyk.io", oauthTokenJSONWithAud(t, "https://api.snyk.io"))
	conf := di.AuthenticationService().Provider().(*authentication.FakeAuthenticationProvider).Engine.GetConfiguration()

	token, err := di.AuthenticationService().Authenticate(t.Context())
	require.NoError(t, err)
	require.NotEmpty(t, token)

	assert.Equal(t, "https://api.snyk.io", conf.GetString(configresolver.UserGlobalKey(types.SettingApiEndpoint)))
	assert.Equal(t, "https://api.snyk.io", conf.GetString(configuration.API_URL))
	assert.Equal(t, "https://app.snyk.io", conf.GetString(configuration.WEB_APP_URL))

	require.Eventually(t, func() bool {
		s := notes.snapshot()
		return len(s.authParams) >= 1 && s.updateMsgs >= 1
	}, 2*time.Second, 5*time.Millisecond, "notifier did not deliver expected events")

	s := notes.snapshot()
	assert.Len(t, s.authParams, 1, "exactly one $/snyk.hasAuthenticated must be sent")
	assert.Equal(t, "https://api.snyk.io", s.authParams[0].ApiUrl)
	assert.Equal(t, token, s.authParams[0].Token)
	assert.Equal(t, 1, s.updateMsgs, "exactly one endpoint-update Info notification must be sent")
	assert.Contains(t, s.lastUpdate, "https://api.snyk.io")
}

// When aud matches the configured endpoint the discovery branch is a no-op —
// no endpoint mutation, no endpoint-update message.
func Test_OAuthCallback_TokenAudMatchesConfigured_NoOp(t *testing.T) {
	notes, _ := setupOAuthEndpointTest(t, "https://api.eu.snyk.io", oauthTokenJSONWithAud(t, "https://api.eu.snyk.io"))
	conf := di.AuthenticationService().Provider().(*authentication.FakeAuthenticationProvider).Engine.GetConfiguration()

	_, err := di.AuthenticationService().Authenticate(t.Context())
	require.NoError(t, err)

	assert.Equal(t, "https://api.eu.snyk.io", conf.GetString(configresolver.UserGlobalKey(types.SettingApiEndpoint)))
	assert.Equal(t, "https://api.eu.snyk.io", conf.GetString(configuration.API_URL))

	require.Eventually(t, func() bool {
		return len(notes.snapshot().authParams) >= 1
	}, 2*time.Second, 5*time.Millisecond, "auth notification did not arrive")

	s := notes.snapshot()
	require.Len(t, s.authParams, 1)
	assert.Empty(t, s.authParams[0].ApiUrl, "AuthenticationParams.ApiUrl must be empty when aud matches customUrl")
	assert.Equal(t, 0, s.updateMsgs, "no endpoint-update notification must be sent when aud matches")
}

// After the discovery branch corrects the endpoint, the deeproxy URL derived
// from the new custom endpoint must resolve to the global deeproxy host. This
// confirms there is no stale cache between Authenticate and the next Snyk
// Code scan.
func Test_OAuthCallback_DifferentInstance_RecomputesDeeproxy(t *testing.T) {
	notes, provider := setupOAuthEndpointTest(t, "https://api.eu.snyk.io", oauthTokenJSONWithAud(t, "https://api.snyk.io"))
	conf := provider.Engine.GetConfiguration()
	logger := provider.Engine.GetLogger()

	_, err := di.AuthenticationService().Authenticate(t.Context())
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return notes.snapshot().updateMsgs >= 1
	}, 2*time.Second, 5*time.Millisecond, "endpoint-update notification did not arrive")

	codeUrl, err := config.GetCodeApiUrlFromCustomEndpoint(conf, nil, logger)
	require.NoError(t, err)
	assert.Equal(t, "https://deeproxy.snyk.io", codeUrl,
		"deeproxy must be re-derived from the aud-corrected api endpoint, not from the pre-auth EU endpoint")
}

// AuthenticationParams emitted to the IDE plugin must carry the aud-derived
// ApiUrl exactly so the IDE persists the corrected value.
func Test_OAuthCallback_DifferentInstance_AuthenticationParamsCarryNewUrl(t *testing.T) {
	notes, _ := setupOAuthEndpointTest(t, "https://api.eu.snyk.io", oauthTokenJSONWithAud(t, "https://api.snyk.io"))

	token, err := di.AuthenticationService().Authenticate(t.Context())
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return len(notes.snapshot().authParams) >= 1
	}, 2*time.Second, 5*time.Millisecond)

	s := notes.snapshot()
	require.Len(t, s.authParams, 1)
	assert.Equal(t, "https://api.snyk.io", s.authParams[0].ApiUrl)
	assert.Equal(t, token, s.authParams[0].Token)
}

// After the discovery branch has corrected the endpoint to https://api.snyk.io,
// an IDE round-trip pushing the same value back via command.ApplyEndpointChange
// (the path applyApiEndpoints uses) must be a no-op: ApplyEndpointChange
// returns false, ClearAuthentication is NOT called as a logout side effect,
// and no second endpoint-update notification is sent.
func Test_DidChangeConfiguration_AfterAuth_PersistsCorrectedEndpoint(t *testing.T) {
	notes, provider := setupOAuthEndpointTest(t, "https://api.eu.snyk.io", oauthTokenJSONWithAud(t, "https://api.snyk.io"))
	conf := provider.Engine.GetConfiguration()

	_, err := di.AuthenticationService().Authenticate(t.Context())
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return notes.snapshot().updateMsgs >= 1
	}, 2*time.Second, 5*time.Millisecond)

	// Simulate the IDE pushing back the corrected endpoint via
	// DidChangeConfiguration → applyApiEndpoints → ApplyEndpointChange.
	provider.ClearAuthenticationCalled = false
	changed := command.ApplyEndpointChange(t.Context(), conf, di.AuthenticationService(), "https://api.snyk.io")
	assert.False(t, changed, "pushing back the same corrected endpoint must be a no-op")
	assert.False(t, provider.ClearAuthenticationCalled, "no logout side effect when the endpoint did not change")

	// Allow any stray notifications to drain. Only the original update must
	// have been emitted.
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 1, notes.snapshot().updateMsgs, "no second endpoint-update notification must be sent on the no-op IDE round-trip")
}

// When the new OAuth token's `aud` names a host that fails the GAF
// allowed-host regex (e.g. attacker-controlled host), the discovery branch
// must NOT fire — the user-facing SettingApiEndpoint is preserved and no
// endpoint-update notification is sent. (configuration.API_URL is owned by
// GAF's defaultFuncApiUrl callback, which re-derives it from the persisted
// access token regardless of snyk-ls validation; we therefore pin snyk-ls
// behavior on SettingApiEndpoint and the absence of the snyk-ls-emitted
// update message.)
func Test_OAuthCallback_TokenAudInvalidHost_NoOp(t *testing.T) {
	notes, provider := setupOAuthEndpointTest(t, "https://api.eu.snyk.io", oauthTokenJSONWithAud(t, "https://api.malicious.io"))
	conf := provider.Engine.GetConfiguration()

	_, err := di.AuthenticationService().Authenticate(t.Context())
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return len(notes.snapshot().authParams) >= 1
	}, 2*time.Second, 5*time.Millisecond)

	assert.Equal(t, "https://api.eu.snyk.io",
		conf.GetString(configresolver.UserGlobalKey(types.SettingApiEndpoint)),
		"user-facing SettingApiEndpoint must be preserved when aud is rejected")

	s := notes.snapshot()
	require.Len(t, s.authParams, 1)
	assert.Empty(t, s.authParams[0].ApiUrl, "AuthenticationParams.ApiUrl must be empty when aud is rejected")
	assert.Equal(t, 0, s.updateMsgs, "no endpoint-update notification must be sent for rejected hosts")
}

// Legacy / opaque (non-JWT) credentials (e.g. PAT-style) cannot be decoded by
// GAF's GetAudienceClaimFromOauthToken. The discovery branch must degrade
// gracefully: no endpoint mutation, no endpoint-update notification,
// AuthenticationParams.ApiUrl empty.
func Test_OAuthCallback_OpaqueToken_NoOp(t *testing.T) {
	notes, provider := setupOAuthEndpointTest(t, "https://api.eu.snyk.io", "opaque-pat-style-12345")
	conf := provider.Engine.GetConfiguration()

	_, err := di.AuthenticationService().Authenticate(t.Context())
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return len(notes.snapshot().authParams) >= 1
	}, 2*time.Second, 5*time.Millisecond)

	assert.Equal(t, "https://api.eu.snyk.io",
		conf.GetString(configresolver.UserGlobalKey(types.SettingApiEndpoint)),
		"opaque token must not mutate the user-facing endpoint")

	s := notes.snapshot()
	require.Len(t, s.authParams, 1)
	assert.Empty(t, s.authParams[0].ApiUrl)
	assert.Equal(t, 0, s.updateMsgs, "no endpoint-update notification must be sent for opaque tokens")
}
