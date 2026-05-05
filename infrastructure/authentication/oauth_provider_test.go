/*
 * © 2023 Snyk Limited
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
	"errors"
	"net/http"
	url2 "net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

var defaultExpiry = time.Now().Add(2 * time.Second)

var _ auth.CancelableAuthenticator = (*fakeOauthAuthenticator)(nil)

type fakeOauthAuthenticator struct {
	calls       map[string][][]any
	m           sync.Mutex
	expiry      time.Time
	isSupported bool
	config      configuration.Configuration
	success     bool
	// When non-empty, fakeAuthenticate persists an oauth2.Token whose
	// AccessToken is this pre-built JWT-shaped string. WithJWTAud builds the
	// JWT eagerly via testutil.BuildJWTWithAud so this struct does not need
	// access to *testing.T inside Authenticate().
	jwtAccessToken string
	// When true, persist a non-JSON, non-JWT opaque token string (e.g. legacy
	// PAT-style) under CONFIG_KEY_OAUTH_TOKEN to exercise the
	// "decode failure -> no API URL discovery" path.
	opaqueToken bool
}

// WithJWTAud configures fakeAuthenticate to embed the given audience claim in
// the AccessToken of the persisted oauth2.Token. Pass a string for the
// single-aud JWT form (e.g. "api.eu.snyk.io") or a []string for the
// array-aud form (e.g. ["https://api.snyk.io"]). The JWT is built eagerly
// so a json.Marshal failure surfaces immediately on the calling test.
func (f *fakeOauthAuthenticator) WithJWTAud(tb testing.TB, aud any) *fakeOauthAuthenticator {
	tb.Helper()
	f.m.Lock()
	defer f.m.Unlock()
	f.jwtAccessToken = testutil.BuildJWTWithAud(tb, aud)
	f.opaqueToken = false
	return f
}

// WithOpaqueToken configures fakeAuthenticate to persist a non-JSON, non-JWT
// opaque token string under CONFIG_KEY_OAUTH_TOKEN, simulating legacy PAT-
// style credentials that GAF's GetAudienceClaimFromOauthToken cannot decode.
func (f *fakeOauthAuthenticator) WithOpaqueToken() *fakeOauthAuthenticator {
	f.m.Lock()
	defer f.m.Unlock()
	f.opaqueToken = true
	f.jwtAccessToken = ""
	return f
}

func NewFakeOauthAuthenticator(tokenExpiry time.Time, isSupported bool, config configuration.Configuration, success bool) *fakeOauthAuthenticator {
	return &fakeOauthAuthenticator{
		isSupported: isSupported,
		config:      config,
		expiry:      tokenExpiry,
		success:     success,
	}
}

func (f *fakeOauthAuthenticator) addCall(params []any, op string) {
	f.m.Lock()
	defer f.m.Unlock()
	if f.calls == nil {
		f.calls = make(map[string][][]any)
	}
	calls := f.calls[op]
	var opParams []any
	opParams = append(opParams, params...)
	f.calls[op] = append(calls, opParams)
}
func (f *fakeOauthAuthenticator) GetCallParams(callNo int, op string) []any {
	f.m.Lock()
	defer f.m.Unlock()
	calls := f.calls[op]
	if calls == nil {
		return nil
	}
	params := calls[callNo]
	if params == nil {
		return nil
	}
	return params
}
func (f *fakeOauthAuthenticator) GetAllCalls(op string) [][]any {
	f.m.Lock()
	defer f.m.Unlock()
	calls := f.calls[op]
	if calls == nil {
		return nil
	}
	return calls
}

func (f *fakeOauthAuthenticator) fakeAuthenticate() error {
	if !f.success {
		return errors.New("fake auth error")
	}

	f.m.Lock()
	opaque := f.opaqueToken
	jwtAccessToken := f.jwtAccessToken
	f.m.Unlock()

	if opaque {
		f.config.Set(auth.CONFIG_KEY_OAUTH_TOKEN, "opaque-pat-style-12345")
		return nil
	}

	accessToken := "aaa"
	if jwtAccessToken != "" {
		accessToken = jwtAccessToken
	}

	token := &oauth2.Token{AccessToken: accessToken, TokenType: "bbb", RefreshToken: "ccc", Expiry: f.expiry}

	tokenString, err := json.Marshal(token)
	if err != nil {
		return err
	}
	f.config.Set(auth.CONFIG_KEY_OAUTH_TOKEN, string(tokenString))
	return nil
}

func (f *fakeOauthAuthenticator) Authenticate() error {
	f.addCall(nil, "Authenticate")
	return f.fakeAuthenticate()
}

func (f *fakeOauthAuthenticator) CancelableAuthenticate(_ context.Context) error {
	f.addCall(nil, "CancelableAuthenticate")
	return f.fakeAuthenticate()
}

func (f *fakeOauthAuthenticator) AddAuthenticationHeader(_ *http.Request) error {
	f.addCall(nil, "AddAuthenticationHeader")
	return nil
}
func (f *fakeOauthAuthenticator) IsSupported() bool {
	f.addCall(nil, "IsSupported")
	return f.isSupported
}

func TestOAuth2Provider_AuthenticationMethod(t *testing.T) {
	p := &OAuth2Provider{}
	assert.Equal(t, types.OAuthAuthentication, p.AuthenticationMethod())
}

func TestAuthenticateUsesAuthenticator(t *testing.T) {
	engine := testutil.UnitTest(t)
	config := engine.GetConfiguration()
	authenticator := NewFakeOauthAuthenticator(defaultExpiry, true, config, true)

	provider := newOAuthProvider(config, authenticator, engine.GetLogger())

	authToken, err := provider.Authenticate(t.Context())

	assert.NoError(t, err)
	assert.Len(t, authenticator.GetAllCalls("CancelableAuthenticate"), 1)
	assert.Greater(t, len(authToken), 0, "empty token returned")
}

func TestAuthURL_ShouldReturnURL(t *testing.T) {
	engine := testutil.UnitTest(t)
	config := engine.GetConfiguration()
	authenticator := NewFakeOauthAuthenticator(time.Now().Add(10*time.Second), true, config, true)
	provider := newOAuthProvider(config, authenticator, engine.GetLogger())
	provider.setAuthUrl("https://auth.fake.snyk.io")
	url := provider.AuthURL(t.Context())

	assert.NotEmpty(t, url)
	_, err := url2.Parse(url)
	assert.NoError(t, err)
}
