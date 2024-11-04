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

	config2 "github.com/snyk/snyk-ls/application/config"
)

var defaultExpiry = time.Now().Add(2 * time.Second)

type fakeOauthAuthenticator struct {
	calls       map[string][][]any
	m           sync.Mutex
	expiry      time.Time
	isSupported bool
	config      configuration.Configuration
	success     bool
}

func NewFakeOauthAuthenticator(tokenExpiry time.Time, isSupported bool, config configuration.Configuration, success bool) auth.Authenticator {
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

func (f *fakeOauthAuthenticator) Authenticate() error {
	f.addCall(nil, "Authenticate")
	if !f.success {
		return errors.New("fake auth error")
	}

	token := &oauth2.Token{AccessToken: "a", TokenType: "b", RefreshToken: "c", Expiry: f.expiry}

	tokenString, err := json.Marshal(token)
	if err != nil {
		return err
	}
	f.config.Set(auth.CONFIG_KEY_OAUTH_TOKEN, string(tokenString))
	return nil
}

func (f *fakeOauthAuthenticator) AddAuthenticationHeader(_ *http.Request) error {
	f.addCall(nil, "AddAuthenticationHeader")
	return nil
}
func (f *fakeOauthAuthenticator) IsSupported() bool {
	f.addCall(nil, "IsSupported")
	return f.isSupported
}

func TestAuthenticateUsesAuthenticator(t *testing.T) {
	config := configuration.New()
	authenticator := NewFakeOauthAuthenticator(defaultExpiry, true, config, true).(*fakeOauthAuthenticator)

	provider := newOAuthProvider(config, authenticator, config2.CurrentConfig().Logger())

	authToken, err := provider.Authenticate(context.Background())

	assert.NoError(t, err)
	assert.Len(t, authenticator.GetAllCalls("Authenticate"), 1)
	assert.Greater(t, len(authToken), 0, "empty token returned")
}

func TestAuthURL_ShouldReturnURL(t *testing.T) {
	config := configuration.New()
	authenticator := NewFakeOauthAuthenticator(time.Now().Add(10*time.Second), true, config, true).(*fakeOauthAuthenticator)
	provider := newOAuthProvider(config, authenticator, config2.CurrentConfig().Logger())
	provider.SetAuthURL("https://auth.fake.snyk.io")
	url := provider.AuthURL(context.Background())

	assert.NotEmpty(t, url)
	_, err := url2.Parse(url)
	assert.NoError(t, err)
}
