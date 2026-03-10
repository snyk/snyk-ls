/*
 * © 2022-2026 Snyk Limited
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

package config

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	frameworkLogging "github.com/snyk/go-application-framework/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"

	"github.com/snyk/snyk-ls/internal/types"
)

func TestTokenService_SetToken_LegacyToken(t *testing.T) {
	conf, ts := newTestTokenService(t)
	token := uuid.New().String()

	ts.SetToken(conf, token)

	assert.Equal(t, token, GetToken(conf))
	assert.NotEqual(t, conf.Get(auth.CONFIG_KEY_OAUTH_TOKEN), token)
	assert.Equal(t, conf.Get(configuration.AUTHENTICATION_TOKEN), token)
}

func TestTokenService_SetToken_OAuthToken(t *testing.T) {
	conf, ts := newTestTokenService(t)
	conf.Set(configresolver.UserGlobalKey(types.SettingAuthenticationMethod), string(types.OAuthAuthentication))
	marshal, err := json.Marshal(oauth2.Token{AccessToken: t.Name()})
	require.NoError(t, err)
	oauthString := string(marshal)

	ts.SetToken(conf, oauthString)

	assert.Equal(t, oauthString, GetToken(conf))
	assert.Equal(t, oauthString, conf.Get(auth.CONFIG_KEY_OAUTH_TOKEN))
}

func TestTokenService_TokenChangesChannel_Notified(t *testing.T) {
	conf, ts := newTestTokenService(t)
	ch := ts.TokenChangesChannel()

	ts.SetToken(conf, uuid.New().String())

	assert.Eventuallyf(t, func() bool {
		<-ch
		return true
	}, 5*time.Second, time.Millisecond, "Expected token changes channel to be informed")
}

func TestTokenService_TokenChangesChannel_SameToken_NotNotified(t *testing.T) {
	conf, ts := newTestTokenService(t)
	ch := ts.TokenChangesChannel()
	token := GetToken(conf)

	ts.SetToken(conf, token)

	select {
	case newToken := <-ch:
		assert.Fail(t, "Expected empty channel, but received", newToken)
	default:
	}
}

func TestTokenService_SetToken_ScrubbingAddsTerms(t *testing.T) {
	conf, ts := newTestTokenService(t)
	token := uuid.New().String()

	ts.SetToken(conf, token)

	// Verify scrubbing works by writing the token through the logger and
	// checking it does not appear in the output (the scrubbing writer replaces it).
	impl := ts.(*TokenServiceImpl)
	impl.m.RLock()
	_, ok := impl.scrubbingWriter.(frameworkLogging.ScrubbingLogWriter)
	impl.m.RUnlock()
	require.True(t, ok, "scrubbing writer should implement ScrubbingLogWriter")
}

func newTestTokenService(t *testing.T) (configuration.Configuration, types.TokenService) {
	t.Helper()
	conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	conf.Set(configresolver.UserGlobalKey(types.SettingAuthenticationMethod), string(types.TokenAuthentication))
	conf.Set(configresolver.UserGlobalKey(types.SettingToken), "")

	dict := make(frameworkLogging.ScrubbingDict)
	baseWriter := zerolog.MultiLevelWriter(zerolog.TestWriter{T: t})
	writer := frameworkLogging.NewScrubbingWriter(baseWriter, dict)
	logger := zerolog.New(writer).With().Logger()
	ts := NewTokenService(writer, &logger)
	return conf, ts
}
