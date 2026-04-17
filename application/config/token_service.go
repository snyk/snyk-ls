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
	"sync"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	frameworkLogging "github.com/snyk/go-application-framework/pkg/logging"

	"github.com/snyk/snyk-ls/internal/types"
)

var _ types.TokenService = (*TokenServiceImpl)(nil)

// TokenServiceImpl manages token lifecycle: writing tokens to the GAF
// configuration, scrubbing sensitive token data from logs, and notifying
// listeners when the token changes.
type TokenServiceImpl struct {
	scrubbingWriter     zerolog.LevelWriter
	tokenChangeChannels []chan string
	logger              *zerolog.Logger
	m                   sync.RWMutex
}

func NewTokenService(scrubbingWriter zerolog.LevelWriter, logger *zerolog.Logger) types.TokenService {
	return &TokenServiceImpl{
		scrubbingWriter: scrubbingWriter,
		logger:          logger,
	}
}

func (ts *TokenServiceImpl) SetToken(conf configuration.Configuration, newTokenString string) {
	ts.m.Lock()
	defer ts.m.Unlock()

	oldTokenString := WriteTokenToConfig(conf, GetAuthenticationMethodFromConfig(conf), newTokenString, ts.logger)

	newOAuthToken, _ := getAsOauthToken(newTokenString, ts.logger)
	if w, ok := ts.scrubbingWriter.(frameworkLogging.ScrubbingLogWriter); ok {
		if newTokenString != "" {
			w.AddTerm(newTokenString, 0)
			if newOAuthToken != nil && newOAuthToken.AccessToken != "" {
				w.AddTerm(newOAuthToken.AccessToken, 0)
				w.AddTerm(newOAuthToken.RefreshToken, 0)
			}
		}
	}

	ts.notifyTokenChannelListeners(newTokenString, oldTokenString)
}

func (ts *TokenServiceImpl) TokenChangesChannel() <-chan string {
	ts.m.Lock()
	defer ts.m.Unlock()

	channel := make(chan string, 1)
	ts.tokenChangeChannels = append(ts.tokenChangeChannels, channel)
	return channel
}

// SetScrubbingWriter replaces the scrubbing writer used for adding token scrub
// terms. Called by ConfigureLogging when the logger is reconfigured.
func (ts *TokenServiceImpl) SetScrubbingWriter(w zerolog.LevelWriter) {
	ts.m.Lock()
	defer ts.m.Unlock()
	ts.scrubbingWriter = w
}

// SetLogger replaces the logger used for token operations.
func (ts *TokenServiceImpl) SetLogger(logger *zerolog.Logger) {
	ts.m.Lock()
	defer ts.m.Unlock()
	ts.logger = logger
}

func (ts *TokenServiceImpl) notifyTokenChannelListeners(newTokenString string, oldTokenString string) {
	if oldTokenString != newTokenString {
		for _, channel := range ts.tokenChangeChannels {
			select {
			case channel <- newTokenString:
			default:
				ts.logger.Warn().Msg("Cannot send cancellation to channel - channel is full")
			}
		}
		ts.tokenChangeChannels = []chan string{}
	}
}
