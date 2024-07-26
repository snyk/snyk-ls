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

package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

func Test_InvalidExpiredCredentialsSendMessageRequest(t *testing.T) {
	// how to process the expected callback
	token := getDummyOAuth2Token(time.Now().Add(-time.Hour))
	tokenBytes, marshallingErr := json.Marshal(token)
	require.NoError(t, marshallingErr)

	checkInvalidCredentialsMessageRequest(t, authentication.ExpirationMsg, string(tokenBytes))
}

func Test_InvalidCredentialsNotExpiredSendMessageRequest(t *testing.T) {
	token := getDummyOAuth2Token(time.Now().Add(+time.Hour))
	tokenBytes, marshallingErr := json.Marshal(token)
	require.NoError(t, marshallingErr)

	checkInvalidCredentialsMessageRequest(t, authentication.InvalidCredsMessage, string(tokenBytes))
}

func getDummyOAuth2Token(expiry time.Time) oauth2.Token {
	token := oauth2.Token{
		AccessToken:  "a",
		TokenType:    "bearer",
		RefreshToken: "c",
		Expiry:       expiry,
	}
	return token
}

func checkInvalidCredentialsMessageRequest(t *testing.T, expected string, tokenString string) {
	t.Helper()
	srv, jsonRpcRecorder := setupServer(t)

	c := testutil.SmokeTest(t, false)
	c.SetSnykIacEnabled(false)
	c.SetSnykOssEnabled(true)
	// we have to reset the token, as smoketest automatically grab it from env
	c.SetToken("")
	di.Init()

	clientParams := types.InitializeParams{
		WorkspaceFolders: []types.WorkspaceFolder{{Uri: uri.PathToUri(t.TempDir()), Name: t.Name()}},
		InitializationOptions: types.Settings{
			Token:                       tokenString,
			EnableTrustedFoldersFeature: "false",
			FilterSeverity:              types.DefaultSeverityFilter(),
			AuthenticationMethod:        types.OAuthAuthentication,
			AutomaticAuthentication:     "false",
		},
	}

	lspClient := srv.Client
	jsonRpcRecorder.ClearCallbacks()

	_, err := lspClient.Call(context.Background(), "initialize", clientParams)
	require.NoError(t, err)
	_, err = lspClient.Call(context.Background(), "initialized", nil)
	require.NoError(t, err)

	assert.Eventuallyf(t, func() bool {
		callbacks := jsonRpcRecorder.FindCallbacksByMethod("window/showMessageRequest")
		for _, callback := range callbacks {
			if strings.Contains(callback.ParamString(), expected) {
				return true
			} else {
				t.Error("wrong callback received", callback.ParamString())
			}
		}
		return false
	}, time.Second*5, time.Millisecond, "callback not received")
}
