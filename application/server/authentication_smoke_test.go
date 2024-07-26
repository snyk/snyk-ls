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
	"os"
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
	srv, jsonRpcRecorder := setupServer(t)

	c := testutil.SmokeTest(t, false)
	c.SetSnykIacEnabled(false)
	c.SetSnykOssEnabled(true)
	di.Init()

	token := oauth2.Token{
		AccessToken:  "a",
		TokenType:    "bearer",
		RefreshToken: "c",
		Expiry:       time.Now().Add(-time.Hour),
	}

	tokenBytes, marshallingErr := json.Marshal(token)
	require.NoError(t, marshallingErr)

	clientParams := types.InitializeParams{
		WorkspaceFolders: []types.WorkspaceFolder{{Uri: uri.PathToUri(t.TempDir()), Name: t.Name()}},
		InitializationOptions: types.Settings{
			Endpoint:                    os.Getenv("SNYK_API"),
			Token:                       string(tokenBytes),
			EnableTrustedFoldersFeature: "false",
			FilterSeverity:              types.DefaultSeverityFilter(),
			AuthenticationMethod:        types.OAuthAuthentication,
			AutomaticAuthentication:     "false",
		},
	}

	lspClient := srv.Client

	_, err := lspClient.Call(context.Background(), "initialize", clientParams)
	require.NoError(t, err)
	_, err = lspClient.Call(context.Background(), "initialized", nil)
	require.NoError(t, err)

	assert.Eventuallyf(t, func() bool {
		callbacks := jsonRpcRecorder.Callbacks()
		for _, callback := range callbacks {
			if strings.Contains(callback.ParamString(), authentication.TokenExpirationMsg) {
				return true
			}
		}
		return false
	}, time.Second*5, time.Millisecond, "callback not received")
}
