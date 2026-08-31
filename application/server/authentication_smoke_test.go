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
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/internal/product"
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
		AccessToken:  "aaa",
		TokenType:    "bearer",
		RefreshToken: "ccc",
		Expiry:       expiry,
	}
	return token
}

func checkInvalidCredentialsMessageRequest(t *testing.T, expected string, tokenString string) {
	t.Helper()
	engine, tokenService := testutil.SmokeTestWithEngine(t, "", "SMOKE_SHARD_4")

	authProvider := &invalidAuthProvider{
		FakeAuthenticationProvider: &authentication.FakeAuthenticationProvider{
			Engine:          engine,
			IsAuthenticated: false,
		},
	}

	tokenService.SetToken(engine.GetConfiguration(), "")

	srv, jsonRpcRecorder, _ := setupServer(t, engine, tokenService, WithRealDI(), WithAuthProvider(authProvider))
	enableOnlyProducts(t, engine, product.ProductOpenSource)
	engine.GetConfiguration().Set(types.SettingIsLspInitialized, true)

	types.SetGlobalUser(engine.GetConfiguration(), types.SettingAuthenticationMethod, string(types.FakeAuthentication))
	tokenService.SetToken(engine.GetConfiguration(), tokenString)

	tempDir := t.TempDir()
	clientParams := types.InitializeParams{
		WorkspaceFolders: []types.WorkspaceFolder{{Uri: uri.PathToUri(types.FilePath(tempDir)), Name: t.Name()}},
		InitializationOptions: types.InitializationOptions{
			Settings: map[string]*types.ConfigSetting{
				types.SettingTrustEnabled:            {Value: false, Changed: true},
				types.SettingSeverityFilterCritical:  {Value: true, Changed: true},
				types.SettingSeverityFilterHigh:      {Value: true, Changed: true},
				types.SettingSeverityFilterMedium:    {Value: true, Changed: true},
				types.SettingSeverityFilterLow:       {Value: true, Changed: true},
				types.SettingAutomaticAuthentication: {Value: false, Changed: true},
			},
		},
	}

	lspClient := srv.Client
	jsonRpcRecorder.ClearCallbacks()

	_, err := lspClient.Call(t.Context(), "initialize", clientParams)
	require.NoError(t, err)
	_, err = lspClient.Call(t.Context(), "initialized", nil)
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

type invalidAuthProvider struct {
	*authentication.FakeAuthenticationProvider
}

func (p *invalidAuthProvider) GetCheckAuthenticationFunction() authentication.AuthenticationFunction {
	return func(_ workflow.Engine) (string, error) {
		return "", errors.New("failed to get active user: (status: 401)")
	}
}
