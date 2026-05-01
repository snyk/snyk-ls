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

package testutil

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// BuildJWTWithAud returns a header.payload.signature string whose payload
// base64url-encodes {"aud": <aud>}. aud may be a string, []string, or nil
// (yields a "aud":null payload). The signature segment is a stub — JWT
// helpers in this codebase rely on aud-claim parsing only, not on signature
// verification.
//
// On json.Marshal failure (e.g. unmarshalable types like channels), the
// helper fails the supplied test loudly via t.Fatalf so callers do not
// silently propagate empty payloads into the system under test.
func BuildJWTWithAud(tb testing.TB, aud any) string {
	tb.Helper()
	const header = `{"alg":"HS256","typ":"JWT"}`
	payloadBytes, err := json.Marshal(map[string]any{"aud": aud})
	if err != nil {
		tb.Fatalf("BuildJWTWithAud: failed to marshal aud claim: %v", err)
		return ""
	}
	h := base64.RawURLEncoding.EncodeToString([]byte(header))
	p := base64.RawURLEncoding.EncodeToString(payloadBytes)
	return h + "." + p + ".sig"
}

// OauthTokenJSONWithAud wraps a JWT-shaped access token (built by
// BuildJWTWithAud) in the oauth2.Token-as-JSON envelope that snyk-ls'
// OAuth2Provider.Authenticate persists in production. The returned string
// is suitable as the input to extractAudHost or as the TokenToReturn of a
// FakeAuthenticationProvider.
//
// audClaim follows the same semantics as BuildJWTWithAud's aud parameter:
// pass a string for the single-aud JWT form (e.g. "api.eu.snyk.io"), a
// []string for the array-aud form, or nil to emit an "aud":null payload.
func OauthTokenJSONWithAud(tb testing.TB, audClaim any) string {
	tb.Helper()
	tok := &oauth2.Token{
		AccessToken: BuildJWTWithAud(tb, audClaim),
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Hour),
	}
	b, err := json.Marshal(tok)
	if err != nil {
		tb.Fatalf("OauthTokenJSONWithAud: failed to marshal oauth2.Token: %v", err)
		return ""
	}
	return string(b)
}
