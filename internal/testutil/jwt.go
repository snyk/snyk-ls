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
func BuildJWTWithAud(t testing.TB, aud any) string {
	t.Helper()
	const header = `{"alg":"HS256","typ":"JWT"}`
	payloadBytes, err := json.Marshal(map[string]any{"aud": aud})
	if err != nil {
		t.Fatalf("BuildJWTWithAud: failed to marshal aud claim: %v", err)
		return ""
	}
	h := base64.RawURLEncoding.EncodeToString([]byte(header))
	p := base64.RawURLEncoding.EncodeToString(payloadBytes)
	return h + "." + p + ".sig"
}
