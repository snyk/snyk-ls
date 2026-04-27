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
)

// BuildJWTWithAud returns a header.payload.signature string whose payload
// base64url-encodes {"aud": <aud>}. aud may be a string, []string, or nil
// (yields a "aud":null payload). The signature segment is a stub — JWT
// helpers in this codebase rely on aud-claim parsing only, not on signature
// verification.
func BuildJWTWithAud(aud any) string {
	const header = `{"alg":"HS256","typ":"JWT"}`
	payloadBytes, _ := json.Marshal(map[string]any{"aud": aud})
	h := base64.RawURLEncoding.EncodeToString([]byte(header))
	p := base64.RawURLEncoding.EncodeToString(payloadBytes)
	return h + "." + p + ".sig"
}
