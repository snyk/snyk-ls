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

package html

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// GenerateSecurityNonce generates a cryptographically secure random nonce.
// A nonce is used in the web browser's Content Security Policy (CSP) to allow specific
// inline styles and scripts, helping to prevent Cross-Site Scripting (XSS) attacks.
func GenerateSecurityNonce() (string, error) {
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", fmt.Errorf("error generating nonce: %w", err)
	}
	return base64.StdEncoding.EncodeToString(nonceBytes), nil
}
