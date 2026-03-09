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

package types

import "github.com/snyk/go-application-framework/pkg/configuration"

// TokenService manages authentication token lifecycle: writing tokens to
// configuration, adding scrub terms to the logger, and notifying listeners
// when the token changes.
type TokenService interface {
	// SetToken writes newToken to conf, adds scrub terms for the token (and
	// embedded OAuth fields), and notifies all TokenChangesChannel listeners
	// when the token value actually changed.
	SetToken(conf configuration.Configuration, newToken string)

	// TokenChangesChannel returns a channel that receives the new token string
	// whenever SetToken detects a change. Each call returns a fresh channel.
	TokenChangesChannel() <-chan string
}
