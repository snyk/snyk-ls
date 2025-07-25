/*
 * © 2022-2024 Snyk Limited
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

package authentication

import (
	"context"
	"errors"

	"github.com/snyk/snyk-ls/internal/types"
)

type AuthenticationFailedError struct {
	ManualAuthentication bool
}

func (e *AuthenticationFailedError) Error() string {
	const authFailMessage = "Failed to authenticate with Snyk. Please make sure you have a valid token. "
	const autoAuthMessage = "You can reset the token to re-authenticate automatically."
	message := authFailMessage

	if !e.ManualAuthentication {
		message += autoAuthMessage
	}

	return message
}

type AuthenticationProvider interface {
	// Authenticate triggers the authentication. This may involve manual steps, like logging in using a browser
	Authenticate(ctx context.Context) (string, error)

	// ClearAuthentication removes all authentication information from the configuration
	ClearAuthentication(ctx context.Context) error

	// AuthURL returns the latest provided AuthenticationURL. This can be empty.
	AuthURL(ctx context.Context) string
	// SetAuthURL sets the latest provided Authentication URL. This is a temporary URL.
	setAuthUrl(url string)

	GetCheckAuthenticationFunction() AuthenticationFunction

	// AuthenticationMethod Returns the AuthenticationMethod associated with the provider
	AuthenticationMethod() types.AuthenticationMethod
}

var ErrEmptyAPIToken = errors.New("auth-provider: api token is not set")
