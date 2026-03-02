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

	"github.com/snyk/snyk-ls/application/config"
)

type AuthenticationService interface {
	// Authenticate attempts to authenticate the user using the given auth parameters, and sends a notification to the
	// client when successful. The auth provider is selected using the passed authMethod, and the endpoint and insecure
	// values are used for the auth flow, rather than reading from saved config.
	// Returns the token on success; the caller decides whether to persist it (e.g. the initializer stores it
	// immediately, while the login command waits for the IDE to send it back via didChangeConfiguration).
	Authenticate(ctx context.Context, authMethod string, endpoint string, insecure bool) (string, error)

	// Provider returns current authentication provider.
	Provider() AuthenticationProvider

	// provider returns current authentication provider.
	// doesn't have a mutex lock.
	provider() AuthenticationProvider

	// UpdateCredentials stores the token in the configuration, and sends a $/snyk.hasAuthenticated notification to the
	// client if sendNotification is true
	UpdateCredentials(newToken string, sendNotification bool, updateApiUrl bool)

	// updateCredentials stores the token in the configuration, and sends a $/snyk.hasAuthenticated notification to the
	// client if sendNotification is true
	// doesn't have a mutex lock
	updateCredentials(newToken string, sendNotification bool, updateApiUrl bool)

	Logout(ctx context.Context)

	// IsAuthenticated returns true if the token is verified
	IsAuthenticated() bool

	// SetProvider sets the authentication provider
	SetProvider(provider AuthenticationProvider)

	// ConfigureProviders updates the providers based on the stored configuration
	ConfigureProviders(c *config.Config)

	// AuthURL retrieves the authentication URL
	AuthURL(ctx context.Context) string

	// IsLoginInProgress returns true while an explicit login flow is running (as opposed to a token refresh).
	IsLoginInProgress() bool
}
