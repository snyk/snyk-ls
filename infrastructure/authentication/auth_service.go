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

// AuthenticateResult holds the outcome of a successful authentication flow.
// Callers decide whether and how to persist the result (e.g. the initializer stores it immediately,
// while the login command returns it to the IDE and waits for didChangeConfiguration).
type AuthenticateResult struct {
	// Token is the authentication token (OAuth2 JSON, API token, or PAT).
	Token string
	// ApiUrl is the API URL derived from the new token's audience claim (OAuth) or the passed-in endpoint (other flows).
	ApiUrl string
}

type AuthenticationService interface {
	// Authenticate runs the auth flow using the given parameters and returns the result without modifying any
	// shared state. The auth provider is selected using the passed authMethod, and the endpoint and insecure
	// values are used for the auth flow, rather than reading from saved config.
	// No config keys are written, no notifications are sent — callers decide what to do with the result.
	Authenticate(ctx context.Context, authMethod string, endpoint string, insecure bool) (AuthenticateResult, error)

	// Provider returns current authentication provider.
	Provider() AuthenticationProvider

	// provider returns current authentication provider.
	// doesn't have a mutex lock.
	provider() AuthenticationProvider

	// UpdateCredentials stores the token in the configuration, and sends a $/snyk.hasAuthenticated notification to the
	// client if sendNotification is true. persist is forwarded in the notification payload.
	UpdateCredentials(newToken string, sendNotification bool, persist bool)

	// updateCredentials stores the token in the configuration, and sends a $/snyk.hasAuthenticated notification to the
	// client if sendNotification is true. persist is forwarded in the notification payload.
	// doesn't have a mutex lock
	updateCredentials(newToken string, sendNotification bool, persist bool)

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
