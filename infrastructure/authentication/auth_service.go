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
	// Authenticate attempts to authenticate the user, and sends a notification to the client when successful
	Authenticate(ctx context.Context) (string, error)

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
}
