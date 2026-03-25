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

package command

import (
	"context"

	gafConfig "github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/internal/types"
)

// ApplyEndpointChange updates API endpoints. If changed and LSP is initialized,
// logs out and clears workspace. Returns true if endpoints changed.
// Logout internally calls configureProviders, so no explicit ConfigureProviders call is needed.
func ApplyEndpointChange(ctx context.Context, c *config.Config, authService authentication.AuthenticationService, endpoint string) bool {
	changed := c.UpdateApiEndpoints(endpoint)
	if changed && c.IsLSPInitialized() {
		authService.Logout(ctx)
		c.Workspace().Clear()
	}
	return changed
}

// ApplyInsecureSetting updates the INSECURE_HTTPS engine config flag.
func ApplyInsecureSetting(c *config.Config, insecure bool) {
	c.Engine().GetConfiguration().Set(gafConfig.INSECURE_HTTPS, insecure)
}

// ApplyAuthMethodChange sets the auth method and calls ConfigureProviders.
// Returns true if the method actually changed.
func ApplyAuthMethodChange(ctx context.Context, c *config.Config, authService authentication.AuthenticationService, authMethod types.AuthenticationMethod) bool {
	if authMethod == types.EmptyAuthenticationMethod {
		return false
	}

	previousMethod := c.AuthenticationMethod()
	c.SetAuthenticationMethod(authMethod)
	authService.ConfigureProviders(c)

	return authMethod != previousMethod
}
