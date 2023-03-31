/*
 * © 2022 Snyk Limited All rights reserved.
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

package cli

import (
	"strings"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/lsp"
)

const (
	OrganizationEnvVar                  = "SNYK_CFG_ORG"
	ApiEnvVar                           = "SNYK_API"
	TokenEnvVar                         = "SNYK_TOKEN"
	DisableAnalyticsEnvVar              = "SNYK_CFG_DISABLE_ANALYTICS"
	IntegrationNameEnvVarKey            = "SNYK_INTEGRATION_NAME"
	IntegrationVersionEnvVarKey         = "SNYK_INTEGRATION_VERSION"
	IntegrationEnvironmentEnvVarKey     = "SNYK_INTEGRATION_ENVIRONMENT"
	IntegrationEnvironmentVersionEnvVar = "SNYK_INTEGRATION_ENVIRONMENT_VERSION"
	IntegrationEnvironmentEnvVarValue   = "language-server"
)

// Returns the input array with additional variables used in the CLI run in the form of "key=value".
// Since we append, our values are overwriting existing env variables (because exec.Cmd.Env chooses the last value
// in case of key duplications).
// appendToken indicates whether we should append the token or not. No token should be appended in cases such as authentication.
func AppendCliEnvironmentVariables(currentEnv []string, appendToken bool) (updatedEnv []string) {
	updatedEnv = currentEnv

	currentConfig := config.CurrentConfig()
	organization := currentConfig.GetOrganization()
	if organization != "" {
		updatedEnv = append(updatedEnv, OrganizationEnvVar+"="+organization)
	}

	if appendToken {
		// there can only be one - highlander principle
		if currentConfig.GetAuthenticationMethod() == lsp.OAuthAuthentication {
			updatedEnv = append(updatedEnv, auth.CONFIG_KEY_OAUTH_TOKEN+"="+currentConfig.Token())
			updatedEnv = append(updatedEnv, strings.ToUpper(configuration.FF_OAUTH_AUTH_FLOW_ENABLED+"=1"))
		} else {
			updatedEnv = append(updatedEnv, TokenEnvVar+"="+currentConfig.Token())
		}
	}
	if currentConfig.SnykApi() != "" {
		updatedEnv = append(updatedEnv, ApiEnvVar+"="+currentConfig.SnykApi())
	}
	if !currentConfig.IsTelemetryEnabled() {
		updatedEnv = append(updatedEnv, DisableAnalyticsEnvVar+"=1")
	}

	if currentConfig.IntegrationName() != "" {
		updatedEnv = append(updatedEnv, IntegrationNameEnvVarKey+"="+currentConfig.IntegrationName())
		updatedEnv = append(updatedEnv, IntegrationVersionEnvVarKey+"="+currentConfig.IntegrationVersion())
	}
	updatedEnv = append(updatedEnv, IntegrationEnvironmentEnvVarKey+"="+IntegrationEnvironmentEnvVarValue)
	updatedEnv = append(updatedEnv, IntegrationEnvironmentVersionEnvVar+"="+config.Version)
	return
}
