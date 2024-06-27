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

	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/lsp"
)

const (
	ApiEnvVar                           = "SNYK_API"
	TokenEnvVar                         = "SNYK_TOKEN"
	DisableAnalyticsEnvVar              = "SNYK_CFG_DISABLE_ANALYTICS"
	IntegrationNameEnvVarKey            = "SNYK_INTEGRATION_NAME"
	IntegrationVersionEnvVarKey         = "SNYK_INTEGRATION_VERSION"
	IntegrationEnvironmentEnvVarKey     = "SNYK_INTEGRATION_ENVIRONMENT"
	IntegrationEnvironmentVersionEnvVar = "SNYK_INTEGRATION_ENVIRONMENT_VERSION"
	SnykOauthTokenEnvVar                = "SNYK_OAUTH_TOKEN"
)

// AppendCliEnvironmentVariables Returns the input array with additional variables used in the CLI run in the form of "key=value".
// Since we append, our values are overwriting existing env variables (because exec.Cmd.Env chooses the last value
// in case of key duplications).
// appendToken indicates whether we should append the token or not. No token should be appended in cases such as authentication.
func AppendCliEnvironmentVariables(currentEnv []string, appendToken bool) []string {
	var updatedEnv []string
	currentConfig := config.CurrentConfig()

	// remove any existing env vars that we are going to set
	valuesToRemove := map[string]bool{
		ApiEnvVar:                                true,
		TokenEnvVar:                              true,
		SnykOauthTokenEnvVar:                     true,
		DisableAnalyticsEnvVar:                   true,
		auth.CONFIG_KEY_OAUTH_TOKEN:              true,
		configuration.FF_OAUTH_AUTH_FLOW_ENABLED: true,
	}

	for _, s := range currentEnv {
		split := strings.Split(s, "=")
		if valuesToRemove[split[0]] {
			continue
		}
		updatedEnv = append(updatedEnv, s)
	}

	if appendToken {
		// there can only be one - highlander principle
		if currentConfig.AuthenticationMethod() == lsp.OAuthAuthentication {
			oAuthToken, err := currentConfig.TokenAsOAuthToken()
			if err == nil && len(oAuthToken.AccessToken) > 0 {
				updatedEnv = append(updatedEnv, SnykOauthTokenEnvVar+"="+oAuthToken.AccessToken)
			}
		} else {
			updatedEnv = append(updatedEnv, TokenEnvVar+"="+currentConfig.Token())
		}
	}
	if currentConfig.SnykApi() != "" {
		updatedEnv = append(updatedEnv, ApiEnvVar+"="+currentConfig.SnykApi())
	}
	if !currentConfig.IsTelemetryEnabled() || !currentConfig.IsAnalyticsPermitted() {
		updatedEnv = append(updatedEnv, DisableAnalyticsEnvVar+"=1")
	}

	if currentConfig.IntegrationName() != "" {
		updatedEnv = append(updatedEnv, IntegrationNameEnvVarKey+"="+currentConfig.IntegrationName())
		updatedEnv = append(updatedEnv, IntegrationVersionEnvVarKey+"="+currentConfig.IntegrationVersion())
		updatedEnv = append(updatedEnv, IntegrationEnvironmentEnvVarKey+"="+currentConfig.IdeName())
		updatedEnv = append(updatedEnv, IntegrationEnvironmentVersionEnvVar+"="+currentConfig.IdeVersion())
	}

	if currentConfig.Logger().GetLevel() == zerolog.TraceLevel {
		updatedEnv = append(updatedEnv, "SNYK_LOG_LEVEL=trace")
	}

	return updatedEnv
}
