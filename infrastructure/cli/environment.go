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
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/types"
)

var (
	ApiEnvVar                           = strings.ToUpper(configuration.API_URL)
	TokenEnvVar                         = strings.ToUpper(configuration.AUTHENTICATION_TOKEN)
	DisableAnalyticsEnvVar              = strings.ToUpper(configuration.ANALYTICS_DISABLED)
	SnykOauthTokenEnvVar                = strings.ToUpper(configuration.AUTHENTICATION_BEARER_TOKEN)
	OAuthEnabledEnvVar                  = strings.ToUpper(configuration.FF_OAUTH_AUTH_FLOW_ENABLED)
	IntegrationNameEnvVarKey            = "SNYK_INTEGRATION_NAME"
	IntegrationVersionEnvVarKey         = "SNYK_INTEGRATION_VERSION"
	IntegrationEnvironmentEnvVarKey     = "SNYK_INTEGRATION_ENVIRONMENT"
	IntegrationEnvironmentVersionEnvVar = "SNYK_INTEGRATION_ENVIRONMENT_VERSION"
)

// AppendCliEnvironmentVariables Returns the input array with additional variables used in the CLI run in the form of "key=value".
// Since we append, our values are overwriting existing env variables (because exec.Cmd.Env chooses the last value
// in case of key duplications).
// appendToken indicates whether we should append the token or not. No token should be appended in cases such as authentication.
func AppendCliEnvironmentVariables(engine workflow.Engine, currentEnv []string, appendToken bool) []string {
	var updatedEnv []string
	logger := engine.GetLogger().With().Str("method", "AppendCliEnvironmentVariables").Logger()

	// remove any existing env vars that we are going to set
	valuesToRemove := map[string]bool{
		ApiEnvVar:                   true,
		TokenEnvVar:                 true,
		SnykOauthTokenEnvVar:        true,
		DisableAnalyticsEnvVar:      true,
		auth.CONFIG_KEY_OAUTH_TOKEN: true,
		OAuthEnabledEnvVar:          true,
	}

	for _, s := range currentEnv {
		split := strings.Split(s, "=")
		if valuesToRemove[split[0]] {
			continue
		}
		updatedEnv = append(updatedEnv, s)
	}

	conf := engine.GetConfiguration()
	if appendToken && config.GetToken(conf) != "" {
		if config.GetAuthenticationMethodFromConfig(conf) == types.OAuthAuthentication {
			logger.Debug().Msg("using oauth2 authentication")
			oAuthToken, err := config.ParseOAuthToken(config.GetToken(conf), engine.GetLogger())
			if err != nil {
				logger.Err(err).Msg("trying to add OAuth2 creds to CLI call and the token cannot be unmarshalled. This should never happen.")
			}
			updatedEnv = append(updatedEnv, SnykOauthTokenEnvVar+"="+oAuthToken.AccessToken)
			updatedEnv = append(updatedEnv, OAuthEnabledEnvVar+"=1")
		} else {
			logger.Debug().Msg("falling back to API key authentication")
			updatedEnv = append(updatedEnv, TokenEnvVar+"="+config.GetToken(conf))
			updatedEnv = append(updatedEnv, OAuthEnabledEnvVar+"=0")
		}
	}

	snykApi := engine.GetConfiguration().GetString(configuration.UserGlobalKey(types.SettingApiEndpoint))
	if snykApi != "" {
		logger.Debug().Msgf("adding endpoint: %s", snykApi)
		updatedEnv = append(updatedEnv, ApiEnvVar+"="+snykApi)
	}

	if conf.GetString(configuration.INTEGRATION_NAME) != "" {
		updatedEnv = append(updatedEnv, IntegrationNameEnvVarKey+"="+conf.GetString(configuration.INTEGRATION_NAME))
		updatedEnv = append(updatedEnv, IntegrationVersionEnvVarKey+"="+conf.GetString(configuration.INTEGRATION_VERSION))
		updatedEnv = append(updatedEnv, IntegrationEnvironmentEnvVarKey+"="+conf.GetString(configuration.INTEGRATION_ENVIRONMENT))
		updatedEnv = append(updatedEnv, IntegrationEnvironmentVersionEnvVar+"="+conf.GetString(configuration.INTEGRATION_ENVIRONMENT_VERSION))
	}

	if engine.GetLogger().GetLevel() == zerolog.TraceLevel {
		logger.Trace().Msgf("setting log-level to trace")
		updatedEnv = append(updatedEnv, "SNYK_LOG_LEVEL=trace")
	}

	return updatedEnv
}
