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
	"encoding/json"
	"testing"
	"time"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestAddConfigValuesToEnv(t *testing.T) {
	t.Run("Adds legacy token to env", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingAuthenticationMethod), string(types.TokenAuthentication))

		updatedEnv := AppendCliEnvironmentVariables(engine, []string{}, true)

		token := config.GetToken(engine.GetConfiguration())
		assert.Contains(t, updatedEnv, TokenEnvVar+"="+token)
	})

	t.Run("Adds values to env", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		const expectedIntegrationName = "ECLIPSE"
		const expectedIntegrationVersion = "20230606.182718"
		const expectedIdeVersion = "4.27.0"
		const expectedIdeName = "Eclipse"

		engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingAuthenticationMethod), string(types.OAuthAuthentication))
		config.SetOrganization(engine.GetConfiguration(), "testOrg")
		config.UpdateApiEndpointsOnConfig(engine.GetConfiguration(), "https://api.eu.snyk.io")
		conf := engine.GetConfiguration()
		conf.Set(configuration.INTEGRATION_NAME, expectedIntegrationName)
		conf.Set(configuration.INTEGRATION_VERSION, expectedIntegrationVersion)
		conf.Set(configuration.INTEGRATION_ENVIRONMENT_VERSION, expectedIdeVersion)
		conf.Set(configuration.INTEGRATION_ENVIRONMENT, expectedIdeName)
		s := oauth2.Token{
			AccessToken:  "test",
			TokenType:    "test",
			RefreshToken: "test",
			Expiry:       time.Time{},
		}
		marshal, err := json.Marshal(s)
		require.NoError(t, err)
		tokenService.SetToken(conf, string(marshal))

		updatedEnv := AppendCliEnvironmentVariables(engine, []string{}, true)

		assert.Contains(t, updatedEnv, ApiEnvVar+"=https://api.eu.snyk.io")
		token, err := config.ParseOAuthToken(config.GetToken(engine.GetConfiguration()), engine.GetLogger())
		require.NoError(t, err)
		assert.Contains(t, updatedEnv, SnykOauthTokenEnvVar+"="+token.AccessToken)
		assert.Contains(t, updatedEnv, IntegrationNameEnvVarKey+"="+expectedIntegrationName)
		assert.Contains(t, updatedEnv, IntegrationVersionEnvVarKey+"="+expectedIntegrationVersion)
		assert.Contains(t, updatedEnv, IntegrationEnvironmentEnvVarKey+"="+expectedIdeName)
		assert.Contains(t, updatedEnv, IntegrationEnvironmentVersionEnvVar+"="+expectedIdeVersion)
		assert.NotContains(t, updatedEnv, "SNYK_CFG_DISABLE_ANALYTICS=1")
	})
	t.Run("Removes existing snyk token env variables", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		tokenService.SetToken(engine.GetConfiguration(), "{\"access_token\": \"testToken\"}")
		engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingAuthenticationMethod), string(types.OAuthAuthentication))
		tokenVar := TokenEnvVar + "={asdf}"
		inputEnv := []string{tokenVar}

		updatedEnv := AppendCliEnvironmentVariables(engine, inputEnv, true)

		token, err := config.ParseOAuthToken(config.GetToken(engine.GetConfiguration()), engine.GetLogger())
		assert.NoError(t, err)
		assert.Contains(t, updatedEnv, SnykOauthTokenEnvVar+"="+token.AccessToken)
		assert.NotContains(t, updatedEnv, tokenVar)
	})
	t.Run("Removes existing authentication env variables", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		tokenService.SetToken(engine.GetConfiguration(), "testToken")
		oauthVar := SnykOauthTokenEnvVar + "={asdf}"
		inputEnv := []string{oauthVar}

		updatedEnv := AppendCliEnvironmentVariables(engine, inputEnv, true)

		assert.Contains(t, updatedEnv, "SNYK_TOKEN="+config.GetToken(engine.GetConfiguration()))
		assert.NotContains(t, updatedEnv, oauthVar)
	})
	t.Run("Adds Snyk Token to env", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		tokenService.SetToken(engine.GetConfiguration(), "testToken")
		engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingAuthenticationMethod), string(types.TokenAuthentication))

		updatedEnv := AppendCliEnvironmentVariables(engine, []string{}, true)

		assert.Contains(t, updatedEnv, "SNYK_TOKEN="+config.GetToken(engine.GetConfiguration()))
		assert.Contains(t, updatedEnv, OAuthEnabledEnvVar+"=0")
	})

	t.Run("Adds OAuth Token to env", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingAuthenticationMethod), string(types.OAuthAuthentication))
		tokenService.SetToken(engine.GetConfiguration(), "{\"access_token\": \"testToken\"}")

		updatedEnv := AppendCliEnvironmentVariables(engine, []string{}, true)

		token, err := config.ParseOAuthToken(config.GetToken(engine.GetConfiguration()), engine.GetLogger())
		assert.NoError(t, err)
		assert.Contains(t, updatedEnv, SnykOauthTokenEnvVar+"="+token.AccessToken)
		assert.Contains(t, updatedEnv, OAuthEnabledEnvVar+"=1")
	})
}
