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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestAddConfigValuesToEnv(t *testing.T) {
	t.Run("Adds legacy token to env", func(t *testing.T) {
		testutil.UnitTest(t)
		c := config.CurrentConfig()
		c.SetAuthenticationMethod(types.TokenAuthentication)

		updatedEnv := AppendCliEnvironmentVariables([]string{}, true)

		token := c.Token()
		assert.Contains(t, updatedEnv, TokenEnvVar+"="+token)
	})

	t.Run("Adds values to env", func(t *testing.T) {
		const expectedIntegrationName = "ECLIPSE"
		const expectedIntegrationVersion = "20230606.182718"
		const expectedIdeVersion = "4.27.0"
		const expectedIdeName = "Eclipse"

		testutil.UnitTest(t)
		c := config.CurrentConfig()
		c.SetAuthenticationMethod(types.OAuthAuthentication)
		c.SetOrganization("testOrg")
		c.UpdateApiEndpoints("https://api.eu.snyk.io")
		c.SetIntegrationName(expectedIntegrationName)
		c.SetIntegrationVersion(expectedIntegrationVersion)
		c.SetIdeVersion(expectedIdeVersion)
		c.SetIdeName(expectedIdeName)
		s := oauth2.Token{
			AccessToken:  "test",
			TokenType:    "test",
			RefreshToken: "test",
			Expiry:       time.Time{},
		}
		marshal, err := json.Marshal(s)
		require.NoError(t, err)
		c.SetToken(string(marshal))

		updatedEnv := AppendCliEnvironmentVariables([]string{}, true)

		assert.Contains(t, updatedEnv, ApiEnvVar+"=https://api.eu.snyk.io")
		token, err := c.TokenAsOAuthToken()
		require.NoError(t, err)
		assert.Contains(t, updatedEnv, SnykOauthTokenEnvVar+"="+token.AccessToken)
		assert.Contains(t, updatedEnv, IntegrationNameEnvVarKey+"="+expectedIntegrationName)
		assert.Contains(t, updatedEnv, IntegrationVersionEnvVarKey+"="+expectedIntegrationVersion)
		assert.Contains(t, updatedEnv, IntegrationEnvironmentEnvVarKey+"="+expectedIdeName)
		assert.Contains(t, updatedEnv, IntegrationEnvironmentVersionEnvVar+"="+expectedIdeVersion)
		assert.NotContains(t, updatedEnv, "SNYK_CFG_DISABLE_ANALYTICS=1")
	})
	t.Run("Removes existing snyk token env variables", func(t *testing.T) {
		testutil.UnitTest(t)
		c := config.CurrentConfig()
		c.SetToken("{\"access_token\": \"testToken\"}")
		c.SetAuthenticationMethod(types.OAuthAuthentication)
		tokenVar := TokenEnvVar + "={asdf}"
		inputEnv := []string{tokenVar}

		updatedEnv := AppendCliEnvironmentVariables(inputEnv, true)

		token, err := c.TokenAsOAuthToken()
		assert.NoError(t, err)
		assert.Contains(t, updatedEnv, SnykOauthTokenEnvVar+"="+token.AccessToken)
		assert.NotContains(t, updatedEnv, tokenVar)
	})
	t.Run("Removes existing authentication env variables", func(t *testing.T) {
		testutil.UnitTest(t)
		c := config.CurrentConfig()
		c.SetToken("testToken")
		oauthVar := SnykOauthTokenEnvVar + "={asdf}"
		inputEnv := []string{oauthVar}

		updatedEnv := AppendCliEnvironmentVariables(inputEnv, true)

		assert.Contains(t, updatedEnv, "SNYK_TOKEN="+c.Token())
		assert.NotContains(t, updatedEnv, oauthVar)
	})
	t.Run("Adds Snyk Token to env", func(t *testing.T) {
		testutil.UnitTest(t)
		c := config.CurrentConfig()
		c.SetToken("testToken")
		c.SetAuthenticationMethod(types.TokenAuthentication)

		updatedEnv := AppendCliEnvironmentVariables([]string{}, true)

		assert.Contains(t, updatedEnv, "SNYK_TOKEN="+c.Token())
		assert.Contains(t, updatedEnv, OAuthEnabledEnvVar+"=0")
	})

	t.Run("Adds OAuth Token to env", func(t *testing.T) {
		testutil.UnitTest(t)
		c := config.CurrentConfig()
		c.SetAuthenticationMethod(types.OAuthAuthentication)
		c.SetToken("{\"access_token\": \"testToken\"}")

		updatedEnv := AppendCliEnvironmentVariables([]string{}, true)

		token, err := c.TokenAsOAuthToken()
		assert.NoError(t, err)
		assert.Contains(t, updatedEnv, SnykOauthTokenEnvVar+"="+token.AccessToken)
		assert.Contains(t, updatedEnv, OAuthEnabledEnvVar+"=1")
	})
}
