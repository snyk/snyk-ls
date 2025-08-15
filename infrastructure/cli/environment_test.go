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
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestAddConfigValuesToEnv(t *testing.T) {
	t.Run("Adds legacy token to env", func(t *testing.T) {
		c := testutil.UnitTest(t)
		c.SetAuthenticationMethod(types.TokenAuthentication)

		updatedEnv := AppendCliEnvironmentVariables([]string{}, true)

		token := c.Token()
		assert.Contains(t, updatedEnv, TokenEnvVar+"="+token)
	})

	t.Run("Adds values to env", func(t *testing.T) {
		c := testutil.UnitTest(t)
		const expectedIntegrationName = "ECLIPSE"
		const expectedIntegrationVersion = "20230606.182718"
		const expectedIdeVersion = "4.27.0"
		const expectedIdeName = "Eclipse"

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
		c := testutil.UnitTest(t)
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
		c := testutil.UnitTest(t)
		c.SetToken("testToken")
		oauthVar := SnykOauthTokenEnvVar + "={asdf}"
		inputEnv := []string{oauthVar}

		updatedEnv := AppendCliEnvironmentVariables(inputEnv, true)

		assert.Contains(t, updatedEnv, "SNYK_TOKEN="+c.Token())
		assert.NotContains(t, updatedEnv, oauthVar)
	})
	t.Run("Adds Snyk Token to env", func(t *testing.T) {
		c := testutil.UnitTest(t)
		c.SetToken("testToken")
		c.SetAuthenticationMethod(types.TokenAuthentication)

		updatedEnv := AppendCliEnvironmentVariables([]string{}, true)

		assert.Contains(t, updatedEnv, "SNYK_TOKEN="+c.Token())
		assert.Contains(t, updatedEnv, OAuthEnabledEnvVar+"=0")
	})

	t.Run("Adds OAuth Token to env", func(t *testing.T) {
		c := testutil.UnitTest(t)
		c.SetAuthenticationMethod(types.OAuthAuthentication)
		c.SetToken("{\"access_token\": \"testToken\"}")

		updatedEnv := AppendCliEnvironmentVariables([]string{}, true)

		token, err := c.TokenAsOAuthToken()
		assert.NoError(t, err)
		assert.Contains(t, updatedEnv, SnykOauthTokenEnvVar+"="+token.AccessToken)
		assert.Contains(t, updatedEnv, OAuthEnabledEnvVar+"=1")
	})
}

func TestEnvSnapshotAndRestore_RestoresPathAndVars(t *testing.T) {
	testutil.UnitTest(t)

	// Set up initial environment state
	t.Setenv("TEST_VAR", "original_value")
	t.Setenv("STATIC_VAR", "static_value")
	t.Setenv("PATH", "/original/path")

	// Take snapshot
	snapshot := TakeEnvSnapshot()

	// Modify environment
	t.Setenv("TEST_VAR", "modified_value")
	t.Setenv("NEW_VAR", "new_value")
	t.Setenv("PATH", "/modified/path")

	// Verify modifications took effect
	require.Equal(t, "modified_value", os.Getenv("TEST_VAR"))
	require.Equal(t, "static_value", os.Getenv("STATIC_VAR"))
	require.Equal(t, "new_value", os.Getenv("NEW_VAR"))
	require.Equal(t, "/modified/path", os.Getenv("PATH"))

	// Restore snapshot
	RestoreEnvSnapshot(snapshot)

	// Verify restoration
	assert.Equal(t, "original_value", os.Getenv("TEST_VAR"))
	assert.Equal(t, "static_value", os.Getenv("STATIC_VAR"))
	assert.Equal(t, "", os.Getenv("NEW_VAR")) // Should be cleared
	assert.Equal(t, "/original/path", os.Getenv("PATH"))
}
