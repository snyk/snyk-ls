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
	"testing"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/lsp"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestAddConfigValuesToEnv(t *testing.T) {
	t.Run("Adds values to env", func(t *testing.T) {
		const expectedIntegrationName = "ECLIPSE"
		const expectedIntegrationVersion = "0.0.1rc1"

		testutil.UnitTest(t)
		c := config.CurrentConfig()
		c.SetOrganization("testOrg")
		c.UpdateApiEndpoints("https://app.snyk.io/api")
		c.SetIntegrationName(expectedIntegrationName)
		c.SetIntegrationVersion(expectedIntegrationVersion)

		updatedEnv := AppendCliEnvironmentVariables([]string{}, true)

		assert.Contains(t, updatedEnv, ApiEnvVar+"=https://app.snyk.io/api")
		assert.Contains(t, updatedEnv, TokenEnvVar+"="+c.Token())
		assert.Contains(t, updatedEnv, IntegrationNameEnvVarKey+"="+expectedIntegrationName)
		assert.Contains(t, updatedEnv, IntegrationVersionEnvVarKey+"="+expectedIntegrationVersion)
		assert.Contains(t, updatedEnv, IntegrationEnvironmentEnvVarKey+"="+IntegrationEnvironmentEnvVarValue)
		assert.Contains(t, updatedEnv, IntegrationEnvironmentVersionEnvVar+"="+config.Version)
		assert.NotContains(t, updatedEnv, "SNYK_CFG_DISABLE_ANALYTICS=1")
	})
	t.Run("Removes existing snyk token env variables", func(t *testing.T) {
		testutil.UnitTest(t)
		c := config.CurrentConfig()
		c.SetAuthenticationMethod(lsp.OAuthAuthentication)
		c.SetToken("testToken")
		tokenVar := TokenEnvVar + "={asdf}"
		inputEnv := []string{tokenVar}

		updatedEnv := AppendCliEnvironmentVariables(inputEnv, true)

		assert.Contains(t, updatedEnv, auth.CONFIG_KEY_OAUTH_TOKEN+"="+config.CurrentConfig().Token())
		assert.Contains(t, updatedEnv, strings.ToUpper(configuration.FF_OAUTH_AUTH_FLOW_ENABLED+"=1"))
		assert.NotContains(t, updatedEnv, tokenVar)
	})
	t.Run("Removes existing oauth env variables", func(t *testing.T) {
		testutil.UnitTest(t)
		c := config.CurrentConfig()
		c.SetAuthenticationMethod(lsp.TokenAuthentication)
		c.SetToken("testToken")
		oauthVar := auth.CONFIG_KEY_OAUTH_TOKEN + "={asdf}"
		inputEnv := []string{oauthVar}

		updatedEnv := AppendCliEnvironmentVariables(inputEnv, true)

		assert.Contains(t, updatedEnv, "SNYK_TOKEN="+config.CurrentConfig().Token())
		assert.NotContains(t, updatedEnv, oauthVar)
	})
	t.Run("Adds Snyk Token to env", func(t *testing.T) {
		testutil.UnitTest(t)
		c := config.CurrentConfig()
		c.SetAuthenticationMethod(lsp.TokenAuthentication)
		c.SetToken("testToken")

		updatedEnv := AppendCliEnvironmentVariables([]string{}, true)

		assert.Contains(t, updatedEnv, "SNYK_TOKEN="+config.CurrentConfig().Token())
	})

	t.Run("Adds OAuth Token to env", func(t *testing.T) {
		testutil.UnitTest(t)
		c := config.CurrentConfig()
		c.SetAuthenticationMethod(lsp.OAuthAuthentication)
		c.SetToken("testToken")

		updatedEnv := AppendCliEnvironmentVariables([]string{}, true)

		assert.Contains(t, updatedEnv, auth.CONFIG_KEY_OAUTH_TOKEN+"="+config.CurrentConfig().Token())
	})

	t.Run("Disables analytics, if telemetry disabled", func(t *testing.T) {
		testutil.UnitTest(t)
		config.CurrentConfig().SetTelemetryEnabled(false)

		updatedEnv := AppendCliEnvironmentVariables([]string{}, true)

		assert.Contains(t, updatedEnv, "SNYK_CFG_DISABLE_ANALYTICS=1")
	})
}
