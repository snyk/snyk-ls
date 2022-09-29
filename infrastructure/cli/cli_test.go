/*
 * Copyright 2022 Snyk Ltd.
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
	"context"
	"testing"

	"github.com/adrg/xdg"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_ExpandParametersFromConfig(t *testing.T) {
	testutil.UnitTest(t)
	config.CurrentConfig().SetOrganization("test-org")
	settings := config.CliSettings{
		Insecure:             true,
		AdditionalParameters: []string{"--all-projects", "-d"},
	}
	config.CurrentConfig().SetCliSettings(&settings)
	var cmd = []string{"a", "b"}
	cmd = SnykCli{}.ExpandParametersFromConfig(cmd)
	assert.Contains(t, cmd, "--insecure")
	assert.Contains(t, cmd, "--all-projects")
	assert.Contains(t, cmd, "-d")
}

func Test_ExpandParametersFromConfigNoAllProjectsForIac(t *testing.T) {
	testutil.UnitTest(t)
	config.CurrentConfig().SetOrganization("test-org")
	settings := config.CliSettings{
		Insecure:             true,
		AdditionalParameters: []string{"--all-projects", "-d"},
	}
	config.CurrentConfig().SetCliSettings(&settings)
	var cmd = []string{"a", "iac"}
	cmd = SnykCli{}.ExpandParametersFromConfig(cmd)
	assert.Contains(t, cmd, "--insecure")
	assert.NotContains(t, cmd, "--all-projects")
	assert.Contains(t, cmd, "-d")
}

func TestAddConfigValuesToEnv(t *testing.T) {
	t.Run("Adds values to env", func(t *testing.T) {
		const expectedIntegrationName = "ECLIPSE"
		const expectedIntegrationVersion = "0.0.1rc1"

		testutil.UnitTest(t)
		config.CurrentConfig().SetOrganization("testOrg")
		config.CurrentConfig().UpdateApiEndpoints("https://app.snyk.io/api")
		config.CurrentConfig().SetIntegrationName(expectedIntegrationName)
		config.CurrentConfig().SetIntegrationVersion(expectedIntegrationVersion)

		updatedEnv := appendCliEnvironmentVariables([]string{})

		assert.Contains(t, updatedEnv, "SNYK_CFG_ORG="+config.CurrentConfig().GetOrganization())
		assert.Contains(t, updatedEnv, "SNYK_API=https://app.snyk.io/api")
		assert.Contains(t, updatedEnv, "SNYK_TOKEN="+config.CurrentConfig().Token())
		assert.Contains(t, updatedEnv, "SNYK_INTEGRATION_NAME="+expectedIntegrationName)
		assert.Contains(t, updatedEnv, "SNYK_INTEGRATION_VERSION="+expectedIntegrationVersion)
		assert.Contains(t, updatedEnv, "SNYK_INTEGRATION_ENVIRONMENT="+IntegrationEnvironmentEnvVarValue)
		assert.Contains(t, updatedEnv, "SNYK_INTEGRATION_ENVIRONMENT_VERSION="+config.Version)
		assert.NotContains(t, updatedEnv, "SNYK_CFG_DISABLE_ANALYTICS=1")
	})

	t.Run("Disables analytics, if telemetry disabled", func(t *testing.T) {
		testutil.UnitTest(t)
		config.CurrentConfig().SetTelemetryEnabled(false)

		updatedEnv := appendCliEnvironmentVariables([]string{})

		assert.Contains(t, updatedEnv, "SNYK_CFG_DISABLE_ANALYTICS=1")
	})
}

func TestGetCommand_AddsToEnvironmentAndSetsDir(t *testing.T) {
	testutil.UnitTest(t)
	config.CurrentConfig().SetOrganization("TestGetCommand_AddsToEnvironmentAndSetsDirOrg")

	cmd := SnykCli{}.getCommand([]string{"executable", "arg"}, xdg.DataHome, context.Background())

	assert.Equal(t, xdg.DataHome, cmd.Dir)
	assert.Contains(t, cmd.Env, "SNYK_CFG_ORG=TestGetCommand_AddsToEnvironmentAndSetsDirOrg")
}
