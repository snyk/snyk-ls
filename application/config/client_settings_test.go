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

package config

import (
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/types"
)

func TestGetEnabledProducts_DefaultValues(t *testing.T) {
	c := New(WithBinarySearchPaths([]string{}))
	require.NoError(t, c.WaitForDefaultEnv(t.Context()))
	SetCurrentConfig(c)

	t.Setenv(ActivateSnykOssKey, "set it to anything to make sure it is reset")
	t.Setenv(ActivateSnykCodeKey, "set it to anything to make sure it is reset")
	t.Setenv(ActivateSnykIacKey, "set it to anything to make sure it is reset")
	t.Setenv(ActivateSnykAdvisorKey, "set it to anything to make sure it is reset")
	t.Setenv(ActivateSnykSecretsKey, "set it to anything to make sure it is reset")
	_ = os.Unsetenv(ActivateSnykOssKey)
	_ = os.Unsetenv(ActivateSnykCodeKey)
	_ = os.Unsetenv(ActivateSnykIacKey)
	_ = os.Unsetenv(ActivateSnykAdvisorKey)
	_ = os.Unsetenv(ActivateSnykSecretsKey)

	c.clientSettingsFromEnv()

	assert.Equal(t, true, c.engine.GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykOssEnabled)))
	assert.Equal(t, false, c.engine.GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykCodeEnabled)))
	assert.Equal(t, true, c.engine.GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykIacEnabled)))
	assert.Equal(t, false, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykAdvisorEnabled)))
	assert.Equal(t, false, c.engine.GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykSecretsEnabled)))
}

func TestConfig_IsErrorReportingEnabledFromEnv_DefaultValues(t *testing.T) {
	c := New(WithBinarySearchPaths([]string{}))
	require.NoError(t, c.WaitForDefaultEnv(t.Context()))
	SetCurrentConfig(c)

	t.Setenv(SendErrorReportsKey, "set it to anything to make sure it is reset")
	_ = os.Unsetenv(SendErrorReportsKey)

	c.clientSettingsFromEnv()

	assert.Equal(t, true, c.engine.GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSendErrorReports)))
}
func TestConfig_IsErrorReportingEnabledFromEnv(t *testing.T) {
	c := New(WithBinarySearchPaths([]string{}))
	require.NoError(t, c.WaitForDefaultEnv(t.Context()))
	SetCurrentConfig(c)

	t.Setenv(SendErrorReportsKey, "true")

	c.clientSettingsFromEnv()

	assert.Equal(t, true, c.engine.GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSendErrorReports)))
}

func TestConfig_IsErrorReportingEnabledFromEnv_Error(t *testing.T) {
	c := New(WithBinarySearchPaths([]string{}))
	require.NoError(t, c.WaitForDefaultEnv(t.Context()))
	SetCurrentConfig(c)

	t.Setenv(SendErrorReportsKey, "hurz")
	c.clientSettingsFromEnv()

	assert.Equal(t, true, c.engine.GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSendErrorReports)))
}

func TestConfig_OrganizationFromEnv(t *testing.T) {
	c := New(WithBinarySearchPaths([]string{}))
	require.NoError(t, c.WaitForDefaultEnv(t.Context()))
	SetCurrentConfig(c)

	orgUuid, _ := uuid.NewRandom()
	expectedOrgId := orgUuid.String()
	t.Setenv(Organization, expectedOrgId)
	c.clientSettingsFromEnv()

	assert.Equal(t, expectedOrgId, c.Engine().GetConfiguration().GetString(configuration.ORGANIZATION))
}

func TestInitializeDefaultProductEnablement(t *testing.T) {
	c := New(WithBinarySearchPaths([]string{}))
	require.NoError(t, c.WaitForDefaultEnv(t.Context()))
	SetCurrentConfig(c)

	t.Setenv(ActivateSnykOssKey, "false")
	t.Setenv(ActivateSnykCodeKey, "true")
	t.Setenv(ActivateSnykIacKey, "false")
	t.Setenv(ActivateSnykAdvisorKey, "true")
	t.Setenv(ActivateSnykSecretsKey, "true")

	c.clientSettingsFromEnv()

	assert.Equal(t, false, c.engine.GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykOssEnabled)))
	assert.Equal(t, true, c.engine.GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykCodeEnabled)))
	assert.Equal(t, false, c.engine.GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykIacEnabled)))
	assert.Equal(t, true, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykAdvisorEnabled)))
	assert.Equal(t, true, c.engine.GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykSecretsEnabled)))
}

func TestGetEnabledProducts_Oss(t *testing.T) {
	c := New(WithBinarySearchPaths([]string{}))
	require.NoError(t, c.WaitForDefaultEnv(t.Context()))
	SetCurrentConfig(c)

	t.Setenv(ActivateSnykOssKey, "false")
	c.clientSettingsFromEnv()
	assert.Equal(t, false, c.engine.GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykOssEnabled)))

	t.Setenv(ActivateSnykOssKey, "true")
	c.clientSettingsFromEnv()
	assert.Equal(t, true, c.engine.GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykOssEnabled)))
}

func TestGetEnabledProducts_Code(t *testing.T) {
	c := New(WithBinarySearchPaths([]string{}))
	require.NoError(t, c.WaitForDefaultEnv(t.Context()))
	SetCurrentConfig(c)

	t.Setenv(ActivateSnykCodeKey, "false")
	c.clientSettingsFromEnv()
	assert.Equal(t, false, c.engine.GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykCodeEnabled)))

	t.Setenv(ActivateSnykCodeKey, "true")
	c.clientSettingsFromEnv()
	assert.Equal(t, true, c.engine.GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykCodeEnabled)))
}

func TestGetEnabledProducts_Iac(t *testing.T) {
	c := New(WithBinarySearchPaths([]string{}))
	require.NoError(t, c.WaitForDefaultEnv(t.Context()))
	SetCurrentConfig(c)

	t.Setenv(ActivateSnykIacKey, "false")
	c.clientSettingsFromEnv()
	assert.Equal(t, false, c.engine.GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykIacEnabled)))

	t.Setenv(ActivateSnykIacKey, "true")
	c.clientSettingsFromEnv()
	assert.Equal(t, true, c.engine.GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykIacEnabled)))
}

func TestGetEnabledProducts_Advisor(t *testing.T) {
	c := New(WithBinarySearchPaths([]string{}))
	require.NoError(t, c.WaitForDefaultEnv(t.Context()))
	SetCurrentConfig(c)

	t.Setenv(ActivateSnykAdvisorKey, "false")
	c.clientSettingsFromEnv()
	assert.Equal(t, false, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykAdvisorEnabled)))

	t.Setenv(ActivateSnykAdvisorKey, "true")
	c.clientSettingsFromEnv()
	assert.Equal(t, true, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykAdvisorEnabled)))
}

func TestGetEnabledProducts_Secrets(t *testing.T) {
	c := New(WithBinarySearchPaths([]string{}))
	require.NoError(t, c.WaitForDefaultEnv(t.Context()))
	SetCurrentConfig(c)

	t.Setenv(ActivateSnykSecretsKey, "false")
	c.clientSettingsFromEnv()
	assert.Equal(t, false, c.engine.GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykSecretsEnabled)))

	t.Setenv(ActivateSnykSecretsKey, "true")
	c.clientSettingsFromEnv()
	assert.Equal(t, true, c.engine.GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingSnykSecretsEnabled)))
}
