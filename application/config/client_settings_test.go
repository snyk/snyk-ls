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
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/types"
)

func initEngineForClientSettingsTest(t *testing.T) workflow.Engine {
	t.Helper()
	e, _ := InitEngine(nil)
	e.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingBinarySearchPaths), []string{})
	require.NoError(t, types.WaitForDefaultEnv(t.Context(), e.GetConfiguration()))
	return e
}

func TestGetEnabledProducts_DefaultValues(t *testing.T) {
	engine := initEngineForClientSettingsTest(t)

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

	ClientSettingsFromEnv(engine.GetConfiguration(), engine.GetLogger())

	assert.Equal(t, true, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykOssEnabled)))
	assert.Equal(t, false, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled)))
	assert.Equal(t, true, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykIacEnabled)))
	assert.Equal(t, false, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykAdvisorEnabled)))
	assert.Equal(t, false, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykSecretsEnabled)))
}

func TestConfig_IsErrorReportingEnabledFromEnv_DefaultValues(t *testing.T) {
	engine := initEngineForClientSettingsTest(t)

	t.Setenv(SendErrorReportsKey, "set it to anything to make sure it is reset")
	_ = os.Unsetenv(SendErrorReportsKey)

	ClientSettingsFromEnv(engine.GetConfiguration(), engine.GetLogger())

	assert.Equal(t, true, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSendErrorReports)))
}
func TestConfig_IsErrorReportingEnabledFromEnv(t *testing.T) {
	engine := initEngineForClientSettingsTest(t)

	t.Setenv(SendErrorReportsKey, "true")

	ClientSettingsFromEnv(engine.GetConfiguration(), engine.GetLogger())

	assert.Equal(t, true, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSendErrorReports)))
}

func TestConfig_IsErrorReportingEnabledFromEnv_Error(t *testing.T) {
	engine := initEngineForClientSettingsTest(t)

	t.Setenv(SendErrorReportsKey, "hurz")
	ClientSettingsFromEnv(engine.GetConfiguration(), engine.GetLogger())

	assert.Equal(t, true, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSendErrorReports)))
}

func TestConfig_OrganizationFromEnv(t *testing.T) {
	engine := initEngineForClientSettingsTest(t)

	orgUuid, _ := uuid.NewRandom()
	expectedOrgId := orgUuid.String()
	t.Setenv(Organization, expectedOrgId)
	ClientSettingsFromEnv(engine.GetConfiguration(), engine.GetLogger())

	assert.Equal(t, expectedOrgId, engine.GetConfiguration().GetString(configuration.ORGANIZATION))
}

func TestInitializeDefaultProductEnablement(t *testing.T) {
	engine := initEngineForClientSettingsTest(t)

	t.Setenv(ActivateSnykOssKey, "false")
	t.Setenv(ActivateSnykCodeKey, "true")
	t.Setenv(ActivateSnykIacKey, "false")
	t.Setenv(ActivateSnykAdvisorKey, "true")
	t.Setenv(ActivateSnykSecretsKey, "true")

	ClientSettingsFromEnv(engine.GetConfiguration(), engine.GetLogger())

	assert.Equal(t, false, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykOssEnabled)))
	assert.Equal(t, true, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled)))
	assert.Equal(t, false, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykIacEnabled)))
	assert.Equal(t, true, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykAdvisorEnabled)))
	assert.Equal(t, true, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykSecretsEnabled)))
}

func TestGetEnabledProducts_Oss(t *testing.T) {
	engine := initEngineForClientSettingsTest(t)

	t.Setenv(ActivateSnykOssKey, "false")
	ClientSettingsFromEnv(engine.GetConfiguration(), engine.GetLogger())
	assert.Equal(t, false, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykOssEnabled)))

	t.Setenv(ActivateSnykOssKey, "true")
	ClientSettingsFromEnv(engine.GetConfiguration(), engine.GetLogger())
	assert.Equal(t, true, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykOssEnabled)))
}

func TestGetEnabledProducts_Code(t *testing.T) {
	engine := initEngineForClientSettingsTest(t)

	t.Setenv(ActivateSnykCodeKey, "false")
	ClientSettingsFromEnv(engine.GetConfiguration(), engine.GetLogger())
	assert.Equal(t, false, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled)))

	t.Setenv(ActivateSnykCodeKey, "true")
	ClientSettingsFromEnv(engine.GetConfiguration(), engine.GetLogger())
	assert.Equal(t, true, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled)))
}

func TestGetEnabledProducts_Iac(t *testing.T) {
	engine := initEngineForClientSettingsTest(t)

	t.Setenv(ActivateSnykIacKey, "false")
	ClientSettingsFromEnv(engine.GetConfiguration(), engine.GetLogger())
	assert.Equal(t, false, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykIacEnabled)))

	t.Setenv(ActivateSnykIacKey, "true")
	ClientSettingsFromEnv(engine.GetConfiguration(), engine.GetLogger())
	assert.Equal(t, true, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykIacEnabled)))
}

func TestGetEnabledProducts_Advisor(t *testing.T) {
	engine := initEngineForClientSettingsTest(t)

	t.Setenv(ActivateSnykAdvisorKey, "false")
	ClientSettingsFromEnv(engine.GetConfiguration(), engine.GetLogger())
	assert.Equal(t, false, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykAdvisorEnabled)))

	t.Setenv(ActivateSnykAdvisorKey, "true")
	ClientSettingsFromEnv(engine.GetConfiguration(), engine.GetLogger())
	assert.Equal(t, true, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykAdvisorEnabled)))
}

func TestGetEnabledProducts_Secrets(t *testing.T) {
	engine := initEngineForClientSettingsTest(t)

	t.Setenv(ActivateSnykSecretsKey, "false")
	ClientSettingsFromEnv(engine.GetConfiguration(), engine.GetLogger())
	assert.Equal(t, false, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykSecretsEnabled)))

	t.Setenv(ActivateSnykSecretsKey, "true")
	ClientSettingsFromEnv(engine.GetConfiguration(), engine.GetLogger())
	assert.Equal(t, true, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykSecretsEnabled)))
}
