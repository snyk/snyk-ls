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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetEnabledProducts_DefaultValues(t *testing.T) {
	c := New(WithBinarySearchPaths([]string{}))
	require.NoError(t, c.WaitForDefaultEnv(t.Context()))
	SetCurrentConfig(c)

	t.Setenv(ActivateSnykOssKey, "set it to anything to make sure it is reset")
	t.Setenv(ActivateSnykCodeKey, "set it to anything to make sure it is reset")
	t.Setenv(ActivateSnykIacKey, "set it to anything to make sure it is reset")
	t.Setenv(ActivateSnykAdvisorKey, "set it to anything to make sure it is reset")
	t.Setenv(ActivateSnykSecretScanKey, "set it to anything to make sure it is reset")
	_ = os.Unsetenv(ActivateSnykOssKey)
	_ = os.Unsetenv(ActivateSnykCodeKey)
	_ = os.Unsetenv(ActivateSnykIacKey)
	_ = os.Unsetenv(ActivateSnykAdvisorKey)
	_ = os.Unsetenv(ActivateSnykSecretScanKey)

	c.clientSettingsFromEnv()

	assert.Equal(t, true, c.IsSnykOssEnabled())
	assert.Equal(t, false, c.IsSnykCodeEnabled())
	assert.Equal(t, true, c.IsSnykIacEnabled())
	assert.Equal(t, false, c.IsSnykAdvisorEnabled())
	assert.Equal(t, false, c.IsSnykSecretScanEnabled())
}

func TestConfig_IsErrorReportingEnabledFromEnv_DefaultValues(t *testing.T) {
	c := New(WithBinarySearchPaths([]string{}))
	require.NoError(t, c.WaitForDefaultEnv(t.Context()))
	SetCurrentConfig(c)

	t.Setenv(SendErrorReportsKey, "set it to anything to make sure it is reset")
	_ = os.Unsetenv(SendErrorReportsKey)

	c.clientSettingsFromEnv()

	assert.Equal(t, true, c.IsErrorReportingEnabled())
}
func TestConfig_IsErrorReportingEnabledFromEnv(t *testing.T) {
	c := New(WithBinarySearchPaths([]string{}))
	require.NoError(t, c.WaitForDefaultEnv(t.Context()))
	SetCurrentConfig(c)

	t.Setenv(SendErrorReportsKey, "true")

	c.clientSettingsFromEnv()

	assert.Equal(t, true, c.IsErrorReportingEnabled())
}

func TestConfig_IsErrorReportingEnabledFromEnv_Error(t *testing.T) {
	c := New(WithBinarySearchPaths([]string{}))
	require.NoError(t, c.WaitForDefaultEnv(t.Context()))
	SetCurrentConfig(c)

	t.Setenv(SendErrorReportsKey, "hurz")
	c.clientSettingsFromEnv()

	assert.Equal(t, true, c.IsErrorReportingEnabled())
}

func TestConfig_OrganizationFromEnv(t *testing.T) {
	c := New(WithBinarySearchPaths([]string{}))
	require.NoError(t, c.WaitForDefaultEnv(t.Context()))
	SetCurrentConfig(c)

	orgUuid, _ := uuid.NewRandom()
	expectedOrgId := orgUuid.String()
	t.Setenv(Organization, expectedOrgId)
	c.clientSettingsFromEnv()

	assert.Equal(t, expectedOrgId, c.Organization())
}

func TestInitializeDefaultProductEnablement(t *testing.T) {
	c := New(WithBinarySearchPaths([]string{}))
	require.NoError(t, c.WaitForDefaultEnv(t.Context()))
	SetCurrentConfig(c)

	t.Setenv(ActivateSnykOssKey, "false")
	t.Setenv(ActivateSnykCodeKey, "true")
	t.Setenv(ActivateSnykIacKey, "false")
	t.Setenv(ActivateSnykAdvisorKey, "true")
	t.Setenv(ActivateSnykSecretScanKey, "true")

	c.clientSettingsFromEnv()

	assert.Equal(t, false, c.IsSnykOssEnabled())
	assert.Equal(t, true, c.IsSnykCodeEnabled())
	assert.Equal(t, false, c.IsSnykIacEnabled())
	assert.Equal(t, true, c.IsSnykAdvisorEnabled())
	assert.Equal(t, true, c.IsSnykSecretScanEnabled())
}

func TestGetEnabledProducts_Oss(t *testing.T) {
	c := New(WithBinarySearchPaths([]string{}))
	require.NoError(t, c.WaitForDefaultEnv(t.Context()))
	SetCurrentConfig(c)

	t.Setenv(ActivateSnykOssKey, "false")
	c.clientSettingsFromEnv()
	assert.Equal(t, false, c.isSnykOssEnabled)

	t.Setenv(ActivateSnykOssKey, "true")
	c.clientSettingsFromEnv()
	assert.Equal(t, true, c.isSnykOssEnabled)
}

func TestGetEnabledProducts_Code(t *testing.T) {
	c := New(WithBinarySearchPaths([]string{}))
	require.NoError(t, c.WaitForDefaultEnv(t.Context()))
	SetCurrentConfig(c)

	t.Setenv(ActivateSnykCodeKey, "false")
	c.clientSettingsFromEnv()
	assert.Equal(t, false, c.IsSnykCodeEnabled())

	t.Setenv(ActivateSnykCodeKey, "true")
	c.clientSettingsFromEnv()
	assert.Equal(t, true, c.IsSnykCodeEnabled())
}

func TestGetEnabledProducts_Iac(t *testing.T) {
	c := New(WithBinarySearchPaths([]string{}))
	require.NoError(t, c.WaitForDefaultEnv(t.Context()))
	SetCurrentConfig(c)

	t.Setenv(ActivateSnykIacKey, "false")
	c.clientSettingsFromEnv()
	assert.Equal(t, false, c.IsSnykIacEnabled())

	t.Setenv(ActivateSnykIacKey, "true")
	c.clientSettingsFromEnv()
	assert.Equal(t, true, c.IsSnykIacEnabled())
}

func TestGetEnabledProducts_Advisor(t *testing.T) {
	c := New(WithBinarySearchPaths([]string{}))
	require.NoError(t, c.WaitForDefaultEnv(t.Context()))
	SetCurrentConfig(c)

	t.Setenv(ActivateSnykAdvisorKey, "false")
	c.clientSettingsFromEnv()
	assert.Equal(t, false, c.IsSnykAdvisorEnabled())

	t.Setenv(ActivateSnykAdvisorKey, "true")
	c.clientSettingsFromEnv()
	assert.Equal(t, true, c.IsSnykAdvisorEnabled())
}

func TestGetEnabledProducts_SecretScan(t *testing.T) {
	c := New(WithBinarySearchPaths([]string{}))
	require.NoError(t, c.WaitForDefaultEnv(t.Context()))
	SetCurrentConfig(c)

	t.Setenv(ActivateSnykSecretScanKey, "false")
	c.clientSettingsFromEnv()
	assert.Equal(t, false, c.IsSnykSecretScanEnabled())

	t.Setenv(ActivateSnykSecretScanKey, "true")
	c.clientSettingsFromEnv()
	assert.Equal(t, true, c.IsSnykSecretScanEnabled())
}
