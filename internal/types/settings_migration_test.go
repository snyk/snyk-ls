/*
 * © 2026 Snyk Limited
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

package types

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMigrateSettingsToLocalFields_FC058 verifies that MigrateSettingsToLocalFields
// converts Settings to map[string]*configuration.LocalConfigField using ideKey mapping.
func TestMigrateSettingsToLocalFields_FC058(t *testing.T) {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	RegisterAllConfigurations(fs)

	riskScore := 500
	filterSeverity := &SeverityFilter{Critical: true, High: true, Medium: false, Low: false}

	settings := &Settings{
		Endpoint:               "https://api.snyk.io",
		ActivateSnykCode:       "true",
		ActivateSnykOpenSource: "true",
		FilterSeverity:         filterSeverity,
		RiskScoreThreshold:     &riskScore,
		ScanningMode:           "auto",
		// Infrastructure/unknown fields - should NOT appear in result
		Token:           "secret-token",
		IntegrationName: "vscode",
		DeviceId:        "device-123",
	}

	result := MigrateSettingsToLocalFields(settings, fs)

	// Endpoint -> api_endpoint
	ep, ok := result[SettingApiEndpoint]
	require.True(t, ok, "api_endpoint should be present")
	assert.Equal(t, "https://api.snyk.io", ep.Value)
	assert.True(t, ep.Changed)

	// ActivateSnykCode -> snyk_code_enabled (value as string from Settings)
	code, ok := result[SettingSnykCodeEnabled]
	require.True(t, ok, "snyk_code_enabled should be present")
	assert.Equal(t, "true", code.Value)
	assert.True(t, code.Changed)

	// ActivateSnykOpenSource -> snyk_oss_enabled
	oss, ok := result[SettingSnykOssEnabled]
	require.True(t, ok, "snyk_oss_enabled should be present")
	assert.Equal(t, "true", oss.Value)
	assert.True(t, oss.Changed)

	// FilterSeverity -> enabled_severities
	sev, ok := result[SettingEnabledSeverities]
	require.True(t, ok, "enabled_severities should be present")
	assert.Equal(t, filterSeverity, sev.Value)
	assert.True(t, sev.Changed)

	// RiskScoreThreshold -> risk_score_threshold
	risk, ok := result[SettingRiskScoreThreshold]
	require.True(t, ok, "risk_score_threshold should be present")
	assert.Equal(t, 500, risk.Value)
	assert.True(t, risk.Changed)

	// ScanningMode -> scan_automatic
	scan, ok := result[SettingScanAutomatic]
	require.True(t, ok, "scan_automatic should be present")
	assert.Equal(t, "auto", scan.Value)
	assert.True(t, scan.Changed)

	// Infrastructure/unknown fields must NOT be present
	assert.NotContains(t, result, "token")
	assert.NotContains(t, result, "integrationName")
	assert.NotContains(t, result, "deviceId")
	// Token, IntegrationName, DeviceId have no ideKey - verify they're not in result by any key
	for k := range result {
		assert.NotEqual(t, "token", k)
		assert.NotEqual(t, "integrationName", k)
		assert.NotEqual(t, "deviceId", k)
	}
}

// TestMigrateSettingsToLocalFields_FC058_EmptyValuesExcluded verifies that empty/zero
// values are NOT included (Changed: false semantics).
func TestMigrateSettingsToLocalFields_FC058_EmptyValuesExcluded(t *testing.T) {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	RegisterAllConfigurations(fs)

	settings := &Settings{
		Endpoint:               "",
		ActivateSnykCode:       "",
		ActivateSnykOpenSource: "",
		FilterSeverity:         nil,
		RiskScoreThreshold:     nil,
		ScanningMode:           "",
	}

	result := MigrateSettingsToLocalFields(settings, fs)

	assert.Empty(t, result, "empty settings should produce empty map")
}

// TestMigrateSettingsToLocalFields_FC058_NilSettings returns nil.
func TestMigrateSettingsToLocalFields_FC058_NilSettings(t *testing.T) {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	RegisterAllConfigurations(fs)

	result := MigrateSettingsToLocalFields(nil, fs)

	assert.Nil(t, result)
}

// TestMigrateSettingsToLocalFields_FC058_SettingsWithoutIdeKeyExcluded verifies that
// settings without ideKey annotation are NOT present in the result.
func TestMigrateSettingsToLocalFields_FC058_SettingsWithoutIdeKeyExcluded(t *testing.T) {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	RegisterAllConfigurations(fs)

	// CweIds, CveIds, RuleIds, IssueViewOpenIssues, IssueViewIgnoredIssues,
	// ReferenceFolder, ReferenceBranch have no ideKey - they can't be set from Settings
	// in the current Settings struct. Verify we don't leak any unmapped fields.
	settings := &Settings{
		Endpoint: "https://api.snyk.io",
	}

	result := MigrateSettingsToLocalFields(settings, fs)

	// Only endpoint (api_endpoint) should be present
	assert.Len(t, result, 1)
	assert.Contains(t, result, SettingApiEndpoint)
}
