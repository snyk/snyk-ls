/*
 * © 2022-2026 Snyk Limited
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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLspFolderConfig_Settings_JSONRoundTrip(t *testing.T) {
	t.Run("empty settings is omitted from JSON", func(t *testing.T) {
		config := LspFolderConfig{
			FolderPath: "/path/to/folder",
			Settings:   nil,
		}

		data, err := json.Marshal(config)
		require.NoError(t, err)

		assert.NotContains(t, string(data), SettingScanAutomatic)
		assert.NotContains(t, string(data), SettingSnykCodeEnabled)
		assert.Contains(t, string(data), "folderPath")
	})

	t.Run("Value and Changed true marshals to value and changed in JSON", func(t *testing.T) {
		config := LspFolderConfig{
			FolderPath: "/path/to/folder",
			Settings: map[string]*ConfigSetting{
				SettingScanAutomatic:   {Value: true, Changed: true},
				SettingScanNetNew:      {Value: false, Changed: true},
				SettingSnykCodeEnabled: {Value: true, Changed: true},
			},
		}

		data, err := json.Marshal(config)
		require.NoError(t, err)

		assert.Contains(t, string(data), SettingScanAutomatic)
		assert.Contains(t, string(data), "true")
		assert.Contains(t, string(data), "changed")
	})

	t.Run("Value nil and Changed true marshals to value null and changed in JSON", func(t *testing.T) {
		config := LspFolderConfig{
			FolderPath: "/path/to/folder",
			Settings: map[string]*ConfigSetting{
				SettingScanAutomatic:   {Value: nil, Changed: true},
				SettingSnykCodeEnabled: {Value: nil, Changed: true},
			},
		}

		data, err := json.Marshal(config)
		require.NoError(t, err)

		assert.Contains(t, string(data), SettingScanAutomatic)
		assert.Contains(t, string(data), "null")
	})

	t.Run("RiskScoreThreshold with int value marshals correctly", func(t *testing.T) {
		config := LspFolderConfig{
			FolderPath: "/path/to/folder",
			Settings: map[string]*ConfigSetting{
				SettingRiskScoreThreshold: {Value: 70, Changed: true},
			},
		}

		data, err := json.Marshal(config)
		require.NoError(t, err)

		assert.Contains(t, string(data), SettingRiskScoreThreshold)
		assert.Contains(t, string(data), "70")
	})
}

func TestLspFolderConfig_Settings_NilRoundTrip(t *testing.T) {
	t.Run("nil settings round-trips correctly", func(t *testing.T) {
		config := LspFolderConfig{
			FolderPath: "/path/to/folder",
			Settings:   nil,
		}

		data, err := json.Marshal(config)
		require.NoError(t, err)
		assert.NotContains(t, string(data), "settings")

		var result LspFolderConfig
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.Nil(t, result.Settings)
		assert.Equal(t, FilePath("/path/to/folder"), result.FolderPath)
	})
}

func TestLspFolderConfig_Settings_UnmarshalJSON(t *testing.T) {
	t.Run("omitted settings is nil", func(t *testing.T) {
		jsonBlob := `{"folderPath": "/path/to/folder"}`

		var config LspFolderConfig
		err := json.Unmarshal([]byte(jsonBlob), &config)

		require.NoError(t, err)
		assert.Equal(t, FilePath("/path/to/folder"), config.FolderPath)
		assert.Nil(t, config.Settings)
	})

	t.Run("value null and changed true indicates clear override", func(t *testing.T) {
		jsonBlob := `{
			"folderPath": "/path/to/folder",
			"settings": {
				"scan_automatic": {"value": null, "changed": true},
				"snyk_code_enabled": {"value": null, "changed": true}
			}
		}`

		var config LspFolderConfig
		err := json.Unmarshal([]byte(jsonBlob), &config)

		require.NoError(t, err)
		require.NotNil(t, config.Settings[SettingScanAutomatic])
		assert.True(t, config.Settings[SettingScanAutomatic].Changed)
		assert.Nil(t, config.Settings[SettingScanAutomatic].Value)
		require.NotNil(t, config.Settings[SettingSnykCodeEnabled])
		assert.True(t, config.Settings[SettingSnykCodeEnabled].Changed)
		assert.Nil(t, config.Settings[SettingSnykCodeEnabled].Value)
	})

	t.Run("value fields indicate set override", func(t *testing.T) {
		jsonBlob := `{
			"folderPath": "/path/to/folder",
			"settings": {
				"scan_automatic": {"value": true, "changed": true},
				"scan_net_new": {"value": false, "changed": true},
				"snyk_code_enabled": {"value": true, "changed": true}
			}
		}`

		var config LspFolderConfig
		err := json.Unmarshal([]byte(jsonBlob), &config)

		require.NoError(t, err)
		require.NotNil(t, config.Settings[SettingScanAutomatic])
		assert.True(t, config.Settings[SettingScanAutomatic].Changed)
		assert.Equal(t, true, config.Settings[SettingScanAutomatic].Value)
		require.NotNil(t, config.Settings[SettingScanNetNew])
		assert.True(t, config.Settings[SettingScanNetNew].Changed)
		assert.Equal(t, false, config.Settings[SettingScanNetNew].Value)
		require.NotNil(t, config.Settings[SettingSnykCodeEnabled])
		assert.True(t, config.Settings[SettingSnykCodeEnabled].Changed)
		assert.Equal(t, true, config.Settings[SettingSnykCodeEnabled].Value)
	})

	t.Run("mixed omitted, null, and value fields", func(t *testing.T) {
		jsonBlob := `{
			"folderPath": "/path/to/folder",
			"settings": {
				"scan_automatic": {"value": true, "changed": true},
				"scan_net_new": {"value": null, "changed": true},
				"risk_score_threshold": {"value": 70, "changed": true}
			}
		}`

		var config LspFolderConfig
		err := json.Unmarshal([]byte(jsonBlob), &config)

		require.NoError(t, err)
		require.NotNil(t, config.Settings[SettingScanAutomatic])
		assert.True(t, config.Settings[SettingScanAutomatic].Changed)
		assert.Equal(t, true, config.Settings[SettingScanAutomatic].Value)
		require.NotNil(t, config.Settings[SettingScanNetNew])
		assert.True(t, config.Settings[SettingScanNetNew].Changed)
		assert.Nil(t, config.Settings[SettingScanNetNew].Value)
		require.NotNil(t, config.Settings[SettingRiskScoreThreshold])
		assert.True(t, config.Settings[SettingRiskScoreThreshold].Changed)
		assert.Equal(t, float64(70), config.Settings[SettingRiskScoreThreshold].Value)
		assert.Nil(t, config.Settings[SettingSnykCodeEnabled])
		assert.Nil(t, config.Settings[SettingSnykOssEnabled])
	})
}

func TestLspFolderConfig_FolderScopeSettings(t *testing.T) {
	t.Run("folder-scope settings marshal and unmarshal", func(t *testing.T) {
		config := LspFolderConfig{
			FolderPath: "/path/to/folder",
			Settings: map[string]*ConfigSetting{
				SettingBaseBranch:    {Value: "main", Source: "folder"},
				SettingScanAutomatic: {Value: true, Changed: true},
			},
		}

		data, err := json.Marshal(config)
		require.NoError(t, err)

		var result LspFolderConfig
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		require.NotNil(t, result.Settings[SettingBaseBranch])
		assert.Equal(t, "main", result.Settings[SettingBaseBranch].Value)
		require.NotNil(t, result.Settings[SettingScanAutomatic])
		assert.Equal(t, true, result.Settings[SettingScanAutomatic].Value)
	})

	t.Run("nil folder-scope setting is omitted from JSON", func(t *testing.T) {
		config := LspFolderConfig{
			FolderPath: "/path/to/folder",
			Settings:   map[string]*ConfigSetting{},
		}

		data, err := json.Marshal(config)
		require.NoError(t, err)
		assert.NotContains(t, string(data), "base_branch")
	})
}
