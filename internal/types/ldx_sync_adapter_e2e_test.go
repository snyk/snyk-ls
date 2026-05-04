//go:build !integration && !smoke

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

	v20241015 "github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config/ldx_sync/2024-10-15"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2E_ExtractFolderSettings_URLNormalization verifies the full URL normalization flow through
// the LDX folder settings path: when the API returns folder_settings keyed by a normalized URL,
// the client must resolve those settings regardless of the URL format used locally.
func TestE2E_ExtractFolderSettings_URLNormalization(t *testing.T) {
	normalizedURL := "https://github.com/snyk/test-repo"
	locked := true

	response := &v20241015.UserConfigResponse{}
	response.Data.Attributes.FolderSettings = &map[string]map[string]v20241015.SettingMetadata{
		normalizedURL: {
			SettingScanAutomatic: {
				Value:  true,
				Origin: v20241015.SettingMetadataOriginOrg,
				Locked: &locked,
			},
			SettingIssueViewOpenIssues: {
				Value:  true,
				Origin: v20241015.SettingMetadataOriginOrg,
			},
		},
	}

	variants := []struct {
		name string
		url  string
	}{
		{"SSH URL", "git@github.com:snyk/test-repo.git"},
		{"HTTPS with credentials", "https://user:password@github.com/snyk/test-repo.git"},
		{"raw normalized HTTPS", "https://github.com/snyk/test-repo"},
	}

	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			result := ExtractFolderSettings(response, v.url)
			require.NotNil(t, result, "expected folder settings for URL variant %q", v.url)

			autoField := result[SettingScanAutomatic]
			require.NotNil(t, autoField)
			assert.Equal(t, true, autoField.Value)
			assert.True(t, autoField.IsLocked)

			issueField := result[SettingIssueViewOpenIssues]
			require.NotNil(t, issueField)
			assert.Equal(t, true, issueField.Value)
		})
	}

	t.Run("collision policy: last sorted key wins", func(t *testing.T) {
		collisionResponse := &v20241015.UserConfigResponse{}
		collisionResponse.Data.Attributes.FolderSettings = &map[string]map[string]v20241015.SettingMetadata{
			"git@github.com:snyk/test-repo.git": {
				SettingScanAutomatic: {
					Value:  false,
					Origin: v20241015.SettingMetadataOriginOrg,
				},
			},
			"https://github.com/snyk/test-repo": {
				SettingScanAutomatic: {
					Value:  true,
					Origin: v20241015.SettingMetadataOriginOrg,
				},
			},
		}

		result := ExtractFolderSettings(collisionResponse, "git@github.com:snyk/test-repo.git")
		require.NotNil(t, result)
		autoField := result[SettingScanAutomatic]
		require.NotNil(t, autoField)
		assert.Equal(t, true, autoField.Value)
	})
}
