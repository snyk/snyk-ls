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
	"github.com/snyk/snyk-ls/internal/util"
	"github.com/stretchr/testify/assert"
)

func ptr[T any](v T) *T {
	return &v
}

func TestConvertLDXSyncResponseToOrgConfig(t *testing.T) {
	t.Run("returns nil for nil response", func(t *testing.T) {
		result := ConvertLDXSyncResponseToOrgConfig("org1", nil)
		assert.Nil(t, result)
	})

	t.Run("converts settings with metadata", func(t *testing.T) {
		response := &v20241015.UserConfigResponse{}
		response.Data.Attributes.Settings = &map[string]v20241015.SettingMetadata{
			"risk_score_threshold": {
				Value:    500,
				Locked:   ptr(true),
				Enforced: ptr(false),
				Origin:   v20241015.SettingMetadataOriginGroup,
			},
			"automatic": {
				Value:    true,
				Locked:   ptr(false),
				Enforced: ptr(true),
				Origin:   v20241015.SettingMetadataOriginOrg,
			},
		}

		result := ConvertLDXSyncResponseToOrgConfig("org1", response)

		assert.NotNil(t, result)
		assert.Equal(t, "org1", result.OrgId)

		// Check risk_score_threshold
		riskField := result.GetField(SettingRiskScoreThreshold)
		assert.NotNil(t, riskField)
		assert.Equal(t, 500, riskField.Value)
		assert.True(t, riskField.IsLocked)
		assert.False(t, riskField.IsEnforced)
		assert.Equal(t, "group", riskField.OriginScope)

		// Check automatic (scan_automatic)
		autoField := result.GetField(SettingScanAutomatic)
		assert.NotNil(t, autoField)
		assert.Equal(t, true, autoField.Value)
		assert.False(t, autoField.IsLocked)
		assert.True(t, autoField.IsEnforced)
		assert.Equal(t, "org", autoField.OriginScope)
	})

	t.Run("handles nil locked/enforced pointers", func(t *testing.T) {
		response := &v20241015.UserConfigResponse{}
		response.Data.Attributes.Settings = &map[string]v20241015.SettingMetadata{
			"net_new": {
				Value:  true,
				Origin: v20241015.SettingMetadataOriginUser,
			},
		}

		result := ConvertLDXSyncResponseToOrgConfig("org1", response)

		field := result.GetField(SettingScanNetNew)
		assert.NotNil(t, field)
		assert.False(t, field.IsLocked)
		assert.False(t, field.IsEnforced)
	})

	t.Run("ignores unknown settings", func(t *testing.T) {
		response := &v20241015.UserConfigResponse{}
		response.Data.Attributes.Settings = &map[string]v20241015.SettingMetadata{
			"unknown_setting": {
				Value:  "test",
				Origin: v20241015.SettingMetadataOriginOrg,
			},
		}

		result := ConvertLDXSyncResponseToOrgConfig("org1", response)

		assert.NotNil(t, result)
		assert.Empty(t, result.Fields)
	})
}

func TestExtractFolderSettings(t *testing.T) {
	t.Run("extracts folder-specific settings", func(t *testing.T) {
		locked := true
		enforced := false
		response := &v20241015.UserConfigResponse{}
		response.Data.Attributes.FolderSettings = &map[string]map[string]v20241015.SettingMetadata{
			"git@github.com:snyk/test-repo.git": {
				"reference_branch": {
					Value:    "develop",
					Origin:   v20241015.SettingMetadataOriginOrg,
					Locked:   &locked,
					Enforced: &enforced,
				},
			},
		}

		result := ExtractFolderSettings(response, "git@github.com:snyk/test-repo.git")

		assert.NotNil(t, result)
		branchField := result[SettingReferenceBranch]
		assert.NotNil(t, branchField)
		assert.Equal(t, "develop", branchField.Value)
		assert.True(t, branchField.IsLocked)
		assert.False(t, branchField.IsEnforced)
	})

	t.Run("returns nil for missing remote URL", func(t *testing.T) {
		response := &v20241015.UserConfigResponse{}
		response.Data.Attributes.FolderSettings = &map[string]map[string]v20241015.SettingMetadata{
			"git@github.com:snyk/test-repo.git": {
				"reference_branch": {
					Value:  "develop",
					Origin: v20241015.SettingMetadataOriginOrg,
				},
			},
		}

		result := ExtractFolderSettings(response, "git@github.com:snyk/other-repo.git")
		assert.Nil(t, result)
	})

	t.Run("returns nil for nil response", func(t *testing.T) {
		result := ExtractFolderSettings(nil, "git@github.com:snyk/test-repo.git")
		assert.Nil(t, result)
	})

	t.Run("returns nil for empty remote URL", func(t *testing.T) {
		response := &v20241015.UserConfigResponse{}
		response.Data.Attributes.FolderSettings = &map[string]map[string]v20241015.SettingMetadata{
			"git@github.com:snyk/test-repo.git": {
				"reference_branch": {
					Value:  "develop",
					Origin: v20241015.SettingMetadataOriginOrg,
				},
			},
		}

		result := ExtractFolderSettings(response, "")
		assert.Nil(t, result)
	})

	t.Run("returns nil for nil folder settings", func(t *testing.T) {
		response := &v20241015.UserConfigResponse{}
		result := ExtractFolderSettings(response, "git@github.com:snyk/test-repo.git")
		assert.Nil(t, result)
	})
}

func TestExtractMachineSettings(t *testing.T) {
	t.Run("extracts machine-scope settings only", func(t *testing.T) {
		locked := true
		response := &v20241015.UserConfigResponse{}
		response.Data.Attributes.Settings = &map[string]v20241015.SettingMetadata{
			// Machine-scope setting
			"cli_path": {
				Value:  "/usr/local/bin/snyk",
				Origin: v20241015.SettingMetadataOriginOrg,
				Locked: &locked,
			},
			// Org-scope setting (should be excluded)
			"automatic": {
				Value:  true,
				Origin: v20241015.SettingMetadataOriginOrg,
			},
		}

		result := ExtractMachineSettings(response)

		assert.NotNil(t, result)
		// Should have machine-scope setting
		cliField := result[SettingCliPath]
		assert.NotNil(t, cliField)
		assert.Equal(t, "/usr/local/bin/snyk", cliField.Value)
		assert.True(t, cliField.IsLocked)

		// Should NOT have org-scope setting
		_, hasAuto := result[SettingScanAutomatic]
		assert.False(t, hasAuto)
	})

	t.Run("returns nil for nil response", func(t *testing.T) {
		result := ExtractMachineSettings(nil)
		assert.Nil(t, result)
	})

	t.Run("returns nil for nil settings", func(t *testing.T) {
		response := &v20241015.UserConfigResponse{}
		result := ExtractMachineSettings(response)
		assert.Nil(t, result)
	})

	t.Run("returns nil when no machine-scope settings present", func(t *testing.T) {
		response := &v20241015.UserConfigResponse{}
		response.Data.Attributes.Settings = &map[string]v20241015.SettingMetadata{
			// Only org-scope setting
			"automatic": {
				Value:  true,
				Origin: v20241015.SettingMetadataOriginOrg,
			},
		}

		result := ExtractMachineSettings(response)
		assert.Nil(t, result)
	})
}

func TestExtractOrgIdFromResponse(t *testing.T) {
	t.Run("returns empty for nil response", func(t *testing.T) {
		result := ExtractOrgIdFromResponse(nil)
		assert.Empty(t, result)
	})

	t.Run("returns empty for nil organizations", func(t *testing.T) {
		response := &v20241015.UserConfigResponse{}
		result := ExtractOrgIdFromResponse(response)
		assert.Empty(t, result)
	})

	t.Run("returns preferred organization", func(t *testing.T) {
		response := &v20241015.UserConfigResponse{}
		response.Data.Attributes.Organizations = &[]v20241015.Organization{
			{Id: "org1", Name: "Org 1", Slug: "org1", IsDefault: ptr(true)},
			{Id: "org2", Name: "Org 2", Slug: "org2", PreferredByAlgorithm: ptr(true)},
		}

		result := ExtractOrgIdFromResponse(response)
		assert.Equal(t, "org2", result)
	})

	t.Run("falls back to default organization", func(t *testing.T) {
		response := &v20241015.UserConfigResponse{}
		response.Data.Attributes.Organizations = &[]v20241015.Organization{
			{Id: "org1", Name: "Org 1", Slug: "org1", IsDefault: ptr(true)},
			{Id: "org2", Name: "Org 2", Slug: "org2"},
		}

		result := ExtractOrgIdFromResponse(response)
		assert.Equal(t, "org1", result)
	})

	t.Run("falls back to first organization", func(t *testing.T) {
		response := &v20241015.UserConfigResponse{}
		response.Data.Attributes.Organizations = &[]v20241015.Organization{
			{Id: "org1", Name: "Org 1", Slug: "org1"},
			{Id: "org2", Name: "Org 2", Slug: "org2"},
		}

		result := ExtractOrgIdFromResponse(response)
		assert.Equal(t, "org1", result)
	})
}

func TestGetLDXSyncKey(t *testing.T) {
	t.Run("every registered setting has an LDX-Sync key mapping", func(t *testing.T) {
		// These settings are derived from the composite "products" LDX-Sync field
		// via convertProductsToIndividualSettings, not mapped 1:1 to an API key.
		productDerived := map[string]bool{
			SettingSnykCodeEnabled: true,
			SettingSnykOssEnabled:  true,
			SettingSnykIacEnabled:  true,
		}

		// settingScopeRegistry is the source of truth for all known settings.
		// Every non-product-derived setting must have a corresponding entry in ldxSyncSettingKeyMap.
		for settingName := range settingScopeRegistry {
			if productDerived[settingName] {
				continue
			}
			key := GetLDXSyncKey(settingName)
			assert.NotEmptyf(t, key, "setting %q is in settingScopeRegistry but has no LDX-Sync key mapping", settingName)
		}
	})

	t.Run("no duplicate LDX-Sync keys", func(t *testing.T) {
		seen := make(map[string]string)
		for settingName := range settingScopeRegistry {
			key := GetLDXSyncKey(settingName)
			if key == "" {
				continue
			}
			if existing, exists := seen[key]; exists {
				t.Errorf("LDX-Sync key %q is mapped by both %q and %q", key, existing, settingName)
			}
			seen[key] = settingName
		}
	})

	t.Run("spot-check specific mappings", func(t *testing.T) {
		assert.Equal(t, "risk_score_threshold", GetLDXSyncKey(SettingRiskScoreThreshold))
		assert.Equal(t, "automatic", GetLDXSyncKey(SettingScanAutomatic))
		assert.Equal(t, "reference_branch", GetLDXSyncKey(SettingReferenceBranch))
	})

	t.Run("returns empty for unknown setting", func(t *testing.T) {
		assert.Empty(t, GetLDXSyncKey("unknown_setting"))
	})
}

func TestPtrToBool(t *testing.T) {
	t.Run("returns false for nil", func(t *testing.T) {
		assert.False(t, util.ptrToBool(nil))
	})

	t.Run("returns true for true pointer", func(t *testing.T) {
		assert.True(t, util.ptrToBool(ptr(true)))
	})

	t.Run("returns false for false pointer", func(t *testing.T) {
		assert.False(t, util.ptrToBool(ptr(false)))
	})
}
