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

// ABOUTME: Tests for LdxSyncService with full API mocking
// ABOUTME: Covers RefreshConfigFromLdxSync and FolderToOrgMapping population

package command

import (
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config"
	v20241015 "github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config/ldx_sync/2024-10-15"

	mock_command "github.com/snyk/snyk-ls/domain/ide/command/mock"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/testutil/workspaceutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

// createLdxSyncResultWithOrg is a helper to create a LdxSyncConfigResult with an org ID for tests
func createLdxSyncResultWithOrg(orgId string) ldx_sync_config.LdxSyncConfigResult {
	orgs := []v20241015.Organization{
		{
			Id:                   orgId,
			Name:                 "Test Org",
			Slug:                 "test-org",
			IsDefault:            util.Ptr(true),
			PreferredByAlgorithm: util.Ptr(true),
		},
	}

	configId := uuid.MustParse("00000000-0000-0000-0000-000000000001")

	return ldx_sync_config.LdxSyncConfigResult{
		Config: &v20241015.UserConfigResponse{
			Data: struct {
				Attributes struct {
					CreatedAt      *time.Time                                       `json:"created_at,omitempty"`
					FolderSettings *map[string]map[string]v20241015.SettingMetadata `json:"folder_settings,omitempty"`
					LastModifiedAt *time.Time                                       `json:"last_modified_at,omitempty"`
					Organizations  *[]v20241015.Organization                        `json:"organizations,omitempty"`
					Scope          *v20241015.UserConfigResponseDataAttributesScope `json:"scope,omitempty"`
					Settings       *map[string]v20241015.SettingMetadata            `json:"settings,omitempty"`
				} `json:"attributes"`
				Id   uuid.UUID                            `json:"id"`
				Type v20241015.UserConfigResponseDataType `json:"type"`
			}{
				Attributes: struct {
					CreatedAt      *time.Time                                       `json:"created_at,omitempty"`
					FolderSettings *map[string]map[string]v20241015.SettingMetadata `json:"folder_settings,omitempty"`
					LastModifiedAt *time.Time                                       `json:"last_modified_at,omitempty"`
					Organizations  *[]v20241015.Organization                        `json:"organizations,omitempty"`
					Scope          *v20241015.UserConfigResponseDataAttributesScope `json:"scope,omitempty"`
					Settings       *map[string]v20241015.SettingMetadata            `json:"settings,omitempty"`
				}{
					Organizations: &orgs,
				},
				Id:   configId,
				Type: "configuration",
			},
		},
		Error: nil,
	}
}

func Test_RefreshConfigFromLdxSync_NoFolders(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mock_command.NewMockLdxSyncApiClient(ctrl)

	service := NewLdxSyncServiceWithApiClient(mockApiClient)

	// No API calls should be made for empty folder list
	service.RefreshConfigFromLdxSync(c, []types.Folder{}, nil)

	// Verify FolderToOrgMapping is empty
	cache := c.GetLdxSyncOrgConfigCache()
	orgId := cache.GetOrgIdForFolder(types.FilePath("/nonexistent"))
	assert.Empty(t, orgId)
}

func Test_RefreshConfigFromLdxSync_SingleFolder_Success(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mock_command.NewMockLdxSyncApiClient(ctrl)

	folderPath := types.FilePath("/test/folder")
	workspaceutil.SetupWorkspace(t, c, folderPath)
	folders := c.Workspace().Folders()

	expectedOrgId := "test-org-id-123"
	expectedResult := createLdxSyncResultWithOrg(expectedOrgId)

	// Expect API call with empty preferredOrg (no folder config exists)
	mockApiClient.EXPECT().
		GetUserConfigForProject(c.Engine(), string(folderPath), "").
		Return(expectedResult)

	service := NewLdxSyncServiceWithApiClient(mockApiClient)
	service.RefreshConfigFromLdxSync(c, folders, nil)

	// Verify FolderToOrgMapping was populated
	cache := c.GetLdxSyncOrgConfigCache()
	orgId := cache.GetOrgIdForFolder(folderPath)
	assert.Equal(t, expectedOrgId, orgId)
}

func Test_RefreshConfigFromLdxSync_WithPreferredOrg(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mock_command.NewMockLdxSyncApiClient(ctrl)

	folderPath := types.FilePath("/test/folder")
	workspaceutil.SetupWorkspace(t, c, folderPath)
	folders := c.Workspace().Folders()

	// Set up folder config with PreferredOrg
	preferredOrg := "test-org-123"
	folderConfig := &types.StoredFolderConfig{
		FolderPath:   folderPath,
		PreferredOrg: preferredOrg,
	}
	err := storedconfig.UpdateStoredFolderConfig(c.Engine().GetConfiguration(), folderConfig, c.Logger())
	require.NoError(t, err)

	expectedOrgId := "resolved-org-id"
	expectedResult := createLdxSyncResultWithOrg(expectedOrgId)

	// Expect API call with preferredOrg from folder config
	mockApiClient.EXPECT().
		GetUserConfigForProject(c.Engine(), string(folderPath), preferredOrg).
		Return(expectedResult)

	service := NewLdxSyncServiceWithApiClient(mockApiClient)
	service.RefreshConfigFromLdxSync(c, folders, nil)

	// Verify FolderToOrgMapping was populated
	cache := c.GetLdxSyncOrgConfigCache()
	orgId := cache.GetOrgIdForFolder(folderPath)
	assert.Equal(t, expectedOrgId, orgId)
}

func Test_RefreshConfigFromLdxSync_MultipleFolders(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mock_command.NewMockLdxSyncApiClient(ctrl)

	folder1Path := types.FilePath("/test/folder1")
	folder2Path := types.FilePath("/test/folder2")
	folder3Path := types.FilePath("/test/folder3")

	workspaceutil.SetupWorkspace(t, c, folder1Path, folder2Path, folder3Path)
	folders := c.Workspace().Folders()

	result1 := createLdxSyncResultWithOrg("org-1")
	result2 := createLdxSyncResultWithOrg("org-2")
	result3 := createLdxSyncResultWithOrg("org-3")

	// Expect API calls for all folders (order may vary due to parallel execution)
	mockApiClient.EXPECT().
		GetUserConfigForProject(c.Engine(), string(folder1Path), "").
		Return(result1)
	mockApiClient.EXPECT().
		GetUserConfigForProject(c.Engine(), string(folder2Path), "").
		Return(result2)
	mockApiClient.EXPECT().
		GetUserConfigForProject(c.Engine(), string(folder3Path), "").
		Return(result3)

	service := NewLdxSyncServiceWithApiClient(mockApiClient)
	service.RefreshConfigFromLdxSync(c, folders, nil)

	// Verify all FolderOrgMappings were populated
	cache := c.GetLdxSyncOrgConfigCache()
	assert.Equal(t, "org-1", cache.GetOrgIdForFolder(folder1Path))
	assert.Equal(t, "org-2", cache.GetOrgIdForFolder(folder2Path))
	assert.Equal(t, "org-3", cache.GetOrgIdForFolder(folder3Path))
}

func Test_RefreshConfigFromLdxSync_ApiError_NotCached(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mock_command.NewMockLdxSyncApiClient(ctrl)

	folderPath := types.FilePath("/test/folder")
	workspaceutil.SetupWorkspace(t, c, folderPath)
	folders := c.Workspace().Folders()

	errorResult := ldx_sync_config.LdxSyncConfigResult{
		Error: assert.AnError,
	}

	mockApiClient.EXPECT().
		GetUserConfigForProject(c.Engine(), string(folderPath), "").
		Return(errorResult)

	service := NewLdxSyncServiceWithApiClient(mockApiClient)
	service.RefreshConfigFromLdxSync(c, folders, nil)

	// Verify FolderToOrgMapping was NOT populated for error result
	cache := c.GetLdxSyncOrgConfigCache()
	orgId := cache.GetOrgIdForFolder(folderPath)
	assert.Empty(t, orgId, "Error results should not populate FolderToOrgMapping")
}

func Test_DefaultLdxSyncApiClient_GetUserConfigForProject(t *testing.T) {
	c := testutil.UnitTest(t)

	client := &DefaultLdxSyncApiClient{}

	// This is an integration-style test that calls the real GAF function
	// It will likely fail or return errors without proper auth/network
	// but verifies the wrapper compiles and delegates correctly
	result := client.GetUserConfigForProject(c.Engine(), "/test/path", "test-org")

	// We expect an error since we're not actually authenticated
	assert.NotNil(t, result.Error, "Expected error from real API call without authentication")
}

func Test_NewLdxSyncService_UsesDefaultApiClient(t *testing.T) {
	service := NewLdxSyncService()

	// Verify it returns a service (we can't easily inspect the private apiClient field,
	// but this ensures the constructor works)
	assert.NotNil(t, service)

	// Type assertion to verify it's the correct concrete type
	defaultService, ok := service.(*DefaultLdxSyncService)
	assert.True(t, ok, "Expected *DefaultLdxSyncService")
	assert.NotNil(t, defaultService.apiClient, "API client should be initialized")
}

func Test_NewLdxSyncServiceWithApiClient_UsesProvidedClient(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockApiClient := mock_command.NewMockLdxSyncApiClient(ctrl)

	service := NewLdxSyncServiceWithApiClient(mockApiClient)

	assert.NotNil(t, service)

	// Type assertion to verify structure
	defaultService, ok := service.(*DefaultLdxSyncService)
	assert.True(t, ok, "Expected *DefaultLdxSyncService")
	assert.Equal(t, mockApiClient, defaultService.apiClient, "Should use provided API client")
}

// Boundary and edge case tests

func Test_RefreshConfigFromLdxSync_EmptyFolderPath(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mock_command.NewMockLdxSyncApiClient(ctrl)

	emptyPath := types.FilePath("")
	workspaceutil.SetupWorkspace(t, c, emptyPath)
	folders := c.Workspace().Folders()

	expectedOrgId := "org-for-empty-path"
	expectedResult := createLdxSyncResultWithOrg(expectedOrgId)

	// Should handle empty path gracefully
	mockApiClient.EXPECT().
		GetUserConfigForProject(c.Engine(), string(emptyPath), "").
		Return(expectedResult)

	service := NewLdxSyncServiceWithApiClient(mockApiClient)
	service.RefreshConfigFromLdxSync(c, folders, nil)

	// Should populate FolderToOrgMapping even with empty path
	cache := c.GetLdxSyncOrgConfigCache()
	orgId := cache.GetOrgIdForFolder(emptyPath)
	assert.Equal(t, expectedOrgId, orgId)
}

func Test_GetOrgIdForFolder_EmptyFolderPath_ReturnsEmpty(t *testing.T) {
	c := testutil.UnitTest(t)

	// Cache is lazily initialized, don't populate it
	cache := c.GetLdxSyncOrgConfigCache()
	orgId := cache.GetOrgIdForFolder(types.FilePath(""))

	// Should return empty string when no mapping exists
	assert.Empty(t, orgId)
}

func Test_RefreshConfigFromLdxSync_ClearsLockedOverridesFromStoredFolderConfigs(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mock_command.NewMockLdxSyncApiClient(ctrl)
	logger := c.Logger()

	// Setup folder with user override
	folderPath := types.FilePath("/test/folder")
	workspaceutil.SetupWorkspace(t, c, folderPath)
	folders := c.Workspace().Folders()

	// Create folder config with user override for a setting that will become locked
	folderConfig := &types.StoredFolderConfig{
		FolderPath:    folderPath,
		UserOverrides: map[string]any{types.SettingEnabledSeverities: []string{"high", "critical"}},
	}
	err := storedconfig.UpdateStoredFolderConfig(c.Engine().GetConfiguration(), folderConfig, logger)
	require.NoError(t, err)

	// Verify override exists before refresh
	storedBefore, err := storedconfig.GetStoredFolderConfigWithOptions(c.Engine().GetConfiguration(), folderPath, logger, storedconfig.GetStoredFolderConfigOptions{
		CreateIfNotExist: false,
		ReadOnly:         true,
	})
	require.NoError(t, err)
	require.NotNil(t, storedBefore)
	require.True(t, storedBefore.HasUserOverride(types.SettingEnabledSeverities), "User override should exist before refresh")

	// Create LDX-Sync result with locked field (use LDX-Sync API field name "severities")
	orgId := "test-org-id"
	result := createLdxSyncResultWithLockedField(orgId, "severities")

	mockApiClient.EXPECT().
		GetUserConfigForProject(c.Engine(), string(folderPath), "").
		Return(result)

	// Setup folder-to-org mapping so clearLockedOverridesFromStoredFolderConfigs can find the org
	cache := c.GetLdxSyncOrgConfigCache()
	cache.SetFolderOrg(folderPath, orgId)

	service := NewLdxSyncServiceWithApiClient(mockApiClient)
	service.RefreshConfigFromLdxSync(c, folders, nil)

	// Verify user override was cleared for the locked field
	storedAfter, err := storedconfig.GetStoredFolderConfigWithOptions(c.Engine().GetConfiguration(), folderPath, logger, storedconfig.GetStoredFolderConfigOptions{
		CreateIfNotExist: false,
		ReadOnly:         true,
	})
	require.NoError(t, err)
	require.NotNil(t, storedAfter)
	assert.False(t, storedAfter.HasUserOverride(types.SettingEnabledSeverities), "User override should be cleared for locked field")
}

func Test_RefreshConfigFromLdxSync_PreservesNonLockedOverrides(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mock_command.NewMockLdxSyncApiClient(ctrl)
	logger := c.Logger()

	// Setup folder with user overrides
	folderPath := types.FilePath("/test/folder2")
	workspaceutil.SetupWorkspace(t, c, folderPath)
	folders := c.Workspace().Folders()

	// Create folder config with user overrides for both locked and non-locked settings
	folderConfig := &types.StoredFolderConfig{
		FolderPath: folderPath,
		UserOverrides: map[string]any{
			types.SettingEnabledSeverities: []string{"high", "critical"}, // Will be locked
			types.SettingScanAutomatic:     true,                         // Will NOT be locked
		},
	}
	err := storedconfig.UpdateStoredFolderConfig(c.Engine().GetConfiguration(), folderConfig, logger)
	require.NoError(t, err)

	// Create LDX-Sync result with only one field locked (use LDX-Sync API field name "severities")
	orgId := "test-org-id-2"
	result := createLdxSyncResultWithLockedField(orgId, "severities")

	mockApiClient.EXPECT().
		GetUserConfigForProject(c.Engine(), string(folderPath), "").
		Return(result)

	// Setup folder-to-org mapping
	cache := c.GetLdxSyncOrgConfigCache()
	cache.SetFolderOrg(folderPath, orgId)

	service := NewLdxSyncServiceWithApiClient(mockApiClient)
	service.RefreshConfigFromLdxSync(c, folders, nil)

	// Verify locked override was cleared but non-locked override was preserved
	storedAfter, err := storedconfig.GetStoredFolderConfigWithOptions(c.Engine().GetConfiguration(), folderPath, logger, storedconfig.GetStoredFolderConfigOptions{
		CreateIfNotExist: false,
		ReadOnly:         true,
	})
	require.NoError(t, err)
	require.NotNil(t, storedAfter)
	assert.False(t, storedAfter.HasUserOverride(types.SettingEnabledSeverities), "Locked override should be cleared")
	assert.True(t, storedAfter.HasUserOverride(types.SettingScanAutomatic), "Non-locked override should be preserved")
}

// createLdxSyncResultWithLockedField creates a LdxSyncConfigResult with a locked field
func createLdxSyncResultWithLockedField(orgId string, lockedFieldName string) ldx_sync_config.LdxSyncConfigResult {
	orgs := []v20241015.Organization{
		{
			Id:                   orgId,
			Name:                 "Test Org",
			Slug:                 "test-org",
			IsDefault:            util.Ptr(true),
			PreferredByAlgorithm: util.Ptr(true),
		},
	}

	// Create settings with a locked field using the correct API field names
	settings := map[string]v20241015.SettingMetadata{
		lockedFieldName: {
			Locked:   util.Ptr(true),
			Enforced: util.Ptr(false),
			Origin:   v20241015.SettingMetadataOriginOrg,
			Value:    []string{"low", "medium", "high", "critical"},
		},
	}

	configId := uuid.MustParse("00000000-0000-0000-0000-000000000002")

	return ldx_sync_config.LdxSyncConfigResult{
		Config: &v20241015.UserConfigResponse{
			Data: struct {
				Attributes struct {
					CreatedAt      *time.Time                                       `json:"created_at,omitempty"`
					FolderSettings *map[string]map[string]v20241015.SettingMetadata `json:"folder_settings,omitempty"`
					LastModifiedAt *time.Time                                       `json:"last_modified_at,omitempty"`
					Organizations  *[]v20241015.Organization                        `json:"organizations,omitempty"`
					Scope          *v20241015.UserConfigResponseDataAttributesScope `json:"scope,omitempty"`
					Settings       *map[string]v20241015.SettingMetadata            `json:"settings,omitempty"`
				} `json:"attributes"`
				Id   uuid.UUID                            `json:"id"`
				Type v20241015.UserConfigResponseDataType `json:"type"`
			}{
				Attributes: struct {
					CreatedAt      *time.Time                                       `json:"created_at,omitempty"`
					FolderSettings *map[string]map[string]v20241015.SettingMetadata `json:"folder_settings,omitempty"`
					LastModifiedAt *time.Time                                       `json:"last_modified_at,omitempty"`
					Organizations  *[]v20241015.Organization                        `json:"organizations,omitempty"`
					Scope          *v20241015.UserConfigResponseDataAttributesScope `json:"scope,omitempty"`
					Settings       *map[string]v20241015.SettingMetadata            `json:"settings,omitempty"`
				}{
					Organizations: &orgs,
					Settings:      &settings,
				},
				Id:   configId,
				Type: "configuration",
			},
		},
		Error: nil,
	}
}
