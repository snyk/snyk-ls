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
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config"
	v20241015 "github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config/ldx_sync/2024-10-15"
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/application/config"
	mockcommand "github.com/snyk/snyk-ls/domain/ide/command/mock"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/testutil/workspaceutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

func defaultResolver(c *config.Config) types.ConfigResolverInterface {
	return testutil.DefaultConfigResolver(c)
}

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
	mockApiClient := mockcommand.NewMockLdxSyncApiClient(ctrl)

	service := NewLdxSyncServiceWithApiClient(mockApiClient, defaultResolver(c))

	// No API calls should be made for empty folder list
	service.RefreshConfigFromLdxSync(context.Background(), c, []types.Folder{}, nil)

	// Verify FolderToOrgMapping is empty
	cache := c.GetLdxSyncOrgConfigCache()
	orgId := cache.GetOrgIdForFolder(types.FilePath("/nonexistent"))
	assert.Empty(t, orgId)
}

func Test_RefreshConfigFromLdxSync_SingleFolder_Success(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mockcommand.NewMockLdxSyncApiClient(ctrl)

	folderPath := types.PathKey("/test/folder")
	workspaceutil.SetupWorkspace(t, c, folderPath)
	folders := c.Workspace().Folders()

	expectedOrgId := "test-org-id-123"
	expectedResult := createLdxSyncResultWithOrg(expectedOrgId)

	// Expect API call with empty preferredOrg (no folder config exists)
	// Use normalized path from Folder object since NewFolder normalizes paths
	mockApiClient.EXPECT().
		GetUserConfigForProject(gomock.Any(), c.Engine(), string(folders[0].Path()), "").
		Return(expectedResult)

	service := NewLdxSyncServiceWithApiClient(mockApiClient, defaultResolver(c))
	service.RefreshConfigFromLdxSync(context.Background(), c, folders, nil)

	// Verify FolderToOrgMapping was populated
	cache := c.GetLdxSyncOrgConfigCache()
	orgId := cache.GetOrgIdForFolder(folderPath)
	assert.Equal(t, expectedOrgId, orgId)
}

func Test_RefreshConfigFromLdxSync_WithPreferredOrg(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mockcommand.NewMockLdxSyncApiClient(ctrl)

	folderPath := types.PathKey("/test/folder")
	workspaceutil.SetupWorkspace(t, c, folderPath)
	folders := c.Workspace().Folders()

	// Set up folder config with PreferredOrg
	preferredOrg := "test-org-123"
	engineConfig := c.Engine().GetConfiguration()
	types.SetPreferredOrgAndOrgSetByUser(engineConfig, folderPath, preferredOrg, true)
	err := storedconfig.UpdateFolderConfig(engineConfig, &types.FolderConfig{FolderPath: folderPath}, c.Logger())
	require.NoError(t, err)

	expectedOrgId := "resolved-org-id"
	expectedResult := createLdxSyncResultWithOrg(expectedOrgId)

	// Expect API call with preferredOrg from folder config
	// Use normalized path from Folder object since NewFolder normalizes paths
	mockApiClient.EXPECT().
		GetUserConfigForProject(gomock.Any(), c.Engine(), string(folders[0].Path()), preferredOrg).
		Return(expectedResult)

	service := NewLdxSyncServiceWithApiClient(mockApiClient, defaultResolver(c))
	service.RefreshConfigFromLdxSync(context.Background(), c, folders, nil)

	// Verify FolderToOrgMapping was populated
	cache := c.GetLdxSyncOrgConfigCache()
	orgId := cache.GetOrgIdForFolder(folderPath)
	assert.Equal(t, expectedOrgId, orgId)
}

func Test_RefreshConfigFromLdxSync_MultipleFolders(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mockcommand.NewMockLdxSyncApiClient(ctrl)

	folder1Path := types.PathKey("/test/folder1")
	folder2Path := types.PathKey("/test/folder2")
	folder3Path := types.PathKey("/test/folder3")

	workspaceutil.SetupWorkspace(t, c, folder1Path, folder2Path, folder3Path)
	folders := c.Workspace().Folders()

	// Create a map of folder path to expected org ID for consistent verification
	// Use the actual folder paths from the workspace (which may be in any order)
	folderOrgMap := make(map[types.FilePath]string)
	for i, folder := range folders {
		orgId := fmt.Sprintf("org-%d", i+1)
		folderOrgMap[folder.Path()] = orgId
		result := createLdxSyncResultWithOrg(orgId)
		mockApiClient.EXPECT().
			GetUserConfigForProject(gomock.Any(), c.Engine(), string(folder.Path()), "").
			Return(result)
	}

	service := NewLdxSyncServiceWithApiClient(mockApiClient, defaultResolver(c))
	service.RefreshConfigFromLdxSync(context.Background(), c, folders, nil)

	// Verify all FolderOrgMappings were populated with the expected org IDs
	cache := c.GetLdxSyncOrgConfigCache()
	for _, folder := range folders {
		expectedOrgId := folderOrgMap[folder.Path()]
		actualOrgId := cache.GetOrgIdForFolder(folder.Path())
		assert.Equal(t, expectedOrgId, actualOrgId, "Org ID mismatch for folder %s", folder.Path())
	}
}

func Test_RefreshConfigFromLdxSync_ApiError_NotCached(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mockcommand.NewMockLdxSyncApiClient(ctrl)

	folderPath := types.PathKey("/test/folder")
	workspaceutil.SetupWorkspace(t, c, folderPath)
	folders := c.Workspace().Folders()

	errorResult := ldx_sync_config.LdxSyncConfigResult{
		Error: assert.AnError,
	}

	// Use normalized path from Folder object since NewFolder normalizes paths
	mockApiClient.EXPECT().
		GetUserConfigForProject(gomock.Any(), c.Engine(), string(folders[0].Path()), "").
		Return(errorResult)

	service := NewLdxSyncServiceWithApiClient(mockApiClient, defaultResolver(c))
	service.RefreshConfigFromLdxSync(context.Background(), c, folders, nil)

	// Verify FolderToOrgMapping was NOT populated for error result
	cache := c.GetLdxSyncOrgConfigCache()
	orgId := cache.GetOrgIdForFolder(folderPath)
	assert.Empty(t, orgId, "Error results should not populate FolderToOrgMapping")
}

func Test_DefaultLdxSyncApiClient_GetUserConfigForProject(t *testing.T) {
	c := testutil.UnitTest(t)

	client := &DefaultLdxSyncApiClient{}

	// This is an integration-style test that calls the real framework function
	// It will likely fail or return errors without proper auth/network
	// but verifies the wrapper compiles and delegates correctly
	result := client.GetUserConfigForProject(context.Background(), c.Engine(), "/test/path", "test-org")

	// We expect an error since we're not actually authenticated
	assert.NotNil(t, result.Error, "Expected error from real API call without authentication")
}

func Test_NewLdxSyncService_UsesDefaultApiClient(t *testing.T) {
	c := testutil.UnitTest(t)
	service := NewLdxSyncService(defaultResolver(c))

	// Verify it returns a service (we can't easily inspect the private apiClient field,
	// but this ensures the constructor works)
	assert.NotNil(t, service)

	// Type assertion to verify it's the correct concrete type
	defaultService, ok := service.(*DefaultLdxSyncService)
	assert.True(t, ok, "Expected *DefaultLdxSyncService")
	assert.NotNil(t, defaultService.apiClient, "API client should be initialized")
}

func Test_NewLdxSyncServiceWithApiClient_UsesProvidedClient(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mockcommand.NewMockLdxSyncApiClient(ctrl)

	service := NewLdxSyncServiceWithApiClient(mockApiClient, defaultResolver(c))

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
	mockApiClient := mockcommand.NewMockLdxSyncApiClient(ctrl)

	emptyPath := types.FilePath("")
	workspaceutil.SetupWorkspace(t, c, emptyPath)
	folders := c.Workspace().Folders()

	expectedOrgId := "org-for-empty-path"
	expectedResult := createLdxSyncResultWithOrg(expectedOrgId)

	// Should handle empty path gracefully
	mockApiClient.EXPECT().
		GetUserConfigForProject(gomock.Any(), c.Engine(), string(emptyPath), "").
		Return(expectedResult)

	service := NewLdxSyncServiceWithApiClient(mockApiClient, defaultResolver(c))
	service.RefreshConfigFromLdxSync(context.Background(), c, folders, nil)

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

func Test_RefreshConfigFromLdxSync_ClearsLockedOverridesFromFolderConfigs(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mockcommand.NewMockLdxSyncApiClient(ctrl)
	logger := c.Logger()

	// Setup folder with user override
	folderPath := types.FilePath("/test/folder")
	workspaceutil.SetupWorkspace(t, c, folderPath)
	folders := c.Workspace().Folders()

	// Create folder config with user override for a setting that will become locked
	prefixKeyConfig := c.Engine().GetConfiguration()
	fp := string(types.PathKey(folderPath))
	prefixKeyConfig.Set(configuration.UserFolderKey(fp, types.SettingEnabledSeverities), &configuration.LocalConfigField{Value: []string{"high", "critical"}, Changed: true})
	err := storedconfig.UpdateFolderConfig(prefixKeyConfig, &types.FolderConfig{FolderPath: folderPath}, logger)
	require.NoError(t, err)

	// Verify override exists before refresh
	require.True(t, types.HasUserOverride(prefixKeyConfig, folderPath, types.SettingEnabledSeverities), "User override should exist before refresh")

	// Create LDX-Sync result with locked field (use LDX-Sync API field name "severities")
	orgId := "test-org-id"
	result := createLdxSyncResultWithLockedField(orgId, "severities")

	// Use normalized path from Folder object since NewFolder normalizes paths
	mockApiClient.EXPECT().
		GetUserConfigForProject(gomock.Any(), c.Engine(), string(folders[0].Path()), "").
		Return(result)

	// Setup folder-to-org mapping so clearLockedOverridesFromFolderConfigs can find the org
	cache := c.GetLdxSyncOrgConfigCache()
	cache.SetFolderOrg(folders[0].Path(), orgId)

	service := NewLdxSyncServiceWithApiClient(mockApiClient, defaultResolver(c))
	service.RefreshConfigFromLdxSync(context.Background(), c, folders, nil)

	// Verify user override was cleared for the locked field
	assert.False(t, types.HasUserOverride(prefixKeyConfig, folderPath, types.SettingEnabledSeverities), "User override should be cleared for locked field")
}

// FC-055: clearLockedOverridesFromFolderConfigs uses prefix keys — after clearing,
// conf.Get(UserFolderKey(path, name)) must be unset so ConfigResolver returns LDX-Sync value
func Test_RefreshConfigFromLdxSync_FC055_ClearsUserFolderKeyPrefixKeys(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mockcommand.NewMockLdxSyncApiClient(ctrl)
	logger := c.Logger()

	folderPath := types.FilePath("/test/folder-fc055")
	workspaceutil.SetupWorkspace(t, c, folderPath)
	folders := c.Workspace().Folders()

	// Create folder config with user override
	prefixKeyConfig := c.Engine().GetConfiguration()
	prefixKeyConfig.Set(configuration.UserFolderKey(string(types.PathKey(folderPath)), types.SettingEnabledSeverities), &configuration.LocalConfigField{Value: []string{"high", "critical"}, Changed: true})
	err := storedconfig.UpdateFolderConfig(prefixKeyConfig, &types.FolderConfig{FolderPath: folderPath}, logger)
	require.NoError(t, err)

	// Simulate dual-write: UserFolderKey prefix key is set (as would happen when user sets override via IDE)
	normalizedPath := string(types.PathKey(folders[0].Path()))
	userFolderKey := configuration.UserFolderKey(normalizedPath, types.SettingEnabledSeverities)
	prefixKeyConfig.Set(userFolderKey, &configuration.LocalConfigField{Value: []string{"high", "critical"}, Changed: true})
	require.True(t, prefixKeyConfig.IsSet(userFolderKey), "UserFolderKey should be set before clear")

	orgId := "test-org-fc055"
	result := createLdxSyncResultWithLockedField(orgId, "severities")

	mockApiClient.EXPECT().
		GetUserConfigForProject(gomock.Any(), c.Engine(), string(folders[0].Path()), "").
		Return(result)

	cache := c.GetLdxSyncOrgConfigCache()
	cache.SetFolderOrg(folders[0].Path(), orgId)

	service := NewLdxSyncServiceWithApiClient(mockApiClient, defaultResolver(c))
	service.RefreshConfigFromLdxSync(context.Background(), c, folders, nil)

	// After clearing locked overrides, UserFolderKey must be unset so ConfigResolver returns LDX-Sync value.
	// Unset sets key to keyDeleted marker; Get returns that, not a *LocalConfigField.
	val := prefixKeyConfig.Get(userFolderKey)
	lf, isLocalConfigField := val.(*configuration.LocalConfigField)
	assert.False(t, isLocalConfigField && lf != nil && lf.Changed,
		"UserFolderKey should be cleared (no active LocalConfigField override) after clearLockedOverridesFromFolderConfigs")
}

func Test_RefreshConfigFromLdxSync_PreservesNonLockedOverrides(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mockcommand.NewMockLdxSyncApiClient(ctrl)
	logger := c.Logger()

	// Setup folder with user overrides
	folderPath := types.FilePath("/test/folder2")
	workspaceutil.SetupWorkspace(t, c, folderPath)
	folders := c.Workspace().Folders()

	// Create folder config with user overrides for both locked and non-locked settings
	prefixKeyConfig := c.Engine().GetConfiguration()
	fp := string(types.PathKey(folderPath))
	prefixKeyConfig.Set(configuration.UserFolderKey(fp, types.SettingEnabledSeverities), &configuration.LocalConfigField{Value: []string{"high", "critical"}, Changed: true})
	prefixKeyConfig.Set(configuration.UserFolderKey(fp, types.SettingScanAutomatic), &configuration.LocalConfigField{Value: true, Changed: true})
	err := storedconfig.UpdateFolderConfig(prefixKeyConfig, &types.FolderConfig{FolderPath: folderPath}, logger)
	require.NoError(t, err)

	// Create LDX-Sync result with only one field locked (use LDX-Sync API field name "severities")
	orgId := "test-org-id-2"
	result := createLdxSyncResultWithLockedField(orgId, "severities")

	// Use normalized path from Folder object since NewFolder normalizes paths
	mockApiClient.EXPECT().
		GetUserConfigForProject(gomock.Any(), c.Engine(), string(folders[0].Path()), "").
		Return(result)

	// Setup folder-to-org mapping
	cache := c.GetLdxSyncOrgConfigCache()
	cache.SetFolderOrg(folders[0].Path(), orgId)

	service := NewLdxSyncServiceWithApiClient(mockApiClient, defaultResolver(c))
	service.RefreshConfigFromLdxSync(context.Background(), c, folders, nil)

	// Verify locked override was cleared but non-locked override was preserved
	assert.False(t, types.HasUserOverride(prefixKeyConfig, folderPath, types.SettingEnabledSeverities), "Locked override should be cleared")
	assert.True(t, types.HasUserOverride(prefixKeyConfig, folderPath, types.SettingScanAutomatic), "Non-locked override should be preserved")
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
			Locked: util.Ptr(true),
			Origin: v20241015.SettingMetadataOriginOrg,
			Value:  []string{"low", "medium", "high", "critical"},
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

// createLdxSyncResultWithOrgSettings creates a result with org-scope "products" setting (maps to snyk_code_enabled etc.)
func createLdxSyncResultWithOrgSettings(orgId string, products []string) ldx_sync_config.LdxSyncConfigResult {
	settings := map[string]v20241015.SettingMetadata{
		"products": {
			Locked: util.Ptr(true),
			Origin: v20241015.SettingMetadataOriginOrg,
			Value:  products,
		},
	}
	return createLdxSyncResultWithSettings(orgId, settings, "00000000-0000-0000-0000-000000000004")
}

// createLdxSyncResultWithMachineSettings creates a result with machine-scope settings
func createLdxSyncResultWithMachineSettings(orgId string, apiEndpoint string) ldx_sync_config.LdxSyncConfigResult {
	settings := map[string]v20241015.SettingMetadata{
		"api_endpoint": {
			Locked: util.Ptr(true),
			Origin: v20241015.SettingMetadataOriginOrg,
			Value:  apiEndpoint,
		},
	}
	return createLdxSyncResultWithSettings(orgId, settings, "00000000-0000-0000-0000-000000000003")
}

func createLdxSyncResultWithSettings(orgId string, settings map[string]v20241015.SettingMetadata, configIdStr string) ldx_sync_config.LdxSyncConfigResult {
	orgs := []v20241015.Organization{
		{
			Id:                   orgId,
			Name:                 "Test Org",
			Slug:                 "test-org",
			IsDefault:            util.Ptr(true),
			PreferredByAlgorithm: util.Ptr(true),
		},
	}
	configId := uuid.MustParse(configIdStr)
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

func Test_RefreshConfigFromLdxSync_SendsConfigurationNotificationWithMachineSettings(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mockcommand.NewMockLdxSyncApiClient(ctrl)

	folderPath := types.PathKey("/test/folder")
	_, notifier := workspaceutil.SetupWorkspace(t, c, folderPath)
	folders := c.Workspace().Folders()

	expectedOrgId := "test-org-id-123"
	expectedEndpoint := "https://custom.endpoint.com"
	expectedResult := createLdxSyncResultWithMachineSettings(expectedOrgId, expectedEndpoint)

	// Mock the API call
	mockApiClient.EXPECT().
		GetUserConfigForProject(gomock.Any(), c.Engine(), string(folders[0].Path()), "").
		Return(expectedResult)

	resolver := newConfigResolverForTest(c)
	service := NewLdxSyncServiceWithApiClient(mockApiClient, resolver)
	service.RefreshConfigFromLdxSync(context.Background(), c, folders, notifier)

	// Verify $/snyk.configuration notification was sent with machine settings from LDX-Sync
	messages := notifier.SentMessages()
	require.Len(t, messages, 1, "Expected $/snyk.configuration notification to be sent")

	lspConfig, ok := messages[0].(types.LspConfigurationParam)
	require.True(t, ok, "Expected message to be LspConfigurationParam")
	require.NotNil(t, lspConfig.Settings)
	require.NotNil(t, lspConfig.Settings[types.SettingApiEndpoint])
	assert.Equal(t, expectedEndpoint, lspConfig.Settings[types.SettingApiEndpoint].Value, "Endpoint from LDX-Sync machine settings should be applied to notification")
}

// FC-101: LDX-Sync refresh writes new RemoteConfigField values; resolver reads updated values
func Test_RefreshConfigFromLdxSync_FC101_ResolverReadsUpdatedRemoteOrgValues(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mockcommand.NewMockLdxSyncApiClient(ctrl)

	folderPath := types.PathKey("/test/folder")
	_, notifier := workspaceutil.SetupWorkspace(t, c, folderPath)
	folders := c.Workspace().Folders()

	expectedOrgId := "test-org-id-fc101"
	expectedResult := createLdxSyncResultWithOrgSettings(expectedOrgId, []string{"code"})

	mockApiClient.EXPECT().
		GetUserConfigForProject(gomock.Any(), c.Engine(), string(folders[0].Path()), "").
		Return(expectedResult)

	resolver := newConfigResolverForTest(c)
	service := NewLdxSyncServiceWithApiClient(mockApiClient, resolver)
	service.RefreshConfigFromLdxSync(context.Background(), c, folders, notifier)

	// Resolver resolves org from FolderMetadataKey (AutoDeterminedOrg). Simulate post-refresh state
	// where folder config has effective org set (as updateFolderConfigOrg would do).
	prefixKeyConf := c.Engine().GetConfiguration()
	prefixKeyConf.Set(configuration.FolderMetadataKey(string(folderPath), types.SettingAutoDeterminedOrg), expectedOrgId)

	fc := &types.FolderConfig{FolderPath: folderPath}
	val, source := resolver.GetValue(types.SettingSnykCodeEnabled, fc)
	assert.True(t, val.(bool), "Resolver should return snyk_code_enabled true from LDX-Sync org settings")
	assert.Equal(t, types.ConfigSourceLDXSyncLocked, source, "Source should be LDX-Sync locked")
}

func Test_applyMachineSetting_CodeEndpoint(t *testing.T) {
	c := testutil.UnitTest(t)
	service := &DefaultLdxSyncService{}

	t.Run("applies when locked", func(t *testing.T) {
		field := &types.LDXSyncField{Value: "https://deeproxy.custom.snyk.io", IsLocked: true}
		applied := service.applyMachineSetting(c, types.SettingCodeEndpoint, field)
		assert.True(t, applied)
		assert.Equal(t, "https://deeproxy.custom.snyk.io", c.Engine().GetConfiguration().GetString(configuration.UserGlobalKey(types.SettingCodeEndpoint)))
	})

	t.Run("applies when default (empty)", func(t *testing.T) {
		c2 := testutil.UnitTest(t)
		field := &types.LDXSyncField{Value: "https://deeproxy.other.snyk.io", IsLocked: false}
		applied := service.applyMachineSetting(c2, types.SettingCodeEndpoint, field)
		assert.True(t, applied)
		assert.Equal(t, "https://deeproxy.other.snyk.io", c2.Engine().GetConfiguration().GetString(configuration.UserGlobalKey(types.SettingCodeEndpoint)))
	})

	t.Run("does not apply when not locked and already set", func(t *testing.T) {
		c3 := testutil.UnitTest(t)
		c3.Engine().GetConfiguration().Set(configuration.UserGlobalKey(types.SettingCodeEndpoint), "https://existing.endpoint.io")
		field := &types.LDXSyncField{Value: "https://deeproxy.other.snyk.io", IsLocked: false}
		applied := service.applyMachineSetting(c3, types.SettingCodeEndpoint, field)
		assert.False(t, applied)
		assert.Equal(t, "https://existing.endpoint.io", c3.Engine().GetConfiguration().GetString(configuration.UserGlobalKey(types.SettingCodeEndpoint)))
	})
}

func Test_applyMachineSetting_ProxySettings(t *testing.T) {
	service := &DefaultLdxSyncService{}

	t.Run("proxy_http applies when locked", func(t *testing.T) {
		c := testutil.UnitTest(t)
		field := &types.LDXSyncField{Value: "http://proxy:8080", IsLocked: true}
		applied := service.applyMachineSetting(c, types.SettingProxyHttp, field)
		assert.True(t, applied)
		assert.Equal(t, "http://proxy:8080", c.Engine().GetConfiguration().GetString(configuration.UserGlobalKey(types.SettingProxyHttp)))
	})

	t.Run("proxy_https applies when locked", func(t *testing.T) {
		c := testutil.UnitTest(t)
		field := &types.LDXSyncField{Value: "https://proxy:8443", IsLocked: true}
		applied := service.applyMachineSetting(c, types.SettingProxyHttps, field)
		assert.True(t, applied)
		assert.Equal(t, "https://proxy:8443", c.Engine().GetConfiguration().GetString(configuration.UserGlobalKey(types.SettingProxyHttps)))
	})

	t.Run("proxy_no_proxy applies when locked", func(t *testing.T) {
		c := testutil.UnitTest(t)
		field := &types.LDXSyncField{Value: "localhost,127.0.0.1", IsLocked: true}
		applied := service.applyMachineSetting(c, types.SettingProxyNoProxy, field)
		assert.True(t, applied)
		assert.Equal(t, "localhost,127.0.0.1", c.Engine().GetConfiguration().GetString(configuration.UserGlobalKey(types.SettingProxyNoProxy)))
	})

	t.Run("proxy_insecure applies when locked", func(t *testing.T) {
		c := testutil.UnitTest(t)
		field := &types.LDXSyncField{Value: true, IsLocked: true}
		applied := service.applyMachineSetting(c, types.SettingProxyInsecure, field)
		assert.True(t, applied)
		assert.True(t, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingProxyInsecure)))
	})

	t.Run("proxy_http applies when default (empty)", func(t *testing.T) {
		c := testutil.UnitTest(t)
		field := &types.LDXSyncField{Value: "http://proxy:8080", IsLocked: false}
		applied := service.applyMachineSetting(c, types.SettingProxyHttp, field)
		assert.True(t, applied)
		assert.Equal(t, "http://proxy:8080", c.Engine().GetConfiguration().GetString(configuration.UserGlobalKey(types.SettingProxyHttp)))
	})

	t.Run("proxy_http does not apply when not locked and already set", func(t *testing.T) {
		c := testutil.UnitTest(t)
		c.Engine().GetConfiguration().Set(configuration.UserGlobalKey(types.SettingProxyHttp), "http://existing:8080")
		field := &types.LDXSyncField{Value: "http://new:8080", IsLocked: false}
		applied := service.applyMachineSetting(c, types.SettingProxyHttp, field)
		assert.False(t, applied)
		assert.Equal(t, "http://existing:8080", c.Engine().GetConfiguration().GetString(configuration.UserGlobalKey(types.SettingProxyHttp)))
	})
}

func Test_applyMachineSetting_PublishSecurityAtInceptionRules(t *testing.T) {
	service := &DefaultLdxSyncService{}

	t.Run("applies when locked", func(t *testing.T) {
		c := testutil.UnitTest(t)
		field := &types.LDXSyncField{Value: true, IsLocked: true}
		applied := service.applyMachineSetting(c, types.SettingPublishSecurityAtInceptionRules, field)
		assert.True(t, applied)
		assert.True(t, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingPublishSecurityAtInceptionRules)))
	})

	t.Run("applies when default (false)", func(t *testing.T) {
		c := testutil.UnitTest(t)
		field := &types.LDXSyncField{Value: true, IsLocked: false}
		applied := service.applyMachineSetting(c, types.SettingPublishSecurityAtInceptionRules, field)
		assert.True(t, applied)
		assert.True(t, c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingPublishSecurityAtInceptionRules)))
	})
}

func Test_applyMachineSetting_CliReleaseChannel(t *testing.T) {
	service := &DefaultLdxSyncService{}

	t.Run("applies when locked", func(t *testing.T) {
		c := testutil.UnitTest(t)
		field := &types.LDXSyncField{Value: "stable", IsLocked: true}
		applied := service.applyMachineSetting(c, types.SettingCliReleaseChannel, field)
		assert.True(t, applied)
		assert.Equal(t, "stable", c.Engine().GetConfiguration().GetString(configuration.UserGlobalKey(types.SettingCliReleaseChannel)))
	})

	t.Run("applies when default (empty)", func(t *testing.T) {
		c := testutil.UnitTest(t)
		field := &types.LDXSyncField{Value: "preview", IsLocked: false}
		applied := service.applyMachineSetting(c, types.SettingCliReleaseChannel, field)
		assert.True(t, applied)
		assert.Equal(t, "preview", c.Engine().GetConfiguration().GetString(configuration.UserGlobalKey(types.SettingCliReleaseChannel)))
	})

	t.Run("does not apply when not locked and already set", func(t *testing.T) {
		c := testutil.UnitTest(t)
		c.Engine().GetConfiguration().Set(configuration.UserGlobalKey(types.SettingCliReleaseChannel), "stable")
		field := &types.LDXSyncField{Value: "preview", IsLocked: false}
		applied := service.applyMachineSetting(c, types.SettingCliReleaseChannel, field)
		assert.False(t, applied)
		assert.Equal(t, "stable", c.Engine().GetConfiguration().GetString(configuration.UserGlobalKey(types.SettingCliReleaseChannel)))
	})
}

func Test_RefreshConfigFromLdxSync_NoNotificationWhenNoChanges(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mockcommand.NewMockLdxSyncApiClient(ctrl)

	folderPath := types.PathKey("/test/folder")
	_, notifier := workspaceutil.SetupWorkspace(t, c, folderPath)
	folders := c.Workspace().Folders()

	// Return empty result (no machine config)
	emptyResult := ldx_sync_config.LdxSyncConfigResult{
		Config: nil,
		Error:  assert.AnError,
	}

	mockApiClient.EXPECT().
		GetUserConfigForProject(gomock.Any(), c.Engine(), string(folders[0].Path()), "").
		Return(emptyResult)

	service := NewLdxSyncServiceWithApiClient(mockApiClient, defaultResolver(c))
	service.RefreshConfigFromLdxSync(context.Background(), c, folders, notifier)

	// Verify NO notification was sent when config wasn't updated
	messages := notifier.SentMessages()
	assert.Empty(t, messages, "No notification should be sent when config is not updated")
}
