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
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	mockcommand "github.com/snyk/snyk-ls/domain/ide/command/mock"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/testutil/workspaceutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

// newTestLdxSyncService creates a service with a mock API client and fake feature flag service
// with UseConfigAPI enabled by default (tests can override by setting Flags[featureflag.UseConfigAPI] = false)
func newTestLdxSyncService(mockApiClient LdxSyncApiClient, engine workflow.Engine) LdxSyncService {
	resolver := testutil.DefaultConfigResolver(engine)
	fakeFfService := featureflag.NewFakeService()
	fakeFfService.Flags[featureflag.UseConfigAPI] = true
	return NewLdxSyncServiceWithApiClient(mockApiClient, resolver, fakeFfService)
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
	engine := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mockcommand.NewMockLdxSyncApiClient(ctrl)

	service := newTestLdxSyncService(mockApiClient, engine)

	// No API calls should be made for empty folder list
	service.RefreshConfigFromLdxSync(context.Background(), engine.GetConfiguration(), engine, engine.GetLogger(), []types.Folder{}, nil)

	// Verify no AutoDeterminedOrg was written for unknown folder
	snapshot := types.ReadFolderConfigSnapshot(engine.GetConfiguration(), types.FilePath("/nonexistent"))
	assert.Empty(t, snapshot.AutoDeterminedOrg)
}

func Test_RefreshConfigFromLdxSync_SingleFolder_Success(t *testing.T) {
	engine := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mockcommand.NewMockLdxSyncApiClient(ctrl)

	folderPath := types.PathKey("/test/folder")
	workspaceutil.SetupWorkspace(t, engine, folderPath)
	folders := config.GetWorkspace(engine.GetConfiguration()).Folders()

	expectedOrgId := "test-org-id-123"
	expectedResult := createLdxSyncResultWithOrg(expectedOrgId)

	// Expect API call with empty preferredOrg (no folder config exists)
	// Use normalized path from Folder object since NewFolder normalizes paths
	mockApiClient.EXPECT().
		GetUserConfigForProject(gomock.Any(), engine, string(folders[0].Path()), "").
		Return(expectedResult)

	service := newTestLdxSyncService(mockApiClient, engine)
	service.RefreshConfigFromLdxSync(context.Background(), engine.GetConfiguration(), engine, engine.GetLogger(), folders, nil)

	// Verify AutoDeterminedOrg was written to GAF folder metadata
	snapshot := types.ReadFolderConfigSnapshot(engine.GetConfiguration(), folderPath)
	assert.Equal(t, expectedOrgId, snapshot.AutoDeterminedOrg)
}

func Test_RefreshConfigFromLdxSync_WithPreferredOrg(t *testing.T) {
	engine := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mockcommand.NewMockLdxSyncApiClient(ctrl)

	folderPath := types.PathKey("/test/folder")
	workspaceutil.SetupWorkspace(t, engine, folderPath)
	folders := config.GetWorkspace(engine.GetConfiguration()).Folders()

	// Set up folder config with PreferredOrg
	preferredOrg := "test-org-123"
	engineConfig := engine.GetConfiguration()
	types.SetPreferredOrgAndOrgSetByUser(engineConfig, folderPath, preferredOrg, true)

	expectedOrgId := "resolved-org-id"
	expectedResult := createLdxSyncResultWithOrg(expectedOrgId)

	// Expect API call with preferredOrg from folder config
	// Use normalized path from Folder object since NewFolder normalizes paths
	mockApiClient.EXPECT().
		GetUserConfigForProject(gomock.Any(), engine, string(folders[0].Path()), preferredOrg).
		Return(expectedResult)

	service := newTestLdxSyncService(mockApiClient, engine)
	service.RefreshConfigFromLdxSync(context.Background(), engine.GetConfiguration(), engine, engine.GetLogger(), folders, nil)

	// Verify AutoDeterminedOrg was written to GAF folder metadata
	snapshot := types.ReadFolderConfigSnapshot(engine.GetConfiguration(), folderPath)
	assert.Equal(t, expectedOrgId, snapshot.AutoDeterminedOrg)
}

func Test_RefreshConfigFromLdxSync_MultipleFolders(t *testing.T) {
	engine := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mockcommand.NewMockLdxSyncApiClient(ctrl)

	folder1Path := types.PathKey("/test/folder1")
	folder2Path := types.PathKey("/test/folder2")
	folder3Path := types.PathKey("/test/folder3")

	workspaceutil.SetupWorkspace(t, engine, folder1Path, folder2Path, folder3Path)
	folders := config.GetWorkspace(engine.GetConfiguration()).Folders()

	// Create a map of folder path to expected org ID for consistent verification
	// Use the actual folder paths from the workspace (which may be in any order)
	folderOrgMap := make(map[types.FilePath]string)
	for i, folder := range folders {
		orgId := fmt.Sprintf("org-%d", i+1)
		folderOrgMap[folder.Path()] = orgId
		result := createLdxSyncResultWithOrg(orgId)
		mockApiClient.EXPECT().
			GetUserConfigForProject(gomock.Any(), engine, string(folder.Path()), "").
			Return(result)
	}

	service := newTestLdxSyncService(mockApiClient, engine)
	service.RefreshConfigFromLdxSync(context.Background(), engine.GetConfiguration(), engine, engine.GetLogger(), folders, nil)

	// Verify all AutoDeterminedOrg values were written to GAF folder metadata
	prefixKeyConfig := engine.GetConfiguration()
	for _, folder := range folders {
		expectedOrgId := folderOrgMap[folder.Path()]
		snapshot := types.ReadFolderConfigSnapshot(prefixKeyConfig, folder.Path())
		assert.Equal(t, expectedOrgId, snapshot.AutoDeterminedOrg, "Org ID mismatch for folder %s", folder.Path())
	}
}

func Test_RefreshConfigFromLdxSync_ApiError_NotCached(t *testing.T) {
	engine := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mockcommand.NewMockLdxSyncApiClient(ctrl)

	folderPath := types.PathKey("/test/folder")
	workspaceutil.SetupWorkspace(t, engine, folderPath)
	folders := config.GetWorkspace(engine.GetConfiguration()).Folders()

	errorResult := ldx_sync_config.LdxSyncConfigResult{
		Error: assert.AnError,
	}

	// Use normalized path from Folder object since NewFolder normalizes paths
	mockApiClient.EXPECT().
		GetUserConfigForProject(gomock.Any(), engine, string(folders[0].Path()), "").
		Return(errorResult)

	service := newTestLdxSyncService(mockApiClient, engine)
	service.RefreshConfigFromLdxSync(context.Background(), engine.GetConfiguration(), engine, engine.GetLogger(), folders, nil)

	// Verify AutoDeterminedOrg was NOT written for error result
	snapshot := types.ReadFolderConfigSnapshot(engine.GetConfiguration(), folderPath)
	assert.Empty(t, snapshot.AutoDeterminedOrg, "Error results should not populate AutoDeterminedOrg")
}

func Test_DefaultLdxSyncApiClient_GetUserConfigForProject(t *testing.T) {
	engine := testutil.UnitTest(t)

	client := &DefaultLdxSyncApiClient{}

	// This is an integration-style test that calls the real framework function
	// It will likely fail or return errors without proper auth/network
	// but verifies the wrapper compiles and delegates correctly
	result := client.GetUserConfigForProject(context.Background(), engine, "/test/path", "test-org")

	// We expect an error since we're not actually authenticated
	assert.NotNil(t, result.Error, "Expected error from real API call without authentication")
}

func Test_NewLdxSyncService_UsesDefaultApiClient(t *testing.T) {
	engine := testutil.UnitTest(t)
	fakeFfService := featureflag.NewFakeService()
	service := NewLdxSyncService(testutil.DefaultConfigResolver(engine), fakeFfService)

	// Verify it returns a service (we can't easily inspect the private apiClient field,
	// but this ensures the constructor works)
	assert.NotNil(t, service)

	// Type assertion to verify it's the correct concrete type
	defaultService, ok := service.(*DefaultLdxSyncService)
	assert.True(t, ok, "Expected *DefaultLdxSyncService")
	assert.NotNil(t, defaultService.apiClient, "API client should be initialized")
}

func Test_NewLdxSyncServiceWithApiClient_UsesProvidedClient(t *testing.T) {
	engine := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mockcommand.NewMockLdxSyncApiClient(ctrl)

	service := newTestLdxSyncService(mockApiClient, engine)

	assert.NotNil(t, service)

	// Type assertion to verify structure
	defaultService, ok := service.(*DefaultLdxSyncService)
	assert.True(t, ok, "Expected *DefaultLdxSyncService")
	assert.Equal(t, mockApiClient, defaultService.apiClient, "Should use provided API client")
}

// Boundary and edge case tests

func Test_RefreshConfigFromLdxSync_EmptyFolderPath(t *testing.T) {
	engine := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mockcommand.NewMockLdxSyncApiClient(ctrl)

	emptyPath := types.FilePath("")
	workspaceutil.SetupWorkspace(t, engine, emptyPath)
	folders := config.GetWorkspace(engine.GetConfiguration()).Folders()

	expectedOrgId := "org-for-empty-path"
	expectedResult := createLdxSyncResultWithOrg(expectedOrgId)

	// Should handle empty path gracefully
	mockApiClient.EXPECT().
		GetUserConfigForProject(gomock.Any(), engine, string(emptyPath), "").
		Return(expectedResult)

	service := newTestLdxSyncService(mockApiClient, engine)
	service.RefreshConfigFromLdxSync(context.Background(), engine.GetConfiguration(), engine, engine.GetLogger(), folders, nil)

	// Empty paths are skipped in GAF folder metadata (ReadFolderConfigSnapshot returns early for empty paths)
	// The service handles empty paths gracefully without panicking
	snapshot := types.ReadFolderConfigSnapshot(engine.GetConfiguration(), emptyPath)
	assert.Empty(t, snapshot.AutoDeterminedOrg, "Empty paths are not stored in GAF folder metadata")
}

func Test_GetOrgIdForFolder_EmptyFolderPath_ReturnsEmpty(t *testing.T) {
	engine := testutil.UnitTest(t)

	// No folder metadata written
	snapshot := types.ReadFolderConfigSnapshot(engine.GetConfiguration(), types.FilePath(""))

	// Should return empty string when no mapping exists
	assert.Empty(t, snapshot.AutoDeterminedOrg)
}

func Test_RefreshConfigFromLdxSync_ClearsLockedOverridesFromFolderConfigs(t *testing.T) {
	engine := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mockcommand.NewMockLdxSyncApiClient(ctrl)

	// Setup folder with user override
	folderPath := types.FilePath("/test/folder")
	workspaceutil.SetupWorkspace(t, engine, folderPath)
	folders := config.GetWorkspace(engine.GetConfiguration()).Folders()

	// Create folder config with user override for a setting that will become locked
	prefixKeyConfig := engine.GetConfiguration()
	fp := string(types.PathKey(folderPath))
	prefixKeyConfig.Set(configresolver.UserFolderKey(fp, types.SettingSeverityFilterCritical), &configresolver.LocalConfigField{Value: true, Changed: true})

	// Verify override exists before refresh
	require.True(t, types.HasUserOverride(prefixKeyConfig, folderPath, types.SettingSeverityFilterCritical), "User override should exist before refresh")

	// Create LDX-Sync result with locked field (use LDX-Sync API field name)
	orgId := "test-org-id"
	result := createLdxSyncResultWithLockedField(orgId, "severity_critical_enabled")

	// Use normalized path from Folder object since NewFolder normalizes paths
	mockApiClient.EXPECT().
		GetUserConfigForProject(gomock.Any(), engine, string(folders[0].Path()), "").
		Return(result)

	service := newTestLdxSyncService(mockApiClient, engine)
	service.RefreshConfigFromLdxSync(context.Background(), engine.GetConfiguration(), engine, engine.GetLogger(), folders, nil)

	// Verify user override was cleared for the locked field
	assert.False(t, types.HasUserOverride(prefixKeyConfig, folderPath, types.SettingSeverityFilterCritical), "User override should be cleared for locked field")
}

// FC-055: clearLockedOverridesFromFolderConfigs uses prefix keys — after clearing,
// conf.Get(UserFolderKey(path, name)) must be unset so ConfigResolver returns LDX-Sync value
func Test_RefreshConfigFromLdxSync_FC055_ClearsUserFolderKeyPrefixKeys(t *testing.T) {
	engine := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mockcommand.NewMockLdxSyncApiClient(ctrl)

	folderPath := types.FilePath("/test/folder-fc055")
	workspaceutil.SetupWorkspace(t, engine, folderPath)
	folders := config.GetWorkspace(engine.GetConfiguration()).Folders()

	// Create folder config with user override
	prefixKeyConfig := engine.GetConfiguration()
	prefixKeyConfig.Set(configresolver.UserFolderKey(string(types.PathKey(folderPath)), types.SettingSeverityFilterCritical), &configresolver.LocalConfigField{Value: true, Changed: true})

	// Simulate dual-write: UserFolderKey prefix key is set (as would happen when user sets override via IDE)
	normalizedPath := string(types.PathKey(folders[0].Path()))
	userFolderKey := configresolver.UserFolderKey(normalizedPath, types.SettingSeverityFilterCritical)
	prefixKeyConfig.Set(userFolderKey, &configresolver.LocalConfigField{Value: true, Changed: true})
	require.True(t, prefixKeyConfig.IsSet(userFolderKey), "UserFolderKey should be set before clear")

	orgId := "test-org-fc055"
	result := createLdxSyncResultWithLockedField(orgId, "severity_critical_enabled")

	mockApiClient.EXPECT().
		GetUserConfigForProject(gomock.Any(), engine, string(folders[0].Path()), "").
		Return(result)

	service := newTestLdxSyncService(mockApiClient, engine)
	service.RefreshConfigFromLdxSync(context.Background(), engine.GetConfiguration(), engine, engine.GetLogger(), folders, nil)

	// After clearing locked overrides, UserFolderKey must be unset so ConfigResolver returns LDX-Sync value.
	// Unset sets key to keyDeleted marker; Get returns that, not a *LocalConfigField.
	val := prefixKeyConfig.Get(userFolderKey)
	lf, isLocalConfigField := val.(*configresolver.LocalConfigField)
	assert.False(t, isLocalConfigField && lf != nil && lf.Changed,
		"UserFolderKey should be cleared (no active LocalConfigField override) after clearLockedOverridesFromFolderConfigs")
}

func Test_RefreshConfigFromLdxSync_PreservesNonLockedOverrides(t *testing.T) {
	engine := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mockcommand.NewMockLdxSyncApiClient(ctrl)

	// Setup folder with user overrides
	folderPath := types.FilePath("/test/folder2")
	workspaceutil.SetupWorkspace(t, engine, folderPath)
	folders := config.GetWorkspace(engine.GetConfiguration()).Folders()

	// Create folder config with user overrides for both locked and non-locked settings
	prefixKeyConfig := engine.GetConfiguration()
	fp := string(types.PathKey(folderPath))
	prefixKeyConfig.Set(configresolver.UserFolderKey(fp, types.SettingSeverityFilterCritical), &configresolver.LocalConfigField{Value: true, Changed: true})
	prefixKeyConfig.Set(configresolver.UserFolderKey(fp, types.SettingScanAutomatic), &configresolver.LocalConfigField{Value: true, Changed: true})

	// Create LDX-Sync result with only one field locked (use LDX-Sync API field name)
	orgId := "test-org-id-2"
	result := createLdxSyncResultWithLockedField(orgId, "severity_critical_enabled")

	// Use normalized path from Folder object since NewFolder normalizes paths
	mockApiClient.EXPECT().
		GetUserConfigForProject(gomock.Any(), engine, string(folders[0].Path()), "").
		Return(result)

	service := newTestLdxSyncService(mockApiClient, engine)
	service.RefreshConfigFromLdxSync(context.Background(), engine.GetConfiguration(), engine, engine.GetLogger(), folders, nil)

	// Verify locked override was cleared but non-locked override was preserved
	assert.False(t, types.HasUserOverride(prefixKeyConfig, folderPath, types.SettingSeverityFilterCritical), "Locked override should be cleared")
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

// createLdxSyncResultWithOrgSettings creates a result with org-scope product_code_enabled setting
func createLdxSyncResultWithOrgSettings(orgId string, products []string) ldx_sync_config.LdxSyncConfigResult {
	settings := map[string]v20241015.SettingMetadata{}
	for _, p := range products {
		switch p {
		case "code":
			settings["product_code_enabled"] = v20241015.SettingMetadata{
				Locked: util.Ptr(true),
				Origin: v20241015.SettingMetadataOriginOrg,
				Value:  true,
			}
		}
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
	engine := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mockcommand.NewMockLdxSyncApiClient(ctrl)

	folderPath := types.PathKey("/test/folder")
	_, notifier := workspaceutil.SetupWorkspace(t, engine, folderPath)
	folders := config.GetWorkspace(engine.GetConfiguration()).Folders()

	expectedOrgId := "test-org-id-123"
	expectedEndpoint := "https://custom.endpoint.com"
	expectedResult := createLdxSyncResultWithMachineSettings(expectedOrgId, expectedEndpoint)

	// Mock the API call
	mockApiClient.EXPECT().
		GetUserConfigForProject(gomock.Any(), engine, string(folders[0].Path()), "").
		Return(expectedResult)

	resolver := newConfigResolverForTest(engine)
	fakeFfService := featureflag.NewFakeService()
	fakeFfService.Flags[featureflag.UseConfigAPI] = true
	service := NewLdxSyncServiceWithApiClient(mockApiClient, resolver, fakeFfService)
	service.RefreshConfigFromLdxSync(context.Background(), engine.GetConfiguration(), engine, engine.GetLogger(), folders, notifier)

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
	engine := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mockcommand.NewMockLdxSyncApiClient(ctrl)

	folderPath := types.PathKey("/test/folder")
	_, notifier := workspaceutil.SetupWorkspace(t, engine, folderPath)
	folders := config.GetWorkspace(engine.GetConfiguration()).Folders()

	expectedOrgId := "test-org-id-fc101"
	expectedResult := createLdxSyncResultWithOrgSettings(expectedOrgId, []string{"code"})

	mockApiClient.EXPECT().
		GetUserConfigForProject(gomock.Any(), engine, string(folders[0].Path()), "").
		Return(expectedResult)

	resolver := newConfigResolverForTest(engine)
	fakeFfService := featureflag.NewFakeService()
	fakeFfService.Flags[featureflag.UseConfigAPI] = true
	service := NewLdxSyncServiceWithApiClient(mockApiClient, resolver, fakeFfService)
	service.RefreshConfigFromLdxSync(context.Background(), engine.GetConfiguration(), engine, engine.GetLogger(), folders, notifier)

	// Resolver resolves org from FolderMetadataKey (AutoDeterminedOrg). Simulate post-refresh state
	// where folder config has effective org set (as updateFolderConfigOrg would do).
	prefixKeyConf := engine.GetConfiguration()
	prefixKeyConf.Set(configresolver.FolderMetadataKey(string(folderPath), types.SettingAutoDeterminedOrg), expectedOrgId)

	fc := &types.FolderConfig{FolderPath: folderPath}
	val, source := resolver.GetValue(types.SettingSnykCodeEnabled, fc)
	assert.True(t, val.(bool), "Resolver should return snyk_code_enabled true from LDX-Sync org settings")
	assert.Equal(t, configresolver.ConfigSourceRemoteLocked, source, "Source should be LDX-Sync locked")
}

func Test_applyMachineSetting_CodeEndpoint(t *testing.T) {
	engine := testutil.UnitTest(t)
	service := &DefaultLdxSyncService{}

	t.Run("applies when locked", func(t *testing.T) {
		field := &types.LDXSyncField{Value: "https://deeproxy.custom.snyk.io", IsLocked: true}
		applied := service.applyMachineSetting(engine.GetConfiguration(), engine, engine.GetLogger(), types.SettingCodeEndpoint, field)
		assert.True(t, applied)
		assert.Equal(t, "https://deeproxy.custom.snyk.io", engine.GetConfiguration().GetString(configresolver.UserGlobalKey(types.SettingCodeEndpoint)))
	})

	t.Run("applies when default (empty)", func(t *testing.T) {
		engine2 := testutil.UnitTest(t)
		field := &types.LDXSyncField{Value: "https://deeproxy.other.snyk.io", IsLocked: false}
		applied := service.applyMachineSetting(engine2.GetConfiguration(), engine2, engine2.GetLogger(), types.SettingCodeEndpoint, field)
		assert.True(t, applied)
		assert.Equal(t, "https://deeproxy.other.snyk.io", engine2.GetConfiguration().GetString(configresolver.UserGlobalKey(types.SettingCodeEndpoint)))
	})

	t.Run("does not apply when not locked and already set", func(t *testing.T) {
		engine3 := testutil.UnitTest(t)
		engine3.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingCodeEndpoint), "https://existing.endpoint.io")
		field := &types.LDXSyncField{Value: "https://deeproxy.other.snyk.io", IsLocked: false}
		applied := service.applyMachineSetting(engine3.GetConfiguration(), engine3, engine3.GetLogger(), types.SettingCodeEndpoint, field)
		assert.False(t, applied)
		assert.Equal(t, "https://existing.endpoint.io", engine3.GetConfiguration().GetString(configresolver.UserGlobalKey(types.SettingCodeEndpoint)))
	})
}

func Test_applyMachineSetting_ProxySettings(t *testing.T) {
	service := &DefaultLdxSyncService{}

	t.Run("proxy_http applies when locked", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		field := &types.LDXSyncField{Value: "http://proxy:8080", IsLocked: true}
		applied := service.applyMachineSetting(engine.GetConfiguration(), engine, engine.GetLogger(), types.SettingProxyHttp, field)
		assert.True(t, applied)
		assert.Equal(t, "http://proxy:8080", engine.GetConfiguration().GetString(configresolver.UserGlobalKey(types.SettingProxyHttp)))
	})

	t.Run("proxy_https applies when locked", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		field := &types.LDXSyncField{Value: "https://proxy:8443", IsLocked: true}
		applied := service.applyMachineSetting(engine.GetConfiguration(), engine, engine.GetLogger(), types.SettingProxyHttps, field)
		assert.True(t, applied)
		assert.Equal(t, "https://proxy:8443", engine.GetConfiguration().GetString(configresolver.UserGlobalKey(types.SettingProxyHttps)))
	})

	t.Run("proxy_no_proxy applies when locked", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		field := &types.LDXSyncField{Value: "localhost,127.0.0.1", IsLocked: true}
		applied := service.applyMachineSetting(engine.GetConfiguration(), engine, engine.GetLogger(), types.SettingProxyNoProxy, field)
		assert.True(t, applied)
		assert.Equal(t, "localhost,127.0.0.1", engine.GetConfiguration().GetString(configresolver.UserGlobalKey(types.SettingProxyNoProxy)))
	})

	t.Run("proxy_insecure applies when locked", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		field := &types.LDXSyncField{Value: true, IsLocked: true}
		applied := service.applyMachineSetting(engine.GetConfiguration(), engine, engine.GetLogger(), types.SettingProxyInsecure, field)
		assert.True(t, applied)
		assert.True(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingProxyInsecure)))
	})

	t.Run("proxy_http applies when default (empty)", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		field := &types.LDXSyncField{Value: "http://proxy:8080", IsLocked: false}
		applied := service.applyMachineSetting(engine.GetConfiguration(), engine, engine.GetLogger(), types.SettingProxyHttp, field)
		assert.True(t, applied)
		assert.Equal(t, "http://proxy:8080", engine.GetConfiguration().GetString(configresolver.UserGlobalKey(types.SettingProxyHttp)))
	})

	t.Run("proxy_http does not apply when not locked and already set", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingProxyHttp), "http://existing:8080")
		field := &types.LDXSyncField{Value: "http://new:8080", IsLocked: false}
		applied := service.applyMachineSetting(engine.GetConfiguration(), engine, engine.GetLogger(), types.SettingProxyHttp, field)
		assert.False(t, applied)
		assert.Equal(t, "http://existing:8080", engine.GetConfiguration().GetString(configresolver.UserGlobalKey(types.SettingProxyHttp)))
	})
}

func Test_applyMachineSetting_PublishSecurityAtInceptionRules(t *testing.T) {
	service := &DefaultLdxSyncService{}

	t.Run("applies when locked", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		field := &types.LDXSyncField{Value: true, IsLocked: true}
		applied := service.applyMachineSetting(engine.GetConfiguration(), engine, engine.GetLogger(), types.SettingPublishSecurityAtInceptionRules, field)
		assert.True(t, applied)
		assert.True(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingPublishSecurityAtInceptionRules)))
	})

	t.Run("applies when default (false)", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		field := &types.LDXSyncField{Value: true, IsLocked: false}
		applied := service.applyMachineSetting(engine.GetConfiguration(), engine, engine.GetLogger(), types.SettingPublishSecurityAtInceptionRules, field)
		assert.True(t, applied)
		assert.True(t, engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingPublishSecurityAtInceptionRules)))
	})
}

func Test_applyMachineSetting_CliReleaseChannel(t *testing.T) {
	service := &DefaultLdxSyncService{}

	t.Run("applies when locked", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		field := &types.LDXSyncField{Value: "stable", IsLocked: true}
		applied := service.applyMachineSetting(engine.GetConfiguration(), engine, engine.GetLogger(), types.SettingCliReleaseChannel, field)
		assert.True(t, applied)
		assert.Equal(t, "stable", engine.GetConfiguration().GetString(configresolver.UserGlobalKey(types.SettingCliReleaseChannel)))
	})

	t.Run("applies when default (empty)", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		field := &types.LDXSyncField{Value: "preview", IsLocked: false}
		applied := service.applyMachineSetting(engine.GetConfiguration(), engine, engine.GetLogger(), types.SettingCliReleaseChannel, field)
		assert.True(t, applied)
		assert.Equal(t, "preview", engine.GetConfiguration().GetString(configresolver.UserGlobalKey(types.SettingCliReleaseChannel)))
	})

	t.Run("does not apply when not locked and already set", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingCliReleaseChannel), "stable")
		field := &types.LDXSyncField{Value: "preview", IsLocked: false}
		applied := service.applyMachineSetting(engine.GetConfiguration(), engine, engine.GetLogger(), types.SettingCliReleaseChannel, field)
		assert.False(t, applied)
		assert.Equal(t, "stable", engine.GetConfiguration().GetString(configresolver.UserGlobalKey(types.SettingCliReleaseChannel)))
	})
}

func Test_RefreshConfigFromLdxSync_NoNotificationWhenNoChanges(t *testing.T) {
	engine := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mockcommand.NewMockLdxSyncApiClient(ctrl)

	folderPath := types.PathKey("/test/folder")
	_, notifier := workspaceutil.SetupWorkspace(t, engine, folderPath)
	folders := config.GetWorkspace(engine.GetConfiguration()).Folders()

	// Return empty result (no machine config)
	emptyResult := ldx_sync_config.LdxSyncConfigResult{
		Config: nil,
		Error:  assert.AnError,
	}

	mockApiClient.EXPECT().
		GetUserConfigForProject(gomock.Any(), engine, string(folders[0].Path()), "").
		Return(emptyResult)

	service := newTestLdxSyncService(mockApiClient, engine)
	service.RefreshConfigFromLdxSync(context.Background(), engine.GetConfiguration(), engine, engine.GetLogger(), folders, notifier)

	// Verify NO notification was sent when config wasn't updated
	messages := notifier.SentMessages()
	assert.Empty(t, messages, "No notification should be sent when config is not updated")
}

// createLdxSyncResultWithFolderSettings creates a LdxSyncConfigResult with folder-specific settings
// The folderSettingsURL is the normalized URL key in the FolderSettings map (as the backend would return)
func createLdxSyncResultWithFolderSettings(orgId string, folderSettingsURL string, folderSettings map[string]v20241015.SettingMetadata, remoteUrl string) ldx_sync_config.LdxSyncConfigResult {
	result := createLdxSyncResultWithOrg(orgId)
	fs := map[string]map[string]v20241015.SettingMetadata{
		folderSettingsURL: folderSettings,
	}
	result.Config.Data.Attributes.FolderSettings = &fs
	result.RemoteUrl = remoteUrl
	return result
}

func Test_RefreshConfigFromLdxSync_WritesFolderSettings(t *testing.T) {
	engine := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mockcommand.NewMockLdxSyncApiClient(ctrl)

	folderPath := types.PathKey("/test/folder")
	workspaceutil.SetupWorkspace(t, engine, folderPath)
	folders := config.GetWorkspace(engine.GetConfiguration()).Folders()

	orgId := "test-org-folder-settings"
	normalizedURL := "https://github.com/snyk/test-repo"
	folderSettings := map[string]v20241015.SettingMetadata{
		"reference_branch": {
			Value:  "develop",
			Origin: v20241015.SettingMetadataOriginOrg,
			Locked: util.Ptr(true),
		},
	}

	expectedResult := createLdxSyncResultWithFolderSettings(orgId, normalizedURL, folderSettings, normalizedURL)

	mockApiClient.EXPECT().
		GetUserConfigForProject(gomock.Any(), engine, string(folders[0].Path()), "").
		Return(expectedResult)

	service := newTestLdxSyncService(mockApiClient, engine)
	service.RefreshConfigFromLdxSync(context.Background(), engine.GetConfiguration(), engine, engine.GetLogger(), folders, nil)

	// Verify folder settings were written to configuration via RemoteOrgFolderKey
	fp := string(types.PathKey(folders[0].Path()))
	key := configresolver.RemoteOrgFolderKey(orgId, fp, types.SettingReferenceBranch)
	got := engine.GetConfiguration().Get(key)
	require.NotNil(t, got, "RemoteOrgFolderKey %q should have a value", key)
	field, ok := got.(*configresolver.RemoteConfigField)
	require.True(t, ok, "Expected *RemoteConfigField, got %T", got)
	assert.Equal(t, "develop", field.Value)
	assert.True(t, field.IsLocked)
}

func Test_RefreshConfigFromLdxSync_FolderSettingsWithURLNormalization(t *testing.T) {
	engine := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mockcommand.NewMockLdxSyncApiClient(ctrl)

	folderPath := types.PathKey("/test/folder")
	workspaceutil.SetupWorkspace(t, engine, folderPath)
	folders := config.GetWorkspace(engine.GetConfiguration()).Folders()

	orgId := "test-org-url-norm"
	normalizedURL := "https://github.com/snyk/test-repo"
	rawSSHURL := "git@github.com:snyk/test-repo.git"
	folderSettings := map[string]v20241015.SettingMetadata{
		"reference_branch": {
			Value:  "feature/test",
			Origin: v20241015.SettingMetadataOriginOrg,
			Locked: util.Ptr(false),
		},
		"reference_folder": {
			Value:  "/src/main",
			Origin: v20241015.SettingMetadataOriginOrg,
			Locked: util.Ptr(true),
		},
	}

	// Backend returns FolderSettings keyed by normalized URL, but RemoteUrl is raw SSH
	expectedResult := createLdxSyncResultWithFolderSettings(orgId, normalizedURL, folderSettings, rawSSHURL)

	mockApiClient.EXPECT().
		GetUserConfigForProject(gomock.Any(), engine, string(folders[0].Path()), "").
		Return(expectedResult)

	service := newTestLdxSyncService(mockApiClient, engine)
	service.RefreshConfigFromLdxSync(context.Background(), engine.GetConfiguration(), engine, engine.GetLogger(), folders, nil)

	// Verify folder settings were written despite URL mismatch (normalization bridges the gap)
	fp := string(types.PathKey(folders[0].Path()))
	branchKey := configresolver.RemoteOrgFolderKey(orgId, fp, types.SettingReferenceBranch)
	got := engine.GetConfiguration().Get(branchKey)
	require.NotNil(t, got, "RemoteOrgFolderKey %q should have a value after URL normalization", branchKey)
	field, ok := got.(*configresolver.RemoteConfigField)
	require.True(t, ok, "Expected *RemoteConfigField, got %T", got)
	assert.Equal(t, "feature/test", field.Value)
	assert.False(t, field.IsLocked)

	folderKey := configresolver.RemoteOrgFolderKey(orgId, fp, types.SettingReferenceFolder)
	got2 := engine.GetConfiguration().Get(folderKey)
	require.NotNil(t, got2, "RemoteOrgFolderKey %q should have a value", folderKey)
	field2, ok2 := got2.(*configresolver.RemoteConfigField)
	require.True(t, ok2)
	assert.Equal(t, "/src/main", field2.Value)
	assert.True(t, field2.IsLocked)
}

func Test_RefreshConfigFromLdxSync_FolderSettingsNoRemoteUrl(t *testing.T) {
	engine := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mockcommand.NewMockLdxSyncApiClient(ctrl)

	folderPath := types.PathKey("/test/folder")
	workspaceutil.SetupWorkspace(t, engine, folderPath)
	folders := config.GetWorkspace(engine.GetConfiguration()).Folders()

	orgId := "test-org-no-remote"
	normalizedURL := "https://github.com/snyk/test-repo"
	folderSettings := map[string]v20241015.SettingMetadata{
		"reference_branch": {
			Value:  "main",
			Origin: v20241015.SettingMetadataOriginOrg,
		},
	}

	// Empty RemoteUrl — folder settings should be skipped
	expectedResult := createLdxSyncResultWithFolderSettings(orgId, normalizedURL, folderSettings, "")

	mockApiClient.EXPECT().
		GetUserConfigForProject(gomock.Any(), engine, string(folders[0].Path()), "").
		Return(expectedResult)

	service := newTestLdxSyncService(mockApiClient, engine)
	service.RefreshConfigFromLdxSync(context.Background(), engine.GetConfiguration(), engine, engine.GetLogger(), folders, nil)

	// Verify folder settings were NOT written (no remote URL to normalize)
	fp := string(types.PathKey(folders[0].Path()))
	key := configresolver.RemoteOrgFolderKey(orgId, fp, types.SettingReferenceBranch)
	got := engine.GetConfiguration().Get(key)
	assert.Nil(t, got, "Folder settings should not be written when RemoteUrl is empty")
}

func Test_RefreshConfigFromLdxSync_FolderSettingsLockedClearsOverrides(t *testing.T) {
	engine := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mockcommand.NewMockLdxSyncApiClient(ctrl)

	folderPath := types.FilePath("/test/folder")
	workspaceutil.SetupWorkspace(t, engine, folderPath)
	folders := config.GetWorkspace(engine.GetConfiguration()).Folders()

	// Set up a user override for reference_branch at folder level
	prefixKeyConfig := engine.GetConfiguration()
	fp := string(types.PathKey(folderPath))
	prefixKeyConfig.Set(
		configresolver.UserFolderKey(fp, types.SettingReferenceBranch),
		&configresolver.LocalConfigField{Value: "user-branch", Changed: true},
	)
	require.True(t, types.HasUserOverride(prefixKeyConfig, folderPath, types.SettingReferenceBranch),
		"User override should exist before refresh")

	orgId := "test-org-folder-locked"
	normalizedURL := "https://github.com/snyk/test-repo"
	folderSettings := map[string]v20241015.SettingMetadata{
		"reference_branch": {
			Value:  "locked-branch",
			Origin: v20241015.SettingMetadataOriginOrg,
			Locked: util.Ptr(true),
		},
	}

	expectedResult := createLdxSyncResultWithFolderSettings(orgId, normalizedURL, folderSettings, normalizedURL)

	mockApiClient.EXPECT().
		GetUserConfigForProject(gomock.Any(), engine, string(folders[0].Path()), "").
		Return(expectedResult)

	service := newTestLdxSyncService(mockApiClient, engine)
	service.RefreshConfigFromLdxSync(context.Background(), engine.GetConfiguration(), engine, engine.GetLogger(), folders, nil)

	// Verify user override was cleared for the locked folder setting
	assert.False(t, types.HasUserOverride(prefixKeyConfig, folderPath, types.SettingReferenceBranch),
		"User override should be cleared for locked folder setting")
}

// Test useConfigAPI FF gating: when FF is enabled, config should be written; when disabled, it should be skipped
func Test_RefreshConfigFromLdxSync_UseConfigAPIFFGating_Enabled(t *testing.T) {
	engine := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mockcommand.NewMockLdxSyncApiClient(ctrl)

	folderPath := types.PathKey("/test/folder")
	workspaceutil.SetupWorkspace(t, engine, folderPath)
	folders := config.GetWorkspace(engine.GetConfiguration()).Folders()

	expectedOrgId := "test-org-id-ff-enabled"
	// Use result with org settings instead of just org ID
	expectedResult := createLdxSyncResultWithOrgSettings(expectedOrgId, []string{"code"})

	mockApiClient.EXPECT().
		GetUserConfigForProject(gomock.Any(), engine, string(folders[0].Path()), "").
		Return(expectedResult)

	// Create service with FF enabled
	ffService := featureflag.NewFakeService()
	ffService.Flags[featureflag.UseConfigAPI] = true
	service := NewLdxSyncServiceWithApiClient(mockApiClient, testutil.DefaultConfigResolver(engine), ffService)

	service.RefreshConfigFromLdxSync(context.Background(), engine.GetConfiguration(), engine, engine.GetLogger(), folders, nil)

	// Verify AutoDeterminedOrg was written (always written regardless of FF)
	snapshot := types.ReadFolderConfigSnapshot(engine.GetConfiguration(), folderPath)
	assert.Equal(t, expectedOrgId, snapshot.AutoDeterminedOrg, "AutoDeterminedOrg should always be set")

	// Verify org config was written (because FF is enabled)
	orgKey := configresolver.RemoteOrgKey(expectedOrgId, types.SettingSnykCodeEnabled)
	orgConfig := engine.GetConfiguration().Get(orgKey)
	assert.NotNil(t, orgConfig, "Org config should be written when useConfigAPI FF is enabled")
}

// Test useConfigAPI FF gating: when FF is disabled, org config should NOT be written
func Test_RefreshConfigFromLdxSync_UseConfigAPIFFGating_Disabled(t *testing.T) {
	engine := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mockcommand.NewMockLdxSyncApiClient(ctrl)

	folderPath := types.PathKey("/test/folder")
	workspaceutil.SetupWorkspace(t, engine, folderPath)
	folders := config.GetWorkspace(engine.GetConfiguration()).Folders()

	expectedOrgId := "test-org-id-ff-disabled"
	expectedResult := createLdxSyncResultWithOrg(expectedOrgId)

	mockApiClient.EXPECT().
		GetUserConfigForProject(gomock.Any(), engine, string(folders[0].Path()), "").
		Return(expectedResult)

	// Create service with FF disabled (default)
	ffService := featureflag.NewFakeService()
	ffService.Flags[featureflag.UseConfigAPI] = false
	service := NewLdxSyncServiceWithApiClient(mockApiClient, testutil.DefaultConfigResolver(engine), ffService)

	service.RefreshConfigFromLdxSync(context.Background(), engine.GetConfiguration(), engine, engine.GetLogger(), folders, nil)

	// Verify AutoDeterminedOrg was still written (always written regardless of FF)
	snapshot := types.ReadFolderConfigSnapshot(engine.GetConfiguration(), folderPath)
	assert.Equal(t, expectedOrgId, snapshot.AutoDeterminedOrg, "AutoDeterminedOrg should always be set")

	// Verify org config was NOT written (because FF is disabled)
	orgKey := configresolver.RemoteOrgKey(expectedOrgId, types.SettingSnykCodeEnabled)
	orgConfig := engine.GetConfiguration().Get(orgKey)
	assert.Nil(t, orgConfig, "Org config should NOT be written when useConfigAPI FF is disabled")
}
