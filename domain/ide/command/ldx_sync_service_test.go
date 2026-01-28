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
// ABOUTME: Covers RefreshConfigFromLdxSync and ResolveOrg with various scenarios

package command

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config"

	mock_command "github.com/snyk/snyk-ls/domain/ide/command/mock"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/testutil/workspaceutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_RefreshConfigFromLdxSync_NoFolders(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mock_command.NewMockLdxSyncApiClient(ctrl)

	service := NewLdxSyncServiceWithApiClient(mockApiClient)

	// No API calls should be made for empty folder list
	service.RefreshConfigFromLdxSync(c, []types.Folder{})

	// Verify cache is empty
	result := c.GetLdxSyncResult(types.FilePath("/nonexistent"))
	assert.Nil(t, result)
}

func Test_RefreshConfigFromLdxSync_SingleFolder_Success(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mock_command.NewMockLdxSyncApiClient(ctrl)

	folderPath := types.FilePath("/test/folder")
	workspaceutil.SetupWorkspace(t, c, folderPath)
	folders := c.Workspace().Folders()

	expectedResult := ldx_sync_config.LdxSyncConfigResult{
		Error: nil,
	}

	// Expect API call with empty preferredOrg (no folder config exists)
	mockApiClient.EXPECT().
		GetUserConfigForProject(c.Engine(), string(folderPath), "").
		Return(expectedResult)

	service := NewLdxSyncServiceWithApiClient(mockApiClient)
	service.RefreshConfigFromLdxSync(c, folders)

	// Verify result was cached
	cachedResult := c.GetLdxSyncResult(folderPath)
	require.NotNil(t, cachedResult)
	assert.Equal(t, expectedResult, *cachedResult)
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
	folderConfig := &types.FolderConfig{
		FolderPath:   folderPath,
		PreferredOrg: preferredOrg,
	}
	err := storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), folderConfig, c.Logger())
	require.NoError(t, err)

	expectedResult := ldx_sync_config.LdxSyncConfigResult{
		Error: nil,
	}

	// Expect API call with preferredOrg from folder config
	mockApiClient.EXPECT().
		GetUserConfigForProject(c.Engine(), string(folderPath), preferredOrg).
		Return(expectedResult)

	service := NewLdxSyncServiceWithApiClient(mockApiClient)
	service.RefreshConfigFromLdxSync(c, folders)

	// Verify result was cached
	cachedResult := c.GetLdxSyncResult(folderPath)
	require.NotNil(t, cachedResult)
	assert.Equal(t, expectedResult, *cachedResult)
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

	result1 := ldx_sync_config.LdxSyncConfigResult{Error: nil}
	result2 := ldx_sync_config.LdxSyncConfigResult{Error: nil}
	result3 := ldx_sync_config.LdxSyncConfigResult{Error: nil}

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
	service.RefreshConfigFromLdxSync(c, folders)

	// Verify all results were cached
	assert.NotNil(t, c.GetLdxSyncResult(folder1Path))
	assert.NotNil(t, c.GetLdxSyncResult(folder2Path))
	assert.NotNil(t, c.GetLdxSyncResult(folder3Path))
}

func Test_RefreshConfigFromLdxSync_ApiError_NotCached(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mock_command.NewMockLdxSyncApiClient(ctrl)

	folderPath := types.FilePath("/test/folder")
	workspaceutil.SetupWorkspace(t, c, folderPath)
	folders := c.Workspace().Folders()

	apiError := errors.New("LDX-Sync API error")
	errorResult := ldx_sync_config.LdxSyncConfigResult{
		Error: apiError,
	}

	mockApiClient.EXPECT().
		GetUserConfigForProject(c.Engine(), string(folderPath), "").
		Return(errorResult)

	service := NewLdxSyncServiceWithApiClient(mockApiClient)
	service.RefreshConfigFromLdxSync(c, folders)

	// Verify error result was NOT cached
	cachedResult := c.GetLdxSyncResult(folderPath)
	assert.Nil(t, cachedResult, "Error results should not be cached")
}

func Test_ResolveOrg_WithCachedResult_Success(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mock_command.NewMockLdxSyncApiClient(ctrl)

	folderPath := types.FilePath("/test/folder")

	// Pre-populate cache
	cachedResult := ldx_sync_config.LdxSyncConfigResult{
		Error: nil,
	}
	c.UpdateLdxSyncCache(map[types.FilePath]*ldx_sync_config.LdxSyncConfigResult{
		folderPath: &cachedResult,
	})

	expectedOrg := ldx_sync_config.Organization{
		Id: "resolved-org-id",
	}

	// Expect ResolveOrgFromUserConfig to be called with cached result
	mockApiClient.EXPECT().
		ResolveOrgFromUserConfig(c.Engine(), cachedResult).
		Return(expectedOrg, nil)

	service := NewLdxSyncServiceWithApiClient(mockApiClient)
	org, err := service.ResolveOrg(c, folderPath)

	require.NoError(t, err)
	assert.Equal(t, expectedOrg.Id, org.Id)
}

func Test_ResolveOrg_WithCachedResult_Error(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mock_command.NewMockLdxSyncApiClient(ctrl)

	folderPath := types.FilePath("/test/folder")

	// Pre-populate cache
	cachedResult := ldx_sync_config.LdxSyncConfigResult{
		Error: nil,
	}
	c.UpdateLdxSyncCache(map[types.FilePath]*ldx_sync_config.LdxSyncConfigResult{
		folderPath: &cachedResult,
	})

	resolveError := errors.New("failed to resolve org")

	// Expect ResolveOrgFromUserConfig to return error
	mockApiClient.EXPECT().
		ResolveOrgFromUserConfig(c.Engine(), cachedResult).
		Return(ldx_sync_config.Organization{}, resolveError)

	service := NewLdxSyncServiceWithApiClient(mockApiClient)
	org, err := service.ResolveOrg(c, folderPath)

	assert.Error(t, err)
	assert.Equal(t, resolveError, err)
	assert.Empty(t, org.Id)
}

func Test_ResolveOrg_NoCachedResult_ReturnsError(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mock_command.NewMockLdxSyncApiClient(ctrl)

	folderPath := types.FilePath("/test/folder")
	// Use valid UUID format to avoid API resolution issues in tests
	globalOrg := "5b1ddf00-0000-0000-0000-000000000099"

	// Set global org
	c.SetOrganization(globalOrg)

	// No cache entry exists
	// No API calls expected - should return error instead of falling back

	service := NewLdxSyncServiceWithApiClient(mockApiClient)
	org, err := service.ResolveOrg(c, folderPath)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no organization was able to be determined for folder")
	assert.Empty(t, org.Id)
}

func Test_ResolveOrg_MultipleFolders_DifferentCachedResults(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mock_command.NewMockLdxSyncApiClient(ctrl)

	folder1Path := types.FilePath("/test/folder1")
	folder2Path := types.FilePath("/test/folder2")

	cachedResult1 := ldx_sync_config.LdxSyncConfigResult{Error: nil}
	cachedResult2 := ldx_sync_config.LdxSyncConfigResult{Error: nil}

	// Pre-populate cache with different results
	c.UpdateLdxSyncCache(map[types.FilePath]*ldx_sync_config.LdxSyncConfigResult{
		folder1Path: &cachedResult1,
		folder2Path: &cachedResult2,
	})

	org1 := ldx_sync_config.Organization{Id: "org-1"}
	org2 := ldx_sync_config.Organization{Id: "org-2"}

	mockApiClient.EXPECT().
		ResolveOrgFromUserConfig(c.Engine(), cachedResult1).
		Return(org1, nil)

	mockApiClient.EXPECT().
		ResolveOrgFromUserConfig(c.Engine(), cachedResult2).
		Return(org2, nil)

	service := NewLdxSyncServiceWithApiClient(mockApiClient)

	resolvedOrg1, err1 := service.ResolveOrg(c, folder1Path)
	require.NoError(t, err1)
	assert.Equal(t, org1.Id, resolvedOrg1.Id)

	resolvedOrg2, err2 := service.ResolveOrg(c, folder2Path)
	require.NoError(t, err2)
	assert.Equal(t, org2.Id, resolvedOrg2.Id)
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

func Test_DefaultLdxSyncApiClient_ResolveOrgFromUserConfig(t *testing.T) {
	c := testutil.UnitTest(t)
	client := &DefaultLdxSyncApiClient{}

	// Create a valid LdxSyncConfigResult with proper structure
	// Uses helper from folder_handler_test.go (same package)
	expectedOrgId := "test-org-from-ldx-sync"
	cachedResult := createLdxSyncResult(expectedOrgId, "Test Org", "test-org", true)

	// Call real GAF function through wrapper
	org, err := client.ResolveOrgFromUserConfig(c.Engine(), *cachedResult)

	require.NoError(t, err)
	assert.Equal(t, expectedOrgId, org.Id)
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

	expectedResult := ldx_sync_config.LdxSyncConfigResult{Error: nil}

	// Should handle empty path gracefully
	mockApiClient.EXPECT().
		GetUserConfigForProject(c.Engine(), string(emptyPath), "").
		Return(expectedResult)

	service := NewLdxSyncServiceWithApiClient(mockApiClient)
	service.RefreshConfigFromLdxSync(c, folders)

	// Should cache even with empty path
	cachedResult := c.GetLdxSyncResult(emptyPath)
	assert.NotNil(t, cachedResult)
}

func Test_ResolveOrg_EmptyFolderPath_ReturnsError(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mock_command.NewMockLdxSyncApiClient(ctrl)

	emptyPath := types.FilePath("")
	globalOrg := "5b1ddf00-0000-0000-0000-000000000088"
	c.SetOrganization(globalOrg)

	service := NewLdxSyncServiceWithApiClient(mockApiClient)
	org, err := service.ResolveOrg(c, emptyPath)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no organization was able to be determined for folder")
	assert.Empty(t, org.Id)
}

func Test_ResolveOrg_EmptyGlobalOrg_ReturnsError(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	mockApiClient := mock_command.NewMockLdxSyncApiClient(ctrl)

	folderPath := types.FilePath("/test/folder")
	// Don't set any organization - empty string

	service := NewLdxSyncServiceWithApiClient(mockApiClient)
	org, err := service.ResolveOrg(c, folderPath)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no organization was able to be determined for folder")
	assert.Empty(t, org.Id)
}
