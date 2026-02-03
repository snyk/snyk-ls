/*
 * © 2025 Snyk Limited
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

package command

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	mcpconfig "github.com/snyk/studio-mcp/pkg/mcp"

	"github.com/snyk/snyk-ls/application/config"
	mock_command "github.com/snyk/snyk-ls/domain/ide/command/mock"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/testutil/workspaceutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"

	"github.com/google/uuid"
	v20241015 "github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config/ldx_sync/2024-10-15"
)

// setupLdxSyncService returns a real LdxSyncService implementation for tests that specifically test cache logic
// For most tests, prefer using mock.NewMockLdxSyncService() instead of pre-populating cache
func setupLdxSyncService(t *testing.T) LdxSyncService {
	t.Helper()
	return NewLdxSyncService()
}

// createLdxSyncResult is a helper to create a properly structured LdxSyncConfigResult for tests
func createLdxSyncResult(orgId, orgName, orgSlug string, isDefault bool) *ldx_sync_config.LdxSyncConfigResult {
	orgs := []v20241015.Organization{
		{
			Id:                   orgId,
			Name:                 orgName,
			Slug:                 orgSlug,
			IsDefault:            util.Ptr(isDefault),
			PreferredByAlgorithm: util.Ptr(true), // Always mark as preferred for test purposes
		},
	}

	// Create a UUID for the config ID
	configId := uuid.MustParse("00000000-0000-0000-0000-000000000001")

	return &ldx_sync_config.LdxSyncConfigResult{
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
		RemoteUrl:   "https://github.com/test/repo.git",
		ProjectRoot: "/fake/test-folder",
		Error:       nil,
	}
}

func Test_sendFolderConfigs_SendsNotification(t *testing.T) {
	c := testutil.UnitTest(t)
	engineConfig := c.Engine().GetConfiguration()

	// Setup mock LdxSyncService
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockLdxSyncService := mock_command.NewMockLdxSyncService(ctrl)

	// Setup workspace with a folder
	folderPaths := []types.FilePath{types.FilePath("/fake/test-folder-0")}
	_, notifier := workspaceutil.SetupWorkspace(t, c, folderPaths...)

	logger := c.Logger()
	storedConfig := &types.FolderConfig{
		FolderPath:                  folderPaths[0],
		PreferredOrg:                "test-org",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true,
	}
	err := storedconfig.UpdateFolderConfig(engineConfig, storedConfig, logger)
	require.NoError(t, err)

	// Mock ResolveOrg to return the expected organization
	expectedOrgId := "resolved-org-id"
	mockLdxSyncService.EXPECT().
		ResolveOrg(c, gomock.Any()).
		Return(ldx_sync_config.Organization{Id: expectedOrgId}, nil).
		AnyTimes()

	sendFolderConfigs(c, notifier, featureflag.NewFakeService(), mockLdxSyncService)

	// Verify notification was sent
	messages := notifier.SentMessages()
	require.Len(t, messages, 1)

	folderConfigsParam, ok := messages[0].(types.FolderConfigsParam)
	require.True(t, ok, "Expected FolderConfigsParam notification")
	require.Len(t, folderConfigsParam.FolderConfigs, 1)
	assert.Equal(t, "test-org", folderConfigsParam.FolderConfigs[0].PreferredOrg, "Notification should contain correct organization")
	assert.True(t, folderConfigsParam.FolderConfigs[0].OrgSetByUser, "Notification should reflect OrgSetByUser flag")
	assert.Equal(t, expectedOrgId, folderConfigsParam.FolderConfigs[0].AutoDeterminedOrg, "AutoDeterminedOrg should be set from ResolveOrg")
}

func Test_sendFolderConfigs_NoFolders_NoNotification(t *testing.T) {
	c := testutil.UnitTest(t)
	_, _ = testutil.SetUpEngineMock(t, c)

	// Setup workspace with no folders
	_, notifier := workspaceutil.SetupWorkspace(t, c)

	mockService := setupLdxSyncService(t)
	sendFolderConfigs(c, notifier, featureflag.NewFakeService(), mockService)

	// Verify no notification was sent
	messages := notifier.SentMessages()
	assert.Empty(t, messages)
}

func Test_HandleFolders_TriggersMcpConfigWorkflow(t *testing.T) {
	c := testutil.UnitTest(t)
	mockEngine, _ := testutil.SetUpEngineMock(t, c)

	originalService := Service()
	t.Cleanup(func() {
		SetService(originalService)
	})
	SetService(types.NewCommandServiceMock())

	// Clear token to prevent RefreshConfigFromLdxSync from being called in this test
	c.SetToken("")

	called := make(chan struct{}, 1)
	mockEngine.EXPECT().InvokeWithConfig(mcpconfig.WORKFLOWID_MCP_CONFIG, gomock.Any()).
		DoAndReturn(func(_ workflow.Identifier, _ configuration.Configuration) ([]workflow.Data, error) {
			called <- struct{}{}
			return nil, nil
		}).Times(1)

	_, n := workspaceutil.SetupWorkspace(t, c, types.FilePath("/workspace/one"))

	mockService := setupLdxSyncService(t)
	HandleFolders(c, context.Background(), nil, n, persistence.NewNopScanPersister(), scanstates.NewNoopStateAggregator(), featureflag.NewFakeService(), mockService)

	select {
	case <-called:
		// ok
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for MCP config workflow invocation")
	}
}

// Test LdxSyncService.ResolveOrg error handling - returns error when cache is empty
func Test_SetAutoBestOrgFromLdxSync_ErrorHandling(t *testing.T) {
	c := testutil.UnitTest(t)
	_, gafConfig := testutil.SetUpEngineMock(t, c)

	folderConfig := &types.FolderConfig{
		FolderPath: types.FilePath(t.TempDir()),
	}

	// Set global org
	gafConfig.Set(configuration.ORGANIZATION, "fallback-global-org")

	// Don't populate cache - should return error
	mockService := setupLdxSyncService(t)
	org, err := mockService.ResolveOrg(c, folderConfig.FolderPath)

	require.Error(t, err, "Should return error when cache is empty")
	assert.Contains(t, err.Error(), "no organization was able to be determined for folder")
	assert.Empty(t, org.Id)
}

// Test LdxSyncService.ResolveOrg returns error when cache is empty
func Test_SetAutoBestOrgFromLdxSync_NoCachereturnsError(t *testing.T) {
	c := testutil.UnitTest(t)
	_, gafConfig := testutil.SetUpEngineMock(t, c)

	// Set organization in GAF config
	gafConfig.Set(configuration.ORGANIZATION, "fallback-org-id")

	// Ensure no resolver is set (default state)
	originalService := Service()
	t.Cleanup(func() {
		SetService(originalService)
	})
	mockService := types.NewCommandServiceMock()
	SetService(mockService)

	folderConfig := &types.FolderConfig{
		FolderPath: types.FilePath(t.TempDir()),
	}

	mockLdxSync := setupLdxSyncService(t)
	org, err := mockLdxSync.ResolveOrg(c, folderConfig.FolderPath)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no organization was able to be determined for folder")
	assert.Empty(t, org.Id)
}

// Test sendFolderConfigs when cache is empty (should leave AutoDeterminedOrg empty)
func Test_sendFolderConfigs_EmptyCache_NoAutoDeterminedOrg(t *testing.T) {
	c := testutil.UnitTest(t)
	_, engineConfig := testutil.SetUpEngineMock(t, c)

	// Setup workspace with a folder
	folderPaths := []types.FilePath{types.FilePath("/fake/test-folder-0")}
	_, notifier := workspaceutil.SetupWorkspace(t, c, folderPaths...)

	// Set global org
	engineConfig.Set(configuration.ORGANIZATION, "global-fallback-org")

	logger := c.Logger()
	storedConfig := &types.FolderConfig{
		FolderPath:                  folderPaths[0],
		PreferredOrg:                "test-org",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true,
	}
	err := storedconfig.UpdateFolderConfig(engineConfig, storedConfig, logger)
	require.NoError(t, err)

	// Don't populate cache - should not set AutoDeterminedOrg
	mockService := setupLdxSyncService(t)
	sendFolderConfigs(c, notifier, featureflag.NewFakeService(), mockService)

	// Verify notification was still sent
	messages := notifier.SentMessages()
	require.Len(t, messages, 1)

	folderConfigsParam, ok := messages[0].(types.FolderConfigsParam)
	require.True(t, ok, "Expected FolderConfigsParam notification")
	require.Len(t, folderConfigsParam.FolderConfigs, 1)
	// AutoDeterminedOrg should be empty when cache is empty
	assert.Empty(t, folderConfigsParam.FolderConfigs[0].AutoDeterminedOrg, "AutoDeterminedOrg should be empty when cache is empty")
}

// Test sendFolderConfigs with multiple folders and different org configurations
func Test_sendFolderConfigs_MultipleFolders_DifferentOrgConfigs(t *testing.T) {
	c := testutil.UnitTest(t)
	engineConfig := c.Engine().GetConfiguration()

	// Setup mock LdxSyncService
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockLdxSyncService := mock_command.NewMockLdxSyncService(ctrl)

	// Setup workspace with multiple folders
	folderPaths := []types.FilePath{
		types.FilePath("/fake/test-folder-0"),
		types.FilePath("/fake/test-folder-1"),
	}
	_, notifier := workspaceutil.SetupWorkspace(t, c, folderPaths...)

	logger := c.Logger()

	// Setup different org configs for each folder - both already migrated to avoid migration path
	storedConfig1 := &types.FolderConfig{
		FolderPath:                  folderPaths[0],
		PreferredOrg:                "user-org-1",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true,
	}
	err := storedconfig.UpdateFolderConfig(engineConfig, storedConfig1, logger)
	require.NoError(t, err)

	storedConfig2 := &types.FolderConfig{
		FolderPath:                  folderPaths[1],
		PreferredOrg:                "",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                false,
	}
	err = storedconfig.UpdateFolderConfig(engineConfig, storedConfig2, logger)
	require.NoError(t, err)

	// Mock ResolveOrg to return different orgs based on folder path
	// Matches original pre-refactor behavior: just concatenate path to make unique org IDs
	mockLdxSyncService.EXPECT().
		ResolveOrg(c, gomock.Any()).
		DoAndReturn(func(_ *config.Config, folderPath types.FilePath) (ldx_sync_config.Organization, error) {
			return ldx_sync_config.Organization{
				Id: "org-id-for-" + string(folderPath),
			}, nil
		}).
		AnyTimes()

	sendFolderConfigs(c, notifier, featureflag.NewFakeService(), mockLdxSyncService)

	// Verify notification was sent with both folders
	messages := notifier.SentMessages()
	require.Len(t, messages, 1)

	folderConfigsParam, ok := messages[0].(types.FolderConfigsParam)
	require.True(t, ok, "Expected FolderConfigsParam notification")
	require.Len(t, folderConfigsParam.FolderConfigs, 2)

	// Verify each folder has its own AutoDeterminedOrg
	for _, fc := range folderConfigsParam.FolderConfigs {
		assert.NotEmpty(t, fc.AutoDeterminedOrg, "AutoDeterminedOrg should be set for each folder")
		assert.Contains(t, fc.AutoDeterminedOrg, "org-id-for-", "AutoDeterminedOrg should be path-specific")
	}
}

func Test_isOrgDefault(t *testing.T) {
	tests := []struct {
		name                 string
		setDefaultOrgValue   string
		setDefaultSlugValue  string
		testValue            string
		expectedIsDefault    bool
		expectedErrorMessage string
	}{
		{
			name:                "empty organization",
			setDefaultOrgValue:  "test-default-org-uuid",
			setDefaultSlugValue: "test-default-org-slug",
			testValue:           "",
			expectedIsDefault:   true,
		},
		{
			name:                "matching UUID",
			setDefaultOrgValue:  "test-default-org-uuid",
			setDefaultSlugValue: "test-default-org-slug",
			testValue:           "test-default-org-uuid",
			expectedIsDefault:   true,
		},
		{
			name:                "matching slug",
			setDefaultOrgValue:  "test-default-org-uuid",
			setDefaultSlugValue: "test-default-org-slug",
			testValue:           "test-default-org-slug",
			expectedIsDefault:   true,
		},
		{
			name:                "non-matching organization",
			setDefaultOrgValue:  "test-default-org-uuid",
			setDefaultSlugValue: "test-default-org-slug",
			testValue:           "different-org-id",
			expectedIsDefault:   false,
		},
		{
			name:                 "failed to fetch default UUID returns error",
			setDefaultOrgValue:   "",
			setDefaultSlugValue:  "test-default-org-slug",
			testValue:            "some-org-id",
			expectedErrorMessage: "could not retrieve the user's default organization",
		},
		{
			name:                 "failed to fetch default slug returns error when UUID not matched",
			setDefaultOrgValue:   "test-default-org-uuid",
			setDefaultSlugValue:  "",
			testValue:            "some-org-id",
			expectedErrorMessage: "could not retrieve the user's default organization slug",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := testutil.UnitTest(t)
			_, gafConfig := testutil.SetUpEngineMock(t, c)

			// Setup mock default values for org config - these will not be overridden by a GAF config clone, which the function does.
			gafConfig.AddDefaultValue(configuration.ORGANIZATION, configuration.ImmutableDefaultValueFunction(tt.setDefaultOrgValue))
			gafConfig.AddDefaultValue(configuration.ORGANIZATION_SLUG, configuration.ImmutableDefaultValueFunction(tt.setDefaultSlugValue))

			isDefault, err := isOrgDefault(c, tt.testValue)

			if tt.expectedErrorMessage != "" {
				require.Error(t, err)
				assert.False(t, isDefault)
				assert.ErrorContains(t, err, tt.expectedErrorMessage)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedIsDefault, isDefault)
			}
		})
	}
}

func Test_MigrateFolderConfigOrgSettings_DefaultOrg(t *testing.T) {
	c := testutil.UnitTest(t)

	// Setup: Use immutable defaults so isOrgDefault() can clone config, set org="", and still retrieve the default org
	gafConfig := c.Engine().GetConfiguration()
	gafConfig.AddDefaultValue(configuration.ORGANIZATION, configuration.ImmutableDefaultValueFunction("default-org-uuid"))
	gafConfig.AddDefaultValue(configuration.ORGANIZATION_SLUG, configuration.ImmutableDefaultValueFunction("default-org-slug"))

	folderConfig := &types.FolderConfig{
		FolderPath:                  types.FilePath(t.TempDir()),
		OrgSetByUser:                false,
		OrgMigratedFromGlobalConfig: false,
		PreferredOrg:                "",
	}

	// Action
	MigrateFolderConfigOrgSettings(c, folderConfig)

	// Assert: User is using default org, should opt into auto-org
	assert.False(t, folderConfig.OrgSetByUser, "OrgSetByUser should be false (opt into auto-org)")
	assert.Empty(t, folderConfig.PreferredOrg, "PreferredOrg should be empty (using auto-org)")
	assert.True(t, folderConfig.OrgMigratedFromGlobalConfig, "Should be marked as migrated")
}

func Test_MigrateFolderConfigOrgSettings_NonDefaultOrg(t *testing.T) {
	c := testutil.UnitTest(t)

	// Setup: Use a regular (mutable) DefaultValueFunction so Set() can override it
	// When isOrgDefault clones config and sets org="", it will get "default-org-uuid"
	// But when we Set() a value, c.Organization() will return the set value
	gafConfig := c.Engine().GetConfiguration()
	gafConfig.AddDefaultValue(configuration.ORGANIZATION, func(c configuration.Configuration, existingValue any) (any, error) {
		if existingValue != nil && existingValue != "" {
			return existingValue, nil
		}
		return "default-org-uuid", nil
	})
	gafConfig.AddDefaultValue(configuration.ORGANIZATION_SLUG, configuration.ImmutableDefaultValueFunction("default-org-slug"))

	// Set the user's non-default org
	c.SetOrganization("non-default-org-id")

	folderConfig := &types.FolderConfig{
		FolderPath:                  types.FilePath(t.TempDir()),
		OrgSetByUser:                false,
		OrgMigratedFromGlobalConfig: false,
		PreferredOrg:                "",
	}

	// Action
	MigrateFolderConfigOrgSettings(c, folderConfig)

	// Assert: User explicitly set non-default org, should opt out and copy org
	assert.True(t, folderConfig.OrgSetByUser, "OrgSetByUser should be true (user explicitly set)")
	assert.Equal(t, "non-default-org-id", folderConfig.PreferredOrg, "PreferredOrg should be copied from global")
	assert.True(t, folderConfig.OrgMigratedFromGlobalConfig, "Should be marked as migrated")
}

func Test_MigrateFolderConfigOrgSettings_Unauthenticated_MigrationSkipped(t *testing.T) {
	c := testutil.UnitTest(t)

	// Setup: Unauthenticated state - using default value functions that return errors where API calls would be
	gafConfig := c.Engine().GetConfiguration()
	gafConfig.AddDefaultValue(configuration.ORGANIZATION, func(c configuration.Configuration, existingValue any) (any, error) {
		if existingValue != nil && existingValue != "" {
			return existingValue, nil
		}
		return "", fmt.Errorf("unable to retrieve org ID: API request failed (status: 401)")
	})
	gafConfig.AddDefaultValue(configuration.ORGANIZATION_SLUG, func(c configuration.Configuration, existingValue any) (any, error) {
		if existingValue != nil && existingValue != "" {
			return existingValue, nil
		}
		return "", fmt.Errorf("unable to retrieve org slug: API request failed (status: 401)")
	})

	// User has a custom global org set
	gafConfig.Set(configuration.ORGANIZATION, "custom-org-id")

	// Setup: Pre-feature folder with zero-value fields (never read during EA)
	folderConfig := &types.FolderConfig{
		FolderPath: types.FilePath(t.TempDir()),
	}

	// Action
	MigrateFolderConfigOrgSettings(c, folderConfig)

	// Assert: Migration should be skipped when isOrgDefault fails (line 191 in folder_handler.go)
	assert.False(t, folderConfig.OrgMigratedFromGlobalConfig, "Should remain unmigrated (migration skipped)")
	assert.False(t, folderConfig.OrgSetByUser, "OrgSetByUser should remain false")
	assert.Empty(t, folderConfig.PreferredOrg, "PreferredOrg should remain empty")
}

// Test LdxSyncService.ResolveOrgwith cached result
func Test_GetOrgFromCachedLdxSync_WithCache(t *testing.T) {
	c := testutil.UnitTest(t)
	gafConfig := c.Engine().GetConfiguration()

	folderPath := types.FilePath("/fake/test-folder")

	// Populate cache with a result
	expectedOrgId := "cached-org-id"
	cachedResult := createLdxSyncResult(expectedOrgId, "Cached Org", "cached-org", false)
	c.UpdateLdxSyncCache(map[types.FilePath]*ldx_sync_config.LdxSyncConfigResult{
		folderPath: cachedResult,
	})

	// Set a different global org to ensure we're using the cache
	gafConfig.Set(configuration.ORGANIZATION, "different-global-org")

	mockService := setupLdxSyncService(t)
	org, err := mockService.ResolveOrg(c, folderPath)

	require.NoError(t, err)
	assert.Equal(t, expectedOrgId, org.Id, "Should return org from cache")
}

// Test LdxSyncService.ResolveOrg without cached result (returns error)
func Test_GetOrgFromCachedLdxSync_WithoutCache_ReturnsError(t *testing.T) {
	c := testutil.UnitTest(t)
	_, gafConfig := testutil.SetUpEngineMock(t, c)

	folderPath := types.FilePath("/fake/test-folder")

	// Set global org
	gafConfig.Set(configuration.ORGANIZATION, "global-org-id")

	// Don't populate cache
	mockService := setupLdxSyncService(t)
	org, err := mockService.ResolveOrg(c, folderPath)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no organization was able to be determined for folder")
	assert.Empty(t, org.Id)
}
