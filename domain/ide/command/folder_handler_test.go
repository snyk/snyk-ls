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

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	mcpconfig "github.com/snyk/studio-mcp/pkg/mcp"

	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/testutil/workspaceutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

// populateFolderOrgCache is a helper to populate the LDX-Sync org config cache for tests
func populateFolderOrgCache(c interface {
	GetLdxSyncOrgConfigCache() *types.LDXSyncConfigCache
}, folderPath types.FilePath, orgId string) {
	cache := c.GetLdxSyncOrgConfigCache()
	cache.SetFolderOrg(util.PathKey(folderPath), orgId)
}

func Test_sendFolderConfigs_SendsNotification(t *testing.T) {
	c := testutil.UnitTest(t)
	engineConfig := c.Engine().GetConfiguration()

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

	// Populate cache with LDX-Sync result
	expectedOrgId := "resolved-org-id"
	populateFolderOrgCache(c, folderPaths[0], expectedOrgId)

	sendFolderConfigs(c, notifier, featureflag.NewFakeService())

	// Verify notification was sent
	messages := notifier.SentMessages()
	require.Len(t, messages, 1)

	folderConfigsParam, ok := messages[0].(types.FolderConfigsParam)
	require.True(t, ok, "Expected FolderConfigsParam notification")
	require.Len(t, folderConfigsParam.FolderConfigs, 1)
	assert.Equal(t, "test-org", folderConfigsParam.FolderConfigs[0].PreferredOrg, "Notification should contain correct organization")
	assert.True(t, folderConfigsParam.FolderConfigs[0].OrgSetByUser, "Notification should reflect OrgSetByUser flag")
	assert.Equal(t, expectedOrgId, folderConfigsParam.FolderConfigs[0].AutoDeterminedOrg, "AutoDeterminedOrg should be set from cache")
}

func Test_sendFolderConfigs_NoFolders_NoNotification(t *testing.T) {
	c := testutil.UnitTest(t)
	_, _ = testutil.SetUpEngineMock(t, c)

	// Setup workspace with no folders
	_, notifier := workspaceutil.SetupWorkspace(t, c)

	sendFolderConfigs(c, notifier, featureflag.NewFakeService())

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

	HandleFolders(c, context.Background(), nil, n, persistence.NewNopScanPersister(), scanstates.NewNoopStateAggregator(), featureflag.NewFakeService())

	select {
	case <-called:
		// ok
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for MCP config workflow invocation")
	}
}

// Test cache lookup when cache is empty - AutoDeterminedOrg should remain empty
func Test_sendFolderConfigs_EmptyCache_AutoDeterminedOrgEmpty(t *testing.T) {
	c := testutil.UnitTest(t)
	_, engineConfig := testutil.SetUpEngineMock(t, c)

	// Setup workspace with a folder
	folderPaths := []types.FilePath{types.FilePath(t.TempDir())}
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

	// Don't populate cache - AutoDeterminedOrg should remain empty
	sendFolderConfigs(c, notifier, featureflag.NewFakeService())

	// Verify notification was sent
	messages := notifier.SentMessages()
	require.Len(t, messages, 1)

	folderConfigsParam, ok := messages[0].(types.FolderConfigsParam)
	require.True(t, ok, "Expected FolderConfigsParam notification")
	require.Len(t, folderConfigsParam.FolderConfigs, 1)
	// AutoDeterminedOrg should be empty when cache is empty
	assert.Empty(t, folderConfigsParam.FolderConfigs[0].AutoDeterminedOrg, "AutoDeterminedOrg should be empty when cache is empty")
}

// Test sendFolderConfigs when cache has org ID
func Test_sendFolderConfigs_CachePopulated_AutoDeterminedOrgSet(t *testing.T) {
	c := testutil.UnitTest(t)
	_, engineConfig := testutil.SetUpEngineMock(t, c)

	// Setup workspace with a folder
	folderPaths := []types.FilePath{types.FilePath(t.TempDir())}
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

	// Populate cache with org ID
	expectedOrgId := "cached-org-id"
	populateFolderOrgCache(c, folderPaths[0], expectedOrgId)

	sendFolderConfigs(c, notifier, featureflag.NewFakeService())

	// Verify notification was sent
	messages := notifier.SentMessages()
	require.Len(t, messages, 1)

	folderConfigsParam, ok := messages[0].(types.FolderConfigsParam)
	require.True(t, ok, "Expected FolderConfigsParam notification")
	require.Len(t, folderConfigsParam.FolderConfigs, 1)
	assert.Equal(t, expectedOrgId, folderConfigsParam.FolderConfigs[0].AutoDeterminedOrg, "AutoDeterminedOrg should be set from cache")
}

// Test sendFolderConfigs with multiple folders and different org configurations
func Test_sendFolderConfigs_MultipleFolders_DifferentOrgConfigs(t *testing.T) {
	c := testutil.UnitTest(t)
	engineConfig := c.Engine().GetConfiguration()

	// Setup workspace with multiple folders
	folderPaths := []types.FilePath{
		types.FilePath(t.TempDir() + "/folder-0"),
		types.FilePath(t.TempDir() + "/folder-1"),
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

	// Populate cache with different orgs for each folder
	populateFolderOrgCache(c, folderPaths[0], "org-id-for-folder-0")
	populateFolderOrgCache(c, folderPaths[1], "org-id-for-folder-1")

	sendFolderConfigs(c, notifier, featureflag.NewFakeService())

	// Verify notification was sent with both folders
	messages := notifier.SentMessages()
	require.Len(t, messages, 1)

	folderConfigsParam, ok := messages[0].(types.FolderConfigsParam)
	require.True(t, ok, "Expected FolderConfigsParam notification")
	require.Len(t, folderConfigsParam.FolderConfigs, 2)

	// Verify each folder has its own AutoDeterminedOrg (order is not guaranteed due to map iteration)
	expectedOrgs := map[types.FilePath]string{
		folderPaths[0]: "org-id-for-folder-0",
		folderPaths[1]: "org-id-for-folder-1",
	}
	for _, fc := range folderConfigsParam.FolderConfigs {
		expectedOrg, found := expectedOrgs[fc.FolderPath]
		require.True(t, found, "Unexpected folder path: %s", fc.FolderPath)
		assert.NotEmpty(t, fc.AutoDeterminedOrg, "AutoDeterminedOrg should be set for folder %s", fc.FolderPath)
		assert.Equal(t, expectedOrg, fc.AutoDeterminedOrg, "AutoDeterminedOrg should be folder-specific for %s", fc.FolderPath)
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

// Test GetOrgIdForFolder with cached result
func Test_GetOrgIdForFolder_WithCache(t *testing.T) {
	c := testutil.UnitTest(t)

	folderPath := types.FilePath(t.TempDir())

	// Populate cache with org ID
	expectedOrgId := "cached-org-id"
	populateFolderOrgCache(c, folderPath, expectedOrgId)

	// Get org from cache
	cache := c.GetLdxSyncOrgConfigCache()
	orgId := cache.GetOrgIdForFolder(folderPath)

	assert.Equal(t, expectedOrgId, orgId, "Should return org from cache")
}

// Test GetOrgIdForFolder without cached result returns empty string
func Test_GetOrgIdForFolder_WithoutCache_ReturnsEmpty(t *testing.T) {
	c := testutil.UnitTest(t)

	folderPath := types.FilePath(t.TempDir())

	// Don't populate cache
	cache := c.GetLdxSyncOrgConfigCache()
	orgId := cache.GetOrgIdForFolder(folderPath)

	assert.Empty(t, orgId, "Should return empty string when cache is empty")
}
