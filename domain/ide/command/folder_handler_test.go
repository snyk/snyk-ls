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
	"strconv"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
	"github.com/snyk/snyk-ls/internal/util"
)

// setupMockOrgResolver sets up a mock organization resolver that returns the given organization
func setupMockOrgResolver(t *testing.T, org ldx_sync_config.Organization) {
	t.Helper()
	originalService := Service()
	t.Cleanup(func() {
		SetService(originalService)
	})

	ctrl := gomock.NewController(t)
	mockResolver := mock_types.NewMockOrgResolver(ctrl)
	mockResolver.EXPECT().ResolveOrganization(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(org, nil).AnyTimes()
	mockService := types.NewCommandServiceMock(nil)
	mockService.SetOrgResolver(mockResolver)
	SetService(mockService)
}

// setupMockOrgResolverWithError sets up a mock organization resolver that returns an error
func setupMockOrgResolverWithError(t *testing.T, err error) {
	t.Helper()
	originalService := Service()
	t.Cleanup(func() {
		SetService(originalService)
	})

	ctrl := gomock.NewController(t)
	mockResolver := mock_types.NewMockOrgResolver(ctrl)
	mockResolver.EXPECT().ResolveOrganization(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(ldx_sync_config.Organization{}, err).AnyTimes()
	mockService := types.NewCommandServiceMock(nil)
	mockService.SetOrgResolver(mockResolver)
	SetService(mockService)
}

// setupTestWorkspace creates a test workspace with the specified number of folders
func setupTestWorkspace(t *testing.T, c *config.Config, folderCount int) (
	notifier *notification.MockNotifier,
	folderPaths []types.FilePath,
) {
	t.Helper()

	// Create mock dependencies
	notifier = notification.NewMockNotifier()
	scanNotifier := scanner.NewMockScanNotifier()
	scanPersister := persistence.NewNopScanPersister()
	scanStateAggregator := scanstates.NewNoopStateAggregator()
	sc := scanner.NewTestScanner()
	hoverService := hover.NewFakeHoverService()

	// Create workspace
	w := workspace.New(c, performance.NewInstrumentor(), sc, hoverService, scanNotifier, notifier, scanPersister, scanStateAggregator, featureflag.NewFakeService())

	// Create and add folders
	safeTestName := testsupport.PathSafeTestName(t)
	folderPaths = make([]types.FilePath, folderCount)
	for i := range folderCount {
		folderPath := types.FilePath(t.TempDir())
		folderPaths[i] = folderPath
		folderName := safeTestName + "_test-folder_" + strconv.Itoa(i)
		folder := workspace.NewFolder(c, folderPath, folderName, sc, hoverService, scanNotifier, notifier, scanPersister, scanStateAggregator, featureflag.NewFakeService())
		w.AddFolder(folder)
	}

	// Set workspace on config
	c.SetWorkspace(w)

	return notifier, folderPaths
}

func Test_sendFolderConfigs_SendsNotification(t *testing.T) {
	c := testutil.UnitTest(t)
	mockEngine, engineConfig := testutil.SetUpEngineMock(t, c)
	mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
	mockEngine.EXPECT().GetLogger().Return(c.Logger()).AnyTimes()

	// Setup mock organization resolver
	expectedOrg := ldx_sync_config.Organization{
		Id:        "resolved-org-id",
		Name:      "Resolved Org",
		Slug:      "resolved-org",
		IsDefault: util.Ptr(false),
	}
	setupMockOrgResolver(t, expectedOrg)

	// Setup workspace with a folder
	notifier, folderPaths := setupTestWorkspace(t, c, 1)

	logger := c.Logger()
	storedConfig := &types.FolderConfig{
		FolderPath:                  folderPaths[0],
		PreferredOrg:                "test-org",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true,
	}
	err := storedconfig.UpdateFolderConfig(engineConfig, storedConfig, logger)
	require.NoError(t, err)

	sendFolderConfigs(c, notifier, featureflag.NewFakeService())

	// Verify notification was sent
	messages := notifier.SentMessages()
	require.Len(t, messages, 1)

	folderConfigsParam, ok := messages[0].(types.FolderConfigsParam)
	require.True(t, ok, "Expected FolderConfigsParam notification")
	require.Len(t, folderConfigsParam.FolderConfigs, 1)
	assert.Equal(t, "test-org", folderConfigsParam.FolderConfigs[0].PreferredOrg, "Notification should contain correct organization")
	assert.True(t, folderConfigsParam.FolderConfigs[0].OrgSetByUser, "Notification should reflect OrgSetByUser flag")
	assert.Equal(t, "resolved-org-id", folderConfigsParam.FolderConfigs[0].AutoDeterminedOrg, "AutoDeterminedOrg should be set by LDX-Sync")
}

func Test_sendFolderConfigs_NoFolders_NoNotification(t *testing.T) {
	c := testutil.UnitTest(t)
	mockEngine, engineConfig := testutil.SetUpEngineMock(t, c)
	mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
	mockEngine.EXPECT().GetLogger().Return(c.Logger()).AnyTimes()

	// Setup workspace with no folders
	notifier, _ := setupTestWorkspace(t, c, 0)

	sendFolderConfigs(c, notifier, featureflag.NewFakeService())

	// Verify no notification was sent
	messages := notifier.SentMessages()
	assert.Empty(t, messages)
}

// setupOrgResolverTest is a helper function to reduce duplication in org resolver tests
func setupOrgResolverTest(t *testing.T, orgID, orgName, orgSlug string, isDefault bool) (*config.Config, *types.FolderConfig, ldx_sync_config.Organization) {
	t.Helper()

	c := testutil.UnitTest(t)
	mockEngine, _ := testutil.SetUpEngineMock(t, c)
	mockEngine.EXPECT().GetConfiguration().AnyTimes()
	mockEngine.EXPECT().GetLogger().Return(c.Logger()).AnyTimes()

	expectedOrg := ldx_sync_config.Organization{
		Id:        orgID,
		Name:      orgName,
		Slug:      orgSlug,
		IsDefault: &isDefault,
	}

	// Setup mock organization resolver
	setupMockOrgResolver(t, expectedOrg)

	folderConfig := &types.FolderConfig{
		FolderPath: types.FilePath(t.TempDir()),
	}

	return c, folderConfig, expectedOrg
}

// Test GetBestOrgFromLdxSync with default org
func Test_SetAutoBestOrgFromLdxSync_DefaultOrg(t *testing.T) {
	c, folderConfig, expectedOrg := setupOrgResolverTest(t, "default-org-id", "Default Org", "default-org", true)

	org, err := GetBestOrgFromLdxSync(c, folderConfig)

	require.NoError(t, err)
	assert.Equal(t, expectedOrg.Id, org.Id)
	assert.True(t, *org.IsDefault)
}

// Test GetBestOrgFromLdxSync with non-default org
func Test_SetAutoBestOrgFromLdxSync_NonDefaultOrg(t *testing.T) {
	c, folderConfig, expectedOrg := setupOrgResolverTest(t, "specific-org-id", "Specific Org", "specific-org", false)

	org, err := GetBestOrgFromLdxSync(c, folderConfig)

	require.NoError(t, err)
	assert.Equal(t, expectedOrg.Id, org.Id)
	assert.False(t, *org.IsDefault)
}

// Test GetBestOrgFromLdxSync error handling
func Test_SetAutoBestOrgFromLdxSync_ErrorHandling(t *testing.T) {
	c := testutil.UnitTest(t)
	mockEngine, _ := testutil.SetUpEngineMock(t, c)
	mockEngine.EXPECT().GetConfiguration().AnyTimes()
	mockEngine.EXPECT().GetLogger().Return(c.Logger()).AnyTimes()

	// Setup mock organization resolver to return error
	setupMockOrgResolverWithError(t, assert.AnError)

	folderConfig := &types.FolderConfig{
		FolderPath: types.FilePath(t.TempDir()),
	}

	_, err := GetBestOrgFromLdxSync(c, folderConfig)

	require.Error(t, err)
}

// Test sendFolderConfigs with LDX-Sync error (should continue with other folders)
func Test_sendFolderConfigs_LdxSyncError_ContinuesProcessing(t *testing.T) {
	c := testutil.UnitTest(t)
	mockEngine, engineConfig := testutil.SetUpEngineMock(t, c)
	mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
	mockEngine.EXPECT().GetLogger().Return(c.Logger()).AnyTimes()

	// Setup mock organization resolver to return error
	setupMockOrgResolverWithError(t, assert.AnError)

	// Setup workspace with a folder
	notifier, folderPaths := setupTestWorkspace(t, c, 1)

	logger := c.Logger()
	storedConfig := &types.FolderConfig{
		FolderPath:                  folderPaths[0],
		PreferredOrg:                "test-org",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true,
	}
	err := storedconfig.UpdateFolderConfig(engineConfig, storedConfig, logger)
	require.NoError(t, err)
	sendFolderConfigs(c, notifier, featureflag.NewFakeService())

	// Verify notification was still sent despite error
	messages := notifier.SentMessages()
	require.Len(t, messages, 1)

	folderConfigsParam, ok := messages[0].(types.FolderConfigsParam)
	require.True(t, ok, "Expected FolderConfigsParam notification")
	require.Len(t, folderConfigsParam.FolderConfigs, 1)
	// AutoDeterminedOrg should be empty due to error
	assert.Empty(t, folderConfigsParam.FolderConfigs[0].AutoDeterminedOrg, "AutoDeterminedOrg should be empty when LDX-Sync fails")
}

// Test sendFolderConfigs with multiple folders and different org configurations
func Test_sendFolderConfigs_MultipleFolders_DifferentOrgConfigs(t *testing.T) {
	c := testutil.UnitTest(t)
	mockEngine, engineConfig := testutil.SetUpEngineMock(t, c)
	mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
	mockEngine.EXPECT().GetLogger().Return(c.Logger()).AnyTimes()

	// Setup mock organization resolver to return different orgs based on input path
	originalService := Service()
	t.Cleanup(func() {
		SetService(originalService)
	})

	ctrl := gomock.NewController(t)
	mockResolver := mock_types.NewMockOrgResolver(ctrl)
	mockResolver.EXPECT().ResolveOrganization(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(config configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, path string) (ldx_sync_config.Organization, error) {
			return ldx_sync_config.Organization{
				Id:        "org-id-for-" + path,
				Name:      "Org Name for " + path,
				Slug:      "org-slug-for-" + path,
				IsDefault: util.Ptr(false),
			}, nil
		}).AnyTimes()
	mockService := types.NewCommandServiceMock(nil)
	mockService.SetOrgResolver(mockResolver)
	SetService(mockService)

	// Setup workspace with multiple folders
	notifier, folderPaths := setupTestWorkspace(t, c, 2)

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

	sendFolderConfigs(c, notifier, featureflag.NewFakeService())

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
			mockEngine, gafConfig := testutil.SetUpEngineMock(t, c)
			mockEngine.EXPECT().GetConfiguration().Return(gafConfig).AnyTimes()

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
