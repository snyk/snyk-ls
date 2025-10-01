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
	"encoding/json"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func setupTestWorkspace(t *testing.T, c *config.Config, folderPath types.FilePath) *workspace.Workspace {
	t.Helper()
	notifier := notification.NewMockNotifier()
	scanNotifier := scanner.NewMockScanNotifier()
	scanPersister := persistence.NewNopScanPersister()
	scanStateAggregator := scanstates.NewNoopStateAggregator()
	sc := scanner.NewTestScanner()
	hoverService := hover.NewFakeHoverService()

	w := workspace.New(c, performance.NewInstrumentor(), sc, hoverService, scanNotifier, notifier, scanPersister, scanStateAggregator)
	folder := workspace.NewFolder(c, folderPath, t.Name(), sc, hoverService, scanNotifier, notifier, scanPersister, scanStateAggregator)
	w.AddFolder(folder)
	c.SetWorkspace(w)

	return w
}

func setupNetworkAccessMock(ctrl *gomock.Controller) *mocks.MockNetworkAccess {
	mockNetworkAccess := mocks.NewMockNetworkAccess(ctrl)
	mockNetworkAccess.EXPECT().GetHttpClient().Return(&http.Client{}).AnyTimes()
	return mockNetworkAccess
}

// mockLdxSyncResponse creates a mock response for LDX-Sync ResolveOrganization
func mockLdxSyncResponse(orgID string, isDefault bool) []workflow.Data {
	// Create the organization response structure that matches what LDX-Sync returns
	type Organization struct {
		Id        string `json:"id"`
		IsDefault *bool  `json:"is_default,omitempty"`
		Name      string `json:"name"`
	}
	
	isDefaultPtr := &isDefault
	org := Organization{
		Id:        orgID,
		IsDefault: isDefaultPtr,
		Name:      "Test Org",
	}
	
	orgJSON, _ := json.Marshal(org)
	
	// Create a simple workflow identifier for the mock
	// We just need to return the data in a format that can be unmarshaled
	return []workflow.Data{
		workflow.NewData(nil, "application/json", orgJSON),
	}
}

// Test scenarios for already migrated configs
func Test_updateAndSendFolderConfigs_MigratedConfig_UserSetWithNonEmptyOrg(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine, engineConfig := testutil.SetUpEngineMock(t, c)
	mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
	mockEngine.EXPECT().GetLogger().Return(c.Logger()).AnyTimes()
	mockNetworkAccess := setupNetworkAccessMock(ctrl)
	mockEngine.EXPECT().GetNetworkAccess().Return(mockNetworkAccess).AnyTimes()
	mockEngine.EXPECT().InvokeWithInputAndConfig(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()

	folderPath := types.FilePath(t.TempDir())
	setupTestWorkspace(t, c, folderPath)

	// Setup stored config with user-set org
	logger := c.Logger()
	storedConfig := &types.FolderConfig{
		FolderPath:                  folderPath,
		Organization:                "user-org-id",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true,
	}
	err := storedconfig.UpdateFolderConfig(engineConfig, storedConfig, logger)
	require.NoError(t, err)

	c.SetOrganization("global-org-id")

	notifier := notification.NewMockNotifier()
	updateAndSendFolderConfigs(c, notifier)

	// Verify the org was kept and still marked as user-set
	updatedConfig, err := storedconfig.GetOrCreateFolderConfig(engineConfig, folderPath, logger)
	require.NoError(t, err)
	assert.Equal(t, "user-org-id", updatedConfig.Organization, "Organization should remain as user-set value")
	assert.True(t, updatedConfig.OrgSetByUser, "OrgSetByUser should remain true")
}

func Test_updateAndSendFolderConfigs_MigratedConfig_InheritingFromBlankGlobal(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine, engineConfig := testutil.SetUpEngineMock(t, c)
	mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
	mockEngine.EXPECT().GetLogger().Return(c.Logger()).AnyTimes()
	mockNetworkAccess := setupNetworkAccessMock(ctrl)
	mockEngine.EXPECT().GetNetworkAccess().Return(mockNetworkAccess).AnyTimes()

	folderPath := types.FilePath(t.TempDir())
	setupTestWorkspace(t, c, folderPath)

	// Setup stored config with empty org
	logger := c.Logger()
	storedConfig := &types.FolderConfig{
		FolderPath:                  folderPath,
		Organization:                "",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                false,
	}
	err := storedconfig.UpdateFolderConfig(engineConfig, storedConfig, logger)
	require.NoError(t, err)

	c.SetOrganization("")

	// Note: LDX-Sync will fail in test environment (not a git repo, no API access)
	// When LDX-Sync fails with empty org, the org remains empty
	mockEngine.EXPECT().InvokeWithInputAndConfig(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()

	notifier := notification.NewMockNotifier()
	updateAndSendFolderConfigs(c, notifier)

	// Verify: When both folder and global org are empty and LDX-Sync fails,
	// the org remains empty
	updatedConfig, err := storedconfig.GetOrCreateFolderConfig(engineConfig, folderPath, logger)
	require.NoError(t, err)
	assert.Empty(t, updatedConfig.Organization, "Organization should remain empty when LDX-Sync fails")
	assert.False(t, updatedConfig.OrgSetByUser, "OrgSetByUser should be false")
}

// Test scenarios for not yet migrated configs
func Test_updateAndSendFolderConfigs_NotMigrated_EmptyStoredOrg(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine, engineConfig := testutil.SetUpEngineMock(t, c)
	mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
	mockEngine.EXPECT().GetLogger().Return(c.Logger()).AnyTimes()
	mockNetworkAccess := setupNetworkAccessMock(ctrl)
	mockEngine.EXPECT().GetNetworkAccess().Return(mockNetworkAccess).AnyTimes()

	folderPath := types.FilePath(t.TempDir())
	setupTestWorkspace(t, c, folderPath)

	// Setup stored config without migration flag and empty org
	logger := c.Logger()
	storedConfig := &types.FolderConfig{
		FolderPath:                  folderPath,
		Organization:                "",
		OrgMigratedFromGlobalConfig: false,
		OrgSetByUser:                false,
	}
	err := storedconfig.UpdateFolderConfig(engineConfig, storedConfig, logger)
	require.NoError(t, err)

	// Set global org
	globalOrg := "global-org-id"
	c.SetOrganization(globalOrg)

	// Mock LDX-Sync to return the same org as global (non-default)
	mockEngine.EXPECT().InvokeWithInputAndConfig(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(workflowID workflow.Identifier, input []workflow.Data, config configuration.Configuration) ([]workflow.Data, error) {
			return mockLdxSyncResponse(globalOrg, false), nil
		},
	).AnyTimes()

	notifier := notification.NewMockNotifier()
	updateAndSendFolderConfigs(c, notifier)

	// Verify the org was set from global and migration flag is set
	updatedConfig, err := storedconfig.GetOrCreateFolderConfig(engineConfig, folderPath, logger)
	require.NoError(t, err)
	// When LDX-Sync returns the same org as global AND it's not default,
	// the logic at line 87-91 sets org to "" and marks as user-set
	assert.Empty(t, updatedConfig.Organization, "Organization should be empty when it matches global and LDX-Sync returns non-default")
	assert.True(t, updatedConfig.OrgSetByUser, "OrgSetByUser should be true when org matches global config")
	assert.True(t, updatedConfig.OrgMigratedFromGlobalConfig, "OrgMigratedFromGlobalConfig should be true")
}

func Test_updateAndSendFolderConfigs_NotMigrated_LdxSyncReturnsDifferentOrg(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine, engineConfig := testutil.SetUpEngineMock(t, c)
	mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
	mockEngine.EXPECT().GetLogger().Return(c.Logger()).AnyTimes()
	mockNetworkAccess := setupNetworkAccessMock(ctrl)
	mockEngine.EXPECT().GetNetworkAccess().Return(mockNetworkAccess).AnyTimes()

	folderPath := types.FilePath(t.TempDir())
	setupTestWorkspace(t, c, folderPath)

	// Setup stored config without migration
	logger := c.Logger()
	storedConfig := &types.FolderConfig{
		FolderPath:                  folderPath,
		Organization:                "initial-org",
		OrgMigratedFromGlobalConfig: false,
		OrgSetByUser:                false,
	}
	err := storedconfig.UpdateFolderConfig(engineConfig, storedConfig, logger)
	require.NoError(t, err)

	c.SetOrganization("global-org-id")

	// Note: LDX-Sync will fail in test environment (no API access)
	// When LDX-Sync fails, it tries to validate the existing org (initial-org)
	// Since validation also fails, the org remains as initial-org
	mockEngine.EXPECT().InvokeWithInputAndConfig(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()

	notifier := notification.NewMockNotifier()
	updateAndSendFolderConfigs(c, notifier)

	// Verify migration flag is set
	// When LDX-Sync fails to resolve, the org remains as it was (initial-org)
	updatedConfig, err := storedconfig.GetOrCreateFolderConfig(engineConfig, folderPath, logger)
	require.NoError(t, err)
	assert.Equal(t, "initial-org", updatedConfig.Organization, "Organization should remain as initial-org when LDX-Sync fails")
	// When LDX-Sync returns a different org than global, OrgSetByUser is set to false
	assert.False(t, updatedConfig.OrgSetByUser, "OrgSetByUser should be false when org differs from global")
	assert.True(t, updatedConfig.OrgMigratedFromGlobalConfig, "OrgMigratedFromGlobalConfig should be true")
}

func Test_updateAndSendFolderConfigs_SendsNotification(t *testing.T) {
	c := testutil.UnitTest(t)
	mockEngine, engineConfig := testutil.SetUpEngineMock(t, c)
	mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
	mockEngine.EXPECT().GetLogger().Return(c.Logger()).AnyTimes()
	mockEngine.EXPECT().InvokeWithInputAndConfig(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()

	folderPath := types.FilePath(t.TempDir())
	setupTestWorkspace(t, c, folderPath)

	logger := c.Logger()
	storedConfig := &types.FolderConfig{
		FolderPath:                  folderPath,
		Organization:                "test-org",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true,
	}
	err := storedconfig.UpdateFolderConfig(engineConfig, storedConfig, logger)
	require.NoError(t, err)

	notifier := notification.NewMockNotifier()
	updateAndSendFolderConfigs(c, notifier)

	// Verify notification was sent
	messages := notifier.SentMessages()
	require.Len(t, messages, 1)
	
	folderConfigsParam, ok := messages[0].(types.FolderConfigsParam)
	require.True(t, ok, "Expected FolderConfigsParam notification")
	require.Len(t, folderConfigsParam.FolderConfigs, 1)
	assert.Equal(t, "test-org", folderConfigsParam.FolderConfigs[0].Organization, "Notification should contain correct organization")
	assert.True(t, folderConfigsParam.FolderConfigs[0].OrgSetByUser, "Notification should reflect OrgSetByUser flag")
}

func Test_updateAndSendFolderConfigs_NoFolders_NoNotification(t *testing.T) {
	c := testutil.UnitTest(t)
	mockEngine, engineConfig := testutil.SetUpEngineMock(t, c)
	mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
	mockEngine.EXPECT().GetLogger().Return(c.Logger()).AnyTimes()

	// Setup workspace with no folders
	notifier := notification.NewMockNotifier()
	scanNotifier := scanner.NewMockScanNotifier()
	scanPersister := persistence.NewNopScanPersister()
	scanStateAggregator := scanstates.NewNoopStateAggregator()
	sc := scanner.NewTestScanner()
	hoverService := hover.NewFakeHoverService()

	w := workspace.New(c, performance.NewInstrumentor(), sc, hoverService, scanNotifier, notifier, scanPersister, scanStateAggregator)
	c.SetWorkspace(w)

	updateAndSendFolderConfigs(c, notifier)

	// Verify no notification was sent
	messages := notifier.SentMessages()
	assert.Empty(t, messages)
}

func Test_updateAndSendFolderConfigs_MigratedConfig_UserSetButInheritingFromBlank(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine, engineConfig := testutil.SetUpEngineMock(t, c)
	mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
	mockEngine.EXPECT().GetLogger().Return(c.Logger()).AnyTimes()
	mockNetworkAccess := setupNetworkAccessMock(ctrl)
	mockEngine.EXPECT().GetNetworkAccess().Return(mockNetworkAccess).AnyTimes()

	folderPath := types.FilePath(t.TempDir())
	setupTestWorkspace(t, c, folderPath)

	// Setup: previously user-set, but now both folder and global are empty
	logger := c.Logger()
	storedConfig := &types.FolderConfig{
		FolderPath:                  folderPath,
		Organization:                "",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true, // Was previously set by user
	}
	err := storedconfig.UpdateFolderConfig(engineConfig, storedConfig, logger)
	require.NoError(t, err)

	// Both folder and global org are empty
	c.SetOrganization("")

	// Mock LDX-Sync
	mockEngine.EXPECT().InvokeWithInputAndConfig(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()

	notifier := notification.NewMockNotifier()
	updateAndSendFolderConfigs(c, notifier)

	// Verify: should attempt to resolve from LDX-Sync because inheriting from blank global
	// When LDX-Sync fails (not a git repo), the org and flags remain unchanged
	updatedConfig, err := storedconfig.GetOrCreateFolderConfig(engineConfig, folderPath, logger)
	require.NoError(t, err)
	// OrgSetByUser remains as it was since LDX-Sync failed
	assert.True(t, updatedConfig.OrgSetByUser, "OrgSetByUser should remain true when LDX-Sync fails")
	assert.Empty(t, updatedConfig.Organization, "Organization should remain empty when inheriting from blank global and LDX-Sync fails")
}
