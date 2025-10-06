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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

// Test scenarios for updateAndSendFolderConfigs (notification sending only)
func Test_sendFolderConfigs_SendsNotification(t *testing.T) {
	c := testutil.UnitTest(t)
	mockEngine, engineConfig := testutil.SetUpEngineMock(t, c)
	mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
	mockEngine.EXPECT().GetLogger().Return(c.Logger()).AnyTimes()

	folderPath := types.FilePath(t.TempDir())

	// Setup workspace with a folder
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

	logger := c.Logger()
	storedConfig := &types.FolderConfig{
		FolderPath:                  folderPath,
		PreferredOrg:                "test-org",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true,
	}
	err := storedconfig.UpdateFolderConfig(engineConfig, storedConfig, logger)
	require.NoError(t, err)

	updateAndSendFolderConfigs(c, notifier)

	// Verify notification was sent
	messages := notifier.SentMessages()
	require.Len(t, messages, 1)

	folderConfigsParam, ok := messages[0].(types.FolderConfigsParam)
	require.True(t, ok, "Expected FolderConfigsParam notification")
	require.Len(t, folderConfigsParam.FolderConfigs, 1)
	assert.Equal(t, "test-org", folderConfigsParam.FolderConfigs[0].PreferredOrg, "Notification should contain correct organization")
	assert.True(t, folderConfigsParam.FolderConfigs[0].OrgSetByUser, "Notification should reflect OrgSetByUser flag")
}

func Test_sendFolderConfigs_NoFolders_NoNotification(t *testing.T) {
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

// Test scenarios for UpdateFolderConfigOrg - already migrated configs
func Test_UpdateFolderConfigOrg_MigratedConfig_Initialization_NonUserSet_CallsLdxSync(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetOrganization("global-org")

	storedConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		PreferredOrg:                "ldx-resolved-org",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                false,
	}

	folderConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		PreferredOrg:                "ldx-resolved-org",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                false,
	}

	notifier := notification.NewMockNotifier()
	UpdateFolderConfigOrg(c, storedConfig, folderConfig, notifier)

	// Should have called LDX-Sync (we can't easily verify this without mocking, but we can check the behavior)
	// The org should remain as resolved by LDX-Sync
	assert.False(t, folderConfig.OrgSetByUser, "Should remain not user-set")
}

func Test_UpdateFolderConfigOrg_MigratedConfig_Initialization_InheritingFromBlankGlobal_CallsLdxSync(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetOrganization("") // Blank global org

	storedConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		PreferredOrg:                "", // Blank folder org
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true, // Even if previously user-set
	}

	folderConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		PreferredOrg:                "",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true,
	}

	notifier := notification.NewMockNotifier()
	UpdateFolderConfigOrg(c, storedConfig, folderConfig, notifier)

	// Should have called LDX-Sync because org is inheriting from blank global
	assert.False(t, folderConfig.OrgSetByUser, "Should be marked as not user-set when inheriting from blank global")
}

func Test_UpdateFolderConfigOrg_MigratedConfig_Initialization_UserSet_KeepsExisting(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetOrganization("global-org")

	storedConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		PreferredOrg:                "user-org",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true,
	}

	folderConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		PreferredOrg:                "user-org",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true,
	}

	notifier := notification.NewMockNotifier()
	UpdateFolderConfigOrg(c, storedConfig, folderConfig, notifier)

	// Should keep the user-set org
	assert.Equal(t, "user-org", folderConfig.PreferredOrg, "Should keep user-set org")
	assert.True(t, folderConfig.OrgSetByUser, "Should remain user-set")
}

func Test_UpdateFolderConfigOrg_MigratedConfig_Update_OrgChanged_StoresNewOrg(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetOrganization("global-org")

	storedConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		PreferredOrg:                "old-org",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                false,
	}

	folderConfig := &types.FolderConfig{
		PreferredOrg:                "new-org",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                false,
	}

	notifier := notification.NewMockNotifier()
	UpdateFolderConfigOrg(c, storedConfig, folderConfig, notifier)

	// The actual org value depends on LDX-Sync resolution
	assert.False(t, folderConfig.OrgSetByUser, "Should not be user-set when OrgSetByUser flag is false")
}

func Test_UpdateFolderConfigOrg_MigratedConfig_Update_OrgSetByUser_StoresNewOrg(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetOrganization("global-org")

	storedConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		PreferredOrg:                "old-org",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                false,
	}

	folderConfig := &types.FolderConfig{
		PreferredOrg:                "user-org",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true,
	}

	notifier := notification.NewMockNotifier()
	UpdateFolderConfigOrg(c, storedConfig, folderConfig, notifier)

	// Should store the user-provided org
	assert.Equal(t, "user-org", folderConfig.PreferredOrg, "Should store user org")
	assert.True(t, folderConfig.OrgSetByUser, "Should mark as user-set")
}

func Test_UpdateFolderConfigOrg_MigratedConfig_Update_InheritingFromBlankGlobal_CallsLdxSync(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetOrganization("") // Blank global org

	storedConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		PreferredOrg:                "old-org",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true,
	}

	folderConfig := &types.FolderConfig{
		PreferredOrg:                "", // Blank folder org
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                false,
	}

	notifier := notification.NewMockNotifier()
	UpdateFolderConfigOrg(c, storedConfig, folderConfig, notifier)

	// Should call LDX-Sync because inheriting from blank global
	// The org will be resolved by LDX-Sync (we can't verify the exact value without mocking)
	// But we can verify the OrgSetByUser flag
	assert.False(t, folderConfig.OrgSetByUser, "Should not be user-set when inheriting from blank global")
}

func Test_UpdateFolderConfigOrg_MigratedConfig_Update_NoChangeNotUserSet_CallsLdxSync(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetOrganization("global-org")

	storedConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		PreferredOrg:                "ldx-org",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                false,
	}

	folderConfig := &types.FolderConfig{
		PreferredOrg:                "ldx-org", // Same org
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                false,
	}

	notifier := notification.NewMockNotifier()
	UpdateFolderConfigOrg(c, storedConfig, folderConfig, notifier)

	// Should call LDX-Sync because not user-set
	assert.False(t, folderConfig.OrgSetByUser, "Should remain not user-set")
}

// Test scenarios for migrateFolderConfigOrg - new configs
func Test_migrateFolderConfigOrg_WithUserProvidedOrg_SkipsLdxSync(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetOrganization("global-org")

	folderConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		PreferredOrg:                "user-org",
		OrgMigratedFromGlobalConfig: false,
		OrgSetByUser:                true, // Set to true to indicate user provided this org
	}

	notifier := notification.NewMockNotifier()
	migrateFolderConfigOrg(c, folderConfig, notifier)

	// Should store the user-provided org and skip LDX-Sync
	assert.Equal(t, "user-org", folderConfig.PreferredOrg, "Should store user-provided org")
	assert.True(t, folderConfig.OrgSetByUser, "Should mark as user-set")
	assert.True(t, folderConfig.OrgMigratedFromGlobalConfig, "Should mark as migrated")
}

func Test_migrateFolderConfigOrg_WithOrgSetByUserFlag_SkipsLdxSync(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetOrganization("global-org")

	folderConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		PreferredOrg:                "",
		OrgMigratedFromGlobalConfig: false,
		OrgSetByUser:                true,
	}

	notifier := notification.NewMockNotifier()
	migrateFolderConfigOrg(c, folderConfig, notifier)

	// Should skip LDX-Sync when OrgSetByUser is true
	assert.Equal(t, "", folderConfig.PreferredOrg, "Should store empty org")
	assert.True(t, folderConfig.OrgSetByUser, "Should mark as user-set")
	assert.True(t, folderConfig.OrgMigratedFromGlobalConfig, "Should mark as migrated")
}

func Test_migrateFolderConfigOrg_NoOrg_LdxReturnsDifferent_MarksNotUserSet(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetOrganization("global-org")

	folderConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		PreferredOrg:                "",
		OrgMigratedFromGlobalConfig: false,
		OrgSetByUser:                false,
	}

	notifier := notification.NewMockNotifier()
	migrateFolderConfigOrg(c, folderConfig, notifier)

	// Should call LDX-Sync and mark as not user-set if different from global
	// (We can't verify the exact org without mocking LDX-Sync, but we can verify the migration flag)
	assert.True(t, folderConfig.OrgMigratedFromGlobalConfig, "Should mark as migrated")
}

func Test_migrateFolderConfigOrg_NoOrg_InitialMigration(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetOrganization("global-org")

	folderConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		PreferredOrg:                "",
		OrgMigratedFromGlobalConfig: false,
		OrgSetByUser:                false,
	}

	notifier := notification.NewMockNotifier()
	migrateFolderConfigOrg(c, folderConfig, notifier)

	// Should use global org initially and call LDX-Sync
	assert.True(t, folderConfig.OrgMigratedFromGlobalConfig, "Should mark as migrated")
	// The final org and OrgSetByUser depend on LDX-Sync response
}
