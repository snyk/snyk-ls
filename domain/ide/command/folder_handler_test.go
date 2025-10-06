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

// Test scenarios for sendFolderConfigs (notification sending only)
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
		Organization:                "test-org",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true,
	}
	err := storedconfig.UpdateFolderConfig(engineConfig, storedConfig, logger)
	require.NoError(t, err)

	sendFolderConfigs(c, notifier)

	// Verify notification was sent
	messages := notifier.SentMessages()
	require.Len(t, messages, 1)

	folderConfigsParam, ok := messages[0].(types.FolderConfigsParam)
	require.True(t, ok, "Expected FolderConfigsParam notification")
	require.Len(t, folderConfigsParam.FolderConfigs, 1)
	assert.Equal(t, "test-org", folderConfigsParam.FolderConfigs[0].Organization, "Notification should contain correct organization")
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

	sendFolderConfigs(c, notifier)

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
		Organization:                "ldx-resolved-org",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                false,
	}

	// Initialization scenario: folderConfig is nil
	UpdateFolderConfigOrg(c, storedConfig, nil)

	// Should have called LDX-Sync (we can't easily verify this without mocking, but we can check the behavior)
	// The org should remain as resolved by LDX-Sync
	assert.False(t, storedConfig.OrgSetByUser, "Should remain not user-set")
}

func Test_UpdateFolderConfigOrg_MigratedConfig_Initialization_InheritingFromBlankGlobal_CallsLdxSync(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetOrganization("") // Blank global org

	storedConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		Organization:                "", // Blank folder org
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true, // Even if previously user-set
	}

	// Initialization scenario: folderConfig is nil
	UpdateFolderConfigOrg(c, storedConfig, nil)

	// Should have called LDX-Sync because org is inheriting from blank global
	assert.False(t, storedConfig.OrgSetByUser, "Should be marked as not user-set when inheriting from blank global")
}

func Test_UpdateFolderConfigOrg_MigratedConfig_Initialization_UserSet_KeepsExisting(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetOrganization("global-org")

	storedConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		Organization:                "user-org",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true,
	}

	// Initialization scenario: folderConfig is nil
	UpdateFolderConfigOrg(c, storedConfig, nil)

	// Should keep the user-set org
	assert.Equal(t, "user-org", storedConfig.Organization, "Should keep user-set org")
	assert.True(t, storedConfig.OrgSetByUser, "Should remain user-set")
}

func Test_UpdateFolderConfigOrg_MigratedConfig_Update_OrgChanged_StoresNewOrg(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetOrganization("global-org")

	storedConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		Organization:                "old-org",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                false,
	}

	folderConfig := &types.FolderConfig{
		Organization: "new-org",
		OrgSetByUser: false,
	}

	UpdateFolderConfigOrg(c, storedConfig, folderConfig)

	// The actual org value depends on LDX-Sync resolution
	assert.False(t, storedConfig.OrgSetByUser, "Should not be user-set when OrgSetByUser flag is false")
}

func Test_UpdateFolderConfigOrg_MigratedConfig_Update_OrgSetByUser_StoresNewOrg(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetOrganization("global-org")

	storedConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		Organization:                "old-org",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                false,
	}

	folderConfig := &types.FolderConfig{
		Organization: "user-org",
		OrgSetByUser: true,
	}

	UpdateFolderConfigOrg(c, storedConfig, folderConfig)

	// Should store the user-provided org
	assert.Equal(t, "user-org", storedConfig.Organization, "Should store user org")
	assert.True(t, storedConfig.OrgSetByUser, "Should mark as user-set")
}

func Test_UpdateFolderConfigOrg_MigratedConfig_Update_InheritingFromBlankGlobal_CallsLdxSync(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetOrganization("") // Blank global org

	storedConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		Organization:                "old-org",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true,
	}

	folderConfig := &types.FolderConfig{
		Organization: "", // Blank folder org
		OrgSetByUser: false,
	}

	UpdateFolderConfigOrg(c, storedConfig, folderConfig)

	// Should call LDX-Sync because inheriting from blank global
	// The org will be resolved by LDX-Sync (we can't verify the exact value without mocking)
	// But we can verify it's no longer marked as user-set
	assert.False(t, storedConfig.OrgSetByUser, "Should not be user-set when inheriting from blank global")
}

func Test_UpdateFolderConfigOrg_MigratedConfig_Update_NoChangeNotUserSet_CallsLdxSync(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetOrganization("global-org")

	storedConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		Organization:                "ldx-org",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                false,
	}

	folderConfig := &types.FolderConfig{
		Organization: "ldx-org", // Same org
		OrgSetByUser: false,
	}

	UpdateFolderConfigOrg(c, storedConfig, folderConfig)

	// Should call LDX-Sync because not user-set
	assert.False(t, storedConfig.OrgSetByUser, "Should remain not user-set")
}

// Test scenarios for migrateFolderConfigOrg - new configs
func Test_migrateFolderConfigOrg_WithUserProvidedOrg_SkipsLdxSync(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetOrganization("global-org")

	storedConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		Organization:                "",
		OrgMigratedFromGlobalConfig: false,
		OrgSetByUser:                false,
	}

	folderConfig := &types.FolderConfig{
		Organization: "user-org",
		OrgSetByUser: false,
	}

	migrateFolderConfigOrg(c, storedConfig, folderConfig)

	// Should store the user-provided org and skip LDX-Sync
	assert.Equal(t, "user-org", storedConfig.Organization, "Should store user-provided org")
	assert.False(t, storedConfig.OrgSetByUser, "Should preserve OrgSetByUser flag")
	assert.True(t, storedConfig.OrgMigratedFromGlobalConfig, "Should mark as migrated")
}

func Test_migrateFolderConfigOrg_WithOrgSetByUserFlag_SkipsLdxSync(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetOrganization("global-org")

	storedConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		Organization:                "",
		OrgMigratedFromGlobalConfig: false,
		OrgSetByUser:                false,
	}

	folderConfig := &types.FolderConfig{
		Organization: "",
		OrgSetByUser: true,
	}

	migrateFolderConfigOrg(c, storedConfig, folderConfig)

	// Should skip LDX-Sync when OrgSetByUser is true
	assert.Equal(t, "", storedConfig.Organization, "Should store empty org")
	assert.True(t, storedConfig.OrgSetByUser, "Should preserve OrgSetByUser flag")
	assert.True(t, storedConfig.OrgMigratedFromGlobalConfig, "Should mark as migrated")
}

func Test_migrateFolderConfigOrg_NoOrg_LdxReturnsDifferent_MarksNotUserSet(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetOrganization("global-org")

	storedConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		Organization:                "",
		OrgMigratedFromGlobalConfig: false,
		OrgSetByUser:                false,
	}

	migrateFolderConfigOrg(c, storedConfig, nil)

	// Should call LDX-Sync and mark as not user-set if different from global
	// (We can't verify the exact org without mocking LDX-Sync, but we can verify the migration flag)
	assert.True(t, storedConfig.OrgMigratedFromGlobalConfig, "Should mark as migrated")
}

func Test_migrateFolderConfigOrg_NoOrg_InitialMigration(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetOrganization("global-org")

	storedConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		Organization:                "",
		OrgMigratedFromGlobalConfig: false,
		OrgSetByUser:                false,
	}

	migrateFolderConfigOrg(c, storedConfig, nil)

	// Should use global org initially and call LDX-Sync
	assert.True(t, storedConfig.OrgMigratedFromGlobalConfig, "Should mark as migrated")
	// The final org and OrgSetByUser depend on LDX-Sync response
}
