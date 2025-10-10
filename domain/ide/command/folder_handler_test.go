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

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

// MockOrgResolver is a mock implementation of OrgResolver for testing
type MockOrgResolver struct {
	ResolveFunc func(config configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, path string, givenOrg string) (ldx_sync_config.Organization, error)
}

func (m *MockOrgResolver) ResolveOrganization(config configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, path string, givenOrg string) (ldx_sync_config.Organization, error) {
	if m.ResolveFunc != nil {
		return m.ResolveFunc(config, engine, logger, path, givenOrg)
	}
	// Default behavior: return a default org
	isDefault := true
	return ldx_sync_config.Organization{
		Id:        "default-org-id",
		Name:      "Default Org",
		IsDefault: &isDefault,
	}, nil
}

// Test scenarios for updateAndSendFolderConfigs (notification sending only)
func Test_sendFolderConfigs_SendsNotification(t *testing.T) {
	c := testutil.UnitTest(t)
	mockEngine, engineConfig := testutil.SetUpEngineMock(t, c)
	mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
	mockEngine.EXPECT().GetLogger().Return(c.Logger()).AnyTimes()

	// Setup mock org resolver
	mockResolver := &MockOrgResolver{
		ResolveFunc: func(config configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, path string, givenOrg string) (ldx_sync_config.Organization, error) {
			isDefault := false
			return ldx_sync_config.Organization{
				Id:        "resolved-org-id",
				Name:      "Resolved Org",
				Slug:      "resolved-org",
				IsDefault: &isDefault,
			}, nil
		},
	}
	SetOrgResolver(mockResolver)
	defer ResetOrgResolver()

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

	sendFolderConfigs(c, notifier)

	// Verify notification was sent
	messages := notifier.SentMessages()
	require.Len(t, messages, 1)

	folderConfigsParam, ok := messages[0].(types.FolderConfigsParam)
	require.True(t, ok, "Expected FolderConfigsParam notification")
	require.Len(t, folderConfigsParam.FolderConfigs, 1)
	assert.Equal(t, "test-org", folderConfigsParam.FolderConfigs[0].PreferredOrg, "Notification should contain correct organization")
	assert.True(t, folderConfigsParam.FolderConfigs[0].OrgSetByUser, "Notification should reflect OrgSetByUser flag")
	assert.Equal(t, "resolved-org", folderConfigsParam.FolderConfigs[0].AutoDeterminedOrg, "AutoDeterminedOrg should be set by LDX-Sync")
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

// setupOrgResolverTest is a helper function to reduce duplication in org resolver tests
func setupOrgResolverTest(t *testing.T, orgID, orgName string, isDefault bool) (*config.Config, *types.FolderConfig, ldx_sync_config.Organization) {
	t.Helper()

	c := testutil.UnitTest(t)
	mockEngine, _ := testutil.SetUpEngineMock(t, c)
	mockEngine.EXPECT().GetConfiguration().AnyTimes()
	mockEngine.EXPECT().GetLogger().Return(c.Logger()).AnyTimes()

	expectedOrg := ldx_sync_config.Organization{
		Id:        orgID,
		Name:      orgName,
		IsDefault: &isDefault,
	}

	mockResolver := &MockOrgResolver{
		ResolveFunc: func(config configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, path string, givenOrg string) (ldx_sync_config.Organization, error) {
			return expectedOrg, nil
		},
	}
	SetOrgResolver(mockResolver)
	t.Cleanup(ResetOrgResolver)

	folderConfig := &types.FolderConfig{
		FolderPath: types.FilePath(t.TempDir()),
	}

	return c, folderConfig, expectedOrg
}

func Test_SetAutoDeterminedOrg(t *testing.T) {
	t.Run("sets slug when available", func(t *testing.T) {
		fc := &types.FolderConfig{}
		org := ldx_sync_config.Organization{
			Id:   "test-id",
			Slug: "test-slug",
		}

		SetAutoDeterminedOrg(fc, org)

		assert.Equal(t, "test-slug", fc.AutoDeterminedOrg, "should use slug when available")
	})

	t.Run("falls back to ID when slug is empty", func(t *testing.T) {
		fc := &types.FolderConfig{}
		org := ldx_sync_config.Organization{
			Id:   "test-id",
			Slug: "",
		}

		SetAutoDeterminedOrg(fc, org)

		assert.Equal(t, "test-id", fc.AutoDeterminedOrg, "should fall back to ID when slug is empty")
	})

	t.Run("handles empty organization", func(t *testing.T) {
		fc := &types.FolderConfig{
			AutoDeterminedOrg: "original-value",
		}
		org := ldx_sync_config.Organization{}

		SetAutoDeterminedOrg(fc, org)

		assert.Empty(t, fc.AutoDeterminedOrg, "should clear AutoDeterminedOrg for empty organization")
	})
}

// Test GetBestOrgFromLdxSync with default org
func Test_SetAutoBestOrgFromLdxSync_DefaultOrg(t *testing.T) {
	c, folderConfig, expectedOrg := setupOrgResolverTest(t, "default-org-id", "Default Org", true)

	org, err := GetBestOrgFromLdxSync(c, folderConfig, "")

	require.NoError(t, err)
	assert.Equal(t, expectedOrg.Id, org.Id)
	assert.True(t, *org.IsDefault)
}

// Test GetBestOrgFromLdxSync with non-default org
func Test_SetAutoBestOrgFromLdxSync_NonDefaultOrg(t *testing.T) {
	c, folderConfig, expectedOrg := setupOrgResolverTest(t, "specific-org-id", "Specific Org", false)

	org, err := GetBestOrgFromLdxSync(c, folderConfig, "")

	require.NoError(t, err)
	assert.Equal(t, expectedOrg.Id, org.Id)
	assert.False(t, *org.IsDefault)
}

// Test GetBestOrgFromLdxSync with given org parameter
func Test_SetAutoBestOrgFromLdxSync_WithGivenOrg(t *testing.T) {
	c := testutil.UnitTest(t)
	mockEngine, _ := testutil.SetUpEngineMock(t, c)
	mockEngine.EXPECT().GetConfiguration().AnyTimes()
	mockEngine.EXPECT().GetLogger().Return(c.Logger()).AnyTimes()

	// Setup mock org resolver to verify givenOrg is passed through
	var capturedGivenOrg string
	mockResolver := &MockOrgResolver{
		ResolveFunc: func(config configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, path string, givenOrg string) (ldx_sync_config.Organization, error) {
			capturedGivenOrg = givenOrg
			isDefault := false
			return ldx_sync_config.Organization{
				Id:        givenOrg,
				Name:      "Given Org",
				IsDefault: &isDefault,
			}, nil
		},
	}
	SetOrgResolver(mockResolver)
	defer ResetOrgResolver()

	folderConfig := &types.FolderConfig{
		FolderPath: types.FilePath(t.TempDir()),
	}

	org, err := GetBestOrgFromLdxSync(c, folderConfig, "given-org-id")

	require.NoError(t, err)
	assert.Equal(t, "given-org-id", capturedGivenOrg, "givenOrg should be passed to resolver")
	assert.Equal(t, "given-org-id", org.Id)
}

// Test GetBestOrgFromLdxSync error handling
func Test_SetAutoBestOrgFromLdxSync_ErrorHandling(t *testing.T) {
	c := testutil.UnitTest(t)
	mockEngine, _ := testutil.SetUpEngineMock(t, c)
	mockEngine.EXPECT().GetConfiguration().AnyTimes()
	mockEngine.EXPECT().GetLogger().Return(c.Logger()).AnyTimes()

	// Setup mock org resolver to return error
	mockResolver := &MockOrgResolver{
		ResolveFunc: func(config configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, path string, givenOrg string) (ldx_sync_config.Organization, error) {
			return ldx_sync_config.Organization{}, assert.AnError
		},
	}
	SetOrgResolver(mockResolver)
	defer ResetOrgResolver()

	folderConfig := &types.FolderConfig{
		FolderPath: types.FilePath(t.TempDir()),
	}

	_, err := GetBestOrgFromLdxSync(c, folderConfig, "")

	require.Error(t, err)
}

// Test sendFolderConfigs with LDX-Sync error (should continue with other folders)
func Test_sendFolderConfigs_LdxSyncError_ContinuesProcessing(t *testing.T) {
	c := testutil.UnitTest(t)
	mockEngine, engineConfig := testutil.SetUpEngineMock(t, c)
	mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
	mockEngine.EXPECT().GetLogger().Return(c.Logger()).AnyTimes()

	// Setup mock org resolver to return error
	mockResolver := &MockOrgResolver{
		ResolveFunc: func(config configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, path string, givenOrg string) (ldx_sync_config.Organization, error) {
			return ldx_sync_config.Organization{}, assert.AnError
		},
	}
	SetOrgResolver(mockResolver)
	defer ResetOrgResolver()

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

	sendFolderConfigs(c, notifier)

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

	// Setup mock org resolver to return different orgs based on path
	mockResolver := &MockOrgResolver{
		ResolveFunc: func(config configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, path string, givenOrg string) (ldx_sync_config.Organization, error) {
			isDefault := false
			return ldx_sync_config.Organization{
				Id:        "org-for-" + path,
				Name:      "Org for " + path,
				Slug:      "org-for-" + path,
				IsDefault: &isDefault,
			}, nil
		},
	}
	SetOrgResolver(mockResolver)
	defer ResetOrgResolver()

	folderPath1 := types.FilePath(t.TempDir())
	folderPath2 := types.FilePath(t.TempDir())

	// Setup workspace with multiple folders
	notifier := notification.NewMockNotifier()
	scanNotifier := scanner.NewMockScanNotifier()
	scanPersister := persistence.NewNopScanPersister()
	scanStateAggregator := scanstates.NewNoopStateAggregator()
	sc := scanner.NewTestScanner()
	hoverService := hover.NewFakeHoverService()

	w := workspace.New(c, performance.NewInstrumentor(), sc, hoverService, scanNotifier, notifier, scanPersister, scanStateAggregator)
	folder1 := workspace.NewFolder(c, folderPath1, "folder1", sc, hoverService, scanNotifier, notifier, scanPersister, scanStateAggregator)
	folder2 := workspace.NewFolder(c, folderPath2, "folder2", sc, hoverService, scanNotifier, notifier, scanPersister, scanStateAggregator)
	w.AddFolder(folder1)
	w.AddFolder(folder2)
	c.SetWorkspace(w)

	logger := c.Logger()

	// Setup different org configs for each folder
	storedConfig1 := &types.FolderConfig{
		FolderPath:                  folderPath1,
		PreferredOrg:                "user-org-1",
		OrgMigratedFromGlobalConfig: false,
		OrgSetByUser:                true,
	}
	err := storedconfig.UpdateFolderConfig(engineConfig, storedConfig1, logger)
	require.NoError(t, err)

	storedConfig2 := &types.FolderConfig{
		FolderPath:                  folderPath2,
		PreferredOrg:                "",
		OrgMigratedFromGlobalConfig: false,
		OrgSetByUser:                false,
	}
	err = storedconfig.UpdateFolderConfig(engineConfig, storedConfig2, logger)
	require.NoError(t, err)

	sendFolderConfigs(c, notifier)

	// Verify notification was sent with both folders
	messages := notifier.SentMessages()
	require.Len(t, messages, 1)

	folderConfigsParam, ok := messages[0].(types.FolderConfigsParam)
	require.True(t, ok, "Expected FolderConfigsParam notification")
	require.Len(t, folderConfigsParam.FolderConfigs, 2)

	// Verify each folder has its own AutoDeterminedOrg
	for _, fc := range folderConfigsParam.FolderConfigs {
		assert.NotEmpty(t, fc.AutoDeterminedOrg, "AutoDeterminedOrg should be set for each folder")
		assert.Contains(t, fc.AutoDeterminedOrg, "org-for-", "AutoDeterminedOrg should be path-specific")
	}
}
