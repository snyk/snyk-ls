/*
 * © 2025-2026 Snyk Limited
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
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"

	mcpconfig "github.com/snyk/studio-mcp/pkg/mcp"

	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/testutil/workspaceutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// setAutoDeterminedOrg is a helper to write LDX-Sync org resolution into GAF folder metadata.
func setAutoDeterminedOrg(conf configuration.Configuration, folderPath types.FilePath, orgId string) {
	types.SetAutoDeterminedOrg(conf, folderPath, orgId)
}

// newConfigResolverForTest creates a ConfigResolver with configuration for tests that need folder/org-scope
// settings in the LS→IDE notification. Uses engine.GetConfiguration() and adds FlagMetadata.
func newConfigResolverForTest(engine workflow.Engine) types.ConfigResolverInterface {
	return newConfigResolverForTestWithGaf(engine, engine.GetConfiguration())
}

// newConfigResolverForTestWithGaf creates a ConfigResolver with the given engineConfig. Use when
// tests need a specific configuration (e.g. from SetUpEngineMock) that supports AddFlagSet.
func newConfigResolverForTestWithGaf(engine workflow.Engine, engineConfig configuration.Configuration) types.ConfigResolverInterface {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	_ = engineConfig.AddFlagSet(fs)

	logger := engine.GetLogger()
	resolver := types.NewConfigResolver(logger)
	prefixKeyResolver := configuration.NewConfigResolver(engineConfig)
	resolver.SetPrefixKeyResolver(prefixKeyResolver, engineConfig)
	return resolver
}

func Test_sendFolderConfigs_SendsNotification(t *testing.T) {
	engine := testutil.UnitTest(t)
	engineConfig := engine.GetConfiguration()

	// Setup workspace with a folder
	folderPaths := []types.FilePath{types.FilePath("/fake/test-folder-0")}
	_, notifier := workspaceutil.SetupWorkspace(t, engine, folderPaths...)

	logger := engine.GetLogger()
	storedConfig := &types.FolderConfig{FolderPath: folderPaths[0]}
	types.SetPreferredOrgAndOrgSetByUser(engineConfig, folderPaths[0], "test-org", true)
	err := storedconfig.UpdateFolderConfig(engineConfig, storedConfig, logger)
	require.NoError(t, err)

	// Write LDX-Sync result into folder metadata
	expectedOrgId := "resolved-org-id"
	setAutoDeterminedOrg(engineConfig, folderPaths[0], expectedOrgId)

	resolver := newConfigResolverForTest(engine)
	sendFolderConfigs(engine.GetConfiguration(), engine, engine.GetLogger(), notifier, featureflag.NewFakeService(), resolver)

	// Verify single unified $/snyk.configuration notification was sent
	messages := notifier.SentMessages()
	require.Len(t, messages, 1)

	configParam, ok := messages[0].(types.LspConfigurationParam)
	require.True(t, ok, "Expected LspConfigurationParam notification")
	require.Len(t, configParam.FolderConfigs, 1)
	require.NotNil(t, configParam.FolderConfigs[0].Settings[types.SettingPreferredOrg])
	assert.Equal(t, "test-org", configParam.FolderConfigs[0].Settings[types.SettingPreferredOrg].Value, "Notification should contain correct organization")
	require.NotNil(t, configParam.FolderConfigs[0].Settings[types.SettingAutoDeterminedOrg])
	assert.Equal(t, expectedOrgId, configParam.FolderConfigs[0].Settings[types.SettingAutoDeterminedOrg].Value, "AutoDeterminedOrg should be set from cache")
}

func Test_sendFolderConfigs_NoFolders_NoNotification(t *testing.T) {
	engine := testutil.UnitTest(t)
	_, _ = testutil.SetUpEngineMock(t, engine)

	// Setup workspace with no folders
	_, notifier := workspaceutil.SetupWorkspace(t, engine)

	sendFolderConfigs(engine.GetConfiguration(), engine, engine.GetLogger(), notifier, featureflag.NewFakeService(), types.NewConfigResolver(engine.GetLogger()))

	// A unified notification is always sent (with empty folder configs when no folders)
	messages := notifier.SentMessages()
	require.Len(t, messages, 1)
	configParam, ok := messages[0].(types.LspConfigurationParam)
	require.True(t, ok, "Expected LspConfigurationParam notification")
	assert.Empty(t, configParam.FolderConfigs)
}

func Test_HandleFolders_TriggersMcpConfigWorkflow(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	mockEngine, engineConfig := testutil.SetUpEngineMock(t, engine)

	originalService := Service()
	t.Cleanup(func() {
		SetService(originalService)
	})
	SetService(types.NewCommandServiceMock())

	// Clear token to prevent RefreshConfigFromLdxSync from being called in this test
	tokenService.SetToken(engineConfig, "")

	called := make(chan struct{}, 1)
	mockEngine.EXPECT().InvokeWithConfig(mcpconfig.WORKFLOWID_MCP_CONFIG, gomock.Any()).
		DoAndReturn(func(_ workflow.Identifier, _ configuration.Configuration) ([]workflow.Data, error) {
			called <- struct{}{}
			return nil, nil
		}).Times(1)

	_, n := workspaceutil.SetupWorkspace(t, mockEngine, types.FilePath("/workspace/one"))

	HandleFolders(engineConfig, mockEngine, mockEngine.GetLogger(), context.Background(), nil, n, persistence.NewNopScanPersister(), scanstates.NewNoopStateAggregator(), featureflag.NewFakeService(), types.NewConfigResolver(mockEngine.GetLogger()))

	select {
	case <-called:
		// ok
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for MCP config workflow invocation")
	}
}

// Test cache lookup when cache is empty - AutoDeterminedOrg should remain empty
func Test_sendFolderConfigs_EmptyCache_AutoDeterminedOrgEmpty(t *testing.T) {
	engine := testutil.UnitTest(t)
	_, engineConfig := testutil.SetUpEngineMock(t, engine)

	// Setup workspace with a folder
	folderPaths := []types.FilePath{types.FilePath(t.TempDir())}
	_, notifier := workspaceutil.SetupWorkspace(t, engine, folderPaths...)

	logger := engine.GetLogger()
	storedConfig := &types.FolderConfig{FolderPath: folderPaths[0]}
	types.SetPreferredOrgAndOrgSetByUser(engineConfig, folderPaths[0], "test-org", true)
	err := storedconfig.UpdateFolderConfig(engineConfig, storedConfig, logger)
	require.NoError(t, err)

	// Don't populate cache - AutoDeterminedOrg should remain empty
	resolver := newConfigResolverForTest(engine)
	sendFolderConfigs(engine.GetConfiguration(), engine, engine.GetLogger(), notifier, featureflag.NewFakeService(), resolver)

	// Verify single unified $/snyk.configuration notification was sent
	messages := notifier.SentMessages()
	require.Len(t, messages, 1)

	configParam, ok := messages[0].(types.LspConfigurationParam)
	require.True(t, ok, "Expected LspConfigurationParam notification")
	require.Len(t, configParam.FolderConfigs, 1)
	assert.Nil(t, configParam.FolderConfigs[0].Settings[types.SettingAutoDeterminedOrg], "AutoDeterminedOrg should be nil when cache is empty")
}

// Test sendFolderConfigs when cache has org ID
func Test_sendFolderConfigs_CachePopulated_AutoDeterminedOrgSet(t *testing.T) {
	engine := testutil.UnitTest(t)
	mockEngine, engineConfig := testutil.SetUpEngineMock(t, engine)

	// Setup workspace with a folder
	folderPaths := []types.FilePath{types.FilePath(t.TempDir())}
	_, notifier := workspaceutil.SetupWorkspace(t, mockEngine, folderPaths...)

	logger := engine.GetLogger()
	storedConfig := &types.FolderConfig{FolderPath: folderPaths[0]}
	types.SetPreferredOrgAndOrgSetByUser(engineConfig, folderPaths[0], "test-org", true)
	err := storedconfig.UpdateFolderConfig(engineConfig, storedConfig, logger)
	require.NoError(t, err)

	// Write LDX-Sync org into folder metadata
	expectedOrgId := "cached-org-id"
	setAutoDeterminedOrg(engineConfig, folderPaths[0], expectedOrgId)

	resolver := newConfigResolverForTest(mockEngine)
	sendFolderConfigs(engineConfig, mockEngine, mockEngine.GetLogger(), notifier, featureflag.NewFakeService(), resolver)

	// Verify single unified $/snyk.configuration notification was sent
	messages := notifier.SentMessages()
	require.Len(t, messages, 1)

	configParam, ok := messages[0].(types.LspConfigurationParam)
	require.True(t, ok, "Expected LspConfigurationParam notification")
	require.Len(t, configParam.FolderConfigs, 1)
	require.NotNil(t, configParam.FolderConfigs[0].Settings[types.SettingAutoDeterminedOrg])
	assert.Equal(t, expectedOrgId, configParam.FolderConfigs[0].Settings[types.SettingAutoDeterminedOrg].Value, "AutoDeterminedOrg should be set from cache")
}

// Test sendFolderConfigs with multiple folders and different org configurations
func Test_sendFolderConfigs_MultipleFolders_DifferentOrgConfigs(t *testing.T) {
	engine := testutil.UnitTest(t)
	engineConfig := engine.GetConfiguration()

	// Setup workspace with multiple folders
	folderPaths := []types.FilePath{
		types.FilePath(t.TempDir() + "/folder-0"),
		types.FilePath(t.TempDir() + "/folder-1"),
	}
	_, notifier := workspaceutil.SetupWorkspace(t, engine, folderPaths...)

	logger := engine.GetLogger()

	// Setup different org configs for each folder
	storedConfig1 := &types.FolderConfig{FolderPath: folderPaths[0]}
	types.SetPreferredOrgAndOrgSetByUser(engineConfig, folderPaths[0], "user-org-1", true)
	err := storedconfig.UpdateFolderConfig(engineConfig, storedConfig1, logger)
	require.NoError(t, err)

	storedConfig2 := &types.FolderConfig{FolderPath: folderPaths[1]}
	types.SetPreferredOrgAndOrgSetByUser(engineConfig, folderPaths[1], "", false)
	err = storedconfig.UpdateFolderConfig(engineConfig, storedConfig2, logger)
	require.NoError(t, err)

	// Write LDX-Sync orgs into folder metadata
	setAutoDeterminedOrg(engineConfig, folderPaths[0], "org-id-for-folder-0")
	setAutoDeterminedOrg(engineConfig, folderPaths[1], "org-id-for-folder-1")

	resolver := newConfigResolverForTest(engine)
	sendFolderConfigs(engine.GetConfiguration(), engine, engine.GetLogger(), notifier, featureflag.NewFakeService(), resolver)

	// Verify single unified $/snyk.configuration notification was sent
	messages := notifier.SentMessages()
	require.Len(t, messages, 1)

	configParam, ok := messages[0].(types.LspConfigurationParam)
	require.True(t, ok, "Expected LspConfigurationParam notification")
	require.Len(t, configParam.FolderConfigs, 2)

	expectedOrgs := map[types.FilePath]string{
		types.PathKey(folderPaths[0]): "org-id-for-folder-0",
		types.PathKey(folderPaths[1]): "org-id-for-folder-1",
	}
	for _, fc := range configParam.FolderConfigs {
		expectedOrg, found := expectedOrgs[types.PathKey(fc.FolderPath)]
		require.True(t, found, "Unexpected folder path: %s", fc.FolderPath)
		require.NotNil(t, fc.Settings[types.SettingAutoDeterminedOrg], "AutoDeterminedOrg should be set for folder %s", fc.FolderPath)
		assert.Equal(t, expectedOrg, fc.Settings[types.SettingAutoDeterminedOrg].Value, "AutoDeterminedOrg should be folder-specific for %s", fc.FolderPath)
	}
}

// Test GetOrgIdForFolder with GAF folder metadata set
func Test_GetOrgIdForFolder_WithCache(t *testing.T) {
	engine := testutil.UnitTest(t)
	engineConfig := engine.GetConfiguration()

	folderPath := types.FilePath(t.TempDir())

	// Write LDX-Sync org into folder metadata
	expectedOrgId := "cached-org-id"
	setAutoDeterminedOrg(engineConfig, folderPath, expectedOrgId)

	// Read org from GAF folder metadata via snapshot
	snapshot := types.ReadFolderConfigSnapshot(engineConfig, folderPath)
	assert.Equal(t, expectedOrgId, snapshot.AutoDeterminedOrg, "Should return org from folder metadata")
}

// Test GetOrgIdForFolder without folder metadata set returns empty string
func Test_GetOrgIdForFolder_WithoutCache_ReturnsEmpty(t *testing.T) {
	engine := testutil.UnitTest(t)
	engineConfig := engine.GetConfiguration()

	folderPath := types.FilePath(t.TempDir())

	// Don't write any folder metadata
	snapshot := types.ReadFolderConfigSnapshot(engineConfig, folderPath)
	assert.Empty(t, snapshot.AutoDeterminedOrg, "Should return empty string when folder metadata is not set")
}

func Test_BuildLspConfiguration_MachineScopeSettings(t *testing.T) {
	engine := testutil.UnitTest(t)
	_, engineConfig := testutil.SetUpEngineMock(t, engine)

	resolver := newConfigResolverForTestWithGaf(engine, engineConfig)
	engineConfig.Set(configuration.UserGlobalKey(types.SettingApiEndpoint), "https://custom.api")

	lspConfig := BuildLspConfiguration(engine.GetConfiguration(), engine, engine.GetLogger(), nil, resolver)

	require.NotNil(t, lspConfig.Settings)
	require.NotNil(t, lspConfig.Settings[types.SettingApiEndpoint])
	assert.Equal(t, "https://custom.api", lspConfig.Settings[types.SettingApiEndpoint].Value)
}

func Test_BuildLspConfiguration_SkipsWriteOnlySettings(t *testing.T) {
	engine := testutil.UnitTest(t)
	_, engineConfig := testutil.SetUpEngineMock(t, engine)
	resolver := newConfigResolverForTestWithGaf(engine, engineConfig)
	lspConfig := BuildLspConfiguration(engine.GetConfiguration(), engine, engine.GetLogger(), nil, resolver)

	// Write-only settings must not appear in LS→IDE notification
	require.NotNil(t, lspConfig.Settings)
	assert.NotContains(t, lspConfig.Settings, types.SettingToken)
	assert.NotContains(t, lspConfig.Settings, types.SettingSendErrorReports)
	assert.NotContains(t, lspConfig.Settings, types.SettingEnableSnykLearnCodeActions)
	assert.NotContains(t, lspConfig.Settings, types.SettingEnableSnykOssQuickFixActions)
	assert.NotContains(t, lspConfig.Settings, types.SettingEnableSnykOpenBrowserActions)
}

func Test_BuildLspConfiguration_PopulatesSourceFromResolver(t *testing.T) {
	engine := testutil.UnitTest(t)
	_, engineConfig := testutil.SetUpEngineMock(t, engine)
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	_ = engineConfig.AddFlagSet(fs)

	// Set LDX-Sync locked machine config
	engineConfig.Set(configuration.RemoteMachineKey(types.SettingApiEndpoint), &configuration.RemoteConfigField{
		Value: "https://locked.api", IsLocked: true,
	})

	logger := engine.GetLogger()
	resolver := types.NewConfigResolver(logger)
	prefixKeyResolver := configuration.NewConfigResolver(engineConfig)
	resolver.SetPrefixKeyResolver(prefixKeyResolver, engineConfig)

	lspConfig := BuildLspConfiguration(engine.GetConfiguration(), engine, engine.GetLogger(), nil, resolver)

	require.NotNil(t, lspConfig.Settings[types.SettingApiEndpoint])
	assert.Equal(t, "https://locked.api", lspConfig.Settings[types.SettingApiEndpoint].Value)
	assert.Equal(t, "ldx-sync-locked", lspConfig.Settings[types.SettingApiEndpoint].Source)
	assert.True(t, lspConfig.Settings[types.SettingApiEndpoint].IsLocked)
}
