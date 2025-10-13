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

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/resolve_organization_workflow"
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

// setupMockWorkflowForOrg sets up mock workflow responses for GetBestOrgFromLdxSync calls
func setupMockWorkflowForOrg(mockEngine *mocks.MockEngine, orgId, orgName, orgSlug string, isDefault bool) {
	mockOrg := resolve_organization_workflow.Organization{
		Id:        orgId,
		Name:      orgName,
		Slug:      orgSlug,
		IsDefault: &isDefault,
	}
	mockOutput := resolve_organization_workflow.ResolveOrganizationOutput{
		Organization: mockOrg,
	}
	outputData := workflow.NewData(
		workflow.NewTypeIdentifier(resolve_organization_workflow.WORKFLOWID_RESOLVE_ORGANIZATION, "resolve-org-output"),
		"application/go-struct",
		mockOutput,
	)
	mockEngine.EXPECT().InvokeWithInputAndConfig(
		resolve_organization_workflow.WORKFLOWID_RESOLVE_ORGANIZATION,
		gomock.Any(),
		gomock.Any(),
	).Return([]workflow.Data{outputData}, nil).AnyTimes()
}

// setupMockWorkflowForOrgWithError sets up a workflow that returns an error
func setupMockWorkflowForOrgWithError(mockEngine *mocks.MockEngine, err error) {
	mockEngine.EXPECT().InvokeWithInputAndConfig(
		resolve_organization_workflow.WORKFLOWID_RESOLVE_ORGANIZATION,
		gomock.Any(),
		gomock.Any(),
	).Return(nil, err).AnyTimes()
}

// setupMockIsDefaultOrgWorkflow sets up mock workflow responses for isOrgDefaultOrUnknownSlug calls
func setupMockIsDefaultOrgWorkflow(mockEngine *mocks.MockEngine, isDefaultOrg bool, isUnknownSlug bool) {
	mockOutput := resolve_organization_workflow.IsDefaultOrganizationOutput{
		IsDefaultOrg:  isDefaultOrg,
		IsUnknownSlug: isUnknownSlug,
	}
	outputData := workflow.NewData(
		workflow.NewTypeIdentifier(resolve_organization_workflow.WORKFLOWID_IS_DEFAULT_ORGANIZATION, "is-default-org-output"),
		"application/go-struct",
		mockOutput,
	)
	mockEngine.EXPECT().InvokeWithInputAndConfig(
		resolve_organization_workflow.WORKFLOWID_IS_DEFAULT_ORGANIZATION,
		gomock.Any(),
		gomock.Any(),
	).Return([]workflow.Data{outputData}, nil).AnyTimes()
}

// setupMockIsDefaultOrgWorkflowWithError sets up is_default_organization workflow that returns an error
func setupMockIsDefaultOrgWorkflowWithError(mockEngine *mocks.MockEngine, err error) {
	mockEngine.EXPECT().InvokeWithInputAndConfig(
		resolve_organization_workflow.WORKFLOWID_IS_DEFAULT_ORGANIZATION,
		gomock.Any(),
		gomock.Any(),
	).Return(nil, err).AnyTimes()
}

// Test scenarios for updateAndSendFolderConfigs (notification sending only)
func Test_sendFolderConfigs_SendsNotification(t *testing.T) {
	c := testutil.UnitTest(t)
	mockEngine, engineConfig := testutil.SetUpEngineMock(t, c)
	mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
	mockEngine.EXPECT().GetLogger().Return(c.Logger()).AnyTimes()

	// Setup mock workflow response
	setupMockWorkflowForOrg(mockEngine, "resolved-org-id", "Resolved Org", "resolved-org", false)

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
	assert.Equal(t, "resolved-org-id", folderConfigsParam.FolderConfigs[0].AutoDeterminedOrg, "AutoDeterminedOrg should be set by LDX-Sync")
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
func setupOrgResolverTest(t *testing.T, orgID, orgName, orgSlug string, isDefault bool) (*config.Config, *types.FolderConfig, resolve_organization_workflow.Organization) {
	t.Helper()

	c := testutil.UnitTest(t)
	mockEngine, _ := testutil.SetUpEngineMock(t, c)
	mockEngine.EXPECT().GetConfiguration().AnyTimes()
	mockEngine.EXPECT().GetLogger().Return(c.Logger()).AnyTimes()

	expectedOrg := resolve_organization_workflow.Organization{
		Id:        orgID,
		Name:      orgName,
		Slug:      orgSlug,
		IsDefault: &isDefault,
	}

	// Setup mock workflow response
	setupMockWorkflowForOrg(mockEngine, orgID, orgName, orgSlug, isDefault)

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

	// Setup mock workflow to return error
	setupMockWorkflowForOrgWithError(mockEngine, assert.AnError)

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

	// Setup mock workflow to return error
	setupMockWorkflowForOrgWithError(mockEngine, assert.AnError)

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

	folderPath1 := types.FilePath(t.TempDir())
	folderPath2 := types.FilePath(t.TempDir())

	// Setup mock workflow to return different orgs based on input path
	mockEngine.EXPECT().InvokeWithInputAndConfig(
		resolve_organization_workflow.WORKFLOWID_RESOLVE_ORGANIZATION,
		gomock.Any(),
		gomock.Any(),
	).DoAndReturn(func(_ workflow.Identifier, input []workflow.Data, _ configuration.Configuration) ([]workflow.Data, error) {
		workflowInput := input[0].GetPayload().(resolve_organization_workflow.ResolveOrganizationInput)
		path := workflowInput.Directory

		isDefault := false
		mockOrg := resolve_organization_workflow.Organization{
			Id:        "org-for-" + path,
			Name:      "Org for " + path,
			Slug:      "org-for-" + path,
			IsDefault: &isDefault,
		}
		mockOutput := resolve_organization_workflow.ResolveOrganizationOutput{
			Organization: mockOrg,
		}
		outputData := workflow.NewData(
			workflow.NewTypeIdentifier(resolve_organization_workflow.WORKFLOWID_RESOLVE_ORGANIZATION, "resolve-org-output"),
			"application/go-struct",
			mockOutput,
		)
		return []workflow.Data{outputData}, nil
	}).AnyTimes()

	// Setup mock workflow for is_default_organization (called by MigrateFolderConfigOrgSettings)
	// For this test, return that it's not the default org
	setupMockIsDefaultOrgWorkflow(mockEngine, false, false)

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
