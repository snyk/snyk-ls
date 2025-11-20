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
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/configuration"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/local_workflows/ignore_workflow"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/domain/snyk/mock_snyk"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/testutil/workspaceutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
)

// testIgnoreOperationUsesFolderOrg is a shared helper function that tests ignore operations
// (create/edit/delete) use the correct folder-specific org for a single folder scenario.
func testIgnoreOperationUsesFolderOrg(
	t *testing.T,
	c *config.Config,
	ctrl *gomock.Controller,
	folderPath types.FilePath,
	expectedOrg, issueID, ignoreID string,
	workflowID workflow.Identifier,
	commandArgs []any,
) {
	t.Helper()

	// Create a mock issue for the folder
	issue := createMockIssueWithContentroot(issueID, folderPath)

	// Set up issue provider that returns the issue
	issueProvider := mock_snyk.NewMockIssueProvider(ctrl)
	issueProvider.EXPECT().Issue(issueID).Return(issue).AnyTimes()

	// Set up mock engine to capture workflow invocation
	// Note: SetUpEngineMock must be called after SetupFoldersWithOrgs to ensure folder configs are saved
	// The storage is shared, so folder configs will be accessible, but we need to ensure the global org is set
	mockEngine, mockEngineConfig := testutil.SetUpEngineMock(t, c)
	// Ensure the global org is set on the mock engine config (needed for FolderOrganization fallback)
	mockEngineConfig.Set(configuration.ORGANIZATION, c.Organization())

	// Re-save folder config to ensure it's accessible through the mock engine's config
	// This is necessary because GetOrCreateFolderConfig might create new configs if not found
	folderConfigToSave := &types.FolderConfig{
		FolderPath:                  folderPath,
		PreferredOrg:                expectedOrg,
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true,
	}
	err := storedconfig.UpdateFolderConfig(mockEngineConfig, folderConfigToSave, c.Logger())
	require.NoError(t, err, "Should be able to save folder config")

	// Verify folder config is accessible after mock engine setup (storage is shared)
	folderConfig := c.FolderConfig(folderPath)
	require.NotNil(t, folderConfig, "Folder config should be accessible")
	require.Equal(t, expectedOrg, folderConfig.PreferredOrg, "Folder should have the expected org")
	require.True(t, folderConfig.OrgSetByUser, "Folder should have OrgSetByUser=true")

	// Capture the config from the workflow invocation
	var capturedOrg string
	mockEngine.EXPECT().InvokeWithConfig(workflowID, gomock.Any()).
		Do(func(_ workflow.Identifier, config configuration.Configuration) {
			capturedOrg = config.GetString(configuration.ORGANIZATION)
		}).
		Return([]workflow.Data{workflow.NewData(workflow.NewTypeIdentifier(workflowID, "test"), "json", []byte(`{"id":"`+ignoreID+`"}`))}, nil).
		Times(1)

	// Analytics workflow is called during ignore command execution
	mockEngine.EXPECT().InvokeWithInputAndConfig(localworkflows.WORKFLOWID_REPORT_ANALYTICS, gomock.Any(), gomock.Any()).
		Return(nil, nil).
		AnyTimes()

	server := mock_types.NewMockServer(ctrl)
	server.EXPECT().Callback(gomock.Any(), "window/showDocument", gomock.Any()).Return(nil, nil).AnyTimes()
	notifier := notification.NewMockNotifier()

	cmd := &submitIgnoreRequest{
		command: types.CommandData{
			Arguments: commandArgs,
		},
		issueProvider: issueProvider,
		notifier:      notifier,
		srv:           server,
		c:             c,
	}

	// Execute the full command (this will call executeIgnoreWorkflow)
	_, err = cmd.Execute(t.Context())
	require.NoError(t, err)

	// Verify workflow was invoked with correct org
	assert.Equal(t, expectedOrg, capturedOrg, "Workflow should be invoked with folder's org")
}

// Test_IgnoreOperations_UseFolderOrganization is an INTEGRATION TEST that verifies
// ignore create/edit/delete operations use the folder-specific org in the workflow configuration.
// This test uses testutil.IntegTest() to run in the integration test suite.
func Test_IgnoreOperations_UseFolderOrganization(t *testing.T) {
	c := testutil.IntegTest(t)

	// Set up two folders with different orgs
	folderPath1, folderPath2, _, folderOrg1, folderOrg2 := testutil.SetupFoldersWithOrgs(t, c)

	// Set up workspace with the folders
	// This is required for FolderOrganizationForSubPath to work (used by initializeCreateConfiguration, initializeEditConfigurations, initializeDeleteConfiguration)
	_, _ = workspaceutil.SetupWorkspace(t, c, folderPath1, folderPath2)

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	// Test Create Ignore
	t.Run("Create ignore uses folder org", func(t *testing.T) {
		// Test folder 1
		t.Run("folder 1", func(t *testing.T) {
			testIgnoreOperationUsesFolderOrg(
				t, c, ctrl, folderPath1, folderOrg1, "issue1", "ignore123",
				ignore_workflow.WORKFLOWID_IGNORE_CREATE,
				[]any{"create", "issue1", "wont_fix", "test reason", "2025-12-31"},
			)
		})

		// Test folder 2
		t.Run("folder 2", func(t *testing.T) {
			testIgnoreOperationUsesFolderOrg(
				t, c, ctrl, folderPath2, folderOrg2, "issue2", "ignore456",
				ignore_workflow.WORKFLOWID_IGNORE_CREATE,
				[]any{"create", "issue2", "wont_fix", "test reason", "2025-12-31"},
			)
		})
	})

	// Test Edit Ignore
	t.Run("Edit ignore uses folder org", func(t *testing.T) {
		// Test folder 1
		t.Run("folder 1", func(t *testing.T) {
			testIgnoreOperationUsesFolderOrg(
				t, c, ctrl, folderPath1, folderOrg1, "issue1", "ignore123",
				ignore_workflow.WORKFLOWID_IGNORE_EDIT,
				[]any{"update", "issue1", "wont_fix", "updated reason", "2026-12-31", "ignore123"},
			)
		})

		// Test folder 2
		t.Run("folder 2", func(t *testing.T) {
			testIgnoreOperationUsesFolderOrg(
				t, c, ctrl, folderPath2, folderOrg2, "issue2", "ignore456",
				ignore_workflow.WORKFLOWID_IGNORE_EDIT,
				[]any{"update", "issue2", "wont_fix", "updated reason", "2026-12-31", "ignore456"},
			)
		})
	})

	// Test Delete Ignore
	t.Run("Delete ignore uses folder org", func(t *testing.T) {
		// Test folder 1
		t.Run("folder 1", func(t *testing.T) {
			testIgnoreOperationUsesFolderOrg(
				t, c, ctrl, folderPath1, folderOrg1, "issue1", "ignore123",
				ignore_workflow.WORKFLOWID_IGNORE_DELETE,
				[]any{"delete", "issue1", "ignore123"},
			)
		})

		// Test folder 2
		t.Run("folder 2", func(t *testing.T) {
			testIgnoreOperationUsesFolderOrg(
				t, c, ctrl, folderPath2, folderOrg2, "issue2", "ignore456",
				ignore_workflow.WORKFLOWID_IGNORE_DELETE,
				[]any{"delete", "issue2", "ignore456"},
			)
		})
	})
}

// Test_IgnoreOperations_FallBackToGlobalOrg is an INTEGRATION TEST that verifies
// ignore operations fall back to global org when no folder-specific org is configured.
// This test uses testutil.IntegTest() to run in the integration test suite.
func Test_IgnoreOperations_FallBackToGlobalOrg(t *testing.T) {
	c := testutil.IntegTest(t)

	folderPath, _ := testutil.SetupGlobalOrgOnly(t, c)

	// Set up workspace with the folder
	// This is required for FolderOrganizationForSubPath to work (used by initializeCreateConfiguration)
	_, _ = workspaceutil.SetupWorkspace(t, c, folderPath)

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	// Note: We don't need to mock issueProvider since we're only testing the initialization method
	server := mock_types.NewMockServer(ctrl)
	server.EXPECT().Callback(gomock.Any(), "window/showDocument", gomock.Any()).Return(nil, nil).AnyTimes()
	notifier := notification.NewMockNotifier()
	cmd := &submitIgnoreRequest{
		command: types.CommandData{
			Arguments: []any{"create", "issue1", "wont_fix", "test reason", "2025-12-31"},
		},
		issueProvider: nil, // Not needed for testing initialization methods
		notifier:      notifier,
		srv:           server,
		c:             c,
	}

	// When no folder org is set, FolderOrganization falls back to global org
	// (this is the correct behavior - it should return the global org as fallback)
	engine := c.Engine()
	// Get the global org from the engine config (this might trigger API calls, but we need it for the test)
	engineGlobalOrg := engine.GetConfiguration().GetString(configuration.ORGANIZATION)
	require.NotEmpty(t, engineGlobalOrg, "Engine config should have global org set")

	// FolderOrganization should return the global org when no folder org is configured (fallback behavior)
	folderOrg := c.FolderOrganization(folderPath)
	assert.Equal(t, engineGlobalOrg, folderOrg, "FolderOrganization should fall back to global org when no folder org is configured")

	// Test initializeCreateConfiguration - when FolderOrganization returns the global org,
	// it doesn't override the org (since folderOrg == globalOrg), so the cloned config keeps the global org
	gafConfig, err := cmd.initializeCreateConfiguration(engine.GetConfiguration().Clone(), "finding1", folderPath)
	require.NoError(t, err)
	configOrg := gafConfig.GetString(configuration.ORGANIZATION)
	// When FolderOrganization returns the global org, initializeCreateConfiguration doesn't override it,
	// so it keeps the global org from the cloned config (which is the correct fallback behavior)
	assert.Equal(t, engineGlobalOrg, configOrg, "Config should keep global org when folder org is not configured (fallback behavior)")
}

// createMockIssueWithContentroot creates a mock issue with ContentRoot set (required for ignore commands)
// It uses testutil.NewMockIssue and then sets the ContentRoot.
func createMockIssueWithContentroot(id string, contentRoot types.FilePath) *snyk.Issue {
	issue := testutil.NewMockIssue(id, types.FilePath(filepath.Join(string(contentRoot), "test.js")))
	issue.ContentRoot = contentRoot
	return issue
}
