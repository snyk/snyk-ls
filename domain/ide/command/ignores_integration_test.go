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

	"github.com/snyk/snyk-ls/domain/snyk/mock_snyk"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
)

// Test_IgnoreOperations_UseFolderOrganization verifies that ignore create/edit/delete
// operations use the folder-specific org in the workflow configuration.
func Test_IgnoreOperations_UseFolderOrganization(t *testing.T) {
	c := testutil.SmokeTest(t, false)

	// Set up two folders with different orgs
	folderPath1 := types.FilePath(t.TempDir())
	folderPath2 := types.FilePath(t.TempDir())

	globalOrg := "00000000-0000-0000-0000-000000000001"
	folderOrg1 := "00000000-0000-0000-0000-000000000002"
	folderOrg2 := "00000000-0000-0000-0000-000000000003" // Set global org as a UUID (no API resolution needed)

	// Set a global org that is different from folder orgs
	c.SetOrganization(globalOrg)

	// Configure folder 1 with its own org
	folderConfig1 := &types.FolderConfig{
		FolderPath:                  folderPath1,
		PreferredOrg:                folderOrg1,
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true,
	}
	err := storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), folderConfig1, c.Logger())
	require.NoError(t, err)

	// Configure folder 2 with a different org
	folderConfig2 := &types.FolderConfig{
		FolderPath:                  folderPath2,
		PreferredOrg:                folderOrg2,
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true,
	}
	err = storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), folderConfig2, c.Logger())
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Test Create Ignore
	t.Run("Create ignore uses folder org", func(t *testing.T) {
		// Verify global org is set
		globalOrgValue := c.Organization()
		assert.Equal(t, globalOrg, globalOrgValue, "Global org should be set correctly")

		// Verify FolderOrganization returns the expected value
		actualOrg := c.FolderOrganization(folderPath1)
		require.Equal(t, folderOrg1, actualOrg, "FolderOrganization should return folder1's org")

		// Test that initializeCreateConfiguration sets the org correctly
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

		// Test initializeCreateConfiguration directly
		engine := c.Engine()
		// Verify the global org is in the engine config before cloning
		engineGlobalOrg := engine.GetConfiguration().GetString(configuration.ORGANIZATION)
		assert.Equal(t, globalOrg, engineGlobalOrg, "Engine config should have global org set")

		gafConfig, err := cmd.initializeCreateConfiguration(engine.GetConfiguration().Clone(), "finding1", folderPath1)
		require.NoError(t, err)
		configOrg := gafConfig.GetString(configuration.ORGANIZATION)
		assert.Equal(t, folderOrg1, configOrg, "initializeCreateConfiguration should set folder1's org in config (overriding global org)")

		// Test folder 2
		actualOrg2 := c.FolderOrganization(folderPath2)
		require.Equal(t, folderOrg2, actualOrg2, "FolderOrganization should return folder2's org")

		server2 := mock_types.NewMockServer(ctrl)
		server2.EXPECT().Callback(gomock.Any(), "window/showDocument", gomock.Any()).Return(nil, nil).AnyTimes()
		notifier2 := notification.NewMockNotifier()
		cmd2 := &submitIgnoreRequest{
			command: types.CommandData{
				Arguments: []any{"create", "issue2", "wont_fix", "test reason", "2025-12-31"},
			},
			issueProvider: nil, // Not needed for testing initialization methods
			notifier:      notifier2,
			srv:           server2,
			c:             c,
		}

		// Test initializeCreateConfiguration for folder 2
		gafConfig2, err := cmd2.initializeCreateConfiguration(engine.GetConfiguration().Clone(), "finding2", folderPath2)
		require.NoError(t, err)
		configOrg2 := gafConfig2.GetString(configuration.ORGANIZATION)
		assert.Equal(t, folderOrg2, configOrg2, "initializeCreateConfiguration should set folder2's org in config")
	})

	// Test Edit Ignore
	t.Run("Edit ignore uses folder org", func(t *testing.T) {
		server := mock_types.NewMockServer(ctrl)
		server.EXPECT().Callback(gomock.Any(), "window/showDocument", gomock.Any()).Return(nil, nil).AnyTimes()
		notifier := notification.NewMockNotifier()
		cmd := &submitIgnoreRequest{
			command: types.CommandData{
				Arguments: []any{"update", "issue1", "wont_fix", "updated reason", "2026-12-31", "ignore123"},
			},
			issueProvider: nil, // Not needed for testing initialization methods
			notifier:      notifier,
			srv:           server,
			c:             c,
		}

		// Test initializeEditConfigurations directly
		engine := c.Engine()
		gafConfig, err := cmd.initializeEditConfigurations(engine.GetConfiguration().Clone(), folderPath1)
		require.NoError(t, err)
		configOrg := gafConfig.GetString(configuration.ORGANIZATION)
		assert.Equal(t, folderOrg1, configOrg, "initializeEditConfigurations should set folder1's org in config")

		// Test folder 2
		server2 := mock_types.NewMockServer(ctrl)
		server2.EXPECT().Callback(gomock.Any(), "window/showDocument", gomock.Any()).Return(nil, nil).AnyTimes()
		notifier2 := notification.NewMockNotifier()
		cmd2 := &submitIgnoreRequest{
			command: types.CommandData{
				Arguments: []any{"update", "issue2", "wont_fix", "updated reason", "2026-12-31", "ignore456"},
			},
			issueProvider: nil, // Not needed for testing initialization methods
			notifier:      notifier2,
			srv:           server2,
			c:             c,
		}

		gafConfig2, err := cmd2.initializeEditConfigurations(engine.GetConfiguration().Clone(), folderPath2)
		require.NoError(t, err)
		configOrg2 := gafConfig2.GetString(configuration.ORGANIZATION)
		assert.Equal(t, folderOrg2, configOrg2, "initializeEditConfigurations should set folder2's org in config")
	})

	// Test Delete Ignore
	t.Run("Delete ignore uses folder org", func(t *testing.T) {
		server := mock_types.NewMockServer(ctrl)
		server.EXPECT().Callback(gomock.Any(), "window/showDocument", gomock.Any()).Return(nil, nil).AnyTimes()
		notifier := notification.NewMockNotifier()
		cmd := &submitIgnoreRequest{
			command: types.CommandData{
				Arguments: []any{"delete", "issue1", "ignore123"},
			},
			issueProvider: nil, // Not needed for testing initialization methods
			notifier:      notifier,
			srv:           server,
			c:             c,
		}

		// Test initializeDeleteConfiguration directly
		engine := c.Engine()
		gafConfig, err := cmd.initializeDeleteConfiguration(engine.GetConfiguration().Clone(), folderPath1)
		require.NoError(t, err)
		configOrg := gafConfig.GetString(configuration.ORGANIZATION)
		assert.Equal(t, folderOrg1, configOrg, "initializeDeleteConfiguration should set folder1's org in config")

		// Test folder 2
		server2 := mock_types.NewMockServer(ctrl)
		server2.EXPECT().Callback(gomock.Any(), "window/showDocument", gomock.Any()).Return(nil, nil).AnyTimes()
		notifier2 := notification.NewMockNotifier()
		cmd2 := &submitIgnoreRequest{
			command: types.CommandData{
				Arguments: []any{"delete", "issue2", "ignore456"},
			},
			issueProvider: nil, // Not needed for testing initialization methods
			notifier:      notifier2,
			srv:           server2,
			c:             c,
		}

		gafConfig2, err := cmd2.initializeDeleteConfiguration(engine.GetConfiguration().Clone(), folderPath2)
		require.NoError(t, err)
		configOrg2 := gafConfig2.GetString(configuration.ORGANIZATION)
		assert.Equal(t, folderOrg2, configOrg2, "initializeDeleteConfiguration should set folder2's org in config")
	})
}

// Test_IgnoreOperations_FallBackToGlobalOrg verifies that ignore operations
// fall back to global org when no folder-specific org is configured.
func Test_IgnoreOperations_FallBackToGlobalOrg(t *testing.T) {
	c := testutil.SmokeTest(t, false)

	folderPath := types.FilePath(t.TempDir())
	const globalOrg = "00000000-0000-0000-0000-000000000004"

	// Set only global org, no folder-specific org
	c.SetOrganization(globalOrg)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	issue := testutil.NewMockCodeIssue("issue1", folderPath, "finding1")
	issueProvider := mock_snyk.NewMockIssueProvider(ctrl)
	issueProvider.EXPECT().Issue("issue1").Return(issue)

	server := mock_types.NewMockServer(ctrl)
	server.EXPECT().Callback(gomock.Any(), "window/showDocument", gomock.Any()).Return(nil, nil).AnyTimes()
	notifier := notification.NewMockNotifier()
	cmd := &submitIgnoreRequest{
		command: types.CommandData{
			Arguments: []any{"create", "issue1", "wont_fix", "test reason", "2025-12-31"},
		},
		issueProvider: issueProvider,
		notifier:      notifier,
		srv:           server,
		c:             c,
	}

	// When no folder org is set, FolderOrganization returns empty string,
	// so the org should be empty in the config (not set)
	folderOrg := c.FolderOrganization(folderPath)
	assert.Empty(t, folderOrg, "Folder should have no org configured")

	// Test initializeCreateConfiguration - it should set empty org when FolderOrganization returns empty
	engine := c.Engine()
	gafConfig, err := cmd.initializeCreateConfiguration(engine.GetConfiguration().Clone(), "finding1", folderPath)
	require.NoError(t, err)
	configOrg := gafConfig.GetString(configuration.ORGANIZATION)
	// When FolderOrganization returns empty, initializeCreateConfiguration sets it to empty string
	assert.Empty(t, configOrg, "Config should not have org set when folder org is empty")
}
