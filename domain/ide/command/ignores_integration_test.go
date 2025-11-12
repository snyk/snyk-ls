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

	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
)

// Test_IgnoreOperations_UseFolderOrganization is an INTEGRATION TEST that verifies
// ignore create/edit/delete operations use the folder-specific org in the workflow configuration.
// This test uses testutil.IntegTest() to run in the integration test suite.
func Test_IgnoreOperations_UseFolderOrganization(t *testing.T) {
	c := testutil.IntegTest(t)

	// Set up two folders with different orgs
	folderPath1, folderPath2, _, folderOrg1, folderOrg2 := testutil.SetupFoldersWithOrgs(t, c)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Test Create Ignore
	t.Run("Create ignore uses folder org", func(t *testing.T) {
		// Verify FolderOrganization returns the expected value
		// Note: We don't check c.Organization() here as it triggers GetString() which can make API calls
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

// Test_IgnoreOperations_FallBackToGlobalOrg is an INTEGRATION TEST that verifies
// ignore operations fall back to global org when no folder-specific org is configured.
// This test uses testutil.IntegTest() to run in the integration test suite.
func Test_IgnoreOperations_FallBackToGlobalOrg(t *testing.T) {
	c := testutil.IntegTest(t)

	folderPath, _ := testutil.SetupGlobalOrgOnly(t, c)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

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
