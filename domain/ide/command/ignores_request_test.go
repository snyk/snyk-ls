package command

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/local_workflows/ignore_workflow"

	"github.com/snyk/snyk-ls/domain/snyk/mock_snyk"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/testutil/workspaceutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
)

func Test_submitIgnoreRequest_Execute(t *testing.T) {
	tests := []struct {
		name                         string
		arguments                    []any
		mockIssueProviderExpectation func(issueProvider *mock_snyk.MockIssueProvider)
		expectedError                error
		expectedIssueCalled          bool
	}{
		{
			name:                         "Invalid issueId type",
			arguments:                    []any{"create", 123},
			mockIssueProviderExpectation: func(issueProvider *mock_snyk.MockIssueProvider) {},
			expectedError:                errors.New("issueId type should be a string"),
			expectedIssueCalled:          false,
		},
		{
			name:      "Issue not found",
			arguments: []any{"create", "issueId"},
			mockIssueProviderExpectation: func(issueProvider *mock_snyk.MockIssueProvider) {
				issueProvider.EXPECT().Issue(gomock.Any()).Return(nil)
			},
			expectedError:       errors.New("issue not found"),
			expectedIssueCalled: true,
		},
		{
			name:      "Invalid workflow type argument",
			arguments: []any{123, "issueId"},
			mockIssueProviderExpectation: func(issueProvider *mock_snyk.MockIssueProvider) {
			},
			expectedError:       errors.New("workflow type should be a string"),
			expectedIssueCalled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := testutil.UnitTest(t)
			ctrl := gomock.NewController(t)
			server := mock_types.NewMockServer(ctrl)
			issueProvider := mock_snyk.NewMockIssueProvider(ctrl)
			if tt.mockIssueProviderExpectation != nil {
				tt.mockIssueProviderExpectation(issueProvider)
			}
			cmd := &submitIgnoreRequest{
				command:       types.CommandData{Arguments: tt.arguments},
				issueProvider: issueProvider,
				srv:           server,
				c:             c,
			}

			_, err := cmd.Execute(t.Context())

			if tt.expectedError != nil {
				assert.EqualError(t, err, tt.expectedError.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_submitIgnoreRequest_initializeCreateConfiguration(t *testing.T) {
	tests := []struct {
		name           string
		arguments      []any
		expectedConfig map[string]any
		expectedError  error
	}{
		{
			name:      "Successful creation",
			arguments: []any{"create", "issueId", "wont_fix", "reason", "expiration"},
			expectedConfig: map[string]any{
				ignore_workflow.FindingsIdKey:     "finding123",
				ignore_workflow.EnrichResponseKey: true,
				ignore_workflow.InteractiveKey:    false,
				ignore_workflow.IgnoreTypeKey:     "wont_fix",
				ignore_workflow.ReasonKey:         "reason",
				ignore_workflow.ExpirationKey:     "expiration",
			},
		},
		{
			name:          "insufficient arguments",
			arguments:     []any{"create", "issueId", "wont_fix", "reason"},
			expectedError: errors.New("insufficient arguments for ignore-create workflow"),
		},
		{
			name:          "GetCommandArgs fails",
			arguments:     []any{"create", "issueId", 123, "reason", "expiration"},
			expectedError: errors.New("ignoreType should be a string"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := testutil.UnitTest(t)

			// Setup fake workspace
			folderPaths := []types.FilePath{types.FilePath("/fake/test-folder-0")}
			_, _ = workspaceutil.SetupWorkspace(t, c, folderPaths...)
			contentRoot := folderPaths[0]

			// Configure folder with org
			err := storedconfig.UpdateStoredFolderConfig(c.Engine().GetConfiguration(), &types.StoredFolderConfig{
				FolderPath:                  contentRoot,
				PreferredOrg:                "test-org",
				OrgSetByUser:                true,
				OrgMigratedFromGlobalConfig: true,
			}, c.Logger())
			require.NoError(t, err)

			cmd := &submitIgnoreRequest{
				command: types.CommandData{
					Arguments: tt.arguments,
				},
				c: c,
			}

			gafConfig := c.Engine().GetConfiguration()
			config, err := cmd.initializeCreateConfiguration(gafConfig, "finding123", contentRoot)

			if tt.expectedError != nil {
				assert.EqualError(t, err, tt.expectedError.Error())
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, config)

				// Check all expected config values
				for key, expectedValue := range tt.expectedConfig {
					assert.Equal(t, expectedValue, config.Get(key))
				}

				// Verify INPUT_DIRECTORY is set to the contentRoot we passed
				assert.Equal(t, string(contentRoot), config.Get(configuration.INPUT_DIRECTORY))
			}
		})
	}
}

func Test_getIgnoreIdFromCmdArgs(t *testing.T) {
	tests := []struct {
		name          string
		arguments     []any
		expectedId    string
		expectedError error
	}{
		{
			name:          "valid ignoreId",
			arguments:     []any{"create", "issueId", "wont_fix", "reason", "expiration", "ignore123"},
			expectedId:    "ignore123",
			expectedError: nil,
		},
		{
			name:          "invalid ignoreId type",
			arguments:     []any{"create", "issueId", "wont_fix", "reason", "expiration", 123},
			expectedId:    "",
			expectedError: fmt.Errorf("ignoreId should be a string"),
		},
		{
			name:          "missing ignoreId",
			arguments:     []any{"create", "issueId", "wont_fix", "reason", "expiration"},
			expectedId:    "",
			expectedError: fmt.Errorf("missing ignoreId"),
		},
		{
			name:          "empty arguments",
			arguments:     []any{},
			expectedId:    "",
			expectedError: fmt.Errorf("missing ignoreId"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.UnitTest(t)
			cmd := &submitIgnoreRequest{
				command: types.CommandData{
					Arguments: tt.arguments,
				},
			}

			ignoreId, err := getIgnoreIdFromCmdArgs(cmd)

			assert.Equal(t, tt.expectedId, ignoreId)
			if tt.expectedError != nil {
				assert.EqualError(t, err, tt.expectedError.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_GetCommandArgs(t *testing.T) {
	tests := []struct {
		name           string
		arguments      []any
		expectedType   string
		expectedReason string
		expectedExp    string
		expectedError  error
	}{
		{
			name:           "valid arguments",
			arguments:      []any{"create", "issueId", "wont_fix", "reason", "expiration"},
			expectedType:   "wont_fix",
			expectedReason: "reason",
			expectedExp:    "expiration",
			expectedError:  nil,
		},
		{
			name:           "insufficient arguments",
			arguments:      []any{"create", "issueId", "wont_fix", "reason"},
			expectedType:   "",
			expectedReason: "",
			expectedExp:    "",
			expectedError:  fmt.Errorf("insufficient arguments for ignore command"),
		},
		{
			name:           "invalid ignoreType",
			arguments:      []any{"create", "issueId", 123, "reason", "expiration"},
			expectedType:   "",
			expectedReason: "",
			expectedExp:    "",
			expectedError:  fmt.Errorf("ignoreType should be a string"),
		},
		{
			name:           "invalid reason",
			arguments:      []any{"create", "issueId", "wont_fix", 123, "expiration"},
			expectedType:   "",
			expectedReason: "",
			expectedExp:    "",
			expectedError:  fmt.Errorf("reason should be a string"),
		},
		{
			name:           "invalid expiration",
			arguments:      []any{"create", "issueId", "wont_fix", "reason", 123},
			expectedType:   "",
			expectedReason: "",
			expectedExp:    "",
			expectedError:  fmt.Errorf("expiration should be a string"),
		},
		{
			name:           "empty arguments",
			arguments:      []any{},
			expectedType:   "",
			expectedReason: "",
			expectedExp:    "",
			expectedError:  fmt.Errorf("insufficient arguments for ignore command"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.UnitTest(t)
			cmd := &submitIgnoreRequest{
				command: types.CommandData{
					Arguments: tt.arguments,
				},
			}

			ignoreType, reason, expiration, err := GetCommandArgs(cmd)

			assert.Equal(t, tt.expectedType, ignoreType)
			assert.Equal(t, tt.expectedReason, reason)
			assert.Equal(t, tt.expectedExp, expiration)

			if tt.expectedError != nil {
				assert.EqualError(t, err, tt.expectedError.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_getStringArgument(t *testing.T) {
	tests := []struct {
		name          string
		arguments     []any
		index         int
		argName       string
		expectedValue string
		expectedError error
	}{
		{
			name:          "valid string argument",
			arguments:     []any{"arg1", "arg2", "arg3"},
			index:         1,
			argName:       "testArg",
			expectedValue: "arg2",
			expectedError: nil,
		},
		{
			name:          "index out of bounds",
			arguments:     []any{"arg1", "arg2"},
			index:         2,
			argName:       "testArg",
			expectedValue: "",
			expectedError: fmt.Errorf("missing argument: testArg"),
		},
		{
			name:          "wrong argument type",
			arguments:     []any{"arg1", 123, "arg3"},
			index:         1,
			argName:       "testArg",
			expectedValue: "",
			expectedError: fmt.Errorf("testArg should be a string"),
		},
		{
			name:          "empty arguments",
			arguments:     []any{},
			index:         0,
			argName:       "testArg",
			expectedValue: "",
			expectedError: fmt.Errorf("missing argument: testArg"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.UnitTest(t)

			cmd := &submitIgnoreRequest{
				command: types.CommandData{
					Arguments: tt.arguments,
				},
			}

			value, err := getStringArgument(cmd, tt.index, tt.argName)

			assert.Equal(t, tt.expectedValue, value)
			if tt.expectedError != nil {
				assert.EqualError(t, err, tt.expectedError.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_createBaseConfiguration(t *testing.T) {
	// Arrange
	c := testutil.UnitTest(t)
	gafConfig := c.Engine().GetConfiguration()

	contentRoot := types.FilePath("/test/content/root")

	// Act
	result := initializeBaseConfiguration(gafConfig, contentRoot)

	// Assert
	assert.Equal(t, true, result.Get(ignore_workflow.EnrichResponseKey))
	assert.Equal(t, false, result.Get(ignore_workflow.InteractiveKey))
	assert.Equal(t, string(contentRoot), result.Get(configuration.INPUT_DIRECTORY))
}

func Test_addCreateAndUpdateConfiguration(t *testing.T) {
	// Arrange
	c := testutil.UnitTest(t)
	ignoreType := "testIgnoreType"
	reason := "testReason"
	expiration := "testExpiration"
	gafConfig := c.Engine().GetConfiguration()

	// Act
	result := addCreateAndUpdateConfiguration(gafConfig, ignoreType, reason, expiration)

	// Assert
	assert.Equal(t, ignoreType, result.Get(ignore_workflow.IgnoreTypeKey))
	assert.Equal(t, reason, result.Get(ignore_workflow.ReasonKey))
	assert.Equal(t, expiration, result.Get(ignore_workflow.ExpirationKey))
}

func Test_submitIgnoreRequest_SendsAnalyticsWithFolderOrg(t *testing.T) {
	c := testutil.UnitTest(t)

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockEngine, engineConfig := testutil.SetUpEngineMock(t, c)

	const testFolderOrg = "test-folder-org"

	// Setup fake workspace with the folder
	folderPaths := []types.FilePath{types.FilePath("/fake/test-folder-0")}
	_, _ = workspaceutil.SetupWorkspace(t, c, folderPaths...)
	folderPath := folderPaths[0]

	folderConfig := &types.StoredFolderConfig{
		FolderPath:                  folderPath,
		PreferredOrg:                testFolderOrg,
		OrgSetByUser:                true,
		OrgMigratedFromGlobalConfig: true,
	}
	err := storedconfig.UpdateStoredFolderConfig(engineConfig, folderConfig, c.Logger())
	require.NoError(t, err, "failed to configure folder org")

	// Capture analytics WF's data and config to verify folder org
	capturedCh := testutil.MockAndCaptureWorkflowInvocation(t, mockEngine, localworkflows.WORKFLOWID_REPORT_ANALYTICS, 1)

	cmd := &submitIgnoreRequest{
		c: c,
	}

	// Act: Send ignore request analytics
	cmd.sendIgnoreRequestAnalytics(nil, folderPath)

	// Assert: Verify analytics sent with correct folder org
	captured := testsupport.RequireEventuallyReceive(t, capturedCh, time.Second, 10*time.Millisecond, "analytics should have been sent")
	actualOrg := captured.Config.Get(configuration.ORGANIZATION)
	assert.Equal(t, testFolderOrg, actualOrg, "analytics should use folder-specific org")
}

func Test_submitIgnoreRequest_SendsAnalyticsWithGlobalOrgFallback(t *testing.T) {
	c := testutil.UnitTest(t)

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockEngine, _ := testutil.SetUpEngineMock(t, c)

	const testGlobalOrg = "test-global-org"

	// Setup fake workspace with one folder, but we'll send analytics for a path outside of it
	_, _ = workspaceutil.SetupWorkspace(t, c, types.FilePath("/fake/test-folder-0"))

	// Set a global org in the config
	c.SetOrganization(testGlobalOrg)

	// Capture analytics WF's data and config to verify global org is used
	capturedCh := testutil.MockAndCaptureWorkflowInvocation(t, mockEngine, localworkflows.WORKFLOWID_REPORT_ANALYTICS, 1)

	cmd := &submitIgnoreRequest{
		c: c,
	}

	// Act: Send ignore request analytics for a path not in any workspace folder.
	// Note: This is an unrealistic scenario in production (IDE should only send ignore requests
	// for files within the workspace), but tests defensive behavior to ensure we don't crash
	// and still send analytics with global org fallback if workspace context is unavailable.
	pathNotInWorkspace := types.FilePath("/some/random/path/outside/workspace/file.txt")
	cmd.sendIgnoreRequestAnalytics(nil, pathNotInWorkspace)

	// Assert: Verify analytics sent with global org as fallback
	captured := testsupport.RequireEventuallyReceive(t, capturedCh, time.Second, 10*time.Millisecond, "analytics should have been sent")
	actualOrg := captured.Config.Get(configuration.ORGANIZATION)
	assert.Equal(t, testGlobalOrg, actualOrg, "analytics should fall back to global org when folder org cannot be determined")
}

func Test_submitIgnoreRequest_initializeCreateConfiguration_FallsBackToGlobalOrg(t *testing.T) {
	c := testutil.UnitTest(t)

	globalOrg := "00000000-0000-0000-0000-000000000004"
	c.SetOrganization(globalOrg)

	folderPath := types.FilePath("/fake/test-folder")

	// Set up workspace with the folder
	// This is required for FolderOrganizationForSubPath to work (used by initializeCreateConfiguration)
	_, _ = workspaceutil.SetupWorkspace(t, c, folderPath)

	// Verify FolderOrganization() returns the global org (fallback behavior)
	folderOrg := c.FolderOrganization(folderPath)
	assert.Equal(t, globalOrg, folderOrg, "FolderOrganization should fall back to global org when no folder org is configured")

	// Create command
	cmd := &submitIgnoreRequest{
		command: types.CommandData{
			Arguments: []any{"create", "issue1", "wont_fix", "test reason", "2025-12-31"},
		},
		c: c,
	}

	// Test initializeCreateConfiguration - when FolderOrganization returns the global org,
	// it sets the org in the config (which is the global org)
	engine := c.Engine()
	gafConfig, err := cmd.initializeCreateConfiguration(engine.GetConfiguration().Clone(), "finding1", folderPath)
	require.NoError(t, err)
	configOrg := gafConfig.GetString(configuration.ORGANIZATION)
	// When FolderOrganization returns the global org, initializeCreateConfiguration sets it in the config
	assert.Equal(t, globalOrg, configOrg, "Config should use global org when folder org is not configured (fallback behavior)")
}
