package command

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/local_workflows/ignore_workflow"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk/mock_snyk"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/testutil/workspaceutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
)

type fakeTreeRefresher struct {
	calls     int
	lastState scanstates.StateSnapshot
}

func (f *fakeTreeRefresher) Emit(state scanstates.StateSnapshot) {
	f.calls++
	f.lastState = state
}

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
			engine := testutil.UnitTest(t)
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
				engine:        engine,
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
			engine := testutil.UnitTest(t)

			// Setup fake workspace
			folderPaths := []types.FilePath{types.FilePath("/fake/test-folder-0")}
			_, _ = workspaceutil.SetupWorkspace(t, engine, folderPaths...)
			contentRoot := folderPaths[0]

			// Configure folder with org
			engineConf := engine.GetConfiguration()
			types.SetPreferredOrgAndOrgSetByUser(engineConf, contentRoot, "test-org", true)

			cmd := &submitIgnoreRequest{
				command: types.CommandData{
					Arguments: tt.arguments,
				},
				engine: engine,
			}

			engineConfig := engine.GetConfiguration()
			config, err := cmd.initializeCreateConfiguration(engineConfig, "finding123", contentRoot)

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
	engine := testutil.UnitTest(t)
	engineConfig := engine.GetConfiguration()

	contentRoot := types.FilePath("/test/content/root")

	// Act
	result := initializeBaseConfiguration(engineConfig, contentRoot)

	// Assert
	assert.Equal(t, true, result.Get(ignore_workflow.EnrichResponseKey))
	assert.Equal(t, false, result.Get(ignore_workflow.InteractiveKey))
	assert.Equal(t, string(contentRoot), result.Get(configuration.INPUT_DIRECTORY))
}

func Test_addCreateAndUpdateConfiguration(t *testing.T) {
	// Arrange
	engine := testutil.UnitTest(t)
	ignoreType := "testIgnoreType"
	reason := "testReason"
	expiration := "testExpiration"
	engineConfig := engine.GetConfiguration()

	// Act
	result := addCreateAndUpdateConfiguration(engineConfig, ignoreType, reason, expiration)

	// Assert
	assert.Equal(t, ignoreType, result.Get(ignore_workflow.IgnoreTypeKey))
	assert.Equal(t, reason, result.Get(ignore_workflow.ReasonKey))
	assert.Equal(t, expiration, result.Get(ignore_workflow.ExpirationKey))
}

func Test_submitIgnoreRequest_SendsAnalyticsWithFolderOrg(t *testing.T) {
	engine := testutil.UnitTest(t)

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockEngine, engineConfig := testutil.SetUpEngineMock(t, engine)

	const testFolderOrg = "test-folder-org"

	// Setup fake workspace with the folder
	folderPaths := []types.FilePath{types.FilePath("/fake/test-folder-0")}
	_, _ = workspaceutil.SetupWorkspace(t, mockEngine, folderPaths...)
	folderPath := folderPaths[0]

	types.SetPreferredOrgAndOrgSetByUser(engineConfig, folderPath, testFolderOrg, true)

	// Capture analytics WF's data and config to verify folder org
	capturedCh := testutil.MockAndCaptureWorkflowInvocation(t, mockEngine, localworkflows.WORKFLOWID_REPORT_ANALYTICS, 1)

	cmd := &submitIgnoreRequest{
		engine:         mockEngine,
		configResolver: testutil.DefaultConfigResolver(engine),
	}

	// Act: Send ignore request analytics
	cmd.sendIgnoreRequestAnalytics(nil, folderPath)

	// Assert: Verify analytics sent with correct folder org
	captured := testsupport.RequireEventuallyReceive(t, capturedCh, time.Second, 10*time.Millisecond, "analytics should have been sent")
	actualOrg := captured.Config.Get(configuration.ORGANIZATION)
	assert.Equal(t, testFolderOrg, actualOrg, "analytics should use folder-specific org")
}

func Test_submitIgnoreRequest_SendsAnalyticsWithGlobalOrgFallback(t *testing.T) {
	engine := testutil.UnitTest(t)

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockEngine, mockConf := testutil.SetUpEngineMock(t, engine)

	const testGlobalOrg = "test-global-org"

	// Setup fake workspace with one folder, but we'll send analytics for a path outside of it
	_, _ = workspaceutil.SetupWorkspace(t, mockEngine, types.FilePath("/fake/test-folder-0"))

	// Set a global org in the config
	config.SetOrganization(mockConf, testGlobalOrg)

	// Capture analytics WF's data and config to verify global org is used
	capturedCh := testutil.MockAndCaptureWorkflowInvocation(t, mockEngine, localworkflows.WORKFLOWID_REPORT_ANALYTICS, 1)

	cmd := &submitIgnoreRequest{
		engine:         mockEngine,
		configResolver: testutil.DefaultConfigResolver(engine),
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
	engine := testutil.UnitTest(t)

	globalOrg := "00000000-0000-0000-0000-000000000004"
	config.SetOrganization(engine.GetConfiguration(), globalOrg)

	folderPath := types.FilePath("/fake/test-folder")

	// Set up workspace with the folder
	// This is required for FolderOrganizationForSubPath to work (used by initializeCreateConfiguration)
	_, _ = workspaceutil.SetupWorkspace(t, engine, folderPath)

	// Verify FolderOrganization() returns the global org (fallback behavior)
	folderOrg := config.FolderOrganization(engine.GetConfiguration(), folderPath, engine.GetLogger())
	assert.Equal(t, globalOrg, folderOrg, "FolderOrganization should fall back to global org when no folder org is configured")

	// Create command
	cmd := &submitIgnoreRequest{
		command: types.CommandData{
			Arguments: []any{"create", "issue1", "wont_fix", "test reason", "2025-12-31"},
		},
		engine: engine,
	}

	// Test initializeCreateConfiguration - when FolderOrganization returns the global org,
	// it sets the org in the config (which is the global org)
	engineConfig, err := cmd.initializeCreateConfiguration(engine.GetConfiguration().Clone(), "finding1", folderPath)
	require.NoError(t, err)
	configOrg := engineConfig.GetString(configuration.ORGANIZATION)
	// When FolderOrganization returns the global org, initializeCreateConfiguration sets it in the config
	assert.Equal(t, globalOrg, configOrg, "Config should use global org when folder org is not configured (fallback behavior)")
}

func Test_submitIgnoreRequest_TriggersTreeRefreshOnSuccess(t *testing.T) {
	workflowTypes := []struct {
		name       string
		args       []any
		workflowID workflow.Identifier
	}{
		{"create", []any{"create", "issueId", "wont_fix", "reason", "2099-01-01"}, ignore_workflow.WORKFLOWID_IGNORE_CREATE},
		{"update", []any{"update", "issueId", "wont_fix", "reason", "2099-01-01", "ignoreId"}, ignore_workflow.WORKFLOWID_IGNORE_EDIT},
		{"delete", []any{"delete", "issueId", "wont_fix", "reason", "2099-01-01", "ignoreId"}, ignore_workflow.WORKFLOWID_IGNORE_DELETE},
	}

	for _, tt := range workflowTypes {
		t.Run(tt.name, func(t *testing.T) {
			engine := testutil.UnitTest(t)
			ctrl := gomock.NewController(t)
			t.Cleanup(ctrl.Finish)

			mockEngine, mockConf := testutil.SetUpEngineMock(t, engine)

			folderPath := types.FilePath(t.TempDir())
			issue := testutil.NewMockIssue("issueId", types.FilePath(filepath.Join(string(folderPath), "test.js")))
			issue.ContentRoot = folderPath
			_, _ = workspaceutil.SetupWorkspace(t, mockEngine, folderPath)
			types.SetPreferredOrgAndOrgSetByUser(mockConf, folderPath, "test-org", true)

			issueProvider := mock_snyk.NewMockIssueProvider(ctrl)
			issueProvider.EXPECT().Issue("issueId").Return(issue).AnyTimes()

			mockEngine.EXPECT().InvokeWithConfig(tt.workflowID, gomock.Any()).
				Return([]workflow.Data{workflow.NewData(workflow.NewTypeIdentifier(tt.workflowID, "test"), "json", []byte(`{"id":"ignoreId"}`))}, nil).
				Times(1)
			mockEngine.EXPECT().InvokeWithInputAndConfig(localworkflows.WORKFLOWID_REPORT_ANALYTICS, gomock.Any(), gomock.Any()).
				Return(nil, nil).AnyTimes()

			server := mock_types.NewMockServer(ctrl)
			server.EXPECT().Callback(gomock.Any(), "window/showDocument", gomock.Any()).Return(nil, nil).AnyTimes()

			knownState := scanstates.StateSnapshot{}
			fake := &fakeTreeRefresher{}

			cmd := &submitIgnoreRequest{
				command:        types.CommandData{Arguments: tt.args},
				issueProvider:  issueProvider,
				notifier:       notification.NewMockNotifier(),
				srv:            server,
				engine:         mockEngine,
				configResolver: testutil.DefaultConfigResolver(mockEngine),
				treeEmitter:    fake,
				scanStateFunc:  func() scanstates.StateSnapshot { return knownState },
			}

			_, err := cmd.Execute(t.Context())
			require.NoError(t, err)
			assert.Equal(t, 1, fake.calls, "tree should be refreshed once after successful ignore")
			assert.Equal(t, knownState, fake.lastState)
		})
	}
}

func Test_submitIgnoreRequest_NoTreeRefreshOnFailure(t *testing.T) {
	engine := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockEngine, mockConf := testutil.SetUpEngineMock(t, engine)

	folderPath := types.FilePath(t.TempDir())
	issue := testutil.NewMockIssue("issueId", types.FilePath(filepath.Join(string(folderPath), "test.js")))
	issue.ContentRoot = folderPath
	_, _ = workspaceutil.SetupWorkspace(t, mockEngine, folderPath)
	types.SetPreferredOrgAndOrgSetByUser(mockConf, folderPath, "test-org", true)

	issueProvider := mock_snyk.NewMockIssueProvider(ctrl)
	issueProvider.EXPECT().Issue("issueId").Return(issue).AnyTimes()

	mockEngine.EXPECT().InvokeWithConfig(ignore_workflow.WORKFLOWID_IGNORE_CREATE, gomock.Any()).
		Return(nil, errors.New("ignore failed")).Times(1)
	mockEngine.EXPECT().InvokeWithInputAndConfig(localworkflows.WORKFLOWID_REPORT_ANALYTICS, gomock.Any(), gomock.Any()).
		Return(nil, nil).AnyTimes()

	fake := &fakeTreeRefresher{}

	cmd := &submitIgnoreRequest{
		command:        types.CommandData{Arguments: []any{"create", "issueId", "wont_fix", "reason", "2099-01-01"}},
		issueProvider:  issueProvider,
		notifier:       notification.NewMockNotifier(),
		engine:         mockEngine,
		configResolver: testutil.DefaultConfigResolver(mockEngine),
		treeEmitter:    fake,
		scanStateFunc:  func() scanstates.StateSnapshot { return scanstates.StateSnapshot{} },
	}

	_, err := cmd.Execute(t.Context())
	assert.Error(t, err)
	assert.Equal(t, 0, fake.calls, "tree must not be refreshed when ignore fails")
}

func Test_submitIgnoreRequest_NilTreeRefresher_DoesNotPanic(t *testing.T) {
	engine := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockEngine, mockConf := testutil.SetUpEngineMock(t, engine)

	folderPath := types.FilePath(t.TempDir())
	issue := testutil.NewMockIssue("issueId", types.FilePath(filepath.Join(string(folderPath), "test.js")))
	issue.ContentRoot = folderPath
	_, _ = workspaceutil.SetupWorkspace(t, mockEngine, folderPath)
	types.SetPreferredOrgAndOrgSetByUser(mockConf, folderPath, "test-org", true)

	issueProvider := mock_snyk.NewMockIssueProvider(ctrl)
	issueProvider.EXPECT().Issue("issueId").Return(issue).AnyTimes()

	mockEngine.EXPECT().InvokeWithConfig(ignore_workflow.WORKFLOWID_IGNORE_CREATE, gomock.Any()).
		Return([]workflow.Data{workflow.NewData(workflow.NewTypeIdentifier(ignore_workflow.WORKFLOWID_IGNORE_CREATE, "test"), "json", []byte(`{"id":"ignoreId"}`))}, nil).
		Times(1)
	mockEngine.EXPECT().InvokeWithInputAndConfig(localworkflows.WORKFLOWID_REPORT_ANALYTICS, gomock.Any(), gomock.Any()).
		Return(nil, nil).AnyTimes()

	server := mock_types.NewMockServer(ctrl)
	server.EXPECT().Callback(gomock.Any(), "window/showDocument", gomock.Any()).Return(nil, nil).AnyTimes()

	cmd := &submitIgnoreRequest{
		command:        types.CommandData{Arguments: []any{"create", "issueId", "wont_fix", "reason", "2099-01-01"}},
		issueProvider:  issueProvider,
		notifier:       notification.NewMockNotifier(),
		srv:            server,
		engine:         mockEngine,
		configResolver: testutil.DefaultConfigResolver(mockEngine),
		// treeEmitter and scanStateFunc intentionally nil
	}

	assert.NotPanics(t, func() {
		_, _ = cmd.Execute(t.Context())
	})
}

func Test_validateIgnoreRequest__notifies_user_when_repo_URL_cannot_be_determined(t *testing.T) {
	engine := testutil.UnitTest(t)

	// Use a non-git temp dir so NewRepositoryTarget cannot determine the repo URL.
	nonGitDir := types.FilePath(t.TempDir())

	mockNotifier := notification.NewMockNotifier()
	cmd := &submitIgnoreRequest{
		engine:   engine,
		notifier: mockNotifier,
	}

	logger := engine.GetLogger().With().Str("method", "test").Logger()
	err := cmd.validateIgnoreRequest(logger, nonGitDir)

	require.Error(t, err, "validateIgnoreRequest should return an error when repo URL cannot be determined")

	messages := mockNotifier.SentMessages()
	require.NotEmpty(t, messages, "expected a user-facing warning to be sent via notifier")

	found := false
	for _, msg := range messages {
		if params, ok := msg.(sglsp.ShowMessageParams); ok {
			if params.Type == sglsp.MTWarning && params.Message == userMsgCannotDetermineRepoURL {
				found = true
				break
			}
		}
	}
	assert.True(t, found, "expected a MTWarning ShowMessage with the stable repo-URL message, got: %v", messages)
}
