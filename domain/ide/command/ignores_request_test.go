package command

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/creachadair/jrpc2"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/ignore_workflow"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// TODO replace engine mock with testutil.SetUpEngineMock(t, c)
type MockEngine struct {
	mock.Mock
	config configuration.Configuration
}

func (m *MockEngine) Init() error {
	//TODO implement me
	panic("implement me")
}

func (m *MockEngine) AddExtensionInitializer(initializer workflow.ExtensionInit) {
	//TODO implement me
	panic("implement me")
}

func (m *MockEngine) Register(id workflow.Identifier, config workflow.ConfigurationOptions, callback workflow.Callback) (workflow.Entry, error) {
	//TODO implement me
	panic("implement me")
}

func (m *MockEngine) GetWorkflows() []workflow.Identifier {
	//TODO implement me
	panic("implement me")
}

func (m *MockEngine) GetWorkflow(id workflow.Identifier) (workflow.Entry, bool) {
	//TODO implement me
	panic("implement me")
}

func (m *MockEngine) InvokeWithInput(id workflow.Identifier, input []workflow.Data) ([]workflow.Data, error) {
	//TODO implement me
	panic("implement me")
}

func (m *MockEngine) InvokeWithInputAndConfig(id workflow.Identifier, input []workflow.Data, config configuration.Configuration) ([]workflow.Data, error) {
	//TODO implement me
	panic("implement me")
}

func (m *MockEngine) GetAnalytics() analytics.Analytics {
	//TODO implement me
	panic("implement me")
}

func (m *MockEngine) GetNetworkAccess() networking.NetworkAccess {
	//TODO implement me
	panic("implement me")
}

func (m *MockEngine) SetLogger(logger *zerolog.Logger) {
	//TODO implement me
	panic("implement me")
}

func (m *MockEngine) SetConfiguration(config configuration.Configuration) {
	//TODO implement me
	panic("implement me")
}

func (m *MockEngine) GetLogger() *zerolog.Logger {
	//TODO implement me
	panic("implement me")
}

func (m *MockEngine) GetUserInterface() ui.UserInterface {
	//TODO implement me
	panic("implement me")
}

func (m *MockEngine) SetUserInterface(ui ui.UserInterface) {
	//TODO implement me
	panic("implement me")
}

func (m *MockEngine) GetRuntimeInfo() runtimeinfo.RuntimeInfo {
	//TODO implement me
	panic("implement me")
}

func (m *MockEngine) SetRuntimeInfo(ri runtimeinfo.RuntimeInfo) {
	//TODO implement me
	panic("implement me")
}

func (m *MockEngine) InvokeWithConfig(workflowID workflow.Identifier, config configuration.Configuration) ([]workflow.Data, error) {
	args := m.Called(workflowID, config)
	if args.Get(0) == nil {
		return []workflow.Data{}, args.Error(1)
	}
	return args.Get(0).([]workflow.Data), args.Error(1)
}

func (m *MockEngine) Invoke(workflowID workflow.Identifier) ([]workflow.Data, error) {
	args := m.Called(workflowID)
	if args.Get(0) == nil {
		return []workflow.Data{}, args.Error(1)
	}
	return args.Get(0).([]workflow.Data), args.Error(1)
}

func (m *MockEngine) GetConfiguration() configuration.Configuration {
	return m.config
}

func NewMockIssue(id string, path types.FilePath) *snyk.Issue {
	return &snyk.Issue{
		ID:               id,
		AffectedFilePath: path,
		Product:          product.ProductCode,
		Severity:         types.Medium,
		AdditionalData: snyk.CodeIssueData{
			Key:                "",
			Title:              "",
			Message:            "",
			Rule:               "",
			RuleId:             "",
			RepoDatasetSize:    0,
			ExampleCommitFixes: nil,
			CWE:                nil,
			Text:               "",
			Markers:            nil,
			Cols:               snyk.CodePoint{},
			Rows:               snyk.CodePoint{},
			IsSecurityType:     false,
			IsAutofixable:      false,
			PriorityScore:      0,
			HasAIFix:           false,
			DataFlow:           nil,
			Details:            "",
		},
	}
}

// TODO except for this MockIssueProvider, there are another two IssueProvider Mocks in the snyk-ls. Refactor to make fewer copies.
// MockIssueProvider is a mock implementation of the snyk.IssueProvider interface for testing.
type MockIssueProvider struct {
	mock.Mock
}

func (m *MockIssueProvider) IssuesForFile(path types.FilePath) []types.Issue {
	//TODO implement me
	panic("implement me")
}

func (m *MockIssueProvider) IssuesForRange(path types.FilePath, r types.Range) []types.Issue {
	//TODO implement me
	panic("implement me")
}

func (m *MockIssueProvider) Issues() snyk.IssuesByFile {
	//TODO implement me
	panic("implement me")
}

func (m *MockIssueProvider) Issue(id string) types.Issue {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(types.Issue)
}

// MockServer is a mock implementation of the types.Server interface for testing.
type MockServer struct {
	mock.Mock
}

func (m *MockServer) Notify(ctx context.Context, method string, params any) error {
	//TODO implement me
	panic("implement me")
}

func (m *MockServer) Callback(ctx context.Context, method string, params any) (*jrpc2.Response, error) {
	args := m.Called(ctx, method, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*jrpc2.Response), args.Error(1)
}

func Test_submitIgnoreRequest_Execute(t *testing.T) {
	tests := []struct {
		name                string
		arguments           []any
		mockIssueProvider   func(provider *MockIssueProvider)
		mockEngineSetup     func(engine *MockEngine)
		mockServerSetup     func(server *MockServer)
		expectedError       error
		expectedIssueCalled bool
	}{
		{
			name:                "Invalid issueId type",
			arguments:           []any{"create", 123},
			mockIssueProvider:   func(provider *MockIssueProvider) {},
			mockEngineSetup:     func(engine *MockEngine) {},
			mockServerSetup:     func(server *MockServer) {},
			expectedError:       errors.New("issueId type should be a string"),
			expectedIssueCalled: false,
		},
		{
			name:      "Issue not found",
			arguments: []any{"create", "issueId"},
			mockIssueProvider: func(provider *MockIssueProvider) {
				provider.On("Issue", "issueId").Return(nil)
			},
			mockEngineSetup:     func(engine *MockEngine) {},
			mockServerSetup:     func(server *MockServer) {},
			expectedError:       errors.New("issue not found"),
			expectedIssueCalled: true,
		},
		{
			name:      "Invalid workflow type argument",
			arguments: []any{123, "issueId"},
			mockIssueProvider: func(provider *MockIssueProvider) {
			},
			mockEngineSetup:     func(engine *MockEngine) {},
			mockServerSetup:     func(server *MockServer) {},
			expectedError:       errors.New("workflow type should be a string"),
			expectedIssueCalled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := testutil.UnitTest(t)
			mockEngine := &MockEngine{}
			mockIssueProvider := &MockIssueProvider{}
			if tt.mockIssueProvider != nil {
				tt.mockIssueProvider(mockIssueProvider)
			}

			if tt.mockEngineSetup != nil {
				tt.mockEngineSetup(mockEngine)
			}

			mockServer := &MockServer{}
			if tt.mockServerSetup != nil {
				tt.mockServerSetup(mockServer)
			}

			cmd := &submitIgnoreRequest{
				command:       types.CommandData{Arguments: tt.arguments},
				issueProvider: mockIssueProvider,
				srv:           mockServer,
				c:             c,
			}

			_, err := cmd.Execute(context.Background())

			if tt.expectedError != nil {
				assert.EqualError(t, err, tt.expectedError.Error())
			} else {
				assert.NoError(t, err)
			}
			mockIssueProvider.AssertExpectations(t)
			mockEngine.AssertExpectations(t)
			mockServer.AssertExpectations(t)
		})
	}
}

func Test_submitIgnoreRequest_createIgnoreRequest(t *testing.T) {
	tests := []struct {
		name                  string
		arguments             []any
		mockEngineSetup       func(engine *MockEngine)
		mockCreateConfigSetup func(cmd *submitIgnoreRequest)
		expectedError         error
	}{
		{
			name:      "Successful creation",
			arguments: []any{"create", "issueId", "wont_fix", "reason", "expiration"},
			mockEngineSetup: func(engine *MockEngine) {
				engine.config = configuration.New()
				jsonData := `{"guid": "test-guid", "justification": "test-justification", "status": "accepted", "properties": {"category": "test-category", "expiration": "2024-08-06T13:16:53Z", "ignoredOn": "2024-02-23T16:08:25Z", "ignoredBy": {"name": "test-name"}}}`
				engine.On("InvokeWithConfig", ignore_workflow.WORKFLOWID_IGNORE_CREATE, mock.Anything).Return([]workflow.Data{workflow.NewData(
					workflow.NewTypeIdentifier(ignore_workflow.WORKFLOWID_IGNORE_CREATE, "dummy-data-1"),
					"application/json",
					[]byte(jsonData),
				)}, nil)
			},
			mockCreateConfigSetup: func(cmd *submitIgnoreRequest) {
				// No specific setup needed for successful case
				c := testutil.UnitTest(t)
				cmd.c = c
			},
			expectedError: nil,
		},
		{
			name:      "createTheCreateConfiguration fails",
			arguments: []any{"create", "issueId", "wont_fix", "reason", "expiration"},
			mockEngineSetup: func(engine *MockEngine) {
				engine.config = configuration.New()
			},
			mockCreateConfigSetup: func(cmd *submitIgnoreRequest) {
				cmd.command.Arguments = []any{"create", "issueId", 123, "reason", "expiration"}
			},
			expectedError: errors.New("ignoreType should be a string"),
		},
		{
			name:      "executeIgnoreWorkflow fails",
			arguments: []any{"create", "issueId", "wont_fix", "reason", "expiration"},
			mockEngineSetup: func(engine *MockEngine) {
				engine.config = configuration.New()
				engine.On("InvokeWithConfig", ignore_workflow.WORKFLOWID_IGNORE_CREATE, mock.Anything).Return(nil, errors.New("some error"))
			},
			mockCreateConfigSetup: func(cmd *submitIgnoreRequest) {
				// No specific setup needed for successful case
			},
			expectedError: errors.New("some error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockEngine := &MockEngine{} // Define mockEngine here
			if tt.mockEngineSetup != nil {
				tt.mockEngineSetup(mockEngine)
			}

			cmd := &submitIgnoreRequest{
				command: types.CommandData{
					Arguments: tt.arguments,
				},
			}
			if tt.mockCreateConfigSetup != nil {
				tt.mockCreateConfigSetup(cmd)
			}

			filePath := types.FilePath("/test/content/root")
			issue := NewMockIssue("id1", filePath)
			err := cmd.createIgnoreRequest(mockEngine, "finding123", types.FilePath("/test/content/root"), issue)

			if tt.expectedError != nil {
				assert.EqualError(t, err, tt.expectedError.Error())
			} else {
				assert.NoError(t, err)
			}
			mockEngine.AssertExpectations(t)
		})
	}
}

func Test_submitIgnoreRequest_createTheCreateConfiguration(t *testing.T) {
	tests := []struct {
		name           string
		arguments      []any
		expectedConfig map[string]interface{}
		expectedError  error
	}{
		{
			name:      "Successful creation",
			arguments: []any{"create", "issueId", "wont_fix", "reason", "expiration"},
			expectedConfig: map[string]interface{}{
				ignore_workflow.FindingsIdKey:     "finding123",
				ignore_workflow.EnrichResponseKey: true,
				ignore_workflow.InteractiveKey:    false,
				configuration.INPUT_DIRECTORY:     types.FilePath("/test/content/root"),
				ignore_workflow.IgnoreTypeKey:     "wont_fix",
				ignore_workflow.ReasonKey:         "reason",
				ignore_workflow.ExpirationKey:     "expiration",
			},
			expectedError: nil,
		},
		{
			name:           "insufficient arguments",
			arguments:      []any{"create", "issueId", "wont_fix", "reason"},
			expectedConfig: nil,
			expectedError:  errors.New("insufficient arguments for ignore-create workflow"),
		},
		{
			name:           "GetCommandArgs fails",
			arguments:      []any{"create", "issueId", 123, "reason", "expiration"},
			expectedConfig: nil,
			expectedError:  errors.New("ignoreType should be a string"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &submitIgnoreRequest{
				command: types.CommandData{
					Arguments: tt.arguments,
				},
			}

			gafConfig := configuration.New()
			config, err := cmd.createTheCreateConfiguration(gafConfig, "finding123", types.FilePath("/test/content/root"))

			if tt.expectedError != nil {
				assert.EqualError(t, err, tt.expectedError.Error())
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, config)
				for key, expectedValue := range tt.expectedConfig {
					assert.Equal(t, expectedValue, config.Get(key))
				}
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
	findingId := "testFindingId"
	contentRoot := types.FilePath("/test/content/root")
	gafConfig := configuration.New()

	// Act
	result := createBaseConfiguration(gafConfig, findingId, contentRoot)

	// Assert
	assert.Equal(t, findingId, result.Get(ignore_workflow.FindingsIdKey))
	assert.Equal(t, true, result.Get(ignore_workflow.EnrichResponseKey))
	assert.Equal(t, false, result.Get(ignore_workflow.InteractiveKey))
	assert.Equal(t, contentRoot, result.Get(configuration.INPUT_DIRECTORY))
}

func Test_addUpdateConfiguration(t *testing.T) {
	// Arrange
	ignoreType := "testIgnoreType"
	reason := "testReason"
	expiration := "testExpiration"
	gafConfig := configuration.New()

	// Act
	result := addUpdateConfiguration(gafConfig, ignoreType, reason, expiration)

	// Assert
	assert.Equal(t, ignoreType, result.Get(ignore_workflow.IgnoreTypeKey))
	assert.Equal(t, reason, result.Get(ignore_workflow.ReasonKey))
	assert.Equal(t, expiration, result.Get(ignore_workflow.ExpirationKey))
}
