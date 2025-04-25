package command

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/ignore_workflow"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func newMockIssue(id string, path types.FilePath) *snyk.Issue {
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

func Test_submitIgnoreRequest_Execute(t *testing.T) {
	tests := []struct {
		name                string
		arguments           []any
		mockIssueProvider   func(provider *snyk.IssueProviderMock)
		expectedError       error
		expectedIssueCalled bool
	}{
		{
			name:                "Invalid issueId type",
			arguments:           []any{"create", 123},
			mockIssueProvider:   func(provider *snyk.IssueProviderMock) {},
			expectedError:       errors.New("issueId type should be a string"),
			expectedIssueCalled: false,
		},
		{
			name:      "Issue not found",
			arguments: []any{"create", "issueId"},
			mockIssueProvider: func(provider *snyk.IssueProviderMock) {
				provider.On("Issue", "issueId").Return(nil)
			},
			expectedError:       errors.New("issue not found"),
			expectedIssueCalled: true,
		},
		{
			name:      "Invalid workflow type argument",
			arguments: []any{123, "issueId"},
			mockIssueProvider: func(provider *snyk.IssueProviderMock) {
			},
			expectedError:       errors.New("workflow type should be a string"),
			expectedIssueCalled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := testutil.UnitTest(t)
			server := &types.ServerImplMock{}
			issueProvider := &snyk.IssueProviderMock{}

			cmd := &submitIgnoreRequest{
				command:       types.CommandData{Arguments: tt.arguments},
				issueProvider: issueProvider,
				srv:           server,
				c:             c,
			}

			_, err := cmd.Execute(context.Background())

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
				configuration.INPUT_DIRECTORY:     "/test/content/root",
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
			config, err := cmd.initializeCreateConfiguration(gafConfig, "finding123", types.FilePath("/test/content/root"))

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
	contentRoot := types.FilePath("/test/content/root")
	gafConfig := configuration.New()

	// Act
	result := initializeBaseConfiguration(gafConfig, contentRoot)

	// Assert
	assert.Equal(t, true, result.Get(ignore_workflow.EnrichResponseKey))
	assert.Equal(t, false, result.Get(ignore_workflow.InteractiveKey))
	assert.Equal(t, string(contentRoot), result.Get(configuration.INPUT_DIRECTORY))
}

func Test_addCreateAndUpdateConfiguration(t *testing.T) {
	// Arrange
	ignoreType := "testIgnoreType"
	reason := "testReason"
	expiration := "testExpiration"
	gafConfig := configuration.New()

	// Act
	result := addCreateAndUpdateConfiguration(gafConfig, ignoreType, reason, expiration)

	// Assert
	assert.Equal(t, ignoreType, result.Get(ignore_workflow.IgnoreTypeKey))
	assert.Equal(t, reason, result.Get(ignore_workflow.ReasonKey))
	assert.Equal(t, expiration, result.Get(ignore_workflow.ExpirationKey))
}
