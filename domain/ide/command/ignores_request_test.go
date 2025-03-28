//package command
//
//import (
//	"context"
//	"errors"
//	"testing"
//	"time"
//
//	"github.com/golang/mock/gomock"
//	"github.com/google/uuid"
//	"github.com/snyk/go-application-framework/pkg/local_workflows/ignore_workflow"
//	"github.com/snyk/snyk-ls/domain/snyk"
//	"github.com/snyk/snyk-ls/internal/product"
//	"github.com/snyk/snyk-ls/internal/testutil"
//	"github.com/snyk/snyk-ls/internal/util"
//	"github.com/stretchr/testify/assert"
//
//	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
//	"github.com/snyk/snyk-ls/internal/types"
//)
//
//func Test_submitIgnoreRequest_Execute(t *testing.T) {
//	ctrl := gomock.NewController(t)
//	defer ctrl.Finish()
//
//	c := testutil.UnitTest(t)
//	mockEngine, _ := testutil.SetUpEngineMock(t, c)
//	c.SetEngine(mockEngine)
//
//	mockIssueProvider := mockIssueProvider{}
//	const filePath = "path1"
//	mockIssue := NewMockIssue("id1", filePath)
//
//	type testCase struct {
//		name           string
//		workflowType   string
//		arguments      []any
//		expectedError  error
//		setupMocks     func()
//		expectedStatus string
//	}
//
//	testCases := []testCase{
//		{
//			name:          "invalid workflow type",
//			workflowType:  "invalid",
//			arguments:     []any{"invalid"},
//			expectedError: errors.New("unkown worflow"),
//			setupMocks:    func() {},
//		},
//		{
//			name:          "invalid argument type",
//			workflowType:  "create",
//			arguments:     []any{123},
//			expectedError: errors.New("workflow type should be a string"),
//			setupMocks:    func() {},
//		},
//		{
//			name:          "insufficient arguments for create",
//			workflowType:  "create",
//			arguments:     []any{"create", "issueId"},
//			expectedError: errors.New("insufficient arguments for ignore-create workflow"),
//			setupMocks:    func() {},
//		},
//		{
//			name:         "create success",
//			workflowType: "create",
//			arguments: []any{
//				"create",
//				"issueId",
//				"wont_fix",
//				"reason",
//				time.Now().Add(time.Hour).Format(time.RFC3339),
//				"repoUrl",
//				"branchName",
//			},
//			expectedError:  nil,
//			expectedStatus: "accepted",
//			setupMocks: func() {
//				mockIssueProvider.EXPECT().Issue("issueId").Return(mockIssue)
//				mockIssue.EXPECT().GetFindingsId().Return("findingsId")
//				mockEngine.EXPECT().InvokeWithConfig(ignore_workflow.WORKFLOWID_IGNORE_CREATE, gomock.Any()).Return([]localworkflows.WorkflowResult{
//					{
//						Payload: localworkflows.IgnoresResponse{
//							PolicyData: localworkflows.PolicyData{
//								SuppressionStatus: "accepted",
//							},
//						},
//					},
//				}, nil)
//				mockIssue.EXPECT().SetSuppressionStatus("accepted")
//			},
//		},
//		{
//			name:          "create workflow fails",
//			workflowType:  "create",
//			arguments:     []any{"create", "issueId", "wont_fix", "reason", time.Now().Add(time.Hour).Format(time.RFC3339), "repoUrl", "branchName"},
//			expectedError: errors.New("failed to invoke ignore-create workflow: some error"),
//			setupMocks: func() {
//				mockIssueProvider.EXPECT().Issue("issueId").Return(mockIssue)
//				mockIssue.EXPECT().GetFindingsId().Return("findingsId")
//				mockEngine.EXPECT().InvokeWithConfig(ignore_workflow.WORKFLOWID_IGNORE_CREATE, gomock.Any()).Return([]localworkflows.WorkflowResult{}, errors.New("some error"))
//			},
//		},
//		{
//			name:          "insufficient arguments for update",
//			workflowType:  "update",
//			arguments:     []any{"update", "issueId"},
//			expectedError: errors.New("insufficient arguments for ignore-edit workflow"),
//			setupMocks:    func() {},
//		},
//		{
//			name:         "update success",
//			workflowType: "update",
//			arguments: []any{
//				"update",
//				"issueId",
//				"wont_fix",
//				"reason",
//				time.Now().Add(time.Hour).Format(time.RFC3339),
//				"repoUrl",
//				"branchName",
//				"policyId",
//			},
//			expectedError:  nil,
//			expectedStatus: "rejected",
//			setupMocks: func() {
//				mockIssueProvider.EXPECT().Issue("issueId").Return(mockIssue)
//				mockIssue.EXPECT().GetFindingsId().Return("findingsId")
//				mockEngine.EXPECT().InvokeWithConfig(ignore_workflow.WORKFLOWID_IGNORE_EDIT, gomock.Any()).Return([]localworkflows.WorkflowResult{
//					{
//						Payload: localworkflows.IgnoresResponse{
//							PolicyData: localworkflows.PolicyData{
//								SuppressionStatus: "rejected",
//							},
//						},
//					},
//				}, nil)
//				mockIssue.EXPECT().SetSuppressionStatus("rejected")
//			},
//		},
//		{
//			name:          "update workflow fails",
//			workflowType:  "update",
//			arguments:     []any{"update", "issueId", "wont_fix", "reason", time.Now().Add(time.Hour).Format(time.RFC3339), "repoUrl", "branchName", "policyId"},
//			expectedError: errors.New("failed to invoke ignore-create workflow: some error"),
//			setupMocks: func() {
//				mockIssueProvider.EXPECT().Issue("issueId").Return(mockIssue)
//				mockIssue.EXPECT().GetFindingsId().Return("findingsId")
//				mockEngine.EXPECT().InvokeWithConfig(ignore_workflow.WORKFLOWID_IGNORE_EDIT, gomock.Any()).Return([]localworkflows.WorkflowResult{}, errors.New("some error"))
//			},
//		},
//		{
//			name:          "insufficient arguments for delete",
//			workflowType:  "delete",
//			arguments:     []any{"delete"},
//			expectedError: errors.New("insufficient arguments for ignore-delete workflow"),
//			setupMocks:    func() {},
//		},
//		{
//			name:         "delete success",
//			workflowType: "delete",
//			arguments: []any{
//				"delete",
//				"issueId",
//				"policyId",
//			},
//			expectedError:  nil,
//			expectedStatus: "underReview",
//			setupMocks: func() {
//				mockIssueProvider.EXPECT().Issue("issueId").Return(mockIssue)
//				mockIssue.EXPECT().GetFindingsId().Return("findingsId")
//				mockEngine.EXPECT().InvokeWithConfig(ignore_workflow.WORKFLOWID_IGNORE_DELETE, gomock.Any()).Return([]localworkflows.WorkflowResult{
//					{
//						Payload: localworkflows.IgnoresResponse{
//							PolicyData: localworkflows.PolicyData{
//								SuppressionStatus: "underReview",
//							},
//						},
//					},
//				}, nil)
//				mockIssue.EXPECT().SetSuppressionStatus("underReview")
//			},
//		},
//		{
//			name:          "delete workflow fails",
//			workflowType:  "delete",
//			arguments:     []any{"delete", "issueId", "policyId"},
//			expectedError: errors.New("failed to invoke ignore-create workflow: some error"),
//			setupMocks: func() {
//				mockIssueProvider.EXPECT().Issue("issueId").Return(mockIssue)
//				mockIssue.EXPECT().GetFindingsId().Return("findingsId")
//				mockEngine.EXPECT().InvokeWithConfig(ignore_workflow.WORKFLOWID_IGNORE_DELETE, gomock.Any()).Return([]localworkflows.WorkflowResult{}, errors.New("some error"))
//			},
//		},
//	}
//
//	for _, tc := range testCases {
//		t.Run(tc.name, func(t *testing.T) {
//			tc.setupMocks()
//
//			cmd := &submitIgnoreRequest{
//				command: types.CommandData{
//					Arguments: tc.arguments,
//				},
//				issueProvider: mockIssueProvider,
//				c:             conf,
//			}
//
//			_, err := cmd.Execute(context.Background())
//
//			if tc.expectedError != nil {
//				assert.EqualError(t, err, tc.expectedError.Error())
//			} else {
//				assert.NoError(t, err)
//			}
//		})
//	}
//}
//
//func NewMockIssue(id string, path types.FilePath) *snyk.Issue {
//	return &snyk.Issue{
//		ID:               id,
//		AffectedFilePath: path,
//		Product:          product.ProductOpenSource,
//		Severity:         types.Medium,
//		AdditionalData:   snyk.OssIssueData{Key: util.Result(uuid.NewUUID()).String()},
//	}
//}

package command

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_IgnoreRequestCommand_IsCallingExtension(t *testing.T) {
	c := testutil.UnitTest(t)

	testInput := "some data"
	cmd := setupIgnoreRequestCommand(t, c, testInput)

	mockEngine, engineConfig := testutil.SetUpEngineMock(t, c)
	mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
	mockEngine.EXPECT().InvokeWithInputAndConfig(localworkflows.WORKFLOWID_REPORT_ANALYTICS,
		gomock.Any(), gomock.Any()).Return(nil, nil)

	output, err := cmd.Execute(context.Background())
	require.NoError(t, err)
	require.Emptyf(t, output, "output should be empty")
}

func setupIgnoreRequestCommand(t *testing.T, c *config.Config, testInput string) *reportAnalyticsCommand {
	t.Helper()

	cmd := &submitIgnoreRequest{
		command: types.CommandData{
			CommandId: types.SubmitIgnoreRequest,
			Arguments: []any{testInput},
		},
		issueProvider: snyk.NewMockIssueProvider(),
		notifier:      notification.NewMockNotifier(),
		srv:           types.NewMockServer(),
		c:             c,
	}

	return cmd
}

func Test_submitIgnoreRequest_Execute(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	c := testutil.UnitTest(t)
	mockEngine, _ := testutil.SetUpEngineMock(t, c)
	c.SetEngine(mockEngine)

	mockIssueProvider := mock_snyk.NewMockIssueProvider(ctrl)
	mockIssue := mock_snyk.NewMockIssue(ctrl)
	mockNotifier := notification.NewMockNotifier()
	mockServer := types.NewMockServer(ctrl)
	conf := config.New()
	conf.SetEngine(mockEngine)

	type testCase struct {
		name          string
		arguments     []any
		expectedError error
		setupMocks    func()
	}

	testCases := []testCase{
		{
			name:          "invalid workflow type",
			arguments:     []any{123, "issueId"},
			expectedError: errors.New("workflow type should be a string"),
			setupMocks:    func() {},
		},
		{
			name:          "invalid issueId type",
			arguments:     []any{"create", 123},
			expectedError: errors.New("issueId type should be a string"),
			setupMocks:    func() {},
		},
		{
			name:          "issue not found",
			arguments:     []any{"create", "issueId"},
			expectedError: errors.New("issue not found"),
			setupMocks: func() {
				mockIssueProvider.EXPECT().Issue("issueId").Return(nil)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setupMocks()

			cmd := &submitIgnoreRequest{
				command: types.CommandData{
					Arguments: tc.arguments,
				},
				issueProvider: mockIssueProvider,
				notifier:      mockNotifier,
				srv:           mockServer,
				c:             conf,
			}

			_, err := cmd.Execute(context.Background())

			if tc.expectedError != nil {
				assert.EqualError(t, err, tc.expectedError.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
