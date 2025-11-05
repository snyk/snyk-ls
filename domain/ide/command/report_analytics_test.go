/*
 * © 2023 Snyk Limited
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
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/command/testutils"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_ReportAnalyticsCommand_IsCallingExtension(t *testing.T) {
	t.Run("sends analytics to first folder org", func(t *testing.T) {
		c := testutil.UnitTest(t)

		// Setup workspace with 2 folders
		_, folderPaths := testutils.SetupFakeWorkspace(t, c, 2)

		testInput := "some data"
		cmd := setupReportAnalyticsCommand(t, c, testInput)

		mockEngine, engineConfig := testutil.SetUpEngineMock(t, c)
		mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()

		// Configure first folder with a specific org
		firstFolderOrg := "test-first-folder-org"
		err := storedconfig.UpdateFolderConfig(engineConfig, &types.FolderConfig{
			FolderPath:                  folderPaths[0],
			PreferredOrg:                firstFolderOrg,
			OrgMigratedFromGlobalConfig: true,
			OrgSetByUser:                true,
		}, c.Logger())
		require.NoError(t, err)

		// Capture workflow invocations to verify first folder's org is used
		// We expect 2 calls: 1 for authentication analytics, and 1 for the payload itself
		capturedCh := testutil.MockAndCaptureWorkflowInvocation(t, mockEngine, localworkflows.WORKFLOWID_REPORT_ANALYTICS, 2)
		mockEngine.EXPECT().GetLogger().Return(c.Logger()).AnyTimes()

		output, err := cmd.Execute(t.Context())
		require.NoError(t, err)
		require.Emptyf(t, output, "output should be empty")

		// Verify both analytics calls used first folder's org
		for i := range 2 {
			captured := testsupport.RequireEventuallyReceive(t, capturedCh, time.Second, 10*time.Millisecond, "analytics should have been sent ("+strconv.Itoa(i+1)+"th time)")
			actualOrg := captured.Config.Get(configuration.ORGANIZATION)
			require.Equal(t, firstFolderOrg, actualOrg, "analytics should be sent to first folder's org")
		}
	})

	t.Run("sends analytics to user preferred org when no folders", func(t *testing.T) {
		c := testutil.UnitTest(t)

		// Setup workspace with no folders
		testutils.SetupFakeWorkspace(t, c, 0)

		testInput := "some data"
		cmd := setupReportAnalyticsCommand(t, c, testInput)

		mockEngine, engineConfig := testutil.SetUpEngineMock(t, c)
		mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()

		// Capture workflow invocations to verify empty org (which means user's preferred org from web UI)
		// We expect 2 calls: 1 for authentication analytics, and 1 for the payload itself
		capturedCh := testutil.MockAndCaptureWorkflowInvocation(t, mockEngine, localworkflows.WORKFLOWID_REPORT_ANALYTICS, 2)
		mockEngine.EXPECT().GetLogger().Return(c.Logger()).AnyTimes()

		output, err := cmd.Execute(t.Context())
		require.NoError(t, err)
		require.Emptyf(t, output, "output should be empty")

		// Verify both analytics calls used empty org (which GAF will resolve to the user's preferred org from the web UI)
		for i := range 2 {
			captured := testsupport.RequireEventuallyReceive(t, capturedCh, time.Second, 10*time.Millisecond, "analytics should have been sent ("+strconv.Itoa(i+1)+"th time)")
			actualOrg := captured.Config.Get(configuration.ORGANIZATION)
			require.Equal(t, "", actualOrg, "analytics should be sent with empty org (GAF will resolve to user's preferred org from the web UI)")
		}
	})
}

func Test_ReportAnalyticsCommand_PlugInstalledEvent(t *testing.T) {
	c := testutil.UnitTest(t)

	// Setup workspace with 2 folders
	testutils.SetupFakeWorkspace(t, c, 2)

	testInput := types.AnalyticsEventParam{
		InteractionType: "plugin installed",
		Category:        []string{"install"},
		Status:          "success",
		TargetId:        "pkg:file/none",
		TimestampMs:     123,
		Extension:       map[string]any{"device_id": c.DeviceID()},
	}

	marshal, err := json.Marshal(testInput)
	if err != nil {
		return
	}

	cmd := setupReportAnalyticsCommand(t, c, string(marshal))

	mockEngine, engineConfig := testutil.SetUpEngineMock(t, c)
	mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
	mockEngine.EXPECT().GetLogger().Return(c.Logger()).AnyTimes()

	// Expect authentication analytics (1 time, to first folder's org only)
	mockEngine.EXPECT().InvokeWithInputAndConfig(
		localworkflows.WORKFLOWID_REPORT_ANALYTICS,
		mock.MatchedBy(func(i any) bool {
			inputData, ok := i.([]workflow.Data)
			require.Truef(t, ok, "input should be workflow data")
			require.Lenf(t, inputData, 1, "should only have one input")
			payload := string(inputData[0].GetPayload().([]byte))

			require.Contains(t, payload, "authenticated")
			return true
		}),
		gomock.Any()).Times(1)

	// Expect plugin installed analytics (1 time, to first folder's org only)
	mockEngine.EXPECT().InvokeWithInputAndConfig(
		localworkflows.WORKFLOWID_REPORT_ANALYTICS,
		mock.MatchedBy(func(i any) bool {
			inputData, ok := i.([]workflow.Data)
			require.Truef(t, ok, "input should be workflow data")
			require.Lenf(t, inputData, 1, "should only have one input")

			payload := string(inputData[0].GetPayload().([]byte))

			require.Contains(t, payload, "plugin installed")
			require.Contains(t, payload, "install")
			require.Contains(t, payload, "device_id")
			require.Contains(t, payload, "123")

			return true
		}),
		gomock.Any(),
	).Times(1).Return(nil, nil)

	output, err := cmd.Execute(t.Context())
	require.NoError(t, err)
	require.Emptyf(t, output, "output should be empty")
}

func setupReportAnalyticsCommand(t *testing.T, c *config.Config, testInput string) *reportAnalyticsCommand {
	t.Helper()
	provider := authentication.NewFakeCliAuthenticationProvider(c)
	provider.IsAuthenticated = true

	cmd := &reportAnalyticsCommand{
		command: types.CommandData{
			CommandId: types.ReportAnalyticsCommand,
			Arguments: []any{testInput},
		},
		authenticationService: authentication.NewAuthenticationService(
			c,
			provider,
			error_reporting.NewTestErrorReporter(),
			notification.NewMockNotifier(),
		)}
	return cmd
}
