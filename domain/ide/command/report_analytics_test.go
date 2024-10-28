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
	"context"
	"encoding/json"
	"testing"

	"github.com/golang/mock/gomock"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/mock"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/types"

	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_ReportAnalyticsCommand_IsCallingExtension(t *testing.T) {
	c := testutil.UnitTest(t)

	testInput := "some data"
	cmd := setupReportAnalyticsCommand(t, c, testInput)

	mockEngine, engineConfig := setUpEngineMock(t, c)
	mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
	mockEngine.EXPECT().InvokeWithInputAndConfig(localworkflows.WORKFLOWID_REPORT_ANALYTICS,
		gomock.Any(), gomock.Any()).Return(nil, nil)

	output, err := cmd.Execute(context.Background())
	require.NoError(t, err)
	require.Emptyf(t, output, "output should be empty")
}

func Test_ReportAnalyticsCommand_PlugInstalledEvent(t *testing.T) {
	c := testutil.UnitTest(t)

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

	mockEngine, engineConfig := setUpEngineMock(t, c)
	mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()

	mockEngine.EXPECT().InvokeWithInputAndConfig(
		localworkflows.WORKFLOWID_REPORT_ANALYTICS,
		mock.MatchedBy(func(i interface{}) bool {
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
	).Return(nil, nil)

	output, err := cmd.Execute(context.Background())
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
