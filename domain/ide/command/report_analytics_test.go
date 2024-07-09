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
	"testing"

	"github.com/golang/mock/gomock"

	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/snyk-ls/internal/types"

	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_ReportAnalyticsCommand_IsCallingExtension(t *testing.T) {
	c := testutil.UnitTest(t)

	testInput := "some data"
	cmd := &reportAnalyticsCommand{
		command: types.CommandData{
			CommandId: types.ReportAnalyticsCommand,
			Arguments: []any{testInput},
		},
	}

	mockEngine, engineConfig := setUpEngineMock(t, c)
	mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
	mockEngine.EXPECT().InvokeWithInputAndConfig(localworkflows.WORKFLOWID_REPORT_ANALYTICS,
		gomock.Any(), gomock.Any()).Return(nil, nil)

	output, err := cmd.Execute(context.Background())
	require.NoError(t, err)
	require.Emptyf(t, output, "output should be empty")
}
