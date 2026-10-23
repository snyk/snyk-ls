/*
 * © 2026 Snyk Limited All rights reserved.
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

package testutil

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/internal/types"
)

// A unit test that reaches the real API passes or fails according to the
// credentials the host or its proxy happens to supply. Both keys matter:
// production code compares them to decide whether authentication redirected
// the user elsewhere, so leaving either at the real endpoint reopens the hole.
func Test_UnitTest_DoesNotPointAtTheRealAPI(t *testing.T) {
	conf := UnitTest(t).GetConfiguration()

	assert.NotEqual(t, types.DefaultSnykApiUrl, conf.GetString(configuration.API_URL))
	assert.NotEqual(t, types.DefaultSnykApiUrl, types.GetGlobalString(conf, types.SettingApiEndpoint))
}

func Test_MockAndCaptureWorkflowInvocation_LateSendAfterCleanup_DoesNotPanic(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockEngine := mocks.NewMockEngine(ctrl)

	workflowID := workflow.NewWorkflowIdentifier("test-late-send-workflow")
	engineConfig := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	var lateInvoke func()

	t.Run("subtest", func(t *testing.T) {
		_ = MockAndCaptureWorkflowInvocation(t, mockEngine, workflowID, 1)
		lateInvoke = func() {
			_, _ = mockEngine.InvokeWithInputAndConfig(workflowID, []workflow.Data{}, engineConfig)
		}
	})

	require.NotPanics(t, lateInvoke, "a late analytics send arriving after MockAndCaptureWorkflowInvocation's cleanup must not panic the whole test process")
}
