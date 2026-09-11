/*
 * © 2026 Snyk Limited
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
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// Test_MockAndCaptureWorkflowInvocation_LateSendAfterCleanup_DoesNotPanic reproduces
// the production race deterministically: an async goroutine (e.g. domain/ide/workspace's
// `go sendAnalytics(...)`) may reach the mocked Do() callback and try to send on the
// capture channel after the test that created it has already returned and run its
// t.Cleanup. Go runs t.Cleanup in LIFO order, and t.Run blocks until the subtest's own
// cleanups have executed, so by the time the outer test calls lateInvoke, the subtest's
// cleanup (which used to close the channel) has already run.
func Test_MockAndCaptureWorkflowInvocation_LateSendAfterCleanup_DoesNotPanic(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockEngine := mocks.NewMockEngine(ctrl)

	workflowID := workflow.NewWorkflowIdentifier("test-late-send-workflow")
	engineConfig := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	var lateInvoke func()

	t.Run("subtest", func(t *testing.T) {
		_ = MockAndCaptureWorkflowInvocation(t, mockEngine, workflowID, 1)
		// Deliberately do NOT invoke the mocked call inside the subtest.
		// By the time t.Run below returns, this subtest's own t.Cleanup
		// (which closes the channel) has already run — so calling the
		// mocked method now simulates the real production race: an async
		// goroutine (e.g. domain/ide/workspace's `go sendAnalytics(...)`)
		// reaching the Do() callback after the test's cleanup already
		// closed the capture channel.
		lateInvoke = func() {
			_, _ = mockEngine.InvokeWithInputAndConfig(workflowID, []workflow.Data{}, engineConfig)
		}
	})

	require.NotPanics(t, lateInvoke, "a late analytics send arriving after MockAndCaptureWorkflowInvocation's cleanup must not panic the whole test process")
}
