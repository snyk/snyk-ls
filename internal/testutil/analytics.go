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
	"sync/atomic"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"

	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// DisableOutboundAnalyticsForTest re-registers GAF's
// WORKFLOWID_REPORT_ANALYTICS with a no-op callback so authenticate() does
// not leak real HTTPS POSTs to api.snyk.io (or attacker-controlled hosts
// such as api.malicious.io reachable via the persisted token's aud claim).
//
// GAF's report-analytics workflow ignores configuration.ANALYTICS_DISABLED
// and unconditionally calls invocationCtx.GetNetworkAccess().GetHttpClient()
// to POST analytics events. snyk-ls's NetworkAccess does not expose a
// transport setter, so the cleanest interception point is the workflow
// registry itself: workflow.Engine.Register overwrites the entry for an
// existing identifier, leaving the original analytics workflow inert for
// the lifetime of the engine returned by UnitTestWithEngine.
//
// The returned counter records how many times the analytics workflow was
// invoked during the test, which lets callers assert both that the spy was
// actually wired up and that the production codepath under test reached
// the analytics workflow at all.
func DisableOutboundAnalyticsForTest(t *testing.T, engine workflow.Engine) *atomic.Int32 {
	t.Helper()
	var calls atomic.Int32
	flagset := workflow.ConfigurationOptionsFromFlagset(pflag.NewFlagSet("noop-analytics", pflag.ContinueOnError))
	_, err := engine.Register(
		localworkflows.WORKFLOWID_REPORT_ANALYTICS,
		flagset,
		func(_ workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
			calls.Add(1)
			return nil, nil
		},
	)
	require.NoError(t, err)
	return &calls
}
