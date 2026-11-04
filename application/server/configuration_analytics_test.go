/*
 * © 2025 Snyk Limited
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

package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"

	"github.com/snyk/snyk-ls/infrastructure/analytics"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_sendFolderConfigAnalytics_AdditionalParametersContainOnlyFlagKeys(t *testing.T) {
	engine := testutil.UnitTest(t)
	mockEngine, engineConfig := testutil.SetUpEngineMock(t, engine)
	capturedCh := testutil.MockAndCaptureWorkflowInvocation(t, mockEngine, localworkflows.WORKFLOWID_REPORT_ANALYTICS, 1)

	oldSnapshot := types.FolderConfigSnapshot{AdditionalParameters: []string{"--all-projects"}}
	newSnapshot := types.FolderConfigSnapshot{
		AdditionalParameters: []string{"--all-projects", "--org=secret-org-id", "--project-name", "secret-project", "--file=/Users/jane/pom.xml"},
	}

	sendFolderConfigAnalytics(engineConfig, mockEngine, mockEngine.GetLogger(), "", analytics.TriggerSourceTest, oldSnapshot, newSnapshot, testutil.DefaultConfigResolver(mockEngine))

	captured := testsupport.RequireEventuallyReceive(t, capturedCh, time.Second, 10*time.Millisecond, "analytics should have been sent")
	require.NotEmpty(t, captured.Input)
	payload := string(captured.Input[0].GetPayload().([]byte))

	assert.Contains(t, payload, `[\"--all-projects\",\"--org\",\"--project-name\",\"--file\"]`)
	for _, secret := range []string{"secret-org-id", "secret-project", "/Users/jane", "pom.xml"} {
		assert.NotContains(t, payload, secret)
	}
}

func Test_sendFolderConfigAnalytics_AdditionalParametersEventSending(t *testing.T) {
	tests := []struct {
		name      string
		oldParams []string
		newParams []string
		expectSet bool
	}{
		{"flag added", []string{"--dev"}, []string{"--dev", "--all-projects"}, true},
		{"flag removed", []string{"--dev", "--all-projects"}, []string{"--dev"}, true},
		{"only a value changed", []string{"--org=a"}, []string{"--org=b"}, false},
		{"only the order changed", []string{"--dev", "--all-projects"}, []string{"--all-projects", "--dev"}, false},
		{"only a separate value changed", []string{"--org", "a"}, []string{"--org", "b"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := testutil.UnitTest(t)
			mockEngine, engineConfig := testutil.SetUpEngineMock(t, engine)
			times := 0
			if tt.expectSet {
				times = 1
			}
			capturedCh := testutil.MockAndCaptureWorkflowInvocation(t, mockEngine, localworkflows.WORKFLOWID_REPORT_ANALYTICS, times)

			sendFolderConfigAnalytics(engineConfig, mockEngine, mockEngine.GetLogger(), "", analytics.TriggerSourceTest,
				types.FolderConfigSnapshot{AdditionalParameters: tt.oldParams},
				types.FolderConfigSnapshot{AdditionalParameters: tt.newParams},
				testutil.DefaultConfigResolver(mockEngine))

			if tt.expectSet {
				testsupport.RequireEventuallyReceive(t, capturedCh, time.Second, 10*time.Millisecond, "analytics should have been sent")
				return
			}
			time.Sleep(200 * time.Millisecond)
			assert.Empty(t, capturedCh)
		})
	}
}
