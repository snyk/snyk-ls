/*
 * © 2024 Snyk Limited
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

package code

import (
	"testing"
	"time"

	codeClientObservability "github.com/snyk/code-client-go/observability"
	"github.com/stretchr/testify/assert"

	ux2 "github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/internal/float"
)

func TestCodeAnalytics_TrackScan(t *testing.T) {
	analytics := ux2.NewTestAnalytics()
	codeAnalytics := NewCodeAnalytics(analytics)
	metrics := codeClientObservability.NewScanMetrics(time.Now(), 1)

	codeAnalytics.TrackScan(true, metrics)
	assert.Len(t, analytics.GetAnalytics(), 1)
	assert.Equal(
		t, ux2.AnalysisIsReadyProperties{
			AnalysisType:      ux2.CodeSecurity,
			Result:            ux2.Success,
			FileCount:         1,
			DurationInSeconds: float.ToFixed(metrics.GetDuration().Seconds(), 2),
		}, analytics.GetAnalytics()[0],
	)
}
