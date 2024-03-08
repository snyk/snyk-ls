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
	codeClientObservability "github.com/snyk/code-client-go/observability"

	ux2 "github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/internal/float"
)

type CodeAnalytics interface {
	TrackScan(success bool, scanMetrics codeClientObservability.ScanMetrics)
}

type codeAnalyticsImpl struct {
	analytics ux2.Analytics
}

func NewCodeAnalytics(analytics ux2.Analytics) CodeAnalytics {
	return codeAnalyticsImpl{analytics: analytics}
}

func (sc codeAnalyticsImpl) TrackScan(success bool, scanMetrics codeClientObservability.ScanMetrics) {
	var result ux2.Result
	if success {
		result = ux2.Success
	} else {
		result = ux2.Error
	}

	duration := scanMetrics.GetDuration()
	lastScanDurationInSeconds := float.ToFixed(duration.Seconds(), 2)
	lastScanFileCount := scanMetrics.GetLastScanFileCount()
	sc.analytics.AnalysisIsReady(
		ux2.AnalysisIsReadyProperties{
			AnalysisType:      ux2.CodeSecurity,
			Result:            result,
			FileCount:         lastScanFileCount,
			DurationInSeconds: lastScanDurationInSeconds,
		},
	)
}

var _ CodeAnalytics = &testCodeAnalytics{}

type testCodeAnalytics struct {
	ScanHasBeenTracked bool
}

func newTestCodeAnalytics() *testCodeAnalytics {
	return &testCodeAnalytics{}
}

func (t *testCodeAnalytics) TrackScan(success bool, scanMetrics codeClientObservability.ScanMetrics) {
	t.ScanHasBeenTracked = true
}
