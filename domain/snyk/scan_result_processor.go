/*
 * © 2024 Snyk Limited All rights reserved.
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

package snyk

import (
	"time"

	"github.com/snyk/snyk-ls/internal/product"
)

type ScanData struct {
	Product           product.Product
	Issues            []Issue
	Err               error
	DurationMs        time.Duration
	TimestampFinished time.Time
	Path              string
	IsDeltaScan       bool
	SendAnalytics     bool
	UpdateGlobalCache bool
}

type ScanResultProcessor = func(scanData ScanData)

type SeverityIssueCounts map[Severity]IssueCount
type IssueCount struct {
	Total   int
	Open    int
	Ignored int
}

func NoopResultProcessor(_ ScanData) {}

func (s ScanData) GetSeverityIssueCounts() SeverityIssueCounts {
	sic := make(SeverityIssueCounts)

	for _, issue := range s.Issues {
		updateSeverityCount(sic, issue)
	}

	return sic
}

func updateSeverityCount(sic SeverityIssueCounts, issue Issue) {
	ic, exists := sic[issue.Severity]
	if !exists {
		ic = IssueCount{}
	}
	if issue.IsIgnored {
		ic.Ignored++
	} else {
		ic.Open++
	}
	ic.Total++

	sic[issue.Severity] = ic
}
