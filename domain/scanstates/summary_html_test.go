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

package scanstates

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

func Test_Summary_Html_getSummaryDetailsHtml(t *testing.T) {
	c := testutil.UnitTest(t)

	// invoke method under test
	htmlRenderer, err := NewHtmlRenderer(c)
	assert.NoError(t, err)
	summaryPanel := htmlRenderer.GetSummaryHtml(StateSnapshot{})

	// assert injectable style
	assert.Contains(t, summaryPanel, "${ideStyle}")
	// assert injectable script
	assert.Contains(t, summaryPanel, "${ideFunc}")

	// assert Header section
	assert.Contains(t, summaryPanel, `class="snx-header`)
}

func Test_Summary_Html_getSummaryDetailsHtml_hasCSS(t *testing.T) {
	c := testutil.UnitTest(t)

	// invoke method under test
	htmlRenderer, err := NewHtmlRenderer(c)
	assert.NoError(t, err)
	summaryPanel := htmlRenderer.GetSummaryHtml(StateSnapshot{})
	// assert css section
	assert.Contains(t, summaryPanel, ":root")
}

func Test_Summary_Html_FilterIndicator_NoFilters(t *testing.T) {
	c := testutil.UnitTest(t)

	htmlRenderer, err := NewHtmlRenderer(c)
	assert.NoError(t, err)

	// Default filters - no indicator should be shown
	// We don't set AnyScanSucceeded flags because we don't have a workspace set up
	// The filter indicator only shows when scans have succeeded, so we test it there
	summaryPanel := htmlRenderer.GetSummaryHtml(StateSnapshot{})

	// Both emojis should NOT be present
	assert.NotContains(t, summaryPanel, "🙈")
	assert.NotContains(t, summaryPanel, "ℹ️")
	// The filter message should not be in the HTML
	assert.NotContains(t, summaryPanel, "have been hidden by filters")
}

func Test_Summary_Html_FilterIndicator_SeverityFilter(t *testing.T) {
	c := testutil.UnitTest(t)

	// Set non-default severity filter (only high and critical)
	severityFilter := util.Ptr(types.NewSeverityFilter(true, true, false, false))
	c.SetSeverityFilter(severityFilter)

	htmlRenderer, err := NewHtmlRenderer(c)
	assert.NoError(t, err)

	// Don't set AnyScanSucceeded - just test that the CSS is present
	summaryPanel := htmlRenderer.GetSummaryHtml(StateSnapshot{})

	// The filter info CSS should be in the styles
	assert.Contains(t, summaryPanel, ".snx-filter-info")
	// Both emojis and message won't be present because no scans succeeded
	assert.NotContains(t, summaryPanel, "🙈")
	assert.NotContains(t, summaryPanel, "ℹ️")
	assert.NotContains(t, summaryPanel, "have been hidden by filters")
}

func Test_Summary_Html_FilterIndicator_RiskScoreThreshold(t *testing.T) {
	c := testutil.UnitTest(t)

	// Set risk score threshold
	riskThreshold := 500
	c.SetRiskScoreThreshold(&riskThreshold)

	htmlRenderer, err := NewHtmlRenderer(c)
	assert.NoError(t, err)

	summaryPanel := htmlRenderer.GetSummaryHtml(StateSnapshot{})

	// CSS should contain filter info styles
	assert.Contains(t, summaryPanel, ".snx-filter-info")
	// Both emojis won't be present because no scans succeeded
	assert.NotContains(t, summaryPanel, "🙈")
	assert.NotContains(t, summaryPanel, "ℹ️")
}

func Test_Summary_Html_FilterIndicator_IssueViewOptions(t *testing.T) {
	c := testutil.UnitTest(t)

	// Set non-default issue view options (only open issues)
	issueViewOptions := util.Ptr(types.NewIssueViewOptions(true, false))
	c.SetIssueViewOptions(issueViewOptions)

	htmlRenderer, err := NewHtmlRenderer(c)
	assert.NoError(t, err)

	summaryPanel := htmlRenderer.GetSummaryHtml(StateSnapshot{})

	// CSS should contain filter info styles
	assert.Contains(t, summaryPanel, ".snx-filter-info")
	// Both emojis won't be present because no scans succeeded
	assert.NotContains(t, summaryPanel, "🙈")
	assert.NotContains(t, summaryPanel, "ℹ️")
}

func Test_Summary_Html_FilterIndicator_MultipleFilters(t *testing.T) {
	c := testutil.UnitTest(t)

	// Set multiple filters
	severityFilter := util.Ptr(types.NewSeverityFilter(true, false, false, false))
	c.SetSeverityFilter(severityFilter)

	riskThreshold := 700
	c.SetRiskScoreThreshold(&riskThreshold)

	issueViewOptions := util.Ptr(types.NewIssueViewOptions(false, true))
	c.SetIssueViewOptions(issueViewOptions)

	htmlRenderer, err := NewHtmlRenderer(c)
	assert.NoError(t, err)

	summaryPanel := htmlRenderer.GetSummaryHtml(StateSnapshot{})

	// CSS should contain filter info styles
	assert.Contains(t, summaryPanel, ".snx-filter-info")
	// Both emojis won't be present because no scans succeeded
	assert.NotContains(t, summaryPanel, "🙈")
	assert.NotContains(t, summaryPanel, "ℹ️")
}

func Test_Summary_Html_FilterIndicator_NotShownWhenNoScansSucceeded(t *testing.T) {
	c := testutil.UnitTest(t)

	// Set non-default filter
	severityFilter := util.Ptr(types.NewSeverityFilter(true, true, false, false))
	c.SetSeverityFilter(severityFilter)

	htmlRenderer, err := NewHtmlRenderer(c)
	assert.NoError(t, err)

	// No scans succeeded
	summaryPanel := htmlRenderer.GetSummaryHtml(StateSnapshot{
		AnyScanSucceededWorkingDirectory: false,
		AnyScanSucceededReference:        false,
	})

	// Both emojis should NOT be present (no results to filter)
	assert.NotContains(t, summaryPanel, "🙈")
	assert.NotContains(t, summaryPanel, "ℹ️")
	// The filter message should not be in the HTML
	assert.NotContains(t, summaryPanel, "have been hidden by filters")
}
