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

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_Summary_Html_getSummaryDetailsHtml(t *testing.T) {
	engine := testutil.UnitTest(t)
	resolver := testutil.DefaultConfigResolver(engine)

	// invoke method under test
	htmlRenderer, err := NewHtmlRenderer(engine.GetConfiguration(), engine.GetLogger(), engine, resolver)
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
	engine := testutil.UnitTest(t)
	resolver := testutil.DefaultConfigResolver(engine)

	// invoke method under test
	htmlRenderer, err := NewHtmlRenderer(engine.GetConfiguration(), engine.GetLogger(), engine, resolver)
	assert.NoError(t, err)
	summaryPanel := htmlRenderer.GetSummaryHtml(StateSnapshot{})
	// assert css section
	assert.Contains(t, summaryPanel, ":root")
}

func Test_Summary_Html_DeduplicateAndCount_SinglePass(t *testing.T) {
	issues := []types.Issue{
		&snyk.Issue{Fingerprint: "fp-1", Product: product.ProductCode, AdditionalData: snyk.CodeIssueData{HasAIFix: true}},
		&snyk.Issue{Fingerprint: "fp-1", Product: product.ProductCode, AdditionalData: snyk.CodeIssueData{HasAIFix: true}},
		&snyk.Issue{Fingerprint: "fp-2", Product: product.ProductCode, AdditionalData: snyk.CodeIssueData{HasAIFix: false}},
	}

	counts := deduplicateAndCount(issues)

	assert.Equal(t, 2, counts.uniqueCount, "should have 2 unique issues")
	assert.Equal(t, 1, counts.fixableCount, "only one of the unique issues is fixable")
	assert.Equal(t, 0, counts.ignoredCount)
}
