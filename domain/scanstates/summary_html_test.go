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

func Test_Summary_Html_DeduplicateAndCount_Code_CountsEachInstance(t *testing.T) {
	// Two distinct Code findings share a structural fingerprint; Code is not
	// collapsed, so both are counted.
	sharedFp := testutil.SastFingerprint()
	issues := []types.Issue{
		&snyk.Issue{Fingerprint: sharedFp, Product: product.ProductCode, AdditionalData: snyk.CodeIssueData{HasAIFix: true}},
		&snyk.Issue{Fingerprint: sharedFp, Product: product.ProductCode, AdditionalData: snyk.CodeIssueData{HasAIFix: true}},
		&snyk.Issue{Fingerprint: testutil.SastFingerprint(), Product: product.ProductCode, AdditionalData: snyk.CodeIssueData{HasAIFix: false}},
	}

	counts := deduplicateAndCount(issues)

	assert.Equal(t, 3, counts.uniqueCount, "Code: each instance counts, even with a shared fingerprint")
	assert.Equal(t, 2, counts.fixableCount, "both fixable Code instances are counted")
	assert.Equal(t, 0, counts.ignoredCount)
}

func Test_Summary_Html_DeduplicateAndCount_Secrets_CollapsesSharedFingerprint(t *testing.T) {
	// The same secret at two locations shares one fingerprint and collapses to
	// a single issue. The ignored duplicate is collapsed into the first-seen.
	sharedFp := testutil.Sha256Fingerprint()
	issues := []types.Issue{
		&snyk.Issue{Fingerprint: sharedFp, Product: product.ProductSecrets},
		&snyk.Issue{Fingerprint: sharedFp, Product: product.ProductSecrets, IsIgnored: true},
		&snyk.Issue{Fingerprint: testutil.Sha256Fingerprint(), Product: product.ProductSecrets},
	}

	counts := deduplicateAndCount(issues)

	assert.Equal(t, 2, counts.uniqueCount, "Secrets: shared fingerprint collapses to one issue")
	assert.Equal(t, 0, counts.fixableCount, "Secrets issues are not fixable")
	assert.Equal(t, 0, counts.ignoredCount, "the ignored duplicate was collapsed into the non-ignored first-seen")
}
