/*
 * © 2023-2024 Snyk Limited
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

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_CodeDetailsPanel_html_withDataFlow(t *testing.T) {
	_ = testutil.UnitTest(t)
	expectedVariables := []string{"${headerEnd}", "${cspSource}", "${nonce}", "${severityIcon}"}

	issue := snyk.Issue{
		ID:       "java/DontUsePrintStackTrace",
		Severity: 3,
		AdditionalData: snyk.CodeIssueData{
			DataFlow: []snyk.DataFlowElement{
				{
					Content:  "if (!vulnLines.every(e => selectedLines.includes(e))) return false",
					FilePath: "/Users/cata/git/juice-shop/routes/vulnCodeSnippet.ts",
					FlowRange: snyk.Range{
						End: snyk.Position{
							Character: 42,
							Line:      67,
						},
						Start: snyk.Position{
							Character: 28,
							Line:      67,
						},
					},
					Position: 0,
				},
			},
		},
	}

	// invoke method under test
	issueDetailsPanelHtml := getDetailsHtml(issue)

	// assert
	dataFlowHtml := `
		<div class="data-flow-row">
		  <span class="data-flow-number">1</span>
		  <span class="data-flow-blank"> </span>
		  <span class="data-flow-filepath">/Users/cata/git/juice-shop/routes/vulnCodeSnippet.ts:68</span>
		  <span class="data-flow-delimiter">|</span>
		  <span class="data-flow-text">if (!vulnLines.every(e => selectedLines.includes(e))) return false</span>
		</div>`
	assert.Contains(t, issueDetailsPanelHtml, dataFlowHtml)
	assert.NotContains(t, issueDetailsPanelHtml, "${dataFlow}")

	for _, expectedVariable := range expectedVariables {
		assert.Contains(t, issueDetailsPanelHtml, expectedVariable)
	}
}

func Test_CodeDetailsPanel_html_withExternalFixes(t *testing.T) {
	_ = testutil.UnitTest(t)

	fix := snyk.ExampleCommitFix{
		CommitURL: "https://github.com/apache/flink/commit/1a2b3c4d5e6f7g8h9i0j",
		Lines: []snyk.CommitChangeLine{
			{
				Line:       "    e.printStackTrace();",
				LineNumber: 944,
				LineChange: "removed",
			},
			{
				Line:       "    LOG.error(e);",
				LineNumber: 104,
				LineChange: "added",
			},
		},
	}

	// invoke method under test
	fixesHtml := getExampleFixCodeDiffHtml(fix)

	// assert
	expectedHtml := `
		<div class="tab-content example-line removed"><code>    e.printStackTrace();</code></div>
		<div class="tab-content example-line added"><code>    LOG.error(e);</code></div>`

	assert.Contains(t, fixesHtml, expectedHtml)
}
