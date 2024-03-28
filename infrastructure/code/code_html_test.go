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
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_CodeDetailsPanel_getDetailsHtml_withDataFlow(t *testing.T) {
	_ = testutil.UnitTest(t)

	issue := snyk.Issue{
		ID:       "java/DontUsePrintStackTrace",
		Severity: 3,
		AdditionalData: snyk.CodeIssueData{
			DataFlow: getDataFlowElements(),
		},
	}

	// invoke method under test
	issueDetailsPanelHtml := getDetailsHtml(issue)

	// assert
	dataFlowHtml := `
		<div class="data-flow-row">
		  <span class="data-flow-number">1</span>
		  <span class="data-flow-blank"> </span>
		  <span class="data-flow-filepath">vulnCodeSnippet.ts:68</span>
		  <span class="data-flow-delimiter">|</span>
		  <span class="data-flow-text">if (!vulnLines.every(e => selectedLines.includes(e))) return false</span>
		</div>`
	assert.Contains(t, issueDetailsPanelHtml, dataFlowHtml)
	assert.NotContains(t, issueDetailsPanelHtml, "${dataFlow}")
}

func Test_codeDetailsPanel_getDetailsHtml_withExampleFixes(t *testing.T) {
	_ = testutil.UnitTest(t)

	issue := snyk.Issue{
		ID:       "java/DontUsePrintStackTrace",
		Severity: 3,
		AdditionalData: snyk.CodeIssueData{
			ExampleCommitFixes: getFixes(),
			RepoDatasetSize:    54387,
		},
	}

	// invoke method under test
	issueDetailsPanelHtml := getDetailsHtml(issue)

	// assert
	expectedTabsNav := "<div class=\"tabs-nav\">"
	expectedTab1 := "<span class=\"tab-item is-selected\" id=\"tab-link-0\">apache/flink</span>"
	expectedTab2 := "<span class=\"tab-item \" id=\"tab-link-1\">apache/tomcat</span>"

	assert.Regexp(t, regexp.QuoteMeta(expectedTabsNav), issueDetailsPanelHtml)
	assert.Regexp(t, regexp.QuoteMeta(expectedTab1), issueDetailsPanelHtml)
	assert.Regexp(t, regexp.QuoteMeta(expectedTab2), issueDetailsPanelHtml)
}

func Test_CodeDetailsPanel_html_getExampleFixCodeDiffHtml(t *testing.T) {
	_ = testutil.UnitTest(t)

	fix := getFixes()[0]

	// invoke method under test
	fixesHtml := getExampleFixCodeDiffHtml(fix)

	// assert
	expectedHtml := `
		<div class="example-line removed"><code>    e.printStackTrace();</code></div>
		<div class="example-line added"><code>    LOG.error(e);</code></div>`

	assert.Contains(t, fixesHtml, expectedHtml)
}

func Test_CodeDetailsPanel_html_getTabsHtml(t *testing.T) {
	_ = testutil.UnitTest(t)

	fixes := getFixes()

	// invoke method under test
	tabsHtml := getTabsHtml(fixes)

	// assert
	expectedTabsNav := "<div class=\"tabs-nav\">"
	expectedTab1 := "<span class=\"tab-item is-selected\" id=\"tab-link-0\">apache/flink</span>"
	expectedTab2 := "<span class=\"tab-item \" id=\"tab-link-1\">apache/tomcat</span>"

	assert.Regexp(t, regexp.QuoteMeta(expectedTabsNav), tabsHtml)
	assert.Regexp(t, regexp.QuoteMeta(expectedTab1), tabsHtml)
	assert.Regexp(t, regexp.QuoteMeta(expectedTab2), tabsHtml)
}

func getFixes() []snyk.ExampleCommitFix {
	return []snyk.ExampleCommitFix{
		{
			CommitURL: "apache/flink",
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
		},
		{
			CommitURL: "apache/tomcat",
			Lines: []snyk.CommitChangeLine{
				{
					Line:       "         try { mutex.wait(); } catch ( java.lang.InterruptedException x ) {Thread.interrupted();}",
					LineNumber: 84,
					LineChange: "removed",
				},
				{
					Line:       "             Thread.currentThread().interrupt();",
					LineNumber: 87,
					LineChange: "added",
				},
			},
		}}
}

func getDataFlowElements() []snyk.DataFlowElement {
	return []snyk.DataFlowElement{
		{
			Content:  "if (!vulnLines.every(e => selectedLines.includes(e))) return false",
			FilePath: "vulnCodeSnippet.ts",
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
	}
}
