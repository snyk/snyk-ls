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
	"fmt"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_CodeDetailsPanel_getDetailsHtml_withDataFlow(t *testing.T) {
	_ = testutil.UnitTest(t)

	dataFlow := getDataFlowElements()
	issue := snyk.Issue{
		ID:       "java/DontUsePrintStackTrace",
		Severity: 3,
		AdditionalData: snyk.CodeIssueData{
			DataFlow: dataFlow,
		},
	}

	// invoke method under test
	issueDetailsPanelHtml := getDetailsHtml(issue)

	// assert
	expectedDataFlowHeading := fmt.Sprintf("<h2>Data Flow - %d steps</h2>", len(dataFlow)) // TODO: handle pluralization
	expectedDataFlowHtml := `
		<div class="data-flow-row">
		  <span class="data-flow-number">1</span>
		  <span class="data-flow-blank"> </span>
		  <span class="data-flow-filepath">vulnCodeSnippet.ts:68</span>
		  <span class="data-flow-delimiter">|</span>
		  <span class="data-flow-text">if (!vulnLines.every(e => selectedLines.includes(e))) return false</span>
		</div>`
	assert.Contains(t, issueDetailsPanelHtml, expectedDataFlowHeading)
	assert.Contains(t, issueDetailsPanelHtml, expectedDataFlowHtml)
	assert.NotContains(t, issueDetailsPanelHtml, "${dataFlow}")
	assert.NotContains(t, issueDetailsPanelHtml, "${dataFlowCount}")
}

func Test_codeDetailsPanel_getDetailsHtml_withExampleFixes(t *testing.T) {
	_ = testutil.UnitTest(t)

	fixes := getFixes()
	repoCount := 54387
	issue := snyk.Issue{
		ID:       "java/DontUsePrintStackTrace",
		Severity: 3,
		AdditionalData: snyk.CodeIssueData{
			ExampleCommitFixes: fixes,
			RepoDatasetSize:    repoCount,
		},
	}

	// invoke method under test
	issueDetailsPanelHtml := getDetailsHtml(issue)

	// assert
	expectedFixesDescription := fmt.Sprintf(`\s*This issue was fixed by %d projects. Here are %d example fixes:\s*`, repoCount, len(fixes))
	expectedFixesDescriptionRegex := regexp.MustCompile(expectedFixesDescription)
	expectedTabsNavRegex := regexp.MustCompile(`\s*<div class="tabs-nav">\s*`)
	expectedTab1Regex := regexp.MustCompile(`\s*<span class="tab-item is-selected" id="tab-link-0">apache/flink</span>\s*`)
	expectedTab2Regex := regexp.MustCompile(`\s*<span class="tab-item\s*" id="tab-link-1">apache/tomcat</span>\s*`)

	assert.Regexp(t, expectedFixesDescriptionRegex, issueDetailsPanelHtml)
	assert.Regexp(t, expectedTabsNavRegex, issueDetailsPanelHtml)
	assert.Regexp(t, expectedTab1Regex, issueDetailsPanelHtml)
	assert.Regexp(t, expectedTab2Regex, issueDetailsPanelHtml)
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
	expectedTabsNav := regexp.MustCompile(`<div class="tabs-nav">`)
	expectedTab1 := regexp.MustCompile(`<span class="tab-item is-selected" id="tab-link-0">apache/flink</span>`)
	expectedTab2 := regexp.MustCompile(`<span class="tab-item " id="tab-link-1">apache/tomcat</span>`)

	assert.Regexp(t, expectedTabsNav, tabsHtml)
	assert.Regexp(t, expectedTab1, tabsHtml)
	assert.Regexp(t, expectedTab2, tabsHtml)
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
