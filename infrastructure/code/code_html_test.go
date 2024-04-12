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
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_Code_Html_getDetailsHtml(t *testing.T) {
	_ = testutil.UnitTest(t)

	dataFlow := getDataFlowElements()
	fixes := getFixes()
	repoCount := 54387
	issue := snyk.Issue{
		CWEs:     []string{"CWE-123", "CWE-456"},
		ID:       "java/DontUsePrintStackTrace",
		Severity: 2,
		AdditionalData: snyk.CodeIssueData{
			Title:              "Allocation of Resources Without Limits or Throttling",
			DataFlow:           dataFlow,
			ExampleCommitFixes: fixes,
			RepoDatasetSize:    repoCount,
			IsSecurityType:     true,
			Message:            "Either rethrow this java.lang.InterruptedException or set the interrupted flag on the current thread with 'Thread.currentThread().interrupt()'. Otherwise the information that the current thread was interrupted will be lost.",
		},
	}

	// invoke method under test
	codePanelHtml := getDetailsHtml(issue)

	// assert Data Flow section
	expectedDataFlowHeading := fmt.Sprintf(`<h2 class="data-flow-header">Data Flow - %d steps</h2>`, len(dataFlow))
	assert.Contains(t, codePanelHtml, expectedDataFlowHeading)
	assert.Contains(t, codePanelHtml, `<table class="data-flow-body"><tbody>`)
	assert.Contains(t, codePanelHtml, `main.ts:5`)
	assert.Contains(t, codePanelHtml, `<td class="data-flow-text">import * as http from &#39;http&#39;;</td>`)
	assert.NotContains(t, codePanelHtml, "${dataFlow}")
	assert.NotContains(t, codePanelHtml, "${dataFlowCount}")

	// assert Ignore Details section
	assert.Contains(t, codePanelHtml, "ignore-warning-wrapper hidden")
	assert.Contains(t, codePanelHtml, "ignore-badge hidden")
	assert.Contains(t, codePanelHtml, "ignore-details-section hidden")
	assert.NotContains(t, codePanelHtml, "${ignoreDetails}")

	// assert Fixes section
	expectedFixesDescription := fmt.Sprintf(`\s*This issue was fixed by %d projects. Here are %d example fixes:\s*`, repoCount, len(fixes))
	assert.Regexp(t, regexp.MustCompile(expectedFixesDescription), codePanelHtml)
	assert.Contains(t, codePanelHtml, `<span class="tab-item is-selected" id="tab-link-0">`, "Two tabs, first is selected")
	assert.Contains(t, codePanelHtml, "</svg> apache/flink", "GitHub icon preceding the repo name is present")
	assert.Contains(t, codePanelHtml, "</svg> apache/tomcat", "Second tab is present")
}

func Test_Code_Html_getDetailsHtml_ignored(t *testing.T) {
	_ = testutil.UnitTest(t)

	dataFlow := getDataFlowElements()
	fixes := getFixes()
	repoCount := 54387
	issue := snyk.Issue{
		ID:        "java/DontUsePrintStackTrace",
		Severity:  2,
		CWEs:      []string{"CWE-123", "CWE-456"},
		IsIgnored: true,
		IgnoreDetails: &snyk.IgnoreDetails{
			Category:   "wont-fix",
			Reason:     "After a comprehensive review, our security team determined that the risk associated with this specific XSS vulnerability is mitigated by additional security measures implemented at the network and application layers.",
			Expiration: "13 days",
			IgnoredOn:  time.Now(),
			IgnoredBy:  "John Smith",
		},
		AdditionalData: snyk.CodeIssueData{
			Title:              "Allocation of Resources Without Limits or Throttling",
			DataFlow:           dataFlow,
			ExampleCommitFixes: fixes,
			RepoDatasetSize:    repoCount,
			IsSecurityType:     true,
			Message:            "Either rethrow this java.lang.InterruptedException or set the interrupted flag on the current thread with 'Thread.currentThread().interrupt()'. Otherwise the information that the current thread was interrupted will be lost.",
		},
	}

	// invoke method under test
	codePanelHtml := getDetailsHtml(issue)

	assert.NotContains(t, codePanelHtml, "ignore-warning-wrapper ${visibilityClass}")
	assert.NotContains(t, codePanelHtml, "ignore-badge ${visibilityClass}")
	assert.NotContains(t, codePanelHtml, "${ignoreDetails}")
}

func Test_Code_Html_getDataFlowTable(t *testing.T) {
	_ = testutil.UnitTest(t)

	additionalData := snyk.CodeIssueData{
		DataFlow: getDataFlowElements(),
	}

	// invoke method under test
	dataFlowTable := getDataFlowTableHtml(additionalData)

	// assert
	assert.Contains(t, dataFlowTable, `<td class="data-flow-number">1</td>`)
	assert.Contains(t, dataFlowTable, `<tr class="data-flow-row">`)
	assert.Contains(t, dataFlowTable, `file-path="juice-shop/routes/vulnCodeSnippet.ts"`)
	assert.Contains(t, dataFlowTable, `end-line="67"`)
	assert.Contains(t, dataFlowTable, `vulnCodeSnippet.ts:68`)
	assert.Contains(t, dataFlowTable, `<td class="data-flow-text">if (!vulnLines.every(e =&gt; selectedLines.includes(e))) return false</td>`)
}

func Test_Code_Html_getCodeDiffHtml(t *testing.T) {
	_ = testutil.UnitTest(t)

	// invoke method under test
	fixesHtml := getCodeDiffHtml(getFixes()[0])

	// assert
	assert.Contains(t, fixesHtml, `<div class="example-line removed">`)
	assert.Contains(t, fixesHtml, `<code>    e.printStackTrace();</code>`)
	assert.Contains(t, fixesHtml, `<div class="example-line added">`)
	assert.Contains(t, fixesHtml, `<code>    LOG.error(e);</code>`)
}

func Test_Code_Html_getExampleCommitFixesHtml(t *testing.T) {
	_ = testutil.UnitTest(t)

	// invoke method under test
	fixesHtml := getExampleCommitFixesHtml(getFixes())

	// assert
	assert.Contains(t, fixesHtml, `<span class="tab-item is-selected" id="tab-link-0">`)
	assert.Contains(t, fixesHtml, `<svg class="tab-item-icon" width="18" height="16"`, "SVG code is not escaped")
	assert.Contains(t, fixesHtml, `<code>    LOG.error(e);</code>`, "Code is not escaped")
}

func Test_Code_Html_getIgnoreDetailsHtml(t *testing.T) {
	_ = testutil.UnitTest(t)

	ignoredOn, _ := time.Parse(time.RFC3339, "2024-02-23T16:08:25Z")
	ignoreDetails := &snyk.IgnoreDetails{
		Category:   "wont-fix",
		Reason:     "False positive",
		Expiration: "13 days",
		IgnoredOn:  ignoredOn,
		IgnoredBy:  "John",
	}

	// invoke method under test
	ignoreDetailsHtml, visibilityClass := getIgnoreDetailsHtml(true, ignoreDetails)

	// assert
	assert.Equal(t, "", visibilityClass)
	assert.Contains(t, ignoreDetailsHtml, `<div class="ignore-details-label">Category</div>`)
	assert.Contains(t, ignoreDetailsHtml, `<div class="ignore-details-value">wont-fix</div>`)
	assert.Contains(t, ignoreDetailsHtml, `<div class="ignore-details-label">Ignored On</div>`)
	assert.Contains(t, ignoreDetailsHtml, `<div class="ignore-details-value">February 23, 2024</div>`)
	assert.Contains(t, ignoreDetailsHtml, `<div class="ignore-details-label">Expiration</div>`)
	assert.Contains(t, ignoreDetailsHtml, `<div class="ignore-details-value">13 days</div>`)
	assert.Contains(t, ignoreDetailsHtml, `<div class="ignore-details-label">Ignored By</div>`)
	assert.Contains(t, ignoreDetailsHtml, `<div class="ignore-details-value">John</div>`)
}

func Test_Code_Html_getCWELinks(t *testing.T) {
	_ = testutil.UnitTest(t)

	cwes := []string{"CWE-1", "CWE-2"}

	html := getCWELinks(cwes)

	delimeter := `<span class="delimiter"></span>`
	linkClasses := `class="cwe styled-link" target="_blank" rel="noopener noreferrer"`
	expected := fmt.Sprintf(`%s<a %s href="https://cwe.mitre.org/data/definitions/1.html">CWE-1</a>%s<a %s href="https://cwe.mitre.org/data/definitions/2.html">CWE-2</a>`, delimeter, linkClasses, delimeter, linkClasses)
	assert.Contains(t, expected, html)
}

func Test_Code_Html_getRepoName(t *testing.T) {
	// Source Snyk IntelliJ plugin
	// https://github.com/snyk/snyk-intellij-plugin/blob/master/src/main/kotlin/io/snyk/plugin/ui/toolwindow/panels/SuggestionDescriptionPanelFromLS.kt#L256-L262
	testCases := []struct {
		name     string
		url      string
		expected string
	}{
		{
			name:     "Standard GitHub URL",
			url:      "https://github.com/apache/flink/commit/5d7c5620804eddd59206b24c87ffc89c12fd1184",
			expected: "apache/flink",
		},
		{
			name:     "GitHub URL with parameters",
			url:      "https://github.com/juice-shop/juice-shop/commit/0fa9d5547c5300cf8162b8f31a40aea6847a5c32?diff=split#diff-7e23eb1aa3b7b4d5db89bfd2860277e5L75",
			expected: "juice-shop/juice-shop",
		},
		{
			name:     "GitHub URL with a dot in the repo name",
			url:      "https://github.com/juice-shop/.github/commit/67603b2f2b4f02fbc65f53bda7c3f56a5d341987",
			expected: "juice-shop/.github",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := getRepoName(tc.url)
			if result != tc.expected {
				t.Errorf("For URL '%s', expected '%s', but got '%s'", tc.url, tc.expected, result)
			}
		})
	}
}

func getFixes() []snyk.ExampleCommitFix {
	return []snyk.ExampleCommitFix{
		{
			CommitURL: "https://github.com/apache/flink/commit/5d7c5620804eddd59206b24c87ffc89c12fd1184",
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
			CommitURL: "https://github.com/apache/tomcat/commit/0fa9d5547c5300cf8162b8f31a40aea6847a5c32?diff=split#diff-7e23eb1aa3b7b4d5db89bfd2860277e5L75",
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
			FilePath: "juice-shop/routes/vulnCodeSnippet.ts",
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
		{
			Content:  "import * as http from 'http';",
			FilePath: "main.ts",
			FlowRange: snyk.Range{
				End: snyk.Position{
					Character: 33,
					Line:      4,
				},
				Start: snyk.Position{
					Character: 13,
					Line:      4,
				},
			},
			Position: 1,
		},
		{
			Content:  "import { ExpressAdapter } from '@nestjs/platform-express';",
			FilePath: "main.ts",
			FlowRange: snyk.Range{
				End: snyk.Position{
					Character: 23,
					Line:      5,
				},
				Start: snyk.Position{
					Character: 8,
					Line:      5,
				},
			},
			Position: 2,
		},
		{
			Content:  "import { LoggerFactory } from './log';",
			FilePath: "main.ts",
			FlowRange: snyk.Range{
				End: snyk.Position{
					Character: 10,
					Line:      9,
				},
				Start: snyk.Position{
					Character: 9,
					Line:      97,
				},
			},
			Position: 4,
		},
	}
}
