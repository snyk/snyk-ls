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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_CodeDetailsPanel_html_noLearn(t *testing.T) {
	// arrange
	_ = testutil.UnitTest(t)
	expectedVariables := []string{"${headerEnd}", "${cspSource}", "${nonce}", "${severityIcon}", "${learnIcon}"}

	issue := codeIssue{
		Title:    "Path Traversal",
		Name:     "Path Traversal",
		Severity: "High",
		Id:       "randomId",
		lesson:   nil,
	}

	// invoke method under test
	issueDetailsPanelHtml := getDetailsHtml(&issue)

	// assert
	assert.NotContains(t, issueDetailsPanelHtml, "id='learn--link'")

	for _, expectedVariable := range expectedVariables {
		assert.Contains(t, issueDetailsPanelHtml, expectedVariable)
	}
}

func Test_CodeDetailsPanel_html_withLearn(t *testing.T) {
	_ = testutil.UnitTest(t)

	issue := codeIssue{
		Title:    "Path Traversal",
		Name:     "Path Traversal",
		Severity: "High",
		Id:       "randomId",
		lesson: &learn.Lesson{
			Url: "https://learn.snyk.io/lesson/directory-traversal/?loc=ide",
		},
	}

	// invoke method under test
	issueDetailsPanelHtml := getDetailsHtml(&issue)

	// assert
	learnLink := fmt.Sprintf("<a class='learn--link' id='learn--link' href='%s'>Learn about this vulnerability</a>", issue.lesson.Url)
	assert.Contains(t, issueDetailsPanelHtml, learnLink)
	assert.NotContains(t, issueDetailsPanelHtml, "${learnLink}")

}

func Test_CodeDetailsPanel_html_withDataFlow(t *testing.T) {
	_ = testutil.UnitTest(t)

	issue := codeIssue{
		Title:    "Path Traversal",
		Name:     "Path Traversal",
		Severity: "High",
		Id:       "randomId",
		lesson: &learn.Lesson{
			Url: "https://learn.snyk.io/lesson/directory-traversal/?loc=ide",
		},
		// TODO: add more data flow elements to check the line count - Fix Range
		DataFlow: []*snyk.DataFlowElement{
			{
				Position: 10,
				FilePath: "/Users/cata/git/juice-shop/routes/vulnCodeSnippet.ts",
				Content:  "if (!vulnLines.every(e => selectedLines.includes(e))) return false",
			},
		},
	}

	// invoke method under test
	issueDetailsPanelHtml := getDetailsHtml(&issue)

	// assert
	dataFlowHtml := `
		<div class="data-flow-row">
		  <span class="data-flow-number">1</span>
		  <span class="data-flow-blank"> </span>
		  <span class="data-flow-filepath">/Users/cata/git/juice-shop/routes/vulnCodeSnippet.ts:10</span>
		  <span class="data-flow-delimiter">|</span>
		  <span class="data-flow-text">if (!vulnLines.every(e => selectedLines.includes(e))) return false</span>
		</div>`
	assert.Contains(t, issueDetailsPanelHtml, dataFlowHtml)
	assert.NotContains(t, issueDetailsPanelHtml, "${dataFlow}")

}
