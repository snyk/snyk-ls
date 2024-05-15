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

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_Code_Html_getCodeDetailsHtml(t *testing.T) {
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
	codePanelHtml := getCodeDetailsHtml(issue)

	// assert Data Flow section
	expectedDataFlowHeading := fmt.Sprintf(`Data Flow - %d steps`, len(dataFlow))
	assert.Contains(t, codePanelHtml, expectedDataFlowHeading)
	assert.Contains(t, codePanelHtml, `<table class="data-flow-body">`)
	assert.Contains(t, codePanelHtml, `main.ts:5`)
	assert.Contains(t, codePanelHtml, `<td class="data-flow-text">import * as http from &#39;http&#39;;</td>`)

	// assert Ignore Details section - Elements should not be present
	assert.NotContains(t, codePanelHtml, `class=ignore-warning-wrapper`)
	assert.NotContains(t, codePanelHtml, `class="ignore-badge"`)
	assert.NotContains(t, codePanelHtml, `class="ignore-details-section"`)

	// assert Fixes section
	expectedFixesDescription := fmt.Sprintf(`\s*This issue was fixed by %d projects. Here are %d example fixe.\s*`, repoCount, len(fixes))
	assert.Regexp(t, regexp.MustCompile(expectedFixesDescription), codePanelHtml)
	assert.Contains(t, codePanelHtml, `<span class="tab-item is-selected" id="tab-link-0">`, "Two tabs, first is selected")
	assert.Contains(t, codePanelHtml, "</svg> apache/flink", "GitHub icon preceding the repo name is present")
	assert.Contains(t, codePanelHtml, "</svg> apache/tomcat", "Second tab is present")
}

func Test_Code_Html_getCodeDetailsHtml_ignored(t *testing.T) {
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
	codePanelHtml := getCodeDetailsHtml(issue)

	// assert Ignore Details section - Elements should be present
	assert.Contains(t, codePanelHtml, `class="ignore-warning-wrapper"`)
	assert.Contains(t, codePanelHtml, `class="ignore-badge"`)
	assert.Contains(t, codePanelHtml, `class="ignore-details-section"`)
}

func Test_Code_Html_getCodeDetailsHtml_ignored_customEndpoint(t *testing.T) {
	c := testutil.UnitTest(t)

	customEndpoint := "https://app.dev.snyk.io"
	c.UpdateApiEndpoints(customEndpoint + "/api")

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
	codePanelHtml := getCodeDetailsHtml(issue)

	// assert Ignore Details section - Ignore link must be the custom endpoint
	assert.Contains(t, codePanelHtml, customEndpoint)
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
