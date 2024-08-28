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

func Test_Code_Html_getCodeDetailsHtml(t *testing.T) {
	_ = testutil.UnitTest(t)

	dataFlow := getDataFlowElements()
	fixes := getFixes()
	repoCount := 54387
	issue := snyk.Issue{
		Range:     getIssueRange(),
		CWEs:      []string{"CWE-123", "CWE-456"},
		ID:        "go/NoHardcodedCredentials/test",
		Severity:  2,
		LessonUrl: "https://learn.snyk.io/lesson/no-rate-limiting/?loc=ide",
		AdditionalData: snyk.CodeIssueData{
			Title:              "Allocation of Resources Without Limits or Throttling",
			DataFlow:           dataFlow,
			ExampleCommitFixes: fixes,
			RepoDatasetSize:    repoCount,
			IsSecurityType:     true,
			Text:               getVulnerabilityOverviewText(),
			PriorityScore:      890,
		},
	}

	// invoke method under test
	codePanelHtml := getCodeDetailsHtml(issue, "")

	// assert injectable style
	assert.Contains(t, codePanelHtml, "${ideStyle}")
	// assert injectable script
	assert.Contains(t, codePanelHtml, "${ideScript}")

	// assert Header section
	assert.Contains(t, codePanelHtml, "Priority score: 890")
	assert.Contains(t, codePanelHtml, `href="https://learn.snyk.io/lesson/no-rate-limiting/?loc=ide"`)

	// assert Data Flow section
	expectedDataFlowHeading := fmt.Sprintf(`Data Flow - %d steps`, len(dataFlow))
	assert.Contains(t, codePanelHtml, expectedDataFlowHeading)
	assert.Contains(t, codePanelHtml, `<table class="data-flow-table">`)
	assert.Contains(t, codePanelHtml, `main.ts`)
	assert.Contains(t, codePanelHtml, `line:5`)
	assert.Contains(t, codePanelHtml, `<code>import * as http from &#39;http&#39;;</code>`)

	// assert Ignore Details section - Elements should not be present
	assert.NotContains(t, codePanelHtml, `class=ignore-warning-wrapper`)
	assert.NotContains(t, codePanelHtml, `class="ignore-badge"`)
	assert.NotContains(t, codePanelHtml, `class="ignore-details-section"`)

	// assert Fixes section
	assert.Contains(t, codePanelHtml, ` id="ai-fix-wrapper" class="hidden">`)
	assert.Contains(t, codePanelHtml, ` id="no-ai-fix-wrapper" class="">`)
	expectedFixesDescription := fmt.Sprintf(`This type of vulnerability was fixed in %d open source projects.`, repoCount)
	assert.Regexp(t, regexp.MustCompile(expectedFixesDescription), codePanelHtml)
	assert.Contains(t, codePanelHtml, `<span id="example-link" class="example-repo-link">`, "GitHub icon preceding the repo name is present")

	// assert Footer
	assert.Contains(t, codePanelHtml, `id="action-ignore-line">68</span>`)
	assert.Contains(t, codePanelHtml, `class="ignore-button secondary">Ignore in this file</button>`)
}

func Test_Code_Html_getCodeDetailsHtml_withAIfix(t *testing.T) {
	_ = testutil.UnitTest(t)

	dataFlow := getDataFlowElements()
	fixes := getFixes()
	repoCount := 54387
	issue := snyk.Issue{
		Range:     getIssueRange(),
		CWEs:      []string{"CWE-123", "CWE-456"},
		ID:        "go/NoHardcodedCredentials/test",
		Severity:  2,
		LessonUrl: "https://learn.snyk.io/lesson/no-rate-limiting/?loc=ide",
		AdditionalData: snyk.CodeIssueData{
			Title:              "Allocation of Resources Without Limits or Throttling",
			DataFlow:           dataFlow,
			ExampleCommitFixes: fixes,
			RepoDatasetSize:    repoCount,
			IsSecurityType:     true,
			Text:               getVulnerabilityOverviewText(),
			PriorityScore:      890,
			HasAIFix:           true,
		},
	}

	// invoke method under test
	codePanelHtml := getCodeDetailsHtml(issue, "")

	// assert Fixes section
	assert.Contains(t, codePanelHtml, ` id="ai-fix-wrapper" class="">`)
	assert.Contains(t, codePanelHtml, `✨ Generate AI fix`)
	assert.Contains(t, codePanelHtml, ` id="no-ai-fix-wrapper" class="hidden">`)
}

func Test_Code_Html_getCodeDetailsHtml_ignored(t *testing.T) {
	_ = testutil.UnitTest(t)

	dataFlow := getDataFlowElements()
	fixes := getFixes()
	repoCount := 54387
	issue := snyk.Issue{
		ID:        "java/DontUsePrintStackTrace",
		Severity:  2,
		LessonUrl: "https://learn.snyk.io/lesson/no-rate-limiting/?loc=ide",
		CWEs:      []string{"CWE-123", "CWE-456"},
		IsIgnored: true,
		IgnoreDetails: &snyk.IgnoreDetails{
			Category:   "wont-fix",
			Reason:     getIgnoreReason("long"),
			Expiration: "",
			IgnoredOn:  time.Now(),
			IgnoredBy:  "John Smith",
		},
		AdditionalData: snyk.CodeIssueData{
			Title:              "Allocation of Resources Without Limits or Throttling",
			DataFlow:           dataFlow,
			ExampleCommitFixes: fixes,
			RepoDatasetSize:    repoCount,
			IsSecurityType:     true,
			Text:               getVulnerabilityOverviewText(),
			PriorityScore:      0,
		},
	}

	// invoke method under test
	codePanelHtml := getCodeDetailsHtml(issue, "")

	// assert Header section
	assert.Contains(t, codePanelHtml, "Priority score: 0")
	assert.NotContains(t, codePanelHtml, `href="https://when-no-lesson-data-element-not-in-the-template"`)

	// assert Ignore Details section - Elements should be present
	assert.Contains(t, codePanelHtml, `class="ignore-warning-wrapper"`)
	assert.Contains(t, codePanelHtml, `class="ignore-badge"`)
	assert.Contains(t, codePanelHtml, `data-content="ignore-details"`)
	assert.Contains(t, codePanelHtml, `class="ignore-details-value">Ignored permanently</div>`)
	assert.Contains(t, codePanelHtml, `class="ignore-details-value">No expiration</div>`) // Because category is "wont-fix"

	// assert Footer buttons are not present when issue is ignored
	assert.NotContains(t, codePanelHtml, `id="ignore-actions"`)
}

func Test_Code_Html_getCodeDetailsHtml_ignored_expired(t *testing.T) {
	_ = testutil.UnitTest(t)

	issue := snyk.Issue{
		ID:        "scala/DontUsePrintStackTrace",
		Severity:  2,
		LessonUrl: "https://learn.snyk.io/lesson/no-rate-limiting/?loc=ide",
		CWEs:      []string{"CWE-123", "CWE-456"},
		IsIgnored: true,
		IgnoreDetails: &snyk.IgnoreDetails{
			Category:   "temporary-ignore",
			Reason:     getIgnoreReason("long"),
			Expiration: "2023-08-26T13:16:53.177Z",
			IgnoredOn:  time.Now(),
			IgnoredBy:  "John Smith",
		},
		AdditionalData: snyk.CodeIssueData{},
	}

	// invoke method under test
	codePanelHtml := getCodeDetailsHtml(issue, "")

	// assert Ignore Details section
	// Asserting an expired date to prevent the test from breaking in the future as the current date changes
	assert.Contains(t, codePanelHtml, `class="ignore-details-value">Expired</div>`)
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
		LessonUrl: "https://learn.snyk.io/lesson/no-rate-limiting/?loc=ide",
		IgnoreDetails: &snyk.IgnoreDetails{
			Category:   "wont-fix",
			Reason:     getIgnoreReason("short"),
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
			Text:               getVulnerabilityOverviewText(),
		},
	}

	// invoke method under test
	codePanelHtml := getCodeDetailsHtml(issue, "")

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

func getIssueRange() snyk.Range {
	return snyk.Range{
		Start: snyk.Position{
			Line:      67,
			Character: 28,
		},
		End: snyk.Position{
			Line:      67,
			Character: 42,
		},
	}
}

func getVulnerabilityOverviewText() string {
	return `## Details\n\nA cross-site scripting attack occurs when the attacker tricks a legitimate web-based application or site to accept a request as originating from a trusted source.\n\nThis is done by escaping the context of the web application; the web application then delivers that data to its users along with other trusted dynamic content, without validating it. The browser unknowingly executes malicious script on the client side (through client-side languages; usually JavaScript or HTML)  in order to perform actions that are otherwise typically blocked by the browser's Same Origin Policy.`
}

func getIgnoreReason(version string) string {
	if version == "short" {
		return "Vulnerability found in a test file."
	}
	return `After a comprehensive review, our security team determined that the risk associated with this specific XSS vulnerability is mitigated by additional security measures implemented at the network and application layers.`
}
