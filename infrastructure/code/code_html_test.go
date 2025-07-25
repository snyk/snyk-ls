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

package code

import (
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	codeClientSarif "github.com/snyk/code-client-go/sarif"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_Code_Html_getCodeDetailsHtml_WithInlineIgnores_WithoutIAW(t *testing.T) {
	c := testutil.UnitTest(t)

	dataFlow := getDataFlowElements()
	fixes := getFixes()
	repoCount := 54387
	issue := &snyk.Issue{
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

	// Create a fake API client with the feature flag disabled
	apiClient := &snyk_api.FakeApiClient{
		CodeEnabled: true,
	}
	// Set the response for the FeatureFlagStatus method
	apiClient.SetResponse("FeatureFlagStatus", snyk_api.FFResponse{Ok: false})

	// invoke method under test
	htmlRenderer, err := GetHTMLRenderer(c, apiClient)
	htmlRenderer.inlineIgnoresEnabled = true
	htmlRenderer.iawEnabled = false

	assert.NoError(t, err)
	codePanelHtml := htmlRenderer.GetDetailsHtml(issue)

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
	assert.Contains(t, codePanelHtml, `5`)
	assert.Contains(t, codePanelHtml, `<code>import * as http from &#39;http&#39;;</code>`)

	// assert Ignore Details section - Elements should not be present
	assert.NotContains(t, codePanelHtml, `class="sn-status-message mod-warning"`)
	assert.NotContains(t, codePanelHtml, `class="sn-ignore-badge"`)
	assert.NotContains(t, codePanelHtml, `class="ignore-details-section"`)

	// assert Fixes section
	assert.Contains(t, codePanelHtml, ` id="ai-fix-wrapper" class="hidden">`)
	assert.Contains(t, codePanelHtml, ` id="no-ai-fix-wrapper"`)
	assert.Contains(t, codePanelHtml, `<button id="generate-ai-fix" folder-path="" file-path=""
                  class="generate-ai-fix`)
	expectedFixesDescription := fmt.Sprintf(`This type of vulnerability was fixed in %d open source projects.`, repoCount)
	assert.Regexp(t, regexp.MustCompile(expectedFixesDescription), codePanelHtml)
	assert.Contains(t, codePanelHtml, `<span id="example-link" class="example-repo-link">`, "GitHub icon preceding the repo name is present")

	// assert Footer
	assert.Contains(t, codePanelHtml, `id="action-ignore-line"`)
	assert.Contains(t, codePanelHtml, `class="ignore-button secondary"`)
}

func Test_Code_Html_getCodeDetailsHtml_withAIfix(t *testing.T) {
	c := testutil.UnitTest(t)

	dataFlow := getDataFlowElements()
	fixes := getFixes()
	repoCount := 54387
	issue := &snyk.Issue{
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

	// Create a fake API client with the feature flag disabled
	apiClient := &snyk_api.FakeApiClient{
		CodeEnabled: true,
	}
	// Set the response for the FeatureFlagStatus method
	apiClient.SetResponse("FeatureFlagStatus", snyk_api.FFResponse{Ok: false})

	// invoke method under test
	htmlRenderer, err := GetHTMLRenderer(c, apiClient)
	assert.NoError(t, err)
	codePanelHtml := htmlRenderer.GetDetailsHtml(issue)
	// assert Fixes section
	assert.Contains(t, codePanelHtml, ` id="ai-fix-wrapper" class="">`)
	assert.Contains(t, codePanelHtml, `✨ Generate AI fix`)
	assert.Contains(t, codePanelHtml, ` id="no-ai-fix-wrapper"`)
	assert.Contains(t, codePanelHtml, ` folder-path=""`)
}

func Test_Code_Html_getCodeDetailsHtml_ignored(t *testing.T) {
	c := testutil.UnitTest(t)

	dataFlow := getDataFlowElements()
	fixes := getFixes()
	repoCount := 54387
	issue := &snyk.Issue{
		ID:        "java/DontUsePrintStackTrace",
		Severity:  2,
		LessonUrl: "https://learn.snyk.io/lesson/no-rate-limiting/?loc=ide",
		CWEs:      []string{"CWE-123", "CWE-456"},
		IsIgnored: true,
		IgnoreDetails: &types.IgnoreDetails{
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

	// Create a fake API client with the feature flag disabled
	apiClient := &snyk_api.FakeApiClient{
		CodeEnabled: true,
	}
	// Set the response for the FeatureFlagStatus method
	apiClient.SetResponse("FeatureFlagStatus", snyk_api.FFResponse{Ok: false})

	// invoke method under test
	htmlRenderer, err := GetHTMLRenderer(c, apiClient)
	assert.NoError(t, err)
	codePanelHtml := htmlRenderer.GetDetailsHtml(issue)

	// assert Header section
	assert.Contains(t, codePanelHtml, "Priority score: 0")
	assert.NotContains(t, codePanelHtml, `href="https://when-no-lesson-data-element-not-in-the-template"`)

	// assert Ignore Details section - Elements should be present
	assert.Contains(t, codePanelHtml, `class="sn-status-message mod-warning"`)
	assert.Contains(t, codePanelHtml, `class="sn-ignore-badge"`)
	assert.Contains(t, codePanelHtml, `data-content="ignore-details"`)
	assert.Contains(t, codePanelHtml, `<td class="ignore-details-value">Ignored permanently</td>`)
	assert.Contains(t, codePanelHtml, `<td class="ignore-details-value">No expiration</td>`) // Because category is "wont-fix"

	// assert Footer buttons are not present when issue is ignored
	assert.NotContains(t, codePanelHtml, `id="ignore-actions"`)
}

func Test_Code_Html_getCodeDetailsHtml_ignored_expired(t *testing.T) {
	c := testutil.UnitTest(t)

	issue := &snyk.Issue{
		ID:        "scala/DontUsePrintStackTrace",
		Severity:  2,
		LessonUrl: "https://learn.snyk.io/lesson/no-rate-limiting/?loc=ide",
		CWEs:      []string{"CWE-123", "CWE-456"},
		IsIgnored: true,
		IgnoreDetails: &types.IgnoreDetails{
			Category:   "temporary-ignore",
			Reason:     getIgnoreReason("long"),
			Expiration: "2023-08-26T13:16:53.177Z",
			IgnoredOn:  time.Now(),
			IgnoredBy:  "John Smith",
		},
		AdditionalData: snyk.CodeIssueData{},
	}

	// Create a fake API client with the feature flag disabled
	apiClient := &snyk_api.FakeApiClient{
		CodeEnabled: true,
	}
	// Set the response for the FeatureFlagStatus method
	apiClient.SetResponse("FeatureFlagStatus", snyk_api.FFResponse{Ok: false})

	// invoke method under test
	htmlRenderer, err := GetHTMLRenderer(c, apiClient)
	assert.NoError(t, err)
	codePanelHtml := htmlRenderer.GetDetailsHtml(issue)

	// assert Ignore Details section
	// Asserting an expired date to prevent the test from breaking in the future as the current date changes
	assert.Contains(t, codePanelHtml, `<td class="ignore-details-value">Expired</td>`)
}

func Test_Code_Html_getCodeDetailsHtml_ignored_customEndpoint(t *testing.T) {
	c := testutil.UnitTest(t)

	customEndpoint := "https://app.dev.snyk.io"
	didUpdate := c.UpdateApiEndpoints(customEndpoint + "/api")
	assert.True(t, didUpdate)
	newEndpoint := c.SnykUI()
	assert.Equalf(t, customEndpoint, newEndpoint, "Failed to update endpoint, currently %v", newEndpoint)

	dataFlow := getDataFlowElements()
	fixes := getFixes()
	repoCount := 54387
	issue := &snyk.Issue{
		ID:        "java/DontUsePrintStackTrace",
		Severity:  2,
		CWEs:      []string{"CWE-123", "CWE-456"},
		IsIgnored: true,
		LessonUrl: "https://learn.snyk.io/lesson/no-rate-limiting/?loc=ide",
		IgnoreDetails: &types.IgnoreDetails{
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

	// Create a fake API client with the feature flag disabled
	apiClient := &snyk_api.FakeApiClient{
		CodeEnabled: true,
	}
	// Set the response for the FeatureFlagStatus method
	apiClient.SetResponse("FeatureFlagStatus", snyk_api.FFResponse{Ok: false})

	// invoke method under test
	htmlRenderer, err := GetHTMLRenderer(c, apiClient)
	assert.NoError(t, err)
	codePanelHtml := htmlRenderer.GetDetailsHtml(issue)

	// assert Ignore Details section - Ignore link must be the custom endpoint
	assert.Containsf(t, codePanelHtml, customEndpoint, "HTML does not contain link to custom endpoint %s", codePanelHtml)
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
func Test_Code_Html_getCodeDetailsHtml_hasCSS(t *testing.T) {
	c := testutil.UnitTest(t)

	dataFlow := getDataFlowElements()
	fixes := getFixes()
	repoCount := 54387
	issue := &snyk.Issue{
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

	// Create a fake API client with the feature flag disabled
	apiClient := &snyk_api.FakeApiClient{
		CodeEnabled: true,
	}
	// Set the response for the FeatureFlagStatus method
	apiClient.SetResponse("FeatureFlagStatus", snyk_api.FFResponse{Ok: false})

	// invoke method under test
	htmlRenderer, err := GetHTMLRenderer(c, apiClient)
	assert.NoError(t, err)
	codePanelHtml := htmlRenderer.GetDetailsHtml(issue)
	// assert Fixes section
	assert.Contains(t, codePanelHtml, "--default-font: \"SF Pro Text\", \"Segoe UI\", \"Ubuntu\", Geneva, Verdana, Tahoma, sans-serif;\n")
}
func getDataFlowElements() []snyk.DataFlowElement {
	return []snyk.DataFlowElement{
		{
			Content:  "if (!vulnLines.every(e => selectedLines.includes(e))) return false",
			FilePath: "juice-shop/routes/vulnCodeSnippet.ts",
			FlowRange: types.Range{
				End: types.Position{
					Character: 42,
					Line:      67,
				},
				Start: types.Position{
					Character: 28,
					Line:      67,
				},
			},
			Position: 0,
		},
		{
			Content:  "import * as http from 'http';",
			FilePath: "main.ts",
			FlowRange: types.Range{
				End: types.Position{
					Character: 33,
					Line:      4,
				},
				Start: types.Position{
					Character: 13,
					Line:      4,
				},
			},
			Position: 1,
		},
		{
			Content:  "import { ExpressAdapter } from '@nestjs/platform-express';",
			FilePath: "main.ts",
			FlowRange: types.Range{
				End: types.Position{
					Character: 23,
					Line:      5,
				},
				Start: types.Position{
					Character: 8,
					Line:      5,
				},
			},
			Position: 2,
		},
		{
			Content:  "import { LoggerFactory } from './log';",
			FilePath: "main.ts",
			FlowRange: types.Range{
				End: types.Position{
					Character: 10,
					Line:      9,
				},
				Start: types.Position{
					Character: 9,
					Line:      97,
				},
			},
			Position: 4,
		},
	}
}

func getIssueRange() types.Range {
	return types.Range{
		Start: types.Position{
			Line:      67,
			Character: 28,
		},
		End: types.Position{
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

func Test_Prepare_DataFlowTable(t *testing.T) {
	dataFlow := getDataFlowElements()
	fixes := getFixes()
	repoCount := 54387
	issue := &snyk.Issue{
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
	codeIssueData := issue.AdditionalData.(snyk.CodeIssueData)
	dataFlowKeys, dataFlowItems := prepareDataFlowTable(codeIssueData)

	assert.Equal(t, len(dataFlowKeys), len(dataFlowItems))
	assert.Contains(t, dataFlowItems, "main.ts")
	assert.Equal(t, dataFlowKeys[1], "main.ts")
}

func Test_Prepare_DataFlowTable_Empty(t *testing.T) {
	var codeIssueData snyk.CodeIssueData
	dataFlowKeys, dataFlowItems := prepareDataFlowTable(codeIssueData)

	assert.Equal(t, len(dataFlowKeys), len(dataFlowItems))
	assert.Equal(t, len(dataFlowItems), 0)
	assert.Equal(t, dataFlowKeys, []string(nil))
}

func Test_Code_Html_updateFeatureFlags_VSCodeIntegration_FeatureFlag_Enabled(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetIntegrationName("VS_CODE")

	apiClient := &snyk_api.FakeApiClient{}
	apiClient.SetResponse("FeatureFlagStatus", snyk_api.FFResponse{Ok: true})

	htmlRenderer, err := GetHTMLRenderer(c, apiClient)
	assert.NoError(t, err)

	htmlRenderer.updateFeatureFlags()

	assert.True(t, htmlRenderer.inlineIgnoresEnabled)
}

func Test_Code_Html_updateFeatureFlags_VSCodeIntegration_FeatureFlag_Disabled(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetIntegrationName("VS_CODE")

	apiClient := &snyk_api.FakeApiClient{}
	apiClient.SetResponse("FeatureFlagStatus", snyk_api.FFResponse{Ok: false})

	htmlRenderer, err := GetHTMLRenderer(c, apiClient)
	assert.NoError(t, err)

	htmlRenderer.updateFeatureFlags()

	assert.False(t, htmlRenderer.inlineIgnoresEnabled)
}

func Test_Code_Html_updateFeatureFlags_NonVSCodeIntegration(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetIntegrationName("ECLIPSE") // Set a non-VSCode integration name

	// Create a fake API client
	apiClient := &snyk_api.FakeApiClient{}
	// Set the feature flag to true, to ensure the integration name is the deciding factor
	apiClient.SetResponse("FeatureFlagStatus", snyk_api.FFResponse{Ok: true})

	htmlRenderer, err := GetHTMLRenderer(c, apiClient)
	assert.NoError(t, err)
	assert.NotNil(t, htmlRenderer)

	// Call the method under test
	htmlRenderer.updateFeatureFlags()

	// Assert that inlineIgnoresEnabled is false because the integration is not VS_CODE
	assert.False(t, htmlRenderer.inlineIgnoresEnabled, "inlineIgnoresEnabled should be false for non-VSCode integrations")
}

func Test_prepareIgnoreDetailsRow(t *testing.T) {
	ignoredOn := time.Now()

	testCases := []struct {
		name          string
		ignoreDetails *types.IgnoreDetails
		expectedValue []string
	}{
		{
			name: "should format wont-fix correctly",
			ignoreDetails: &types.IgnoreDetails{
				Category:   "wont-fix",
				Reason:     "test reason",
				Expiration: "",
				IgnoredOn:  ignoredOn,
				IgnoredBy:  "John Smith",
				Status:     codeClientSarif.Accepted,
			},
			expectedValue: []string{
				"Ignored permanently",
				"No expiration",
				formatDate(ignoredOn),
				"John Smith",
				"test reason",
				"Approved",
			},
		},
		{
			name: "should format temporary-ignore correctly",
			ignoreDetails: &types.IgnoreDetails{
				Category:   "temporary-ignore",
				Reason:     "another reason",
				Expiration: time.Now().Add(73 * time.Hour).Format(time.RFC3339),
				IgnoredOn:  ignoredOn,
				IgnoredBy:  "Jane Doe",
				Status:     codeClientSarif.UnderReview,
			},
			expectedValue: []string{
				"Ignored temporarily",
				"3 days",
				formatDate(ignoredOn),
				"Jane Doe",
				"another reason",
				"Pending",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			row := prepareIgnoreDetailsRow(tc.ignoreDetails)
			for i, detail := range row {
				assert.Equal(t, tc.expectedValue[i], detail.Value)
			}
			assert.Equal(t, len(tc.expectedValue), len(row))
		})
	}
}
