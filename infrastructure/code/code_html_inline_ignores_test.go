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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_Code_Html_InlineIgnores_Enabled(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetIntegrationName("VS_CODE")

	// Create a fake API client with the feature flag enabled
	apiClient := &snyk_api.FakeApiClient{
		CodeEnabled: true,
	}
	// Set the response for the FeatureFlagStatus method
	apiClient.SetResponse("FeatureFlagStatus", snyk_api.FFResponse{Ok: true})

	// Get the HTML renderer with the feature flag enabled
	htmlRenderer, err := GetHTMLRenderer(c, apiClient)
	require.NoError(t, err)

	// Create a test issue
	issue := createTestIssue()

	// Get the HTML output
	htmlOutput := htmlRenderer.GetDetailsHtml(issue)

	// Verify that the inline ignores feature is enabled
	assert.True(t, htmlRenderer.inlineIgnoresEnabled, "InlineIgnores should be enabled")

	// Verify that the InlineIgnoresEnabled flag is passed to the template
	// This check should be based on the actual HTML output content, such as checking for UI elements
	// that are conditionally displayed when inline ignores are enabled
	assert.Contains(t, htmlOutput, `<div id="ignore-legacy-actions" class="actions row">`, "HTML should indicate inline ignores are enabled")
}

func Test_Code_Html_InlineIgnores_Disabled(t *testing.T) {
	c := testutil.UnitTest(t)

	// Create a fake API client with the feature flag disabled
	apiClient := &snyk_api.FakeApiClient{
		CodeEnabled: true,
	}
	// Set the response for the FeatureFlagStatus method
	apiClient.SetResponse("FeatureFlagStatus", snyk_api.FFResponse{Ok: false})

	// Get the HTML renderer with the feature flag disabled
	htmlRenderer, err := GetHTMLRenderer(c, apiClient)
	require.NoError(t, err)

	// Verify that the inline ignores feature is disabled
	assert.False(t, htmlRenderer.inlineIgnoresEnabled, "InlineIgnores should be disabled")

	// Create a test issue
	issue := createTestIssue()

	// Get the HTML output
	htmlOutput := htmlRenderer.GetDetailsHtml(issue)

	// Verify that the InlineIgnoresEnabled flag is passed to the template
	// This check should be based on the actual HTML output content
	assert.NotContains(t, htmlOutput, `<div id="ignore-legacy-actions" class="actions row">`, "HTML should indicate inline ignores are disabled")
}

// Helper function to create a test issue
func createTestIssue() *snyk.Issue {
	return &snyk.Issue{
		Range:    getIssueRange(),
		CWEs:     []string{"CWE-123", "CWE-456"},
		ID:       "go/NoHardcodedCredentials/test",
		Severity: 2,
		AdditionalData: snyk.CodeIssueData{
			Title:          "Test Issue",
			IsSecurityType: true,
			PriorityScore:  800,
		},
	}
}
