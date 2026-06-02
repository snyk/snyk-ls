/*
 * © 2026 Snyk Limited
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

package secrets

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_Secrets_Html_BasicIssue(t *testing.T) {
	engine := testutil.UnitTest(t)

	issue := createBasicSecretIssue()

	fakeFeatureFlagService := featureflag.NewFakeService()

	htmlRenderer, err := NewHtmlRenderer(engine, fakeFeatureFlagService)
	assert.NoError(t, err)

	result := htmlRenderer.GetDetailsHtml(issue)

	// assert title and message
	assert.Contains(t, result, "AWS Access Token")
	assert.Contains(t, result, "Detected a hardcoded AWS access token")

	// assert severity icon present
	assert.Contains(t, result, "severity-icon")

	// assert CWEs
	assert.Contains(t, result, "CWE-798")

	// assert categories
	assert.Contains(t, result, "Security")

	// FilePath is passed as template data for IDE script use, not rendered visually

	// assert position line
	assert.Contains(t, result, "id=\"position-line\"")

	// assert CSS is embedded
	assert.Contains(t, result, "--default-font")

	// assert injectable style/script placeholders
	assert.Contains(t, result, "${ideStyle}")
	assert.Contains(t, result, "${ideScript}")

	// assert Ignore Details section is NOT present
	assert.NotContains(t, result, `class="sn-status-message mod-warning"`)
	assert.NotContains(t, result, `class="sn-ignore-badge"`)
	assert.NotContains(t, result, `data-content="ignore-details"`)

	// assert IAW form is NOT present (feature flag disabled)
	assert.NotContains(t, result, `id="ignore-form-container"`)
}

func Test_Secrets_Html_IgnoredIssue(t *testing.T) {
	engine := testutil.UnitTest(t)

	issue := createBasicSecretIssue()
	issue.IsIgnored = true
	issue.IgnoreDetails = &types.IgnoreDetails{
		Category:   "wont-fix",
		Reason:     "Not a real secret, used in test fixtures.",
		Expiration: "",
		IgnoredOn:  time.Now(),
		IgnoredBy:  "John Smith",
		Status:     testapi.SuppressionStatusIgnored,
	}

	fakeFeatureFlagService := featureflag.NewFakeService()

	htmlRenderer, err := NewHtmlRenderer(engine, fakeFeatureFlagService)
	assert.NoError(t, err)

	result := htmlRenderer.GetDetailsHtml(issue)

	// assert ignored banner
	assert.Contains(t, result, `class="sn-status-message mod-warning"`)
	assert.Contains(t, result, "This issue is currently ignored")

	// assert IGNORED badge
	assert.Contains(t, result, "IGNORED")

	// assert ignore details table
	assert.Contains(t, result, `data-content="ignore-details"`)
	assert.Contains(t, result, `<td class="ignore-details-value">No expiration</td>`)
	assert.Contains(t, result, `<td class="ignore-details-value">John Smith</td>`)

	// assert footer ignore actions are NOT present when ignored
	assert.NotContains(t, result, `id="ignore-actions"`)
}

func Test_Secrets_Html_PendingIssue(t *testing.T) {
	engine := testutil.UnitTest(t)

	issue := createBasicSecretIssue()
	issue.IsIgnored = false
	issue.IgnoreDetails = &types.IgnoreDetails{
		Category:   "wont-fix",
		Reason:     "Not a real secret.",
		Expiration: "",
		IgnoredOn:  time.Now(),
		IgnoredBy:  "Jane Doe",
		Status:     testapi.SuppressionStatusPendingIgnoreApproval,
	}

	fakeFeatureFlagService := featureflag.NewFakeService()

	htmlRenderer, err := NewHtmlRenderer(engine, fakeFeatureFlagService)
	assert.NoError(t, err)

	result := htmlRenderer.GetDetailsHtml(issue)

	// assert pending banner
	assert.Contains(t, result, `class="sn-status-message mod-warning"`)
	assert.Contains(t, result, "This issue will be ignored once the request is approved")

	// assert PENDING IGNORE badge
	assert.Contains(t, result, "PENDING IGNORE")

	// assert ignore details table
	assert.Contains(t, result, `data-content="ignore-details"`)

	// assert pending ignore URL
	assert.Contains(t, result, "/ignore-requests")

	// assert footer ignore actions are NOT present when pending
	assert.NotContains(t, result, `id="ignore-actions"`)
}

func Test_Secrets_Html_CCIEnabled(t *testing.T) {
	engine := testutil.UnitTest(t)

	issue := createBasicSecretIssue()

	fakeFeatureFlagService := featureflag.NewFakeService()
	fakeFeatureFlagService.Flags[featureflag.SnykCodeConsistentIgnores] = true

	htmlRenderer, err := NewHtmlRenderer(engine, fakeFeatureFlagService)
	assert.NoError(t, err)

	result := htmlRenderer.GetDetailsHtml(issue)

	// assert IAW form is present
	assert.Contains(t, result, `id="ignore-form-container"`)
	assert.Contains(t, result, `id="ignore-reason-error"`)
	assert.Contains(t, result, `id="ignore-form-submit"`)

	// assert "Create ignore" button in footer
	assert.Contains(t, result, `id="ignore-create"`)
}

func Test_Secrets_Html_hiddenClassIsImportant(t *testing.T) {
	// ignore_styles.css is concatenated AFTER the panel stylesheet,
	// so an equal-specificity component rule (.sn-ignore-issue-container { display: flex })
	// wins over .hidden { display: none } on source order. Pinning !important keeps
	// the form invisible on load until JS removes the hidden class.
	engine := testutil.UnitTest(t)

	issue := createBasicSecretIssue()

	fakeFeatureFlagService := featureflag.NewFakeService()
	fakeFeatureFlagService.Flags[featureflag.SnykCodeConsistentIgnores] = true

	htmlRenderer, err := NewHtmlRenderer(engine, fakeFeatureFlagService)
	assert.NoError(t, err)

	secretsPanelHtml := htmlRenderer.GetDetailsHtml(issue)
	assert.Regexp(t, `\.hidden\s*\{\s*display:\s*none\s*!important\s*;?\s*\}`, secretsPanelHtml)
}

func Test_Secrets_Html_formInputsDoNotUseBorderAsBackground(t *testing.T) {
	// .sn-select / .sn-input / .sn-textarea must not use --input-border
	// as their background-color (the border variable produces a flat appearance
	// where background and border collapse to the same color, particularly in
	// Eclipse). They should use --input-background instead.
	engine := testutil.UnitTest(t)

	issue := createBasicSecretIssue()

	fakeFeatureFlagService := featureflag.NewFakeService()
	fakeFeatureFlagService.Flags[featureflag.SnykCodeConsistentIgnores] = true

	htmlRenderer, err := NewHtmlRenderer(engine, fakeFeatureFlagService)
	assert.NoError(t, err)

	secretsPanelHtml := htmlRenderer.GetDetailsHtml(issue)

	assert.Regexp(t, `\.sn-select[^}]*background-color:\s*var\(--input-background\)`, secretsPanelHtml)
	assert.Regexp(t, `\.sn-input[^}]*background-color:\s*var\(--input-background\)`, secretsPanelHtml)
	assert.Regexp(t, `\.sn-textarea[^}]*background-color:\s*var\(--input-background\)`, secretsPanelHtml)
}

func Test_Secrets_Html_InvalidAdditionalData(t *testing.T) {
	engine := testutil.UnitTest(t)

	issue := &snyk.Issue{
		ID:             "test-issue",
		Severity:       2,
		AdditionalData: snyk.CodeIssueData{}, // wrong type
	}

	fakeFeatureFlagService := featureflag.NewFakeService()

	htmlRenderer, err := NewHtmlRenderer(engine, fakeFeatureFlagService)
	assert.NoError(t, err)

	result := htmlRenderer.GetDetailsHtml(issue)

	assert.Empty(t, result)
}

func Test_Secrets_Html_NilFeatureFlagService(t *testing.T) {
	engine := testutil.UnitTest(t)

	_, err := NewHtmlRenderer(engine, nil)
	assert.Error(t, err)
}

func createBasicSecretIssue() *snyk.Issue {
	return &snyk.Issue{
		ID:       "aws-access-token",
		Severity: types.High,
		Range: types.Range{
			Start: types.Position{Line: 10, Character: 5},
			End:   types.Position{Line: 10, Character: 40},
		},
		CWEs:             []string{"CWE-798"},
		AffectedFilePath: types.FilePath("/test/file.go"),
		AdditionalData: snyk.SecretsIssueData{
			Key:        "secret-key-1",
			Title:      "AWS Access Token",
			Message:    "Detected a hardcoded AWS access token",
			RuleId:     "aws-access-token",
			RuleName:   "AWS Access Token Rule",
			CWE:        []string{"CWE-798"},
			Categories: []string{"Security"},
		},
	}
}
