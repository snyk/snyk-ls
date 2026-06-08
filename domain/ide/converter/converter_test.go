/*
 * © 2022 Snyk Limited All rights reserved.
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

package converter

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
)

func TestToHovers(t *testing.T) {
	engine := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockResolver := mock_types.NewMockConfigResolverInterface(ctrl)
	mockResolver.EXPECT().GetInt(types.SettingHoverVerbosity, nil).Return(1).AnyTimes()
	mockResolver.EXPECT().GetString(types.SettingFormat, nil).Return("md").AnyTimes()
	testIssue := &snyk.Issue{FormattedMessage: "<br><br/><br />"}
	hovers := ToHovers(engine, mockResolver, []types.Issue{testIssue}, nil)
	require.Len(t, hovers, 1, "expected 1 hover")
	assert.Equal(t, "\n\n\n\n\n\n", hovers[0].Message)
}

func TestToDiagnostics_OssIssue_RiskScore(t *testing.T) {
	testutil.UnitTest(t)

	expectedRiskScore := uint16(500)
	testIssue := &snyk.Issue{
		ID:       "test-vuln-id",
		Severity: types.High,
		Product:  product.ProductOpenSource,
		AdditionalData: snyk.OssIssueData{
			Key:       "test-key",
			RiskScore: expectedRiskScore,
		},
	}

	diagnostics := ToDiagnostics([]types.Issue{testIssue})

	require.Len(t, diagnostics, 1)
	scanIssue := diagnostics[0].Data

	ossData, ok := scanIssue.AdditionalData.(types.OssIssueData)
	require.True(t, ok, "additional data should be OssIssueData")
	assert.Equal(t, expectedRiskScore, ossData.RiskScore, "RiskScore should be propagated to LSP layer")
}

func TestToDiagnostics_SecretIssue(t *testing.T) {
	testutil.UnitTest(t)

	testIssue := &snyk.Issue{
		ID:       "secret-rule-id",
		Severity: types.High,
		Product:  product.ProductSecrets,
		Message:  "Hardcoded Secret Found",
		Range: types.Range{
			Start: types.Position{Line: 9, Character: 4},
			End:   types.Position{Line: 9, Character: 19},
		},
		AffectedFilePath: "/repo/src/config.yml",
		ContentRoot:      "/repo",
		AdditionalData: snyk.SecretsIssueData{
			Key:        "secret-key-123",
			Title:      "Hardcoded Secret Found",
			Message:    "A hardcoded secret was detected",
			RuleId:     "hardcoded-secret",
			RuleName:   "Hardcoded Secret",
			CWE:        []string{"CWE-798"},
			Categories: []string{"Security"},
			Cols:       snyk.CodePoint{4, 19},
			Rows:       snyk.CodePoint{9, 9},
		},
	}

	diagnostics := ToDiagnostics([]types.Issue{testIssue})

	require.Len(t, diagnostics, 1)
	scanIssue := diagnostics[0].Data

	assert.Equal(t, "secret-key-123", scanIssue.Id)
	assert.Equal(t, "Hardcoded Secret Found", scanIssue.Title)
	assert.Equal(t, "high", scanIssue.Severity)
	assert.Equal(t, types.FilePath("/repo/src/config.yml"), scanIssue.FilePath)
	assert.Equal(t, types.FilePath("/repo"), scanIssue.ContentRoot)
	assert.Equal(t, product.FilterableIssueTypeSecrets, scanIssue.FilterableIssueType)

	secretData, ok := scanIssue.AdditionalData.(types.SecretIssueData)
	require.True(t, ok, "additional data should be types.SecretsIssueData")
	assert.Equal(t, "secret-key-123", secretData.Key)
	assert.Equal(t, "Hardcoded Secret Found", secretData.Title)
	assert.Equal(t, "A hardcoded secret was detected", secretData.Message)
	assert.Equal(t, "hardcoded-secret", secretData.RuleId)
	assert.Equal(t, "Hardcoded Secret", secretData.RuleName)
	assert.Equal(t, []string{"CWE-798"}, secretData.CWE)
	assert.Equal(t, []string{"Security"}, secretData.Categories)
	assert.Equal(t, types.Point{4, 19}, secretData.Cols)
	assert.Equal(t, types.Point{9, 9}, secretData.Rows)
}

func TestToDiagnostics_SecretIssue_WithIgnoreDetails(t *testing.T) {
	testutil.UnitTest(t)

	testIssue := &snyk.Issue{
		ID:        "secret-rule-id",
		Severity:  types.High,
		Product:   product.ProductSecrets,
		IsIgnored: true,
		IgnoreDetails: &types.IgnoreDetails{
			Category:   "not-vulnerable",
			Reason:     "Known false positive",
			Expiration: "2024-12-31",
			IgnoredBy:  "test@example.com",
		},
		AdditionalData: snyk.SecretsIssueData{
			Key:   "secret-key-456",
			Title: "Ignored Secret",
		},
	}

	diagnostics := ToDiagnostics([]types.Issue{testIssue})

	require.Len(t, diagnostics, 1)
	scanIssue := diagnostics[0].Data

	assert.True(t, scanIssue.IsIgnored)
	assert.Equal(t, "not-vulnerable", scanIssue.IgnoreDetails.Category)
	assert.Equal(t, "Known false positive", scanIssue.IgnoreDetails.Reason)
	assert.Equal(t, "2024-12-31", scanIssue.IgnoreDetails.Expiration)
	assert.Equal(t, "test@example.com", scanIssue.IgnoreDetails.IgnoredBy)
}

func TestGetCvssCalculatorUrl(t *testing.T) {
	testutil.UnitTest(t)

	t.Run("should return CVSS v4.0 calculator URL when first source is v4.0", func(t *testing.T) {
		cvssSources := []types.CvssSource{
			{
				Type:        "primary",
				CvssVersion: "4.0",
				Vector:      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
			},
			{
				Type:        "secondary",
				CvssVersion: "3.1",
				Vector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			},
		}

		url := types.GetCvssCalculatorUrl(cvssSources)
		expected := "https://www.first.org/cvss/calculator/4.0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
		assert.Equal(t, expected, url)
	})

	t.Run("should return CVSS v3.1 calculator URL when source is v3.1", func(t *testing.T) {
		cvssSources := []types.CvssSource{
			{
				Type:        "primary",
				CvssVersion: "3.1",
				Vector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			},
		}

		url := types.GetCvssCalculatorUrl(cvssSources)
		expected := "https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
		assert.Equal(t, expected, url)
	})

	t.Run("should return empty string when no cvssSources", func(t *testing.T) {
		cvssSources := []types.CvssSource{}

		url := types.GetCvssCalculatorUrl(cvssSources)
		expected := ""
		assert.Equal(t, expected, url)
	})

	t.Run("should return CVSS v3.1 calculator URL when first source is v3.1 and second is v4.0", func(t *testing.T) {
		cvssSources := []types.CvssSource{
			{
				Type:        "primary",
				CvssVersion: "3.1",
				Vector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			},
			{
				Type:        "secondary",
				CvssVersion: "4.0",
				Vector:      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
			},
		}
		url := types.GetCvssCalculatorUrl(cvssSources)
		expected := "https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
		assert.Equal(t, expected, url)
	})

	t.Run("should return CVSS v4.0 calculator URL when source is v4.0", func(t *testing.T) {
		cvssSources := []types.CvssSource{
			{
				Type:        "secondary",
				CvssVersion: "4.0",
				Vector:      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
			},
		}
		url := types.GetCvssCalculatorUrl(cvssSources)
		expected := "https://www.first.org/cvss/calculator/4.0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
		assert.Equal(t, expected, url)
	})

	t.Run("should return CVSS v3.1 calculator URL when source is v3.1", func(t *testing.T) {
		cvssSources := []types.CvssSource{
			{
				Type:        "secondary",
				CvssVersion: "3.1",
				Vector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			},
		}
		url := types.GetCvssCalculatorUrl(cvssSources)
		expected := "https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
		assert.Equal(t, expected, url)
	})

	t.Run("should default to CVSS v4.0 when version is not recognized", func(t *testing.T) {
		cvssSources := []types.CvssSource{
			{
				Type:        "primary",
				CvssVersion: "2.0",
				Vector:      "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",
			},
		}
		url := types.GetCvssCalculatorUrl(cvssSources)
		expected := "https://www.first.org/cvss/calculator/4.0#CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P"
		assert.Equal(t, expected, url)
	})

	t.Run("should return CVSS v4.0 calculator URL when second source is v4.0 and first is unrecognized", func(t *testing.T) {
		cvssSources := []types.CvssSource{
			{
				Type:        "primary",
				CvssVersion: "2.0",
				Vector:      "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",
			},
			{
				Type:        "secondary",
				CvssVersion: "4.0",
				Vector:      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
			},
		}
		url := types.GetCvssCalculatorUrl(cvssSources)
		expected := "https://www.first.org/cvss/calculator/4.0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
		assert.Equal(t, expected, url)
	})

	t.Run("should return CVSS v3.1 calculator URL when second source is v3.1 and first is unrecognized", func(t *testing.T) {
		cvssSources := []types.CvssSource{
			{
				Type:        "primary",
				CvssVersion: "2.0",
				Vector:      "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",
			},
			{
				Type:        "secondary",
				CvssVersion: "3.1",
				Vector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			},
		}
		url := types.GetCvssCalculatorUrl(cvssSources)
		expected := "https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
		assert.Equal(t, expected, url)
	})
}

// TestToDiagnostics_FindingId verifies that ScanIssue.FindingId is populated from issue.GetFindingId()
// for each product. A stable FindingId allows clients to correlate the same underlying finding across
// separate scan invocations without relying on the per-result-set Id field.
func TestToDiagnostics_FindingId_Code(t *testing.T) {
	testutil.UnitTest(t)

	const expectedFindingId = "snyk-asset-finding-v1-abc123"
	testIssue := &snyk.Issue{
		ID:        "code-rule-id",
		Severity:  types.High,
		Product:   product.ProductCode,
		FindingId: expectedFindingId,
		AdditionalData: snyk.CodeIssueData{
			Key: "code-key-1",
		},
	}

	diagnostics := ToDiagnostics([]types.Issue{testIssue})

	require.Len(t, diagnostics, 1)
	assert.Equal(t, expectedFindingId, diagnostics[0].Data.FindingId,
		"ScanIssue.FindingId must equal issue.GetFindingId() for Code issues")
}

func TestToDiagnostics_FindingId_OSS(t *testing.T) {
	testutil.UnitTest(t)

	const expectedFindingId = "oss-introducing-finding-id-xyz"
	testIssue := &snyk.Issue{
		ID:        "oss-vuln-id",
		Severity:  types.Medium,
		Product:   product.ProductOpenSource,
		FindingId: expectedFindingId,
		AdditionalData: snyk.OssIssueData{
			Key: "oss-key-1",
		},
	}

	diagnostics := ToDiagnostics([]types.Issue{testIssue})

	require.Len(t, diagnostics, 1)
	assert.Equal(t, expectedFindingId, diagnostics[0].Data.FindingId,
		"ScanIssue.FindingId must equal issue.GetFindingId() for OSS issues")
}

func TestToDiagnostics_FindingId_Secrets(t *testing.T) {
	testutil.UnitTest(t)

	const expectedFindingId = "secret-attrs-key-99"
	testIssue := &snyk.Issue{
		ID:        "secret-rule-id",
		Severity:  types.High,
		Product:   product.ProductSecrets,
		FindingId: expectedFindingId,
		AdditionalData: snyk.SecretsIssueData{
			Key:   "secret-key-99",
			Title: "Hardcoded Secret",
		},
	}

	diagnostics := ToDiagnostics([]types.Issue{testIssue})

	require.Len(t, diagnostics, 1)
	assert.Equal(t, expectedFindingId, diagnostics[0].Data.FindingId,
		"ScanIssue.FindingId must equal issue.GetFindingId() for Secrets issues")
}

// TestToDiagnostics_FindingId_IaC documents that IaC findings currently emit an empty FindingId.
// The IaC scanner does not yet set FindingId on snyk.Issue, so ScanIssue.FindingId is always "".
// When the IaC scanner is updated to set FindingId, this test should be updated to assert the
// expected non-empty value.
func TestToDiagnostics_FindingId_IaC(t *testing.T) {
	testutil.UnitTest(t)

	testIssue := &snyk.Issue{
		ID:       "iac-rule-id",
		Severity: types.High,
		Product:  product.ProductInfrastructureAsCode,
		// FindingId is intentionally not set: the IaC scanner does not yet populate it.
		AdditionalData: snyk.IaCIssueData{
			Key:   "iac-key-1",
			Title: "IaC misconfiguration",
		},
	}

	diagnostics := ToDiagnostics([]types.Issue{testIssue})

	require.Len(t, diagnostics, 1)
	assert.Empty(t, diagnostics[0].Data.FindingId,
		"IaC issues emit empty FindingId until the IaC scanner populates it")
}

// TestToDiagnostics_FindingId_DeterministicConversion verifies that ToDiagnostics is a pure
// function: two calls on the same issue struct produce identical FindingId values.
func TestToDiagnostics_FindingId_DeterministicConversion(t *testing.T) {
	testutil.UnitTest(t)

	const stableFindingId = "stable-code-fingerprint-v1"
	testIssue := &snyk.Issue{
		ID:        "code-rule-id",
		Severity:  types.High,
		Product:   product.ProductCode,
		FindingId: stableFindingId,
		AdditionalData: snyk.CodeIssueData{
			Key: "code-key-stable",
		},
	}

	diagnostics1 := ToDiagnostics([]types.Issue{testIssue})
	diagnostics2 := ToDiagnostics([]types.Issue{testIssue})

	require.Len(t, diagnostics1, 1)
	require.Len(t, diagnostics2, 1)
	assert.Equal(t, diagnostics1[0].Data.FindingId, diagnostics2[0].Data.FindingId,
		"FindingId must be identical across two separate conversions of the same finding")
	assert.Equal(t, stableFindingId, diagnostics1[0].Data.FindingId,
		"FindingId must match the value from issue.GetFindingId()")
}

func TestToCodeAction_KindDerived_RemediationAgent(t *testing.T) {
	testutil.UnitTest(t)

	issue := &snyk.Issue{}
	action := &snyk.CodeAction{
		Title:         "Fix with Snyk Remediation Agent",
		OriginalTitle: "Fix with Snyk Remediation Agent",
		Kind:          types.RemediationAgentQuickFix,
		Command:       nil,
		Edit:          &types.WorkspaceEdit{Changes: map[string][]types.TextEdit{}},
	}
	issue.CodeActions = []types.CodeAction{action}

	result := ToCodeAction(issue, action)

	assert.Equal(t, types.RemediationAgentQuickFix, result.Kind)
}

func TestToCodeAction_KindDerived_Empty_FallsBackToQuickFix(t *testing.T) {
	testutil.UnitTest(t)

	issue := &snyk.Issue{}
	action := &snyk.CodeAction{
		Title:         "Some action",
		OriginalTitle: "Some action",
		Kind:          types.Empty,
		Command:       nil,
		Edit:          &types.WorkspaceEdit{Changes: map[string][]types.TextEdit{}},
	}
	issue.CodeActions = []types.CodeAction{action}

	result := ToCodeAction(issue, action)

	assert.Equal(t, types.QuickFix, result.Kind)
}

func TestToCodeAction_KindDerived_ExistingQuickfix_NoRegression(t *testing.T) {
	testutil.UnitTest(t)

	issue := &snyk.Issue{}
	action := &snyk.CodeAction{
		Title:         "Fix this",
		OriginalTitle: "Fix this",
		// Kind is zero-value (empty string) — existing path
		Edit: &types.WorkspaceEdit{Changes: map[string][]types.TextEdit{}},
	}
	issue.CodeActions = []types.CodeAction{action}

	result := ToCodeAction(issue, action)

	assert.Equal(t, types.QuickFix, result.Kind, "existing actions without explicit Kind must fall back to QuickFix")
}
