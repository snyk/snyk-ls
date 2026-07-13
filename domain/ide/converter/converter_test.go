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
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/domain/snyk/mock_snyk"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
	"github.com/snyk/snyk-ls/internal/util"
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

// TestToDiagnostics_FindingId_Composite verifies that ScanIssue.FindingId is the CP-1 composite
// identity — util.ComputeFindingIdentity(groupingKey, rootRelativePath, range) — for every
// product. The grouping key is issue.GetFindingId(), except IaC, which never populates it and
// instead uses its location-independent publicID (its per-result-set Key bakes the absolute
// path in and so is not worktree-portable). The composite is stable across scans, instance-unique
// (the range discriminates two findings sharing a grouping key), and root-relative (portable
// across a worktree copy), unlike the per-result-set Id field.
//
// NOTE: this test drives ToDiagnostics (no canonical folder root supplied), so it exercises the
// issue-ContentRoot fallback path (canonicalContentRoot falls back to issue.GetContentRoot()).
// The canonical-override path (a folder root supplied to ToDiagnosticsForFolder) is covered in
// converter_finding_identity_test.go.
func TestToDiagnostics_FindingId_Composite(t *testing.T) {
	testutil.UnitTest(t)

	r := types.Range{
		Start: types.Position{Line: 4, Character: 2},
		End:   types.Position{Line: 4, Character: 20},
	}

	cases := []struct {
		name        string
		product     product.Product
		groupingKey string
		// expectedGroupingKey is the grouping key the converter actually uses. It
		// equals groupingKey except for IaC, whose GetFindingId() is empty and which
		// uses its location-independent publicID (never the abs-path-based Key).
		expectedGroupingKey string
		filePath            types.FilePath
		contentRoot         types.FilePath
		expectedRelate      string
		additionalData      types.IssueAdditionalData
	}{
		{"Code", product.ProductCode, "snyk-asset-finding-v1-abc123", "snyk-asset-finding-v1-abc123", "/repo/src/a.go", "/repo", "src/a.go", snyk.CodeIssueData{Key: "code-key-1"}},
		{"OSS", product.ProductOpenSource, "oss-introducing-finding-id-xyz", "oss-introducing-finding-id-xyz", "/repo/package.json", "/repo", "package.json", snyk.OssIssueData{Key: "oss-key-1"}},
		{"Secrets", product.ProductSecrets, "secret-attrs-key-99", "secret-attrs-key-99", "/repo/config.yml", "/repo", "config.yml", snyk.SecretsIssueData{Key: "secret-key-99", Title: "Hardcoded Secret"}},
		// IaC: GetFindingId() is empty (scanner never sets it); the converter uses the
		// location-independent publicID as the grouping key, not the abs-path-based Key.
		{"IaC", product.ProductInfrastructureAsCode, "", "SNYK-CC-TF-1", "/repo/main.tf", "/repo", "main.tf", snyk.IaCIssueData{Key: "iac-key-1", PublicId: "SNYK-CC-TF-1", Title: "IaC misconfiguration"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			testIssue := &snyk.Issue{
				ID:               tc.name + "-rule-id",
				Severity:         types.High,
				Product:          tc.product,
				FindingId:        tc.groupingKey,
				AffectedFilePath: tc.filePath,
				ContentRoot:      tc.contentRoot,
				Range:            r,
				AdditionalData:   tc.additionalData,
			}

			diagnostics := ToDiagnostics([]types.Issue{testIssue})

			require.Len(t, diagnostics, 1)
			expected := util.ComputeFindingIdentity(tc.expectedGroupingKey, tc.expectedRelate,
				r.Start.Line, r.Start.Character, r.End.Line, r.End.Character)
			assert.Equal(t, expected, diagnostics[0].Data.FindingId,
				"ScanIssue.FindingId must be the composite identity for %s issues", tc.name)
			assert.NotEmpty(t, diagnostics[0].Data.FindingId, "FindingId must be non-empty for %s", tc.name)
		})
	}
}

// TestToDiagnostics_FindingId_DeterministicConversion verifies that ToDiagnostics is a pure
// function: two calls on the same issue struct produce identical FindingId values.
func TestToDiagnostics_FindingId_DeterministicConversion(t *testing.T) {
	testutil.UnitTest(t)

	testIssue := &snyk.Issue{
		ID:               "code-rule-id",
		Severity:         types.High,
		Product:          product.ProductCode,
		FindingId:        "stable-code-fingerprint-v1",
		AffectedFilePath: "/repo/src/stable.go",
		ContentRoot:      "/repo",
		Range: types.Range{
			Start: types.Position{Line: 2, Character: 1},
			End:   types.Position{Line: 2, Character: 9},
		},
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
	assert.NotEmpty(t, diagnostics1[0].Data.FindingId, "FindingId must be non-empty")
}

// TestFromRange verifies that sglsp.Range is correctly converted to types.Range.
func TestFromRange(t *testing.T) {
	testutil.UnitTest(t)

	lspRange := sglsp.Range{
		Start: sglsp.Position{Line: 3, Character: 7},
		End:   sglsp.Position{Line: 5, Character: 12},
	}

	got := FromRange(lspRange)

	assert.Equal(t, 3, got.Start.Line)
	assert.Equal(t, 7, got.Start.Character)
	assert.Equal(t, 5, got.End.Line)
	assert.Equal(t, 12, got.End.Character)
}

// TestFromPosition verifies that sglsp.Position is correctly converted to types.Position.
func TestFromPosition(t *testing.T) {
	testutil.UnitTest(t)

	pos := sglsp.Position{Line: 10, Character: 4}
	got := FromPosition(pos)

	assert.Equal(t, 10, got.Line)
	assert.Equal(t, 4, got.Character)
}

// TestToTextEdit verifies that a types.TextEdit is converted to sglsp.TextEdit.
func TestToTextEdit(t *testing.T) {
	testutil.UnitTest(t)

	te := types.TextEdit{
		Range: types.Range{
			Start: types.Position{Line: 1, Character: 0},
			End:   types.Position{Line: 2, Character: 0},
		},
		NewText: "replacement\n",
	}

	got := ToTextEdit(te)

	assert.Equal(t, "replacement\n", got.NewText)
	assert.Equal(t, 1, got.Range.Start.Line)
	assert.Equal(t, 2, got.Range.End.Line)
}

// TestToTextEdits verifies that a slice of types.TextEdit is converted to sglsp.TextEdit slice.
func TestToTextEdits(t *testing.T) {
	testutil.UnitTest(t)

	edits := []types.TextEdit{
		{
			Range:   types.Range{Start: types.Position{Line: 0}, End: types.Position{Line: 1}},
			NewText: "first\n",
		},
		{
			Range:   types.Range{Start: types.Position{Line: 2}, End: types.Position{Line: 3}},
			NewText: "second\n",
		},
	}

	got := ToTextEdits(edits)

	require.Len(t, got, 2)
	assert.Equal(t, "first\n", got[0].NewText)
	assert.Equal(t, "second\n", got[1].NewText)
}

// TestToCodeActions_MainPath verifies that ToCodeActions iterates issues and
// produces one LSPCodeAction per code action, deduplicating by title.
func TestToCodeActions_MainPath(t *testing.T) {
	testutil.UnitTest(t)

	action := &snyk.CodeAction{
		Title:         "Fix with AI",
		OriginalTitle: "Fix with AI",
	}
	issue := &snyk.Issue{
		CodeActions: []types.CodeAction{action},
	}

	actions := ToCodeActions([]types.Issue{issue}, "")

	require.Len(t, actions, 1)
	assert.Equal(t, "Fix with AI", actions[0].Title)
}

// TestToCodeActions_Dedup verifies that two issues sharing the same action title
// produce only one LSPCodeAction (dedup by title).
func TestToCodeActions_Dedup(t *testing.T) {
	testutil.UnitTest(t)

	action1 := &snyk.CodeAction{Title: "Shared Action", OriginalTitle: "Shared Action"}
	action2 := &snyk.CodeAction{Title: "Shared Action", OriginalTitle: "Shared Action"}
	issue1 := &snyk.Issue{CodeActions: []types.CodeAction{action1}}
	issue2 := &snyk.Issue{CodeActions: []types.CodeAction{action2}}

	actions := ToCodeActions([]types.Issue{issue1, issue2}, "")

	assert.Len(t, actions, 1, "duplicate titles must be deduplicated")
}

// TestToInlineValue verifies that a snyk.InlineValue is converted to types.InlineValue.
func TestToInlineValue(t *testing.T) {
	testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	expectedRange := types.Range{
		Start: types.Position{Line: 4, Character: 2},
		End:   types.Position{Line: 4, Character: 10},
	}
	mockVal := mock_snyk.NewMockInlineValue(ctrl)
	mockVal.EXPECT().Range().Return(expectedRange)
	mockVal.EXPECT().Text().Return("myVar = 42")

	got := ToInlineValue(mockVal)

	assert.Equal(t, "myVar = 42", got.Text)
	assert.Equal(t, 4, got.Range.Start.Line)
	assert.Equal(t, 2, got.Range.Start.Character)
}

// TestToInlineValues verifies that a slice of snyk.InlineValue is converted correctly.
func TestToInlineValues(t *testing.T) {
	testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	r1 := types.Range{Start: types.Position{Line: 1}, End: types.Position{Line: 1}}
	r2 := types.Range{Start: types.Position{Line: 5}, End: types.Position{Line: 5}}

	v1 := mock_snyk.NewMockInlineValue(ctrl)
	v1.EXPECT().Range().Return(r1)
	v1.EXPECT().Text().Return("a = 1")

	v2 := mock_snyk.NewMockInlineValue(ctrl)
	v2.EXPECT().Range().Return(r2)
	v2.EXPECT().Text().Return("b = 2")

	got := ToInlineValues([]snyk.InlineValue{v1, v2})

	require.Len(t, got, 2)
	assert.Equal(t, "a = 1", got[0].Text)
	assert.Equal(t, "b = 2", got[1].Text)
}

// TestToHoversDocument verifies that ToHoversDocument returns a DocumentHovers
// with the correct path and product, delegating hover conversion to ToHovers.
func TestToHoversDocument(t *testing.T) {
	engine := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockResolver := mock_types.NewMockConfigResolverInterface(ctrl)
	mockResolver.EXPECT().GetInt(types.SettingHoverVerbosity, nil).Return(1).AnyTimes()
	mockResolver.EXPECT().GetString(types.SettingFormat, nil).Return("md").AnyTimes()

	testIssue := &snyk.Issue{Message: "test message"}
	path := types.FilePath("/repo/src/main.go")
	p := product.ProductCode

	doc := ToHoversDocument(engine, mockResolver, p, path, []types.Issue{testIssue}, nil)

	assert.Equal(t, path, doc.Path)
	assert.Equal(t, p, doc.Product)
	require.Len(t, doc.Hover, 1)
	assert.Equal(t, "test message", doc.Hover[0].Message)
}
