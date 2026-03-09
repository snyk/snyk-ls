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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestToHovers(t *testing.T) {
	testutil.UnitTest(t)
	testIssue := &snyk.Issue{FormattedMessage: "<br><br/><br />"}
	hovers := ToHovers([]types.Issue{testIssue})
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
