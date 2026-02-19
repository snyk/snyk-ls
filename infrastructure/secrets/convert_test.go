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
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	codeClientSarif "github.com/snyk/code-client-go/sarif"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func intPtr(v int) *int       { return &v }
func strPtr(v string) *string { return &v }

func newSourceLocation(filePath string, fromLine int, fromCol, toLine, toCol *int) testapi.FindingLocation {
	loc := testapi.FindingLocation{}
	sl := testapi.SourceLocation{
		FilePath:   filePath,
		FromLine:   fromLine,
		FromColumn: fromCol,
		ToLine:     toLine,
		ToColumn:   toCol,
	}
	_ = loc.FromSourceLocation(sl)
	return loc
}

func newCweProblem(id string) testapi.Problem {
	p := testapi.Problem{}
	_ = p.FromCweProblem(testapi.CweProblem{Id: id})
	return p
}

func newSecretsRuleProblem(id, name string, categories []string) testapi.Problem {
	p := testapi.Problem{}
	_ = p.FromSecretsRuleProblem(testapi.SecretsRuleProblem{Id: id, Name: name, Categories: categories})
	return p
}

func newFinding(key, title, description string, severity testapi.Severity, locations []testapi.FindingLocation, problems []testapi.Problem, suppression *testapi.Suppression) testapi.FindingData {
	id := uuid.New()
	return testapi.FindingData{
		Id: &id,
		Attributes: &testapi.FindingAttributes{
			Key:         key,
			Title:       title,
			Description: description,
			Rating:      testapi.Rating{Severity: severity},
			Locations:   locations,
			Problems:    problems,
			Suppression: suppression,
		},
	}
}

func TestToIssues_SingleFinding_SingleLocation(t *testing.T) {
	c := testutil.UnitTest(t)
	logger := c.Logger()
	converter := NewFindingsConverter(logger)

	loc := newSourceLocation("src/config.yml", 10, intPtr(5), intPtr(10), intPtr(20))
	cwe := newCweProblem("CWE-798")
	rule := newSecretsRuleProblem("hardcoded-secret", "Hardcoded Secret", []string{"Security"})
	finding := newFinding("test-key", "Hardcoded Secret Found", "A hardcoded secret was detected", testapi.SeverityHigh, []testapi.FindingLocation{loc}, []testapi.Problem{cwe, rule}, nil)

	issues := converter.ToIssues([]testapi.FindingData{finding}, "/scan/path", "/folder/path")

	require.Len(t, issues, 1)
	issue := issues[0]

	assert.Equal(t, "hardcoded-secret", issue.GetID())
	assert.Equal(t, types.High, issue.GetSeverity())
	assert.Equal(t, types.CodeSecurityVulnerability, issue.GetIssueType())
	assert.Equal(t, product.ProductSecrets, issue.GetProduct())
	assert.Equal(t, "Hardcoded Secret Found: A hardcoded secret was detected", issue.GetMessage())
	assert.NotEmpty(t, issue.GetFormattedMessage())
	assert.Contains(t, issue.GetFormattedMessage(), "High Severity")
	assert.Contains(t, issue.GetFormattedMessage(), "Hardcoded Secret Found")
	assert.Contains(t, issue.GetFormattedMessage(), "A hardcoded secret was detected")
	assert.Contains(t, issue.GetFormattedMessage(), "CWE-798")
	assert.Equal(t, types.FilePath(filepath.Join("/scan/path", "src/config.yml")), issue.GetAffectedFilePath())
	assert.Equal(t, types.FilePath("/folder/path"), issue.GetContentRoot())
	assert.Equal(t, []string{"CWE-798"}, issue.GetCWEs())
	assert.False(t, issue.GetIsIgnored())
	assert.Nil(t, issue.GetIgnoreDetails())

	// Verify 0-based range conversion (API is 1-based)
	expectedRange := types.Range{
		Start: types.Position{Line: 9, Character: 4},
		End:   types.Position{Line: 9, Character: 19},
	}
	assert.Equal(t, expectedRange, issue.GetRange())

	// Verify additional data
	additionalData, ok := issue.GetAdditionalData().(snyk.SecretIssueData)
	require.True(t, ok)
	assert.Equal(t, "test-key", additionalData.Key)
	assert.Equal(t, "Hardcoded Secret Found", additionalData.Title)
	assert.Equal(t, "A hardcoded secret was detected", additionalData.Message)
	assert.Equal(t, "hardcoded-secret", additionalData.RuleId)
	assert.Equal(t, "Hardcoded Secret", additionalData.RuleName)
	assert.Equal(t, []string{"CWE-798"}, additionalData.CWE)
	assert.Equal(t, []string{"Security"}, additionalData.Categories)
	assert.Equal(t, snyk.CodePoint{4, 19}, additionalData.Cols)
	assert.Equal(t, snyk.CodePoint{9, 9}, additionalData.Rows)
}

func TestToIssues_MultipleLocations_DuplicatesFinding(t *testing.T) {
	c := testutil.UnitTest(t)
	logger := c.Logger()
	converter := NewFindingsConverter(logger)

	loc1 := newSourceLocation("src/config.yml", 10, intPtr(1), intPtr(10), intPtr(30))
	loc2 := newSourceLocation("src/other.yml", 20, intPtr(5), intPtr(20), intPtr(40))
	finding := newFinding("dup-key", "Secret Found", "desc", testapi.SeverityMedium, []testapi.FindingLocation{loc1, loc2}, nil, nil)

	issues := converter.ToIssues([]testapi.FindingData{finding}, "/scan", "/folder")

	require.Len(t, issues, 2)

	assert.Equal(t, types.FilePath(filepath.Join("/scan", "src/config.yml")), issues[0].GetAffectedFilePath())
	assert.Equal(t, types.FilePath(filepath.Join("/scan", "src/other.yml")), issues[1].GetAffectedFilePath())

	// Both share the same rule ID and metadata
	assert.Equal(t, issues[0].GetID(), issues[1].GetID())
	assert.Equal(t, issues[0].GetSeverity(), issues[1].GetSeverity())

	// But different ranges
	assert.Equal(t, 9, issues[0].GetRange().Start.Line)
	assert.Equal(t, 19, issues[1].GetRange().Start.Line)
}

func TestToIssues_MultipleFindings(t *testing.T) {
	c := testutil.UnitTest(t)
	logger := c.Logger()
	converter := NewFindingsConverter(logger)

	loc1 := newSourceLocation("a.yml", 1, nil, nil, nil)
	loc2 := newSourceLocation("b.yml", 5, nil, nil, nil)
	f1 := newFinding("key-1", "Secret 1", "desc1", testapi.SeverityHigh, []testapi.FindingLocation{loc1}, nil, nil)
	f2 := newFinding("key-2", "Secret 2", "desc2", testapi.SeverityLow, []testapi.FindingLocation{loc2}, nil, nil)

	issues := converter.ToIssues([]testapi.FindingData{f1, f2}, "/scan", "/folder")

	require.Len(t, issues, 2)
	assert.Equal(t, "key-1", issues[0].GetID())
	assert.Equal(t, "key-2", issues[1].GetID())
}

func TestToIssues_NilAttributes_Skipped(t *testing.T) {
	c := testutil.UnitTest(t)
	logger := c.Logger()
	converter := NewFindingsConverter(logger)

	finding := testapi.FindingData{Attributes: nil}
	issues := converter.ToIssues([]testapi.FindingData{finding}, "/scan", "/folder")

	assert.Empty(t, issues)
}

func TestToIssues_EmptyLocations_Skipped(t *testing.T) {
	c := testutil.UnitTest(t)
	logger := c.Logger()
	converter := NewFindingsConverter(logger)

	finding := newFinding("key", "title", "desc", testapi.SeverityLow, []testapi.FindingLocation{}, nil, nil)
	issues := converter.ToIssues([]testapi.FindingData{finding}, "/scan", "/folder")

	assert.Empty(t, issues)
}

func TestToIssues_EmptyFindings(t *testing.T) {
	c := testutil.UnitTest(t)
	logger := c.Logger()
	converter := NewFindingsConverter(logger)

	issues := converter.ToIssues([]testapi.FindingData{}, "/scan", "/folder")

	assert.Empty(t, issues)
}

func TestToIssues_RuleIDFallsBackToKey(t *testing.T) {
	c := testutil.UnitTest(t)
	logger := c.Logger()
	converter := NewFindingsConverter(logger)

	loc := newSourceLocation("file.yml", 1, nil, nil, nil)
	// No secrets rule problem, so ruleID should default to key
	finding := newFinding("fallback-key", "title", "desc", testapi.SeverityLow, []testapi.FindingLocation{loc}, nil, nil)

	issues := converter.ToIssues([]testapi.FindingData{finding}, "/scan", "/folder")

	require.Len(t, issues, 1)
	assert.Equal(t, "fallback-key", issues[0].GetID())
}

func TestToRange_FullCoordinates(t *testing.T) {
	testutil.UnitTest(t)
	sl := testapi.SourceLocation{
		FromLine:   10,
		FromColumn: intPtr(5),
		ToLine:     intPtr(12),
		ToColumn:   intPtr(20),
	}

	r := toRange(sl)

	assert.Equal(t, 9, r.Start.Line)
	assert.Equal(t, 4, r.Start.Character)
	assert.Equal(t, 11, r.End.Line)
	assert.Equal(t, 19, r.End.Character)
}

func TestToRange_MinimalCoordinates(t *testing.T) {
	testutil.UnitTest(t)
	sl := testapi.SourceLocation{
		FromLine: 1,
	}

	r := toRange(sl)

	assert.Equal(t, 0, r.Start.Line)
	assert.Equal(t, 0, r.Start.Character)
	assert.Equal(t, 0, r.End.Line)
	assert.Equal(t, 0, r.End.Character)
}

func TestToRange_EndLineBeforeStartLine_ClampsToStart(t *testing.T) {
	testutil.UnitTest(t)
	sl := testapi.SourceLocation{
		FromLine: 10,
		ToLine:   intPtr(5), // before start
	}

	r := toRange(sl)

	// endLine should be clamped to startLine (9)
	assert.Equal(t, 9, r.Start.Line)
	assert.Equal(t, 9, r.End.Line)
}

func TestExtractProblems_CweAndSecrets(t *testing.T) {
	testutil.UnitTest(t)
	problems := []testapi.Problem{
		newCweProblem("CWE-798"),
		newCweProblem("CWE-259"),
		newSecretsRuleProblem("rule-1", "Hardcoded Password", []string{"Security", "Secrets"}),
	}

	cwes, ruleID, ruleName, categories := extractProblems(problems)

	assert.Equal(t, []string{"CWE-798", "CWE-259"}, cwes)
	assert.Equal(t, "rule-1", ruleID)
	assert.Equal(t, "Hardcoded Password", ruleName)
	assert.Equal(t, []string{"Security", "Secrets"}, categories)
}

func TestExtractProblems_NilProblems(t *testing.T) {
	testutil.UnitTest(t)
	cwes, ruleID, ruleName, categories := extractProblems(nil)

	assert.Nil(t, cwes)
	assert.Empty(t, ruleID)
	assert.Empty(t, ruleName)
	assert.Nil(t, categories)
}

func TestExtractProblems_EmptyProblems(t *testing.T) {
	testutil.UnitTest(t)
	cwes, ruleID, ruleName, categories := extractProblems([]testapi.Problem{})

	assert.Nil(t, cwes)
	assert.Empty(t, ruleID)
	assert.Empty(t, ruleName)
	assert.Nil(t, categories)
}

func TestSuppressionToIgnoreDetails_Nil(t *testing.T) {
	testutil.UnitTest(t)
	isIgnored, details := suppressionToIgnoreDetails(nil)

	assert.False(t, isIgnored)
	assert.Nil(t, details)
}

func TestSuppressionToIgnoreDetails_Ignored(t *testing.T) {
	testutil.UnitTest(t)
	justification := "Known false positive"
	createdAt := time.Date(2024, 2, 23, 16, 8, 25, 0, time.UTC)
	expiresAt := time.Date(2024, 8, 6, 13, 16, 53, 0, time.UTC)

	finding := newFinding("key", "title", "desc", testapi.SeverityHigh,
		[]testapi.FindingLocation{newSourceLocation("f.yml", 1, nil, nil, nil)},
		nil,
		&testapi.Suppression{
			Status:        testapi.SuppressionStatusIgnored,
			Justification: &justification,
			CreatedAt:     &createdAt,
			ExpiresAt:     &expiresAt,
		},
	)

	ignoreDetails := finding.GetIgnoreDetails()
	isIgnored, details := suppressionToIgnoreDetails(ignoreDetails)

	assert.True(t, isIgnored)
	require.NotNil(t, details)
	assert.Equal(t, "Known false positive", details.Reason)
	assert.Equal(t, codeClientSarif.Accepted, details.Status)
	assert.Equal(t, createdAt, details.IgnoredOn)
	assert.Contains(t, details.Expiration, "2024-08-06")
}

func TestSuppressionToIgnoreDetails_PendingApproval(t *testing.T) {
	testutil.UnitTest(t)
	finding := newFinding("key", "title", "desc", testapi.SeverityHigh,
		[]testapi.FindingLocation{newSourceLocation("f.yml", 1, nil, nil, nil)},
		nil,
		&testapi.Suppression{
			Status: testapi.SuppressionStatusPendingIgnoreApproval,
		},
	)

	ignoreDetails := finding.GetIgnoreDetails()
	isIgnored, details := suppressionToIgnoreDetails(ignoreDetails)

	assert.False(t, isIgnored)
	require.NotNil(t, details)
	assert.Equal(t, codeClientSarif.UnderReview, details.Status)
	assert.Equal(t, "None given", details.Reason)
}

func TestSuppressionToIgnoreDetails_NoJustification_DefaultReason(t *testing.T) {
	testutil.UnitTest(t)
	finding := newFinding("key", "title", "desc", testapi.SeverityHigh,
		[]testapi.FindingLocation{newSourceLocation("f.yml", 1, nil, nil, nil)},
		nil,
		&testapi.Suppression{
			Status: testapi.SuppressionStatusIgnored,
		},
	)

	ignoreDetails := finding.GetIgnoreDetails()
	isIgnored, details := suppressionToIgnoreDetails(ignoreDetails)

	assert.True(t, isIgnored)
	require.NotNil(t, details)
	assert.Equal(t, "None given", details.Reason)
}

func TestMapSuppressionStatus(t *testing.T) {
	testutil.UnitTest(t)

	t.Run("ignored maps to accepted", func(t *testing.T) {
		assert.Equal(t, codeClientSarif.Accepted, mapSuppressionStatus(testapi.SuppressionStatusIgnored))
	})

	t.Run("pending_ignore_approval maps to underReview", func(t *testing.T) {
		assert.Equal(t, codeClientSarif.UnderReview, mapSuppressionStatus(testapi.SuppressionStatusPendingIgnoreApproval))
	})

	t.Run("other maps to empty", func(t *testing.T) {
		assert.Equal(t, codeClientSarif.SuppresionStatus(""), mapSuppressionStatus(testapi.SuppressionStatusOther))
	})

	t.Run("unknown maps to empty", func(t *testing.T) {
		assert.Equal(t, codeClientSarif.SuppresionStatus(""), mapSuppressionStatus("something_else"))
	})
}

func TestToSeverity(t *testing.T) {
	testutil.UnitTest(t)

	t.Run("high", func(t *testing.T) {
		assert.Equal(t, types.High, toSeverity("high"))
	})
	t.Run("HIGH (case insensitive)", func(t *testing.T) {
		assert.Equal(t, types.High, toSeverity("HIGH"))
	})
	t.Run("medium", func(t *testing.T) {
		assert.Equal(t, types.Medium, toSeverity("medium"))
	})
	t.Run("low", func(t *testing.T) {
		assert.Equal(t, types.Low, toSeverity("low"))
	})
	t.Run("critical", func(t *testing.T) {
		assert.Equal(t, types.Critical, toSeverity("critical"))
	})
	t.Run("unknown defaults to low", func(t *testing.T) {
		assert.Equal(t, types.Low, toSeverity("unknown"))
	})
	t.Run("empty defaults to low", func(t *testing.T) {
		assert.Equal(t, types.Low, toSeverity(""))
	})
}

func TestGetMessage_TitleAndDescription(t *testing.T) {
	c := testutil.UnitTest(t)
	logger := c.Logger()
	converter := NewFindingsConverter(logger)

	msg := converter.getMessage("Hardcoded Secret", "A secret was found in the code")
	assert.Equal(t, "Hardcoded Secret: A secret was found in the code", msg)
}

func TestGetMessage_EmptyTitle(t *testing.T) {
	c := testutil.UnitTest(t)
	logger := c.Logger()
	converter := NewFindingsConverter(logger)

	msg := converter.getMessage("", "A secret was found in the code")
	assert.Equal(t, "A secret was found in the code", msg)
}

func TestGetMessage_TruncatesLongMessages(t *testing.T) {
	c := testutil.UnitTest(t)
	logger := c.Logger()
	converter := NewFindingsConverter(logger)

	longDesc := strings.Repeat("a", 200)
	msg := converter.getMessage("Title", longDesc)
	assert.Len(t, msg, 100+3) // 100 chars + "..."
	assert.True(t, strings.HasSuffix(msg, "..."))
}

func TestFormattedMessageMarkdown_ContainsSeverityTitleCweAndDescription(t *testing.T) {
	c := testutil.UnitTest(t)
	logger := c.Logger()
	converter := NewFindingsConverter(logger)

	result := converter.formattedMessageMarkdown(types.High, "AWS Access Token", "A hardcoded AWS token was detected", []string{"CWE-798"})

	assert.Contains(t, result, "High Severity")
	assert.Contains(t, result, "AWS Access Token")
	assert.Contains(t, result, "A hardcoded AWS token was detected")
	assert.Contains(t, result, "CWE-798")
	assert.Contains(t, result, "https://cwe.mitre.org/data/definitions/798.html")
}

func TestFormattedMessageMarkdown_NoCwes(t *testing.T) {
	c := testutil.UnitTest(t)
	logger := c.Logger()
	converter := NewFindingsConverter(logger)

	result := converter.formattedMessageMarkdown(types.Medium, "Title", "Description", nil)

	assert.Contains(t, result, "Medium Severity")
	assert.Contains(t, result, "Title")
	assert.Contains(t, result, "Description")
	assert.NotContains(t, result, "Vulnerabilit")
}

func TestFormattedMessageMarkdown_EmptyTitle(t *testing.T) {
	c := testutil.UnitTest(t)
	logger := c.Logger()
	converter := NewFindingsConverter(logger)

	result := converter.formattedMessageMarkdown(types.Low, "", "Description", nil)

	assert.Contains(t, result, "Low Severity")
	assert.NotContains(t, result, " | ")
	assert.Contains(t, result, "Description")
}

func TestFormattedMessageMarkdown_MultipleCwes(t *testing.T) {
	c := testutil.UnitTest(t)
	logger := c.Logger()
	converter := NewFindingsConverter(logger)

	result := converter.formattedMessageMarkdown(types.Critical, "Title", "Desc", []string{"CWE-798", "CWE-259"})

	assert.Contains(t, result, "Critical Severity")
	assert.Contains(t, result, "Vulnerabilities: ")
	assert.Contains(t, result, "CWE-798")
	assert.Contains(t, result, "CWE-259")
}

func TestSeverityToMarkdown(t *testing.T) {
	testutil.UnitTest(t)

	assert.Contains(t, severityToMarkdown(types.Critical), "Critical Severity")
	assert.Contains(t, severityToMarkdown(types.High), "High Severity")
	assert.Contains(t, severityToMarkdown(types.Medium), "Medium Severity")
	assert.Contains(t, severityToMarkdown(types.Low), "Low Severity")
	assert.Contains(t, severityToMarkdown(types.Severity(99)), "Unknown Severity")
}

func TestCweToMarkdown_Empty(t *testing.T) {
	testutil.UnitTest(t)
	assert.Empty(t, cweToMarkdown(nil))
	assert.Empty(t, cweToMarkdown([]string{}))
}

func TestCweToMarkdown_SingleCwe(t *testing.T) {
	testutil.UnitTest(t)
	result := cweToMarkdown([]string{"CWE-798"})
	assert.Contains(t, result, "Vulnerability: ")
	assert.Contains(t, result, "[CWE-798](https://cwe.mitre.org/data/definitions/798.html)")
}

func TestCweToMarkdown_MultipleCwes(t *testing.T) {
	testutil.UnitTest(t)
	result := cweToMarkdown([]string{"CWE-798", "CWE-259"})
	assert.Contains(t, result, "Vulnerabilities: ")
	assert.Contains(t, result, " | ")
}

func TestToIssues_IgnoredFinding(t *testing.T) {
	c := testutil.UnitTest(t)
	logger := c.Logger()
	converter := NewFindingsConverter(logger)

	loc := newSourceLocation("secret.yml", 5, intPtr(1), intPtr(5), intPtr(50))
	finding := newFinding("ignored-key", "Ignored Secret", "desc", testapi.SeverityHigh,
		[]testapi.FindingLocation{loc}, nil,
		&testapi.Suppression{Status: testapi.SuppressionStatusIgnored, Justification: strPtr("False positive")},
	)

	issues := converter.ToIssues([]testapi.FindingData{finding}, "/scan", "/folder")

	require.Len(t, issues, 1)
	assert.True(t, issues[0].GetIsIgnored())
	require.NotNil(t, issues[0].GetIgnoreDetails())
	assert.Equal(t, codeClientSarif.Accepted, issues[0].GetIgnoreDetails().Status)
	assert.Equal(t, "False positive", issues[0].GetIgnoreDetails().Reason)
}

func TestToIssues_FindingIdFromUUID(t *testing.T) {
	c := testutil.UnitTest(t)
	logger := c.Logger()
	converter := NewFindingsConverter(logger)

	loc := newSourceLocation("file.yml", 1, nil, nil, nil)
	finding := newFinding("my-key", "title", "desc", testapi.SeverityLow, []testapi.FindingLocation{loc}, nil, nil)

	issues := converter.ToIssues([]testapi.FindingData{finding}, "/scan", "/folder")

	require.Len(t, issues, 1)
	assert.NotEmpty(t, issues[0].GetFindingId())
	assert.Equal(t, "my-key", issues[0].GetFingerprint())
}

func TestToIssues_NilFindingId(t *testing.T) {
	c := testutil.UnitTest(t)
	logger := c.Logger()
	converter := NewFindingsConverter(logger)

	loc := newSourceLocation("file.yml", 1, nil, nil, nil)
	finding := testapi.FindingData{
		Id: nil,
		Attributes: &testapi.FindingAttributes{
			Key:       "key-no-id",
			Title:     "title",
			Rating:    testapi.Rating{Severity: testapi.SeverityLow},
			Locations: []testapi.FindingLocation{loc},
		},
	}

	issues := converter.ToIssues([]testapi.FindingData{finding}, "/scan", "/folder")

	require.Len(t, issues, 1)
	assert.Equal(t, "key-no-id", issues[0].GetFindingId())
}
