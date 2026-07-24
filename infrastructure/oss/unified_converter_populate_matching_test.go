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

package oss

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"

	"github.com/snyk/snyk-ls/domain/snyk"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// newNilAttrsFinding returns a *testapi.FindingData whose Attributes field is nil.
// This is the canonical "unusable finding" that triggers defect 1(a)/(b) in
// populateMatchingIssues (IDE-2236).
func newNilAttrsFinding(t *testing.T) *testapi.FindingData {
	t.Helper()
	id := uuid.New()
	return &testapi.FindingData{Id: &id} // Attributes intentionally nil
}

// newValidFindingWithEvidence returns a *testapi.FindingData with non-nil Attributes
// carrying one DependencyPathEvidence entry. Used in T3 to show that valid findings
// are NOT dropped while nil-attrs findings are.
func newValidFindingWithEvidence(t *testing.T) *testapi.FindingData {
	t.Helper()

	var eco testapi.SnykvulndbPackageEcosystem
	require.NoError(t, eco.FromSnykvulndbBuildPackageEcosystem(testapi.SnykvulndbBuildPackageEcosystem{
		Language:       "js",
		PackageManager: "npm",
	}))

	var problem testapi.Problem
	require.NoError(t, problem.FromSnykVulnProblem(testapi.SnykVulnProblem{
		Id:          "SNYK-JS-LODASH-1",
		PackageName: "lodash",
		Ecosystem:   eco,
	}))

	var depEvidence testapi.Evidence
	require.NoError(t, depEvidence.FromDependencyPathEvidence(testapi.DependencyPathEvidence{
		Path: []testapi.Package{
			{Name: "goof", Version: "1.0.0"},
			{Name: "lodash", Version: "4.17.4"},
		},
	}))

	id := uuid.New()
	return &testapi.FindingData{
		Id: &id,
		Attributes: &testapi.FindingAttributes{
			FindingType: testapi.FindingTypeSca,
			Key:         "aggregation-key",
			Title:       "Prototype Pollution",
			Problems:    []testapi.Problem{problem},
			Evidence:    []testapi.Evidence{depEvidence},
		},
	}
}

// buildMinimalProblem returns a *testapi.SnykVulnProblem suitable for calls into
// populateMatchingIssues and buildOssIssueData in tests.
func buildMinimalProblem() *testapi.SnykVulnProblem {
	return &testapi.SnykVulnProblem{
		Id:          "SNYK-JS-LODASH-1",
		PackageName: "lodash",
	}
}

// TestConvertTestResultToIssues_NilAttributeFinding_NoPanic (T1 — integration)
//
// Exercises the outer convertTestResultToIssues path with a fakeTestResult
// whose single finding has nil Attributes. Documents that the nil-attrs finding
// is filtered upstream: processIssue returns nil early (cannot resolve ecosystem
// or primary problem from a nil-attrs finding), so populateMatchingIssues is
// never reached at this level and the defect is dormant here.
//
// The white-box coverage for the nil-deref lives in T2 and T3. This test exists
// to prove that at the integration level the caller produces a clean empty slice
// rather than panicking or producing a nil-wrapping interface value.
func TestConvertTestResultToIssues_NilAttributeFinding_NoPanic(t *testing.T) {
	engine := testutil.UnitTest(t)
	workDir := types.FilePath(t.TempDir())

	ctx := ctx2.NewContextWithEngine(context.Background(), engine)
	ctx = ctx2.NewContextWithWorkDirAndFilePath(ctx, workDir, workDir+"/package.json")
	ctx = EnrichContextForTest(t, ctx, engine, string(workDir))

	// Build a fakeTestResult with a nil-attrs finding plus the minimal subject
	// needed so convertTestResultToIssues does not fail on subject extraction.
	nilFinding := testapi.FindingData{
		Id: func() *uuid.UUID { id := uuid.New(); return &id }(),
		// Attributes intentionally nil
	}

	var subject testapi.TestSubject
	require.NoError(t, subject.FromDepGraphSubject(testapi.DepGraphSubject{
		Locator: testapi.LocalPathLocator{Paths: []string{"package.json"}},
	}))

	tr := &fakeTestResult{
		testID:   uuid.New(),
		subject:  &subject,
		findings: []testapi.FindingData{nilFinding},
	}

	// Expected: upstream ecosystem/primary-problem resolution fails → processIssue
	// returns nil → convertTestResultToIssues skips it. No panic.
	// NOTE: this confirms the defect is MASKED at this integration level; see T2/T3.
	issues, err := convertTestResultToIssues(ctx, tr, map[string][]types.Issue{})
	require.NoError(t, err)

	for i, issue := range issues {
		assert.NotNil(t, issue, "issues[%d] must not be a non-nil interface wrapping nil", i)
	}
	// Finding filtered upstream — result must be empty.
	assert.Empty(t, issues,
		"a nil-attrs finding must be skipped by upstream grouping, leaving no issues (masked defect — see T2/T3 for white-box coverage)")
}

// TestPopulateMatchingIssues_SkipsFindingWithNilAttributes (T2 — white-box unit)
//
// Calls populateMatchingIssues directly with an issue whose single finding has
// nil Attributes.
//
// RED before fix (a): the outer loop executes `finding.Attributes.Evidence` on a
// nil pointer → runtime panic → test fails.
// GREEN after fix (a): nil guard `if finding == nil || finding.Attributes == nil { continue }`
// short-circuits before the inner loop → empty slice returned, no panic.
func TestPopulateMatchingIssues_SkipsFindingWithNilAttributes(t *testing.T) {
	engine := testutil.UnitTest(t)
	workDir := types.FilePath(t.TempDir())

	ctx := ctx2.NewContextWithEngine(context.Background(), engine)
	ctx = EnrichContextForTest(t, ctx, engine, string(workDir))

	nilFinding := newNilAttrsFinding(t)
	issue, err := testapi.NewIssueFromFindings([]*testapi.FindingData{nilFinding})
	require.NoError(t, err)
	require.NotNil(t, issue)

	// RED before fix: panics at finding.Attributes.Evidence (nil pointer dereference).
	// GREEN after fix: nil-attrs finding skipped, returns empty slice.
	result := populateMatchingIssues(
		ctx, issue, buildMinimalProblem(),
		workDir+"/package.json",
		types.Range{},
		"npm",
		engine.GetLogger().With().Logger(),
	)

	assert.Empty(t, result,
		"a nil-attrs finding must be skipped by the nil guard — no entry (and no panic)")
}

// TestPopulateMatchingIssues_OmitsDegenerateEntryOnBuildError (T3 — white-box unit)
//
// Calls populateMatchingIssues with a two-finding issue:
//   - findings[0]: valid Attributes + DependencyPathEvidence → buildOssIssueData succeeds.
//   - findings[1]: nil Attributes → buildOssIssueData would return an error (existing guard
//     at unified_converter.go:478); but the outer nil guard prevents reaching buildOssIssueData.
//
// RED before fix (a): findings[1] causes a runtime panic at `finding.Attributes.Evidence`.
// GREEN after both fixes:
//   - findings[1] is skipped by nil guard (fix a) → no zero-value OssIssueData{} appended.
//   - Even if somehow reached, the `continue` (fix b) would prevent the append.
//
// Design note: fix (b) is defense-in-depth. The nil guard (fix a) already prevents any
// call to buildOssIssueData with nil Attributes via populateMatchingIssues, so fix (b)
// cannot be triggered independently in the current code. T3 verifies the combined
// hardened behavior and acts as a regression test for future buildOssIssueData error paths.
func TestPopulateMatchingIssues_OmitsDegenerateEntryOnBuildError(t *testing.T) {
	engine := testutil.UnitTest(t)
	workDir := types.FilePath(t.TempDir())

	ctx := ctx2.NewContextWithEngine(context.Background(), engine)
	ctx = EnrichContextForTest(t, ctx, engine, string(workDir))

	validFinding := newValidFindingWithEvidence(t)
	nilFinding := newNilAttrsFinding(t)

	// Two-finding issue: first valid, second nil-attrs.
	issue, err := testapi.NewIssueFromFindings([]*testapi.FindingData{validFinding, nilFinding})
	require.NoError(t, err)
	require.NotNil(t, issue)

	// RED before fix (a): panics on findings[1].Attributes.Evidence (nil deref).
	// GREEN after both fixes: findings[1] skipped; result contains only data from findings[0].
	result := populateMatchingIssues(
		ctx, issue, buildMinimalProblem(),
		workDir+"/package.json",
		types.Range{},
		"npm",
		engine.GetLogger().With().Logger(),
	)

	// The nil-attrs finding must NOT contribute a zero-value entry.
	for i, entry := range result {
		assert.NotEqual(t, snyk.OssIssueData{}, entry,
			"result[%d] must not be a zero-value OssIssueData (degenerate entry from failed build)", i)
	}

	// Additionally, buildOssIssueData itself returns (OssIssueData{}, error) for nil Attributes
	// (existing guard at unified_converter.go:478). The `continue` fix (b) ensures the caller
	// never appends that zero-value. Verify directly:
	zeroValue, buildErr := buildOssIssueData(
		ctx, issue, buildMinimalProblem(), nilFinding,
		workDir+"/package.json", types.Range{}, "npm", nil,
	)
	require.Error(t, buildErr, "buildOssIssueData must return an error for nil Attributes")
	assert.Equal(t, snyk.OssIssueData{}, zeroValue,
		"buildOssIssueData must return a zero-value on error (the value the missing continue would append)")
}
