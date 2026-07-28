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
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"

	"github.com/snyk/snyk-ls/infrastructure/utils"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// newVulnIssueForTest builds a real testapi.Issue for a single OSS vulnerability,
// parameterised only by the per-scan finding UUID. Everything else (vuln id,
// package name/version, dependency path) is identical, so two issues built with
// two different findingID values represent the SAME finding observed in two
// separate scans (the backend mints a fresh finding UUID each scan).
func newVulnIssueForTest(t *testing.T, findingID uuid.UUID) testapi.Issue {
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

	id := findingID
	finding := &testapi.FindingData{
		Id: &id,
		Attributes: &testapi.FindingAttributes{
			FindingType: testapi.FindingTypeSca,
			Key:         "aggregation-key",
			Title:       "Prototype Pollution",
			Description: "Prototype Pollution in lodash",
			Problems:    []testapi.Problem{problem},
			Evidence:    []testapi.Evidence{depEvidence},
		},
	}

	issue, err := testapi.NewIssueFromFindings([]*testapi.FindingData{finding})
	require.NoError(t, err)
	require.NotNil(t, issue)
	return issue
}

// TestProcessIssue_OSS_FindingIdStable_DespiteChangedFindingUUID proves that the
// same OSS vulnerability converted across two separate scans yields the SAME
// issue.FindingId, even though the backend mints a fresh per-scan finding UUID
// each time. Before this change FindingId was the per-scan finding UUID, so the
// two scans produced different identities (IDE-2207 R1/R4).
func TestProcessIssue_OSS_FindingIdStable_DespiteChangedFindingUUID(t *testing.T) {
	engine := testutil.UnitTest(t)
	workDir := types.FilePath(t.TempDir())
	affectedFilePath := workDir + "/package.json"

	buildCtx := func() context.Context {
		ctx := ctx2.NewContextWithEngine(context.Background(), engine)
		ctx = EnrichContextForTest(t, ctx, engine, string(workDir))
		return ctx
	}

	uuid1 := uuid.New()
	uuid2 := uuid.New()
	require.NotEqual(t, uuid1, uuid2, "the two scans must have different finding UUIDs to prove stability")

	issue1 := processIssue(buildCtx(), newVulnIssueForTest(t, uuid1), engine.GetLogger().With().Logger(), affectedFilePath, workDir)
	issue2 := processIssue(buildCtx(), newVulnIssueForTest(t, uuid2), engine.GetLogger().With().Logger(), affectedFilePath, workDir)

	require.NotNil(t, issue1)
	require.NotNil(t, issue2)

	assert.NotEmpty(t, issue1.GetFindingId(), "FindingId must not be empty")
	assert.Equal(t, issue1.GetFindingId(), issue2.GetFindingId(),
		"the same OSS vuln must keep the same FindingId across scans despite a changed finding UUID")

	// FindingId must no longer be the per-scan finding UUID.
	assert.NotEqual(t, uuid1.String(), issue1.GetFindingId(), "FindingId must not be the per-scan finding UUID")
	assert.NotEqual(t, uuid2.String(), issue2.GetFindingId(), "FindingId must not be the per-scan finding UUID")

	// FindingId must be the durable OSS grouping key derived from stable
	// attributes (packageName|version|dependency-chain|ruleId).
	assert.Equal(t, utils.CalculateFingerprintFromAdditionalData(issue1), issue1.GetFindingId(),
		"FindingId must be the stable OSS grouping key derived from stable attributes")
}

// newUnusableIntroducingIssueForTest builds a real testapi.Issue whose introducing
// finding (findings[0]) carries no attributes, so it holds no package name,
// version or dependency chain. A second finding provides the issue's primary
// vuln problem and ecosystem so processIssue reaches the point of building the
// introducing OSS issue data. Because the introducing finding is unusable, that
// build cannot produce a content-bearing finding: converting it anyway would
// mint an OSS grouping key derived from empty package/version fields
// (sha256 of "|||"+id), which collides across distinct vulns at the same
// location and emits a contentless finding.
func newUnusableIntroducingIssueForTest(t *testing.T) testapi.Issue {
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

	// findings[0] has no attributes: getIntroducingFinding falls through to it
	// because no finding exposes a matching direct-dependency path.
	id0 := uuid.New()
	unusableFinding := &testapi.FindingData{Id: &id0}

	// findings[1] carries the SCA problem (primary problem + ecosystem) but has
	// no dependency-path evidence, so getIntroducingFinding does not select it.
	id1 := uuid.New()
	problemFinding := &testapi.FindingData{
		Id: &id1,
		Attributes: &testapi.FindingAttributes{
			FindingType: testapi.FindingTypeSca,
			Key:         "aggregation-key",
			Title:       "Prototype Pollution",
			Problems:    []testapi.Problem{problem},
		},
	}

	issue, err := testapi.NewIssueFromFindings([]*testapi.FindingData{unusableFinding, problemFinding})
	require.NoError(t, err)
	require.NotNil(t, issue)
	return issue
}

// TestProcessIssue_OSS_SkipsUnusableIntroducingFinding proves that when the
// introducing finding is unusable (no attributes → no package/version/chain),
// processIssue skips it entirely rather than emitting a contentless finding with
// a colliding grouping key. Before this change the converter continued with a
// zero-valued OssIssueData and produced a garbage finding whose FindingId was the
// sha256 of empty package attributes (IDE-2207 review, Should Fix).
func TestProcessIssue_OSS_SkipsUnusableIntroducingFinding(t *testing.T) {
	engine := testutil.UnitTest(t)
	workDir := types.FilePath(t.TempDir())
	affectedFilePath := workDir + "/package.json"

	ctx := ctx2.NewContextWithEngine(context.Background(), engine)
	ctx = EnrichContextForTest(t, ctx, engine, string(workDir))

	result := processIssue(ctx, newUnusableIntroducingIssueForTest(t), engine.GetLogger().With().Logger(), affectedFilePath, workDir)

	assert.Nil(t, result, "an unusable introducing finding must be skipped, not converted into a garbage/colliding finding")
}

// fakeTestResult is a minimal testapi.TestResult test double whose Findings and
// dep-graph subject can be set explicitly, so convertTestResultToIssues can be
// exercised end-to-end without a live test API.
type fakeTestResult struct {
	testID   uuid.UUID
	subject  *testapi.TestSubject
	findings []testapi.FindingData
}

func (f *fakeTestResult) GetTestID() *uuid.UUID                            { return &f.testID }
func (f *fakeTestResult) GetTestConfiguration() *testapi.TestConfiguration { return nil }
func (f *fakeTestResult) GetCreatedAt() *time.Time                         { return nil }
func (f *fakeTestResult) Get(key testapi.TestResultKeys) interface{} {
	if key == testapi.TestResultTestSubject {
		return f.subject
	}
	return nil
}
func (f *fakeTestResult) GetTestSubject() *testapi.TestSubject              { return f.subject }
func (f *fakeTestResult) GetSubjectLocators() *[]testapi.TestSubjectLocator { return nil }
func (f *fakeTestResult) GetTestResources() *[]testapi.TestResource         { return nil }
func (f *fakeTestResult) GetExecutionState() testapi.TestExecutionStates    { return "" }
func (f *fakeTestResult) GetErrors() *[]testapi.IoSnykApiCommonError        { return nil }
func (f *fakeTestResult) GetWarnings() *[]testapi.IoSnykApiCommonError      { return nil }
func (f *fakeTestResult) GetPassFail() *testapi.PassFail                    { return nil }
func (f *fakeTestResult) GetOutcomeReason() *testapi.TestOutcomeReason      { return nil }
func (f *fakeTestResult) GetBreachedPolicies() *testapi.PolicyRefSet        { return nil }
func (f *fakeTestResult) GetEffectiveSummary() *testapi.FindingSummary      { return nil }
func (f *fakeTestResult) GetRawSummary() *testapi.FindingSummary            { return nil }
func (f *fakeTestResult) GetTestFacts() *[]testapi.TestFact                 { return nil }
func (f *fakeTestResult) SetMetadata(_ string, _ interface{})               {}
func (f *fakeTestResult) GetMetadataValue(_ string) interface{}             { return nil }
func (f *fakeTestResult) GetMetadata() map[string]interface{}               { return nil }
func (f *fakeTestResult) Findings(_ context.Context) ([]testapi.FindingData, bool, error) {
	return f.findings, true, nil
}

// newUnusableTestResultForTest builds a real testapi.TestResult carrying a single
// SCA finding whose vuln problem has no ecosystem. Such a finding survives
// issue-grouping (it has attributes and a Snyk problem id) but cannot be
// converted: processIssue skips it (returns a nil *snyk.Issue) because the
// ecosystem cannot be resolved. It reproduces, at the caller level, any finding
// that processIssue declines to convert — the nil-attributes introducing finding
// is dropped earlier by grouping, so this exercises the same skip contract that
// convertTestResultToIssues must honor without leaking a nil element.
func newUnusableTestResultForTest(t *testing.T) testapi.TestResult {
	t.Helper()

	// Vuln problem deliberately has no Ecosystem set, so processIssue cannot
	// resolve the ecosystem and skips the finding.
	var problem testapi.Problem
	require.NoError(t, problem.FromSnykVulnProblem(testapi.SnykVulnProblem{
		Id:          "SNYK-JS-LODASH-1",
		PackageName: "lodash",
	}))

	id := uuid.New()
	finding := testapi.FindingData{
		Id: &id,
		Attributes: &testapi.FindingAttributes{
			FindingType: testapi.FindingTypeSca,
			Key:         "aggregation-key",
			Title:       "Prototype Pollution",
			Problems:    []testapi.Problem{problem},
		},
	}

	var subject testapi.TestSubject
	require.NoError(t, subject.FromDepGraphSubject(testapi.DepGraphSubject{
		Locator: testapi.LocalPathLocator{Paths: []string{"package.json"}},
	}))

	return &fakeTestResult{
		testID:   uuid.New(),
		subject:  &subject,
		findings: []testapi.FindingData{finding},
	}
}

// TestConvertTestResultToIssues_SkipsUnusableFinding_NoNilElements proves that
// when processIssue declines to convert a finding (returns a nil *snyk.Issue),
// convertTestResultToIssues actually skips it rather than appending a typed-nil
// pointer wrapped in a non-nil types.Issue interface. Before the append guard the
// returned slice held one element that was a non-nil interface wrapping a nil
// *snyk.Issue, which later panics (e.g. issue.GetRange()). The intended skip must
// yield an empty slice for a single unusable finding.
func TestConvertTestResultToIssues_SkipsUnusableFinding_NoNilElements(t *testing.T) {
	engine := testutil.UnitTest(t)
	workDir := types.FilePath(t.TempDir())

	ctx := ctx2.NewContextWithEngine(context.Background(), engine)
	ctx = ctx2.NewContextWithWorkDirAndFilePath(ctx, workDir, workDir+"/package.json")
	ctx = EnrichContextForTest(t, ctx, engine, string(workDir))

	issues, err := convertTestResultToIssues(ctx, newUnusableTestResultForTest(t), map[string][]types.Issue{})
	require.NoError(t, err)

	for i, issue := range issues {
		assert.NotNil(t, issue, "issues[%d] must not be a non-nil interface wrapping a nil pointer", i)
	}
	assert.Empty(t, issues, "a single unusable finding must be skipped entirely, leaving no elements")
}
