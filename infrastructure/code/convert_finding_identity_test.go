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

	codeClientSarif "github.com/snyk/code-client-go/sarif"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// sarifResponseWithAssetFingerprint builds a minimal SARIF response for a single
// Code finding whose durable server-computed asset fingerprint
// (snyk/asset/finding/v1) is assetFp. The asset fingerprint is stable across
// scans of unchanged code, which is what makes it a valid grouping key.
func sarifResponseWithAssetFingerprint(assetFp string) codeClientSarif.SarifResponse {
	return codeClientSarif.SarifResponse{
		Sarif: codeClientSarif.SarifDocument{
			Runs: []codeClientSarif.Run{
				{
					Tool: codeClientSarif.Tool{
						Driver: codeClientSarif.Driver{
							Rules: []codeClientSarif.Rule{
								{
									ID:   "javascript/rule1",
									Name: "rule1",
									Properties: codeClientSarif.RuleProperties{
										Categories: []string{"Security"},
									},
								},
							},
						},
					},
					Results: []codeClientSarif.Result{
						{
							RuleID: "javascript/rule1",
							Level:  "warning",
							Message: codeClientSarif.ResultMessage{
								Text: "some finding",
							},
							Locations: []codeClientSarif.Location{
								{
									PhysicalLocation: codeClientSarif.PhysicalLocation{
										ArtifactLocation: codeClientSarif.ArtifactLocation{URI: "main.js"},
										Region: codeClientSarif.Region{
											StartLine: 10, EndLine: 10, StartColumn: 5, EndColumn: 15,
										},
									},
								},
							},
							Fingerprints: codeClientSarif.Fingerprints{
								SnykAssetFindingV1: assetFp,
							},
						},
					},
				},
			},
		},
	}
}

// TestCode_FindingId_IsAssetFingerprint_StableAcrossScans confirms that the Code
// converter sources issue.FindingId from the durable Snyk asset fingerprint
// (snyk/asset/finding/v1), which is stable across separate scans of unchanged
// code. This is a regression lock: the grouping key must remain the asset
// fingerprint so the conversion layer produces a stable per-finding identity
// (IDE-2207 R1/R4). No production change is required — Code was already stable.
func TestCode_FindingId_IsAssetFingerprint_StableAcrossScans(t *testing.T) {
	engine := testutil.UnitTest(t)
	baseDir := types.FilePath(t.TempDir())
	const assetFp = "asset-finding-fingerprint-abc123"

	convert := func() []types.Issue {
		sc := SarifConverter{
			sarif:  sarifResponseWithAssetFingerprint(assetFp),
			logger: engine.GetLogger(),
			engine: engine,
		}
		issues, err := sc.toIssues(baseDir)
		require.NoError(t, err)
		require.Len(t, issues, 1)
		return issues
	}

	// Two independent conversions represent two separate scans of unchanged code:
	// the backend returns the same asset fingerprint each time.
	scan1 := convert()
	scan2 := convert()

	assert.Equal(t, assetFp, scan1[0].GetFindingId(),
		"Code FindingId grouping key must be the durable snyk/asset/finding/v1 fingerprint")
	assert.Equal(t, scan1[0].GetFindingId(), scan2[0].GetFindingId(),
		"the same Code finding must keep the same grouping key across scans of unchanged code")
}
