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

package snyk

import (
	"github.com/snyk/snyk-ls/infrastructure/delta"
	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/slices"
	"testing"
)

func Test_New_Issue(t *testing.T) {
	baseIssueList := getIssueList()

	newIssue := Issue{
		ID:        "javascript/NoHardcodedPasswords",
		Severity:  2,
		IssueType: 2,
		Range: Range{
			Start: Position{
				Line:      50,
				Character: 10,
			},
			End: Position{
				Line:      50,
				Character: 17,
			},
		},
		Message:          "Use of Hardcoded Credentials: Do not hardcode passwords in code. Found hardcoded password used in pa...",
		AffectedFilePath: "/var/folders/qt/rlk4r6d55s1fx7bdr7bg0w3h0000gn/T/snyk_tmp_repo2525628625/newfile.js",
		Product:          "Snyk Code",
		Fingerprint:      "1256723f6.6d16dbf.bd25d204.fd9wwb7c.79aff027.fcf30ddd.81d021ss.91c60baad.12567cf6.6d9cc6dbf.bd6cs204.fd94cc7c.79ss027.fcs002d.8dd021f5.91c6ss7d",
	}
	df := initDeltaFinder()

	currentIssueList := slices.Clone(baseIssueList)
	currentIssueList = append(currentIssueList, newIssue)

	baseFindingIdentifiable := convertToFindingsIdentifiable(baseIssueList)
	currentFindingIdentifiable := convertToFindingsIdentifiable(currentIssueList)

	_, deltaList, err := df.Find(baseFindingIdentifiable, currentFindingIdentifiable)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(deltaList))
	finding, ok := deltaList[0].(delta.Fingerprintable)
	assert.True(t, ok)
	assert.Equal(t, newIssue.GetFingerprint(), finding.GetFingerprint())
	assert.True(t, finding.IsNew())
}

func Test_No_New_Issue(t *testing.T) {
	baseIssueList := getIssueList()
	currentIssueList := getIssueList()
	df := initDeltaFinder()

	baseFindingIdentifiable := convertToFindingsIdentifiable(baseIssueList)
	currentFindingIdentifiable := convertToFindingsIdentifiable(currentIssueList)

	_, deltaList, err := df.Find(baseFindingIdentifiable, currentFindingIdentifiable)

	assert.NoError(t, err)
	assert.Empty(t, deltaList)
}

func getIssueList() []Issue {
	issueList := []Issue{
		{
			ID:        "javascript/UseCsurfForExpress",
			Severity:  2,
			IssueType: 2,
			Range: Range{
				Start: Position{
					Line:      30,
					Character: 10,
				},
				End: Position{
					Line:      30,
					Character: 17,
				},
			},
			Message:          "Cross-Site Request Forgery (CSRF): CSRF protection is disabled for your Express app. This allows the...",
			AffectedFilePath: "/var/folders/qt/rlk4r6d55s1fx7bdr7bg0w3h0000gn/T/snyk_tmp_repo2525628625/app.js",
			Product:          "Snyk Code",
			Fingerprint:      "ae77ea27.4773f344.607187b5.d7919eeb.a1fb1152.5fce695c.fee35010.89d75565.630e4ed1.4773f344.aa4dda5f.d7919eeb.f30fb760.49b28873.85bdc101.83642794",
		},
		{
			ID:        "javascript/NoHardcodedPasswords",
			Severity:  2,
			IssueType: 2,
			Range: Range{
				Start: Position{
					Line:      40,
					Character: 10,
				},
				End: Position{
					Line:      40,
					Character: 17,
				},
			},
			Message:          "Use of Hardcoded Credentials: Do not hardcode passwords in code. Found hardcoded password used in pa...",
			AffectedFilePath: "/var/folders/qt/rlk4r6d55s1fx7bdr7bg0w3h0000gn/T/snyk_tmp_repo2525628625/db.js",
			Product:          "Snyk Code",
			Fingerprint:      "12567ef6.6d936dbf.bd65d204.fd94bb7c.79a7d027.fcf3002d.81d021f5.91c60b7d.12567ef6.6d936dbf.bd65d204.fd94bb7c.79a7d027.fcf3002d.81d021f5.91c60b7d",
		},
	}
	return issueList
}

func convertToFindingsIdentifiable(baseIssueList []Issue) []delta.Identifiable {
	baseFindingIdentifiable := make([]delta.Identifiable, len(baseIssueList))
	for i := range baseIssueList {
		baseFindingIdentifiable[i] = &baseIssueList[i]
	}
	return baseFindingIdentifiable
}

func initDeltaFinder() *delta.Finder {
	df := &delta.Finder{}
	fe := &delta.FindingsEnricher{}
	cim := &CodeIdentityMatcher{}
	gd := &delta.FindingsDiffer{}
	return df.Init(fe, cim, gd)
}
