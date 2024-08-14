/*
 * © 2024 Snyk Limited
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

package delta

import (
	"golang.org/x/exp/slices"
	"testing"

	"github.com/stretchr/testify/assert" // using testify for assertions
)

func TestFind_EmptyLists(t *testing.T) {
	f := NewFinder()
	_, err := f.Enrich([]Identifiable{}, []Identifiable{})

	assert.EqualError(t, err, "currentlist is empty")
}

func TestFind_MissingDiffer(t *testing.T) {
	f := NewFinder(WithEnricher(FindingsEnricher{}))
	_, err := f.Enrich(
		[]Identifiable{&mockIdentifiable{globalIdentity: "1"}},
		[]Identifiable{&mockIdentifiable{globalIdentity: "2"}})

	assert.EqualError(t, err, "findings differ not defined")
}

func TestFind_OnlyDiffer(t *testing.T) {
	f := NewFinder(WithDiffer(FindingsDiffer{}))
	deltaList, err := f.Diff(
		[]Identifiable{&mockIdentifiable{globalIdentity: "1"}},
		[]Identifiable{
			&mockIdentifiable{globalIdentity: "1"},
			&mockIdentifiable{globalIdentity: "2"},
		})

	assert.NoError(t, err)
	assert.Len(t, deltaList, 1)
}

func TestFind_DifferWithEnricher(t *testing.T) {
	f := NewFinder(
		WithEnricher(FindingsEnricher{}),
		WithDiffer(FindingsDiffer{}),
	)

	enrichedList, err := f.Enrich(
		[]Identifiable{&mockIdentifiable{globalIdentity: "1"}},
		[]Identifiable{
			&mockIdentifiable{globalIdentity: "1"},
			&mockIdentifiable{globalIdentity: "2"},
		})

	assert.NoError(t, err)
	assert.Len(t, enrichedList, 2)

	assert.True(t, enrichedList[1].GetIsNew())
}

func TestFind_DifferWithEnricherWithMatcher(t *testing.T) {
	f := NewFinder(
		WithEnricher(FindingsEnricher{}),
		WithMatcher(FuzzyMatcher{}),
		WithDiffer(FindingsDiffer{}),
	)

	baseIssueList := []mockIdentifiable{
		{
			ruleId:      "javascript/UseCsurfForExpress",
			startLine:   30,
			endLine:     30,
			startColumn: 10,
			endColumn:   17,
			path:        "/var/folders/qt/rlk4r6d55s1fx7bdr7bg0w3h0000gn/T/snyk_tmp_repo2525628625/app.js",
			fingerprint: "ae77ea27.4773f344.607187b5.d7919eeb.a1fb1152.5fce695c.fee35010.89d75565.630e4ed1.4773f344.aa4dda5f.d7919eeb.f30fb760.49b28873.85bdc101.83642794",
		},
		{
			ruleId:      "javascript/NoHardcodedPasswords",
			startLine:   40,
			endLine:     40,
			startColumn: 10,
			endColumn:   17,
			path:        "/var/folders/qt/rlk4r6d55s1fx7bdr7bg0w3h0000gn/T/snyk_tmp_repo2525628625/db.js",
			fingerprint: "12567ef6.6d936dbf.bd65d204.fd94bb7c.79a7d027.fcf3002d.81d021f5.91c60b7d.12567ef6.6d936dbf.bd65d204.fd94bb7c.79a7d027.fcf3002d.81d021f5.91c60b7d",
		},
	}

	newIssue := mockIdentifiable{
		ruleId:      "javascript/NoHardcodedPasswords",
		startLine:   10,
		endLine:     50,
		startColumn: 10,
		endColumn:   17,
		path:        "/var/folders/qt/rlk4r6d55s1fx7bdr7bg0w3h0000gn/T/snyk_tmp_repo2525628625/newfile.js",
		fingerprint: "1256723f6.6d16dbf.bd25d204.fd9wwb7c.79aff027.fcf30ddd.81d021ss.91c60baad.12567cf6.6d9cc6dbf.bd6cs204.fd94cc7c.79ss027.fcs002d.8dd021f5.91c6ss7d",
	}

	currentIssueList := slices.Clone(baseIssueList)
	currentIssueList = append(currentIssueList, newIssue)
	baseFindingIdentifiable := convertToFindingsIdentifiable(baseIssueList)
	currentFindingIdentifiable := convertToFindingsIdentifiable(currentIssueList)
	enrichedList, err := f.Enrich(baseFindingIdentifiable, currentFindingIdentifiable)

	assert.NoError(t, err)
	assert.Len(t, enrichedList, 3)

	assert.True(t, enrichedList[2].GetIsNew())
	assert.Equal(t, enrichedList[2].GetGlobalIdentity(), currentIssueList[2].GetGlobalIdentity())
}

func TestFind_DifferWithEnricherWithMatcher_NoNewIssues(t *testing.T) {
	f := NewFinder(
		WithEnricher(FindingsEnricher{}),
		WithMatcher(FuzzyMatcher{}),
		WithDiffer(FindingsDiffer{}),
	)

	baseIssueList := []mockIdentifiable{
		{
			ruleId:      "javascript/UseCsurfForExpress",
			startLine:   30,
			endLine:     30,
			startColumn: 10,
			endColumn:   17,
			path:        "/var/folders/qt/rlk4r6d55s1fx7bdr7bg0w3h0000gn/T/snyk_tmp_repo2525628625/app.js",
			fingerprint: "ae77ea27.4773f344.607187b5.d7919eeb.a1fb1152.5fce695c.fee35010.89d75565.630e4ed1.4773f344.aa4dda5f.d7919eeb.f30fb760.49b28873.85bdc101.83642794",
		},
		{
			ruleId:      "javascript/NoHardcodedPasswords",
			startLine:   40,
			endLine:     40,
			startColumn: 10,
			endColumn:   17,
			path:        "/var/folders/qt/rlk4r6d55s1fx7bdr7bg0w3h0000gn/T/snyk_tmp_repo2525628625/db.js",
			fingerprint: "12567ef6.6d936dbf.bd65d204.fd94bb7c.79a7d027.fcf3002d.81d021f5.91c60b7d.12567ef6.6d936dbf.bd65d204.fd94bb7c.79a7d027.fcf3002d.81d021f5.91c60b7d",
		},
	}

	baseFindingIdentifiable := convertToFindingsIdentifiable(baseIssueList)
	enrichedList, err := f.Enrich(baseFindingIdentifiable, baseFindingIdentifiable)

	assert.NoError(t, err)
	assert.Len(t, enrichedList, 2)
	for _, enriched := range enrichedList {
		assert.False(t, enriched.GetIsNew())
		assert.NotEmpty(t, enriched.GetGlobalIdentity())
	}
}
