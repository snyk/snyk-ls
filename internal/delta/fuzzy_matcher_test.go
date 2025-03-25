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
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/slices"
)

func Test_New_Issue(t *testing.T) {
	baseIssueList := getIssueList()

	newIssue := mockIdentifiable{
		ruleId:      "javascript/NoHardcodedPasswords",
		startLine:   10,
		endLine:     50,
		startColumn: 10,
		endColumn:   17,
		path:        "/var/folders/qt/rlk4r6d55s1fx7bdr7bg0w3h0000gn/T/snyk_tmp_repo2525628625/newfile.js",
		fingerprint: "1256723f6.6d16dbf.bd25d204.fd9wwb7c.79aff027.fcf30ddd.81d021ss.91c60baad.12567cf6.6d9cc6dbf.bd6cs204.fd94cc7c.79ss027.fcs002d.8dd021f5.91c6ss7d",
	}
	df := initDeltaFinder()

	currentIssueList := slices.Clone(baseIssueList)
	currentIssueList = append(currentIssueList, newIssue)

	baseFindingIdentifiable := convertToFindingsIdentifiable(baseIssueList)
	currentFindingIdentifiable := convertToFindingsIdentifiable(currentIssueList)

	deltaList, err := df.Diff(baseFindingIdentifiable, currentFindingIdentifiable)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(deltaList))
	finding, ok := deltaList[0].(Fingerprintable)
	assert.True(t, ok)
	assert.Equal(t, newIssue.GetFingerprint(), finding.GetFingerprint())
}

func Test_New_Issue_No_IdChange(t *testing.T) {
	baseIssueList := getIssueList()

	exisingIdentity := uuid.New().String()
	newIssue := mockIdentifiable{
		ruleId:         "javascript/NoHardcodedPasswords",
		startLine:      10,
		endLine:        50,
		startColumn:    10,
		endColumn:      17,
		path:           "/var/folders/qt/rlk4r6d55s1fx7bdr7bg0w3h0000gn/T/snyk_tmp_repo2525628625/newfile.js",
		fingerprint:    "1256723f6.6d16dbf.bd25d204.fd9wwb7c.79aff027.fcf30ddd.81d021ss.91c60baad.12567cf6.6d9cc6dbf.bd6cs204.fd94cc7c.79ss027.fcs002d.8dd021f5.91c6ss7d",
		globalIdentity: exisingIdentity,
	}
	df := initDeltaFinder()

	currentIssueList := slices.Clone(baseIssueList)
	currentIssueList = append(currentIssueList, newIssue)

	baseFindingIdentifiable := convertToFindingsIdentifiable(baseIssueList)
	currentFindingIdentifiable := convertToFindingsIdentifiable(currentIssueList)

	deltaList, err := df.Diff(baseFindingIdentifiable, currentFindingIdentifiable)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(deltaList))
	finding, ok := deltaList[0].(Fingerprintable)
	assert.True(t, ok)
	assert.Equal(t, newIssue.GetFingerprint(), finding.GetFingerprint())
	assert.Equal(t, exisingIdentity, newIssue.GetGlobalIdentity())
}

func Test_No_New_Issue(t *testing.T) {
	baseIssueList := getIssueList()
	currentIssueList := getIssueList()
	df := initDeltaFinder()

	baseFindingIdentifiable := convertToFindingsIdentifiable(baseIssueList)
	currentFindingIdentifiable := convertToFindingsIdentifiable(currentIssueList)

	deltaList, err := df.Diff(baseFindingIdentifiable, currentFindingIdentifiable)

	assert.NoError(t, err)
	assert.Empty(t, deltaList)
}

func getIssueList() []mockIdentifiable {
	issueList := []mockIdentifiable{
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
	return issueList
}

func TestCheckDirs(t *testing.T) {
	tests := []struct {
		name            string
		baseFilePath    string
		currentFilePath string
		baseDir         string
		currentDir      string
		expected        float64
	}{
		{
			name:            "Identical absolute file paths",
			baseFilePath:    "/home/user/docs/file.txt",
			currentFilePath: "/home/user/docs/file.txt",
			baseDir:         "/home/user/docs",
			currentDir:      "/home/user/docs",
			expected:        1,
		},
		{
			name:            "Different files in same dir",
			baseFilePath:    "/home/user/docs/file1.txt",
			currentFilePath: "/home/user/docs/file2.txt",
			baseDir:         "/home/user/docs",
			currentDir:      "/home/user/docs",
			expected:        0.75,
		},
		{
			name:            "Same file, different dirs at same depth",
			baseFilePath:    "/home/user/abc/file.txt",
			currentFilePath: "/home/user/xyz/file.txt",
			baseDir:         "/home/user",
			currentDir:      "/home/user",
			expected:        0.25,
		},
		{
			name:            "One-level difference in subdirectories",
			baseFilePath:    "/home/user/projects/sub/file.txt",
			currentFilePath: "/home/user/projects/file.txt",
			baseDir:         "/home/user",
			currentDir:      "/home/user",
			expected:        0.6,
		},
		{
			name:            "Completely different structure",
			baseFilePath:    "/var/folder/myprojects/subfolder/file1.txt",
			currentFilePath: "/home/user/projects/anotherfolder/file2.txt",
			baseDir:         "/var/folder",
			currentDir:      "/home/user",
			expected:        0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := checkDirs(tt.baseFilePath, tt.currentFilePath, tt.baseDir, tt.currentDir)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func convertToFindingsIdentifiable(baseIssueList []mockIdentifiable) []Identifiable {
	baseFindingIdentifiable := make([]Identifiable, len(baseIssueList))
	for i := range baseIssueList {
		baseFindingIdentifiable[i] = &baseIssueList[i]
	}
	return baseFindingIdentifiable
}

func initDeltaFinder() *Finder {
	df := NewFinder(
		WithEnricher(&FindingsEnricher{}),
		WithMatcher(&FuzzyMatcher{}),
		WithDiffer(&FindingsDiffer{}))
	return df
}
