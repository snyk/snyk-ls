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
	"errors"
	"github.com/adrg/strutil"
	"github.com/adrg/strutil/metrics"
	"math"
	"path/filepath"
	"strings"
)

var _ Matcher = (*CodeMatcher)(nil)

type IssueConfidence struct {
	BaseUUID           string
	IssueIDResultIndex int
	Confidence         float64
}

type DeduplicatedIssuesToIDs map[int]Identity
type IssueConfidenceList []IssueConfidence
type Identity struct {
	IdentityID string
	Confidence float64
}

var weights = struct {
	MinimumAcceptableConfidence float64
	FilePositionDistance        float64
	RecentHistoryDistance       float64
	FingerprintConfidence       float64
	PathSimilarity              float64
	LineSimilarity              float64

	DirSimilarity           float64
	FileNameSimilarity      float64
	FileExtensionSimilarity float64
}{
	MinimumAcceptableConfidence: 0.4,
	FilePositionDistance:        0.3,
	RecentHistoryDistance:       0.2,
	FingerprintConfidence:       0.5,

	PathSimilarity: 0.8,
	LineSimilarity: 0.2,

	DirSimilarity:           0.5,
	FileNameSimilarity:      0.3,
	FileExtensionSimilarity: 0.2,
}

type CodeMatcher struct {
}

func NewCodeMatcher() *CodeMatcher {
	return &CodeMatcher{}
}

func (_ CodeMatcher) Match(baseIssueList, currentIssueList []Identifiable) ([]Identifiable, error) {
	if len(currentIssueList) == 0 || len(baseIssueList) == 0 {
		return nil, errors.New("base or current issue list is empty")
	}

	strongMatchingIssues := make(map[string]IssueConfidence)
	existingAssignedIds := make(map[string]bool)

	for index, issue := range currentIssueList {
		if len(issue.GetGlobalIdentity()) > 0 {
			existingAssignedIds[issue.GetGlobalIdentity()] = true
			continue
		}
		findMatch(issue, index, baseIssueList, strongMatchingIssues)
	}

	finalResult := deduplicateIssues(strongMatchingIssues)

	// Assign identities found to results
	for i, identity := range finalResult {
		if !existingAssignedIds[identity.IdentityID] {
			currentIssueList[i].SetGlobalIdentity(identity.IdentityID)
		}
	}

	return currentIssueList, nil
}

func findMatch(issue Identifiable, index int, baseIssueList []Identifiable, strongMatchingIssues map[string]IssueConfidence) {
	matches := findMatches(issue, index, baseIssueList)

	for _, match := range matches {
		if existingIssue, ok := strongMatchingIssues[match.BaseUUID]; !ok || existingIssue.Confidence < match.Confidence {
			strongMatchingIssues[match.BaseUUID] = match
		}
	}
}

func findMatches(currentIssue Identifiable, index int, baseIssues []Identifiable) IssueConfidenceList {
	similarIssues := make(IssueConfidenceList, 0)

	for _, baseIssue := range baseIssues {
		if baseIssue.RuleId() != currentIssue.RuleId() {
			continue
		}

		fpd := filePositionDistance(baseIssue, currentIssue)
		// Calculation of History is not needed here for IDE since we are not persisting old scan results.
		//We will always return 1.
		hd := historicDistance()
		fd := fingerprintDistance(baseIssue, currentIssue)

		overallConfidence := fpd*weights.FilePositionDistance +
			hd*weights.RecentHistoryDistance +
			fd*weights.FingerprintConfidence

		if overallConfidence == 1 {
			similarIssues = append(similarIssues, IssueConfidence{
				BaseUUID:           baseIssue.GetGlobalIdentity(),
				IssueIDResultIndex: index,
				Confidence:         overallConfidence,
			})
			break
		}

		if overallConfidence > weights.MinimumAcceptableConfidence {
			similarIssues = append(similarIssues, IssueConfidence{
				BaseUUID:           baseIssue.GetGlobalIdentity(),
				IssueIDResultIndex: index,
				Confidence:         overallConfidence,
			})
		}
	}

	return similarIssues
}

func deduplicateIssues(strongMatchingIssues map[string]IssueConfidence) DeduplicatedIssuesToIDs {
	finalResult := make(DeduplicatedIssuesToIDs)
	for _, issue := range strongMatchingIssues {
		if existingIdentity, ok := finalResult[issue.IssueIDResultIndex]; !ok || existingIdentity.Confidence < issue.Confidence {
			finalResult[issue.IssueIDResultIndex] = Identity{
				IdentityID: issue.BaseUUID,
				Confidence: issue.Confidence,
			}
		}
	}
	return finalResult
}

func fingerprintDistance(baseFingerprints, currentFingerprints Identifiable) float64 {
	baseFingerprintable, ok := baseFingerprints.(Fingerprintable)
	if !ok {
		return 0
	}
	currentFingerprintable, ok := currentFingerprints.(Fingerprintable)
	if !ok {
		return 0
	}

	// Split into parts and compare
	parts1 := strings.Split(baseFingerprintable.GetFingerprint(), ".")
	parts2 := strings.Split(currentFingerprintable.GetFingerprint(), ".")
	similar := 0
	for i := 0; i < len(parts1) && i < len(parts2); i++ {
		if parts1[i] == parts2[i] {
			similar++
		}
	}
	totalParts := max(len(parts1), len(parts2))
	if totalParts == 0 {
		return 0
	}
	return float64(similar) / float64(totalParts)
}

func filePositionDistance(baseIssue, currentIssue Identifiable) float64 {
	basePathable, ok := baseIssue.(Pathable)
	if !ok {
		return 0
	}
	currentPathable, ok := currentIssue.(Pathable)
	if !ok {
		return 0
	}

	dirSimilarity := checkDirs(basePathable.Path(), currentPathable.Path())
	fileNameSimilarity := fileNameSimilarity(basePathable.Path(), currentPathable.Path())
	fileExtSimilarity := fileExtSimilarity(filepath.Ext(basePathable.Path()),
		filepath.Ext(currentPathable.Path()))

	pathSimilarity :=
		dirSimilarity*weights.DirSimilarity +
			fileNameSimilarity*weights.FileNameSimilarity +
			fileExtSimilarity*weights.FileExtensionSimilarity

	startLineSimilarity, startColumnSimilarity, endColumnSimilarity, endLineSimilarity :=
		matchDistance(baseIssue, currentIssue)
	// Effectively weighting each line number pos at 25%
	totalLineSimilarity := (startLineSimilarity +
		startColumnSimilarity +
		endColumnSimilarity +
		endLineSimilarity) / 4
	fileLocationConfidence :=
		pathSimilarity*weights.PathSimilarity +
			totalLineSimilarity*weights.LineSimilarity

	return fileLocationConfidence
}

func matchDistance(baseIssue Identifiable, currentIssue Identifiable) (float64, float64, float64, float64) {
	baseRangeable, ok := baseIssue.(Locatable)
	if !ok {
		return 0, 0, 0, 0
	}
	currentRangeable, ok := currentIssue.(Locatable)
	if !ok {
		return 0, 0, 0, 0
	}
	startLineSimilarity := similarityToDistance(baseRangeable.StartLine(), currentRangeable.StartLine())
	startColumnSimilarity := similarityToDistance(baseRangeable.StartColumn(),
		currentRangeable.StartColumn())
	endColumnSimilarity := similarityToDistance(baseRangeable.EndColumn(), currentRangeable.EndColumn())
	endLineSimilarity := similarityToDistance(baseRangeable.EndLine(), currentRangeable.EndLine())
	return startLineSimilarity, startColumnSimilarity, endColumnSimilarity, endLineSimilarity
}

func checkDirs(path1, path2 string) float64 {
	if path1 == path2 {
		return 1
	}

	relativePath := relative(path1, path2)
	relativePathDistance := float64(len(strings.Split(relativePath, "/")))

	longestPossiblePath := math.Max(float64(len(strings.Split(path1, "/"))), float64(len(strings.Split(path2, "/"))))

	return 1 - relativePathDistance/longestPossiblePath
}

func fileNameSimilarity(file1, file2 string) float64 {
	return strutil.Similarity(file1, file2, metrics.NewLevenshtein())
}

func similarityToDistance(value1, value2 int) float64 {
	if value1 == value2 {
		return 1
	}
	return 1 - math.Abs(float64(value1-value2))/math.Max(float64(value1), float64(value2))
}

func fileExtSimilarity(ext1, ext2 string) float64 {
	return strutil.Similarity(ext1, ext2, metrics.NewLevenshtein())
}

func historicDistance() float64 {
	return 1
}

func relative(path1, path2 string) string {
	res, err := filepath.Rel(path1, path2)
	if err != nil {
		return ""
	}
	return res
}
