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
	"math"
	"path/filepath"
	"strings"

	"github.com/adrg/strutil"
	"github.com/adrg/strutil/metrics"

	"github.com/snyk/snyk-ls/internal/types"
)

var _ Matcher = (*FuzzyMatcher)(nil)

type IssueConfidence struct {
	BaseUUID           string  // global identity
	IssueIDResultIndex int     // index in current issue list
	Confidence         float64 // confidence that it's the same issue
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

type FuzzyMatcher struct {
}

func NewFuzzyMatcher() *FuzzyMatcher {
	return &FuzzyMatcher{}
}

func (_ FuzzyMatcher) Match(baseIssueList, currentIssueList []Identifiable) ([]Identifiable, error) {
	if len(currentIssueList) == 0 || len(baseIssueList) == 0 {
		return nil, errors.New("base or current issue list is empty")
	}

	strongMatchingIssues := make(map[string]IssueConfidence)
	existingAssignedIds := make(map[string]bool)

	for index, issue := range currentIssueList {
		if issue.GetGlobalIdentity() != "" {
			existingAssignedIds[issue.GetGlobalIdentity()] = true
			continue
		}

		// match issues to global identities and save it into strongMatchingIssues
		// issue confidence gets the index of the issue in currentIssueList
		findMatch(issue, index, baseIssueList, strongMatchingIssues)
	}

	// map the index -> strongestMatchingIssue
	finalResult := deduplicateIssues(strongMatchingIssues)

	// Assign identities found to results
	// Identity: GlobalIdentity + Confidence
	for index, identity := range finalResult {
		if !existingAssignedIds[identity.IdentityID] {
			currentIssueList[index].SetGlobalIdentity(identity.IdentityID)
		}
	}

	return currentIssueList, nil
}

// findMatch manipulates the strongMatchingIssues parameter to contain an association Global Identity -> Issue
// index: position (index) in current, not base issue list
func findMatch(issue Identifiable, index int, baseIssueList []Identifiable, strongMatchingIssues map[string]IssueConfidence) {
	matches := findMatches(issue, index, baseIssueList)

	// iterate over matches and find the strongest match -> if existing issue has lower confidence, we take the next
	for _, match := range matches {
		if existingIssue, ok := strongMatchingIssues[match.BaseUUID]; !ok || existingIssue.Confidence < match.Confidence {
			strongMatchingIssues[match.BaseUUID] = match
		}
	}
}

func findMatches(currentIssue Identifiable, index int, baseIssues []Identifiable) IssueConfidenceList {
	similarIssues := make(IssueConfidenceList, 0)

	for _, baseIssue := range baseIssues {
		if baseIssue.GetRuleID() != currentIssue.GetRuleID() {
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

		if overallConfidence >= 1 {
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
		index := issue.IssueIDResultIndex
		if existingIdentity, ok := finalResult[index]; !ok || existingIdentity.Confidence < issue.Confidence {
			finalResult[index] = Identity{
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

	baseFingerprint := baseFingerprintable.GetFingerprint()
	currentFingerprint := currentFingerprintable.GetFingerprint()
	if !strings.Contains(baseFingerprint, ".") && !strings.Contains(currentFingerprint, ".") {
		if baseFingerprint == currentFingerprint {
			return 1
		}
		return 0
	}

	// Split into parts and compare
	parts1 := strings.Split(baseFingerprint, ".")
	parts2 := strings.Split(currentFingerprint, ".")
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

	dirSimilarity := checkDirs(basePathable.GetPath(), currentPathable.GetPath())
	baseNameSimilarity := fileNameSimilarity(basePathable.GetPath(), currentPathable.GetPath())
	extSimilarity := fileExtSimilarity(basePathable.GetPath(), currentPathable.GetPath())

	pathSimilarity := dirSimilarity*weights.DirSimilarity + baseNameSimilarity*weights.FileNameSimilarity + extSimilarity*weights.FileExtensionSimilarity
	startLineSimilarity, startColumnSimilarity, endColumnSimilarity, endLineSimilarity := matchDistance(baseIssue, currentIssue)

	// Effectively weighting each line number pos at 25%
	totalLineSimilarity := (startLineSimilarity + startColumnSimilarity + endColumnSimilarity + endLineSimilarity) / 4
	fileLocationConfidence := pathSimilarity*weights.PathSimilarity + totalLineSimilarity*weights.LineSimilarity

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
	startColumnSimilarity := similarityToDistance(baseRangeable.StartColumn(), currentRangeable.StartColumn())
	endColumnSimilarity := similarityToDistance(baseRangeable.EndColumn(), currentRangeable.EndColumn())
	endLineSimilarity := similarityToDistance(baseRangeable.EndLine(), currentRangeable.EndLine())
	return startLineSimilarity, startColumnSimilarity, endColumnSimilarity, endLineSimilarity
}

func checkDirs(base, current types.FilePath) float64 {
	if base == current {
		return 1
	}

	relativePath := relative(base, current)
	relativePathDistance := float64(len(strings.Split(relativePath, "/")))

	longestPossiblePath := math.Max(float64(len(strings.Split(string(base), "/"))), float64(len(strings.Split(string(current), "/"))))

	return 1 - relativePathDistance/longestPossiblePath
}

func fileNameSimilarity(base, current types.FilePath) float64 {
	fileNameBase := filepath.Base(string(base))
	fileNameCurrent := filepath.Base(string(current))
	return strutil.Similarity(fileNameBase, fileNameCurrent, metrics.NewLevenshtein())
}

func similarityToDistance(base, current int) float64 {
	if base == current {
		return 1
	}
	return 1 - math.Abs(float64(base-current))/math.Max(float64(base), float64(current))
}

func fileExtSimilarity(base, current types.FilePath) float64 {
	ext1 := filepath.Ext(string(base))
	ext2 := filepath.Ext(string(current))
	return strutil.Similarity(ext1, ext2, metrics.NewLevenshtein())
}

func historicDistance() float64 {
	return 1
}

func relative(parentPath, targetPath types.FilePath) string {
	res, err := filepath.Rel(string(parentPath), string(targetPath))
	if err != nil {
		return ""
	}
	return res
}
