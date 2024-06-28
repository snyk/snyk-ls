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

package snyk

import (
	"errors"
	"github.com/adrg/strutil"
	"github.com/adrg/strutil/metrics"
	"github.com/snyk/snyk-ls/infrastructure/delta"
	"math"
	"path/filepath"
	"strings"
)

var _ delta.FindingsMatcher = (*CodeIdentityMatcher)(nil)

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

type CodeIdentityMatcher struct {
}

func (_ CodeIdentityMatcher) Match(baseIssueList, currentIssueList []delta.FindingsIdentifiable) error {
	if len(currentIssueList) == 0 || len(baseIssueList) == 0 {
		return errors.New("base or current issue list is empty")
	}

	strongMatchingIssues := make(map[string]IssueConfidence)
	existingAssignedIds := make(map[string]bool)

	for index, issue := range currentIssueList {
		if len(issue.GlobalIdentity()) > 0 {
			existingAssignedIds[issue.GlobalIdentity()] = true
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

	// Assign UUIDs for any new issues
	return nil
}

func findMatch(issue delta.FindingsIdentifiable, index int, baseIssueList []delta.FindingsIdentifiable, strongMatchingIssues map[string]IssueConfidence) {
	matches := findMatches(issue, index, baseIssueList)

	for _, match := range matches {
		if existing, exists := strongMatchingIssues[match.BaseUUID]; !exists || existing.Confidence < match.Confidence {
			strongMatchingIssues[match.BaseUUID] = match
		}
	}
}

func findMatches(currentIssue delta.FindingsIdentifiable, index int, baseIssues []delta.FindingsIdentifiable) IssueConfidenceList {
	similarIssues := make(IssueConfidenceList, 0)

	for _, baseIssue := range baseIssues {
		if baseIssue.RuleId() != currentIssue.RuleId() {
			continue
		}

		filePositionDistance := filePositionConfidence(baseIssue, currentIssue)
		// Calculation of History is not needed here for IDE since we are not persisting old scan results.
		//We will always return 1.
		recentHistoryDistance := historicConfidenceCalculator()
		fingerprintConfidence := fingerprintDistance(baseIssue, currentIssue)

		overallConfidence := filePositionDistance*weights.FilePositionDistance +
			recentHistoryDistance*weights.RecentHistoryDistance +
			fingerprintConfidence*weights.FingerprintConfidence

		if overallConfidence == 1 {
			similarIssues = append(similarIssues, IssueConfidence{
				BaseUUID:           baseIssue.GlobalIdentity(),
				IssueIDResultIndex: index,
				Confidence:         overallConfidence,
			})
			break
		}

		if overallConfidence > weights.MinimumAcceptableConfidence {
			similarIssues = append(similarIssues, IssueConfidence{
				BaseUUID:           baseIssue.GlobalIdentity(),
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
		if existing, exists := finalResult[issue.IssueIDResultIndex]; !exists || existing.Confidence < issue.Confidence {
			finalResult[issue.IssueIDResultIndex] = Identity{
				IdentityID: issue.BaseUUID,
				Confidence: issue.Confidence,
			}
		}
	}
	return finalResult
}

func fingerprintDistance(baseFingerprints, currentFingerprints delta.FindingsIdentifiable) float64 {
	baseFingerprintable, ok := baseFingerprints.(delta.FindingsFingerprintable)
	if !ok {
		return 0
	}
	currentFingerprintable, ok := currentFingerprints.(delta.FindingsFingerprintable)
	if !ok {
		return 0
	}

	// Split into parts and compare
	parts1 := strings.Split(baseFingerprintable.Fingerprint(), ".")
	parts2 := strings.Split(currentFingerprintable.Fingerprint(), ".")
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

func filePositionConfidence(baseIssue, currentIssue delta.FindingsIdentifiable) float64 {
	basePathable, ok := baseIssue.(delta.FindingsPathable)
	if !ok {
		return 0
	}
	currentPathable, ok := currentIssue.(delta.FindingsPathable)
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

func matchDistance(baseIssue delta.FindingsIdentifiable, currentIssue delta.FindingsIdentifiable) (float64, float64, float64, float64) {
	baseRangeable, ok := baseIssue.(delta.FingingsLocationable)
	if !ok {
		return 0, 0, 0, 0
	}
	currentRangeable, ok := currentIssue.(delta.FingingsLocationable)
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

func historicConfidenceCalculator() float64 {
	return 1
}

func relative(path1, path2 string) string {
	res, err := filepath.Rel(path1, path2)
	if err != nil {
		return ""
	}
	return res
}
