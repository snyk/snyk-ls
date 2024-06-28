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
	"github.com/adrg/strutil"
	"github.com/adrg/strutil/metrics"
	"github.com/google/uuid"
	"github.com/snyk/snyk-ls/application/config"
	"math"
	"path/filepath"
	"strings"
)

var _ Matcher = (*CodeIdentityMatcher)(nil)

type IssueConfidence struct {
	HistoricUUID       string
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
	currentIssueList []Identifiable
	config           *config.Config
}

func (cim *CodeIdentityMatcher) Match(c *config.Config, baseIssueList []Identifiable) ([]Identifiable, error) {
	logger := c.Logger().With().Str("method", "Match").Logger()
	if len(cim.currentIssueList) == 0 || len(baseIssueList) == 0 {
		logger.Error().Msg("currentIssueList or baseIssueList is empty")
	}

	strongMatchingIssues := make(map[string]IssueConfidence)
	existingAssignedIds := make(map[string]bool)

	for index, issue := range cim.currentIssueList {
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
			cim.currentIssueList[i].SetGlobalIdentity(identity.IdentityID)
		}
	}

	// Assign UUIDs for any new issues
	assignUUIDForNewProject(cim.currentIssueList)
	return cim.currentIssueList, nil
}

func findMatch(issue Issue, index int, listOfHistoricResults [][]Identifiable, strongMatchingIssues map[string]IssueConfidence) {
	matches := findMatches(issue, index, listOfHistoricResults)

	for _, match := range matches {
		if existing, exists := strongMatchingIssues[match.HistoricUUID]; !exists || existing.Confidence < match.Confidence {
			strongMatchingIssues[match.HistoricUUID] = match
		}
	}
}

func findMatches(issue Identifiable, index int, listOfHistoricResults [][]Identifiable) IssueConfidenceList {
	similarIssues := make(IssueConfidenceList, 0)

	for historicVersionInTime, historicResults := range listOfHistoricResults {
		for _, historicResult := range historicResults {
			if historicResult.RuleId() != issue.RuleId() {
				continue
			}

			filePositionDistance := filePositionConfidence(historicResult, issue)
			recentHistoryDistance := historicConfidenceCalculator(historicVersionInTime, len(listOfHistoricResults))
			fingerprintConfidence := fingerprintDistance(historicResult.Fingerprint(), issue.Fingerprint())

			overallConfidence := filePositionDistance*weights.FilePositionDistance +
				recentHistoryDistance*weights.RecentHistoryDistance +
				fingerprintConfidence*weights.FingerprintConfidence

			if overallConfidence == 1 {
				similarIssues = append(similarIssues, IssueConfidence{
					HistoricUUID:       historicResult.GlobalIdentity(),
					IssueIDResultIndex: index,
					Confidence:         overallConfidence,
				})
				break
			}

			if overallConfidence > weights.MinimumAcceptableConfidence {
				similarIssues = append(similarIssues, IssueConfidence{
					HistoricUUID:       historicResult.GlobalIdentity(),
					IssueIDResultIndex: index,
					Confidence:         overallConfidence,
				})
			}
		}
	}

	return similarIssues
}

func deduplicateIssues(strongMatchingIssues map[string]IssueConfidence) DeduplicatedIssuesToIDs {
	finalResult := make(DeduplicatedIssuesToIDs)
	for _, issue := range strongMatchingIssues {
		if existing, exists := finalResult[issue.IssueIDResultIndex]; !exists || existing.Confidence < issue.Confidence {
			finalResult[issue.IssueIDResultIndex] = Identity{
				IdentityID: issue.HistoricUUID,
				Confidence: issue.Confidence,
			}
		}
	}
	return finalResult
}

func fingerprintDistance(historicFingerprints, currentFingerprints string) float64 {
	// Split into parts and compare
	parts1 := strings.Split(historicFingerprints, ".")
	parts2 := strings.Split(currentFingerprints, ".")
	similar := 0
	for i := 0; i < len(parts1) && i < len(parts2); i++ {
		if parts1[i] == parts2[i] {
			similar++
		}
	}
	totalParts := max(len(parts1), len(parts2))
	if totalParts == 0 {
		return 0.0
	}
	return float64(similar) / float64(totalParts)
}

func filePositionConfidence(historicIssue, currentIssue Identifiable) float64 {
	dirSimilarity := checkDirs(historicIssue.Path(), currentIssue.Path())
	fileNameSimilarity := fileNameSimilarity(historicIssue.Path(), currentIssue.Path())
	fileExtSimilarity := fileExtSimilarity(filepath.Ext(historicIssue.Path()),
		filepath.Ext(currentIssue.Path()))

	pathSimilarity :=
		dirSimilarity*weights.DirSimilarity +
			fileNameSimilarity*weights.FileNameSimilarity +
			fileExtSimilarity*weights.FileExtensionSimilarity

	startLineSimilarity, startColumnSimilarity, endColumnSimilarity, endLineSimilarity :=
		matchDistance(historicIssue, currentIssue)
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

func matchDistance(historicIssue Identifiable, currentIssue Identifiable) (float64, float64, float64, float64) {
	historicRange := historicIssue.GetRange()
	currentRange := currentIssue.GetRange()
	startLineSimilarity := similarityToDistance(historicRange.Start.Line, currentRange.Start.Line)
	startColumnSimilarity := similarityToDistance(historicRange.Start.Character,
		currentRange.Start.Character)
	endColumnSimilarity := similarityToDistance(historicRange.End.Character, currentRange.End.Character)
	endLineSimilarity := similarityToDistance(historicRange.End.Line, currentRange.End.Line)
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

func assignUUIDForNewProject(currentResults []Issue) {
	for i := range currentResults {
		if currentResults[i].GlobalIdentity() == "" {
			currentResults[i].SetGlobalIdentity(uuid.New().String())
		}
	}
}

func historicConfidenceCalculator(currentVersion, totalNumOfVersions int) float64 {
	if currentVersion == 0 {
		return 1
	}
	return 1 - math.Abs(float64(currentVersion-totalNumOfVersions))/math.Max(float64(currentVersion), float64(totalNumOfVersions))
}

func relative(path1, path2 string) string {
	res, err := filepath.Rel(path1, path2)
	if err != nil {
		return ""
	}
	return res
}
