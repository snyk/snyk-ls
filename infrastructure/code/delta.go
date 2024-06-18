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

package code

import (
	"github.com/google/uuid"
	"github.com/snyk/code-client-go/sarif"
	"github.com/xrash/smetrics"
	"math"
	"path/filepath"
	"strings"
	"sync"
)

type IssueConfidence struct {
	HistoricUUID       string
	IssueIDResultIndex int
	Confidence         float64
}

type IdentityCounter struct {
	ExactMatch int
	Similar    int
	New        int
}

type DeduplicatedIssuesToIDs map[int]Identity
type IssueConfidenceList []IssueConfidence
type Identity struct {
	IdentityID string
	Confidence float64
}

var weights = struct {
	FilePositionDistance        float64
	RecentHistoryDistance       float64
	FingerprintConfidence       float64
	MinimumAcceptableConfidence float64
}{
	FilePositionDistance:        0.3,
	RecentHistoryDistance:       0.2,
	FingerprintConfidence:       0.5,
	MinimumAcceptableConfidence: 0.4,
}

func identify(sarif sarif.SarifResponse, listOfHistoricResults []sarif.SarifResponse) (sarif.SarifResponse, error) {
	results := sarif.Sarif.Runs[0].Results
	totalIdentitiesCount := len(results)
	identityCounter := IdentityCounter{}

	if len(listOfHistoricResults) == 0 {
		identityCounter.New = totalIdentitiesCount
		assignUUIDForNewProject(&sarif)
		return sarif, nil
	}

	var wg sync.WaitGroup
	strongMatchingIssues := make(map[string]IssueConfidence) // Map issue index to best identity
	existingAssignedIds := make(map[string]bool)

	for index, issue := range results {
		if len(issue.Identity) > 0 {
			existingAssignedIds[issue.Identity] = true
			identityCounter.ExactMatch++
			continue
		}

		//wg.Add(1)
		findMatch(issue, index, &wg, listOfHistoricResults, strongMatchingIssues)
	}

	//wg.Wait()
	finalResult := deduplicateIssues(strongMatchingIssues)

	// Assign identities found to results
	for index, identity := range finalResult {
		if !existingAssignedIds[identity.IdentityID] {
			results[index].Identity = identity.IdentityID
			if identity.Confidence == 1 {
				identityCounter.ExactMatch++
			} else {
				identityCounter.Similar++
			}
		}
	}

	// Assign UUIDs for any new issues
	assignUUIDForNewProject(&sarif)
	identityCounter.New = totalIdentitiesCount - identityCounter.ExactMatch - identityCounter.Similar
	return sarif, nil
}

func findMatch(issue sarif.Result, index int, wg *sync.WaitGroup, listOfHistoricResults []sarif.SarifResponse, strongMatchingIssues map[string]IssueConfidence) {
	//mutex := sync.RWMutex{}

	//defer wg.Done()
	//mutex.Lock()
	matches := findMatches(issue, index, listOfHistoricResults)
	//	mutex.Unlock()

	for _, match := range matches {
		//	mutex.Lock()
		if existing, exists := strongMatchingIssues[match.HistoricUUID]; !exists || existing.Confidence < match.Confidence {
			strongMatchingIssues[match.HistoricUUID] = match
		}
		//mutex.Unlock()
	}
}

func findMatches(issue sarif.Result, index int, listOfHistoricResults []sarif.SarifResponse) IssueConfidenceList {
	similarIssues := make(IssueConfidenceList, 0)

	for historicVersionInTime, historicLog := range listOfHistoricResults {
		historicResults := historicLog.Sarif.Runs[0].Results
		for _, historicResult := range historicResults {
			if historicResult.RuleID != issue.RuleID {
				continue
			}

			filePositionDistance := filePositionConfidence(historicResult.Locations[0], issue.Locations[0])
			recentHistoryDistance := historicConfidenceCalculator(historicVersionInTime, len(listOfHistoricResults))
			fingerprintConfidence := fingerprintDistance(historicResult.Fingerprints.Num1, issue.Fingerprints.Num1)

			overallConfidence := filePositionDistance*weights.FilePositionDistance +
				recentHistoryDistance*weights.RecentHistoryDistance +
				fingerprintConfidence*weights.FingerprintConfidence

			if overallConfidence == 1 {
				similarIssues = append(similarIssues, IssueConfidence{
					HistoricUUID:       historicResult.Identity,
					IssueIDResultIndex: index,
					Confidence:         overallConfidence,
				})
				break
			}

			if overallConfidence > weights.MinimumAcceptableConfidence {
				similarIssues = append(similarIssues, IssueConfidence{
					HistoricUUID:       historicResult.Identity,
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

func filePositionConfidence(historicLocation, currentLocation sarif.Location) float64 {
	dirSimilarity := checkDirs(historicLocation.PhysicalLocation.ArtifactLocation.URI, currentLocation.PhysicalLocation.ArtifactLocation.URI)
	fileNameSimilarity := fileNameSimilarity(historicLocation.PhysicalLocation.ArtifactLocation.URI, currentLocation.PhysicalLocation.ArtifactLocation.URI)
	fileExtSimilarity := fileExtSimilarity(historicLocation.PhysicalLocation.ArtifactLocation.URI, currentLocation.PhysicalLocation.ArtifactLocation.URI)

	return dirSimilarity*weights.FilePositionDistance + fileNameSimilarity*weights.FingerprintConfidence + fileExtSimilarity*weights.RecentHistoryDistance
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
	return smetrics.Jaro(file1, file2)
}

func fileExtSimilarity(ext1, ext2 string) float64 {
	distance := smetrics.WagnerFischer(ext1, ext2, 1, 1, 1)
	maxLen := max(len(ext1), len(ext2))
	if maxLen == 0 {
		return 1.0
	}
	// Return similarity as a proportion of the longest string length.
	return 1.0 - float64(distance)/float64(maxLen)
}

func assignUUIDForNewProject(sarif *sarif.SarifResponse) {
	for i := range sarif.Sarif.Runs[0].Results {
		if sarif.Sarif.Runs[0].Results[i].Identity == "" {
			sarif.Sarif.Runs[0].Results[i].Identity = uuid.New().String()
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
