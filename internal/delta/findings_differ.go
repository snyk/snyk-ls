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

var _ Differ = (*FindingsDiffer)(nil)

type Differ interface {
	Diff(baseIssueList, currentIssueList []Identifiable) []Identifiable
}

type FindingsDiffer struct {
}

func NewFindingsDiffer() *FindingsDiffer {
	return &FindingsDiffer{}
}

func (FindingsDiffer) Diff(baseIssueList, currentIssueList []Identifiable) []Identifiable {
	var deltaResults []Identifiable

	if len(currentIssueList) == 0 || len(baseIssueList) == 0 {
		return currentIssueList
	}

	// O(N+M) membership set; profiled hot path under large delta scans (IDE-1940).
	baseIDSet := make(map[string]struct{}, len(baseIssueList))
	for _, b := range baseIssueList {
		baseIDSet[b.GetGlobalIdentity()] = struct{}{}
	}
	for _, c := range currentIssueList {
		if _, ok := baseIDSet[c.GetGlobalIdentity()]; !ok {
			deltaResults = append(deltaResults, c)
		}
	}

	return deltaResults
}
