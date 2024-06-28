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

func (_ FindingsDiffer) Diff(baseIssueList, currentIssueList []Identifiable) []Identifiable {
	var deltaResults []Identifiable

	if len(currentIssueList) == 0 || len(baseIssueList) == 0 {
		return currentIssueList
	}

	for i := range currentIssueList {
		found := false
		for j := range baseIssueList {
			if baseIssueList[j].GetGlobalIdentity() == currentIssueList[i].GetGlobalIdentity() {
				found = true
				break
			}
		}
		if !found {
			deltaResults = append(deltaResults, currentIssueList[i])
		}
	}

	return deltaResults
}
