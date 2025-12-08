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
	"github.com/google/uuid"
)

var _ Enricher = (*FindingsEnricher)(nil)

type Enricher interface {
	EnrichWithId(issueList []Identifiable) []Identifiable
	EnrichWithIsNew(issueList, newIssueList []Identifiable) []Identifiable
}

type FindingsEnricher struct {
}

func NewFindingsEnricher() *FindingsEnricher {
	return &FindingsEnricher{}
}

func (FindingsEnricher) EnrichWithId(issueList []Identifiable) []Identifiable {
	for i := range issueList {
		if issueList[i].GetGlobalIdentity() == "" {
			issueList[i].SetGlobalIdentity(uuid.New().String())
		}
	}

	return issueList
}

func (FindingsEnricher) EnrichWithIsNew(allCurrentIssues, newIssues []Identifiable) []Identifiable {
	// Build a set of GlobalIdentities that are new for O(1) lookup
	newIssueIDs := make(map[string]bool, len(newIssues))
	for _, issue := range newIssues {
		// everything in delta list is new
		issue.SetIsNew(true)
		newIssueIDs[issue.GetGlobalIdentity()] = true
	}

	// Set isNew for all current issues based on whether they're in the delta list
	for i := range allCurrentIssues {
		if newIssueIDs[allCurrentIssues[i].GetGlobalIdentity()] {
			// issues that have the same id as a new issue are also new
			allCurrentIssues[i].SetIsNew(true)
		} else {
			// Set IsNew to false for all issues that are not in the delta list.
			allCurrentIssues[i].SetIsNew(false)
		}
	}

	return allCurrentIssues
}
