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
	EnrichWithId(issueList []FindingsIdentifiable) []FindingsIdentifiable
	EnrichWithIsNew(issueList, deltaList []FindingsIdentifiable) []FindingsIdentifiable
}

type FindingsEnricher struct {
}

func (_ FindingsEnricher) EnrichWithId(issueList []FindingsIdentifiable) []FindingsIdentifiable {
	for i := range issueList {
		if issueList[i].GetGlobalIdentity() == "" {
			issueList[i].SetGlobalIdentity(uuid.New().String())
		}
	}

	return issueList
}

func (_ FindingsEnricher) EnrichWithIsNew(issueList, deltaList []FindingsIdentifiable) []FindingsIdentifiable {
	for i := range issueList {
		for j := range deltaList {
			if issueList[i].GetGlobalIdentity() == deltaList[j].GetGlobalIdentity() {
				issueList[i].SetIsNew(true)
			}
		}
	}

	return issueList
}
