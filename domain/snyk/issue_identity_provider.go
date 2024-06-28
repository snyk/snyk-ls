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
	"github.com/google/uuid"
	"github.com/snyk/snyk-ls/application/config"
)

var _ Identifiable = (*Issue)(nil)
var _ IdentityEnricher = (*FindingsIdEnricher)(nil)
var _ Differ = (*FindingsDiffer)(nil)

type Fingerprintable interface {
	Fingerprint() string
}

type Identifiable interface {
	Path() string
	RuleId() string
	GlobalIdentity() string
	SetGlobalIdentity(globalIdentity string)
	SetIsNew(isNew bool)
	IsNew() bool
}

type IdentityEnricher interface {
	EnrichWithId(base []Identifiable) []Identifiable
}

type Differ interface {
	Diff(base []Identifiable) []Identifiable
}

type Matcher interface {
	Match(c *config.Config, base []Identifiable) ([]Identifiable, error)
}

type FindingsDiffer struct {
	currentIssueList []Identifiable
}

type FindingsIdEnricher struct {
}

func (_ FindingsIdEnricher) EnrichWithId(issueList []Identifiable) []Identifiable {
	for i := range issueList {
		if issueList[i].GlobalIdentity() == "" {
			issueList[i].SetGlobalIdentity(uuid.New().String())
		}
	}

	return issueList
}

func (gd FindingsDiffer) Diff(baseIssueList []Identifiable) []Identifiable {
	var deltaResults []Identifiable

	if len(gd.currentIssueList) == 0 || len(baseIssueList) == 0 {
		return deltaResults
	}

	for i := range gd.currentIssueList {
		found := false
		for j := range baseIssueList {
			if baseIssueList[j].GlobalIdentity() == gd.currentIssueList[i].GlobalIdentity() {
				found = true
				break
			}
		}
		if !found {
			deltaResults = append(deltaResults, gd.currentIssueList[i])
		}
	}

	return deltaResults
}
