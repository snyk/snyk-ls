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

var _ Identifiable = (*Issue)(nil)
var _ IdentityEnricher = (*CodeIdentityEnricher)(nil)

type Identifiable interface {
	getRange() Range
	getPath() string
	getFingerprint() string
	getIssueRule() string
	getID() string
	setIsNew() bool
}

type IdentityEnricher interface {
	EnrichWithId(history, current []*Identifiable)
}

// For the IDE this will just set the IsNew value. Not sure if it should be like this. The CLI will probably require a new result
type Differ interface {
	Diff(history, current []Identifiable) []Identifiable
}

type CodeIdentityEnricher struct{}
type CodeDiffer struct{}

func (_ CodeIdentityEnricher) EnrichWithId(history, current []*Identifiable) {
}

func (_ CodeDiffer) Diff(history, current []*Identifiable) {
}

//type Comparable interface {
//	Identifiable
//	CompareTo(Comparable) Comparable
//}
