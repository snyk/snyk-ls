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
	"testing"
)

func TestFindingsDiffer_Diff(t *testing.T) {
	var d Differ = FindingsDiffer{}

	tests := []struct {
		name          string
		baseList      []Identifiable
		currentList   []Identifiable
		expectedDelta []Identifiable
	}{
		{
			name:     "Empty base list",
			baseList: []Identifiable{},
			currentList: []Identifiable{
				&MockIdentifiable{globalIdentity: "issue1"},
				&MockIdentifiable{globalIdentity: "issue2"},
			},
			expectedDelta: []Identifiable{
				&MockIdentifiable{globalIdentity: "issue1"},
				&MockIdentifiable{globalIdentity: "issue2"},
			},
		},
		{
			name: "Empty current list",
			baseList: []Identifiable{
				&MockIdentifiable{globalIdentity: "issue1"},
				&MockIdentifiable{globalIdentity: "issue2"},
			},
			currentList:   []Identifiable{},
			expectedDelta: []Identifiable{},
		},
		{
			name: "No changes",
			baseList: []Identifiable{
				&MockIdentifiable{globalIdentity: "issue1"},
				&MockIdentifiable{globalIdentity: "issue2"},
			},
			currentList: []Identifiable{
				&MockIdentifiable{globalIdentity: "issue1"},
				&MockIdentifiable{globalIdentity: "issue2"},
			},
			expectedDelta: []Identifiable{},
		},
		{
			name: "Added items",
			baseList: []Identifiable{
				&MockIdentifiable{globalIdentity: "issue1"},
				&MockIdentifiable{globalIdentity: "issue2"},
			},
			currentList: []Identifiable{
				&MockIdentifiable{globalIdentity: "issue1"},
				&MockIdentifiable{globalIdentity: "issue2"},
				&MockIdentifiable{globalIdentity: "issue3"},
			},
			expectedDelta: []Identifiable{&MockIdentifiable{globalIdentity: "issue3"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			delta := d.Diff(tt.baseList, tt.currentList)
			if !compareIdentifiableSlices(delta, tt.expectedDelta) {
				t.Errorf("Expected delta: %v, got: %v", tt.expectedDelta, delta)
			}
		})
	}
}

func compareIdentifiableSlices(a, b []Identifiable) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].GetGlobalIdentity() != b[i].GetGlobalIdentity() {
			return false
		}
	}
	return true
}
