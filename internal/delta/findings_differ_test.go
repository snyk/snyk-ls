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
	"fmt"
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
				&mockIdentifiable{globalIdentity: "issue1"},
				&mockIdentifiable{globalIdentity: "issue2"},
			},
			expectedDelta: []Identifiable{
				&mockIdentifiable{globalIdentity: "issue1"},
				&mockIdentifiable{globalIdentity: "issue2"},
			},
		},
		{
			name: "Empty current list",
			baseList: []Identifiable{
				&mockIdentifiable{globalIdentity: "issue1"},
				&mockIdentifiable{globalIdentity: "issue2"},
			},
			currentList:   []Identifiable{},
			expectedDelta: []Identifiable{},
		},
		{
			name: "No changes",
			baseList: []Identifiable{
				&mockIdentifiable{globalIdentity: "issue1"},
				&mockIdentifiable{globalIdentity: "issue2"},
			},
			currentList: []Identifiable{
				&mockIdentifiable{globalIdentity: "issue1"},
				&mockIdentifiable{globalIdentity: "issue2"},
			},
			expectedDelta: []Identifiable{},
		},
		{
			name: "Added items",
			baseList: []Identifiable{
				&mockIdentifiable{globalIdentity: "issue1"},
				&mockIdentifiable{globalIdentity: "issue2"},
			},
			currentList: []Identifiable{
				&mockIdentifiable{globalIdentity: "issue1"},
				&mockIdentifiable{globalIdentity: "issue2"},
				&mockIdentifiable{globalIdentity: "issue3"},
			},
			expectedDelta: []Identifiable{&mockIdentifiable{globalIdentity: "issue3"}},
		},
		{
			name: "Duplicate current identities not in base",
			baseList: []Identifiable{
				&mockIdentifiable{globalIdentity: "a"},
			},
			currentList: []Identifiable{
				&mockIdentifiable{globalIdentity: "b"},
				&mockIdentifiable{globalIdentity: "b"},
			},
			expectedDelta: []Identifiable{
				&mockIdentifiable{globalIdentity: "b"},
				&mockIdentifiable{globalIdentity: "b"},
			},
		},
		{
			name: "Duplicate base identities ignored for membership",
			baseList: []Identifiable{
				&mockIdentifiable{globalIdentity: "a"},
				&mockIdentifiable{globalIdentity: "a"},
			},
			currentList: []Identifiable{
				&mockIdentifiable{globalIdentity: "a"},
				&mockIdentifiable{globalIdentity: "b"},
			},
			expectedDelta: []Identifiable{
				&mockIdentifiable{globalIdentity: "b"},
			},
		},
		{
			name: "Empty global identity in base matches empty in current",
			baseList: []Identifiable{
				&mockIdentifiable{globalIdentity: ""},
			},
			currentList: []Identifiable{
				&mockIdentifiable{globalIdentity: ""},
				&mockIdentifiable{globalIdentity: "x"},
			},
			expectedDelta: []Identifiable{
				&mockIdentifiable{globalIdentity: "x"},
			},
		},
		{
			name:     "Empty base returns current including empty identity",
			baseList: []Identifiable{},
			currentList: []Identifiable{
				&mockIdentifiable{globalIdentity: ""},
			},
			expectedDelta: []Identifiable{
				&mockIdentifiable{globalIdentity: ""},
			},
		},
		{
			name: "Ordering preserved matches currentIssueList order",
			baseList: []Identifiable{
				&mockIdentifiable{globalIdentity: "b"},
				&mockIdentifiable{globalIdentity: "d"},
			},
			currentList: []Identifiable{
				&mockIdentifiable{globalIdentity: "a"},
				&mockIdentifiable{globalIdentity: "b"},
				&mockIdentifiable{globalIdentity: "c"},
				&mockIdentifiable{globalIdentity: "d"},
				&mockIdentifiable{globalIdentity: "e"},
			},
			expectedDelta: []Identifiable{
				&mockIdentifiable{globalIdentity: "a"},
				&mockIdentifiable{globalIdentity: "c"},
				&mockIdentifiable{globalIdentity: "e"},
			},
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

func TestFindingsDiffer_Diff_LargeInput_Parity(t *testing.T) {
	var d Differ = FindingsDiffer{}

	const baseSize = 5000
	const sharedSize = 2500
	const newSize = 2500

	baseList := make([]Identifiable, 0, baseSize)
	for i := 0; i < baseSize; i++ {
		baseList = append(baseList, &mockIdentifiable{globalIdentity: fmt.Sprintf("b-%d", i)})
	}

	currentList := make([]Identifiable, 0, sharedSize+newSize)
	for i := 0; i < sharedSize; i++ {
		currentList = append(currentList, &mockIdentifiable{globalIdentity: fmt.Sprintf("b-%d", i)})
	}
	for i := 0; i < newSize; i++ {
		currentList = append(currentList, &mockIdentifiable{globalIdentity: fmt.Sprintf("c-%d", i)})
	}

	delta := d.Diff(baseList, currentList)

	if len(delta) != newSize {
		t.Fatalf("expected delta length %d, got %d", newSize, len(delta))
	}
	for i, item := range delta {
		want := fmt.Sprintf("c-%d", i)
		if got := item.GetGlobalIdentity(); got != want {
			t.Fatalf("delta[%d] = %q, want %q", i, got, want)
		}
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
