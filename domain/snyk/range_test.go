/*
 * © 2022 Snyk Limited All rights reserved.
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

import "testing"

// dupl linter gives a false positive here, as it doesn't take the boolean expectation into account
//
//nolint:dupl
func Test_Range_Contains(t *testing.T) {
	r := Range{
		Start: Position{5, 10},
		End:   Position{6, 20},
	}
	tests := []struct {
		name       string
		otherRange Range
		want       bool
	}{
		{"Other Range on different line", Range{Start: Position{Line: 4, Character: 1}, End: Position{Line: 4, Character: 20}}, false},
		{"Other Range on same line but left of range", Range{Start: Position{Line: 5, Character: 1}, End: Position{Line: 5, Character: 9}}, false},
		{"Other Range on same line but right of range", Range{Start: Position{Line: 6, Character: 21}, End: Position{Line: 6, Character: 22}}, false},
		{"Other Range starts in range and ends outside", Range{Start: Position{Line: 5, Character: 11}, End: Position{Line: 7, Character: 20}}, false},
		{"Other Range starts before range and ends in range", Range{Start: Position{Line: 5, Character: 1}, End: Position{Line: 5, Character: 20}}, false},
		{"Other Range starts before range and ends within range", Range{Start: Position{Line: 3, Character: 1}, End: Position{Line: 5, Character: 20}}, false},
		{"Other Range starts in range and ends within range", Range{Start: Position{Line: 5, Character: 11}, End: Position{Line: 5, Character: 19}}, true},
		{"Other Range exactly the same", r, true},
		{"Other Range starts exactly with range and ends within range", Range{Start: Position{Line: 5, Character: 10}, End: Position{Line: 5, Character: 19}}, true},
		{"Other Range starts within range and ends exactly with range", Range{Start: Position{Line: 5, Character: 11}, End: Position{Line: 5, Character: 20}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := r.Contains(tt.otherRange); got != tt.want {
				t.Errorf("Contains() = %v, want %v", got, tt.want)
			}
		})
	}
}

// dupl linter gives a false positive here, as it doesn't take the boolean expectation into account
//
//nolint:dupl
func Test_Range_Overlaps(t *testing.T) {
	r := Range{
		Start: Position{5, 10},
		End:   Position{6, 20},
	}
	tests := []struct {
		name       string
		otherRange Range
		want       bool
	}{
		{"Other Range on different line", Range{Start: Position{Line: 4, Character: 1}, End: Position{Line: 4, Character: 20}}, false},
		{"Other Range on same line but left of range", Range{Start: Position{Line: 5, Character: 1}, End: Position{Line: 5, Character: 9}}, false},
		{"Other Range on end line but right of range", Range{Start: Position{Line: 6, Character: 21}, End: Position{Line: 6, Character: 22}}, false},
		{"Other Range starts in range and ends outside", Range{Start: Position{Line: 5, Character: 11}, End: Position{Line: 7, Character: 20}}, true},
		{"Other Range starts before range and ends in range", Range{Start: Position{Line: 5, Character: 1}, End: Position{Line: 5, Character: 20}}, true},
		{"Other Range starts before range on different line and ends in range", Range{Start: Position{Line: 3, Character: 1}, End: Position{Line: 5, Character: 20}}, true},
		{"Other Range starts in range and ends within range", Range{Start: Position{Line: 5, Character: 11}, End: Position{Line: 5, Character: 19}}, true},
		{"Other Range exactly the same", r, true},
		{"Other Range starts exactly with range and ends within range", Range{Start: Position{Line: 5, Character: 10}, End: Position{Line: 5, Character: 19}}, true},
		{"Other Range starts within range and ends exactly with range", Range{Start: Position{Line: 5, Character: 11}, End: Position{Line: 5, Character: 20}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := r.Overlaps(tt.otherRange); got != tt.want {
				t.Errorf("Overlaps() = %v, want %v", got, tt.want)
			}
		})
	}
}
