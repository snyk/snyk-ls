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
	"math"
	"testing"
)

func TestTextEdit_sanitizeRange(t *testing.T) {
	type fields struct {
		NewText string
		Range   Range
	}
	tests := []struct {
		name   string
		fields fields
		want   Range
	}{
		{
			name: "Empty Text",
			fields: fields{
				NewText: "",
				Range: Range{
					Start: Position{Line: 10, Character: 10},
					End:   Position{Line: 20, Character: 20},
				},
			},
			want: Range{},
		},
		{
			name: "Start Line Out of Bounds",
			fields: fields{
				NewText: "Line 1\nLine 2",
				Range: Range{
					Start: Position{Line: 3, Character: 5},
					End:   Position{Line: 1, Character: 2},
				},
			},
			want: Range{},
		},
		{
			name: "Start Character Out of Bounds",
			fields: fields{
				NewText: "Line 1\nLine 2",
				Range: Range{
					Start: Position{Line: 0, Character: 10},
					End:   Position{Line: 1, Character: 2},
				},
			},
			want: Range{},
		},
		{
			name: "End Line Out of Bounds",
			fields: fields{
				NewText: "Line 1\nLine 2",
				Range: Range{
					Start: Position{Line: 0, Character: 2},
					End:   Position{Line: 3, Character: 5},
				},
			},
			want: Range{
				Start: Position{Line: 0, Character: 2},
				End:   Position{Line: 1, Character: 6},
			},
		},
		{
			name: "End Character Out of Bounds",
			fields: fields{
				NewText: "Line 1\nLine 2",
				Range: Range{
					Start: Position{Line: 0, Character: 2},
					End:   Position{Line: 1, Character: 10},
				},
			},
			want: Range{
				Start: Position{Line: 0, Character: 2},
				End:   Position{Line: 1, Character: 6},
			},
		},
		{
			name: "Start After End",
			fields: fields{
				NewText: "Line 1\nLine 2",
				Range: Range{
					Start: Position{Line: 0, Character: 5},
					End:   Position{Line: 0, Character: 2},
				},
			},
			want: Range{},
		},
		{
			name: "MaxInt",
			fields: fields{
				NewText: "Line 1\nLine 2",
				Range: Range{
					Start: Position{Line: 0, Character: 0},
					End:   Position{Line: math.MaxInt32, Character: math.MaxInt32},
				},
			},
			want: Range{
				Start: Position{0, 0},
				End:   Position{1, 6},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &TextEdit{
				NewText: tt.fields.NewText,
				Range:   tt.fields.Range,
			}
			e.SanitizeRange()
			if e.Range != tt.want {
				t.Errorf("SanitizeRange() = %v, want %v", e.Range, tt.want)
			}
		})
	}
}
