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

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

type MockIdentifiable struct {
	globalIdentity string
}

func (m *MockIdentifiable) RuleId() string {
	//Not used, but needed for the interface
	panic("implement me")
}

func (m *MockIdentifiable) SetIsNew(isNew bool) {
	//Not used, but needed for the interface
	panic("implement me")
}

func (m *MockIdentifiable) IsNew() bool {
	//Not used, but needed for the interface
	panic("implement me")
}

func (m *MockIdentifiable) GetGlobalIdentity() string {
	return m.globalIdentity
}

func (m *MockIdentifiable) SetGlobalIdentity(id string) {
	m.globalIdentity = id
}

func TestFindingsEnricher_EnrichWithId(t *testing.T) {
	tests := []struct {
		name     string
		input    []Identifiable
		wantLen  int
		wantFill bool
	}{
		{
			name:     "Empty list",
			input:    []Identifiable{},
			wantLen:  0,
			wantFill: false,
		},
		{
			name: "List with empty IDs",
			input: []Identifiable{
				&MockIdentifiable{globalIdentity: ""},
				&MockIdentifiable{globalIdentity: ""},
			},
			wantLen:  2,
			wantFill: true,
		},
		{
			name: "List with some filled IDs",
			input: []Identifiable{
				&MockIdentifiable{globalIdentity: ""},
				&MockIdentifiable{globalIdentity: "existing-id"},
				&MockIdentifiable{globalIdentity: uuid.New().String()},
			},
			wantLen:  3,
			wantFill: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enricher := FindingsEnricher{}
			result := enricher.EnrichWithId(tt.input)

			assert.Equal(t, tt.wantLen, len(result), "Result length should match input length")

			for i, item := range result {
				if tt.wantFill && tt.input[i].GetGlobalIdentity() == "" {
					assert.NotEmpty(t, item.GetGlobalIdentity(), "Empty ID should be filled")
					_, err := uuid.Parse(item.GetGlobalIdentity())
					assert.NoError(t, err, "Filled ID should be a valid UUID")
				} else {
					assert.Equal(t, tt.input[i].GetGlobalIdentity(), item.GetGlobalIdentity(), "Existing ID should not change")
				}
			}
		})
	}
}
