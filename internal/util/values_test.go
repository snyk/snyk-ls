/*
 * © 2025 Snyk Limited
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

package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsEmptyValue(t *testing.T) {
	t.Run("should identify empty values correctly", func(t *testing.T) {
		testCases := []struct {
			name     string
			value    any
			expected bool
		}{
			// Case 1: Different types that represent "empty"
			{"empty string", "", true},
			{"nil value", nil, true},
			{"nil pointer to string", (*string)(nil), true},
			{"nil slice", ([]string)(nil), true},
			{"nil map", (map[string]string)(nil), true},

			// Case 4: Different zero values of the same type
			{"zero int", 0, true},
			{"zero float64", 0.0, true},
			{"zero bool", false, true},
			{"zero int32", int32(0), true},
			{"zero int64", int64(0), true},
			{"zero float32", float32(0.0), true},

			// Non-empty values
			{"non-empty string", "hello", false},
			{"non-zero int", 42, false},
			{"non-zero float", 3.14, false},
			{"true bool", true, false},
			{"non-empty slice", []string{"item"}, false},
			{"non-empty map", map[string]string{"key": "value"}, false},
			{"pointer to non-empty string", stringPtr("hello"), false},

			// Edge cases
			{"empty slice", []string{}, true},
			{"empty map", map[string]string{}, true},
			{"slice with empty strings", []string{"", ""}, false}, // slice itself is not empty
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				result := IsEmptyValue(tc.value)
				assert.Equal(t, tc.expected, result, "IsEmptyValue(%v) should return %v", tc.value, tc.expected)
			})
		}
	})

	t.Run("should handle interface{} with different underlying types", func(t *testing.T) {
		// Test case 1: Different types that represent "empty"
		var emptyString interface{} = ""
		var nilValue interface{} = nil
		var nilPointer interface{} = (*string)(nil)

		assert.True(t, IsEmptyValue(emptyString), "empty string should be considered empty")
		assert.True(t, IsEmptyValue(nilValue), "nil should be considered empty")
		assert.True(t, IsEmptyValue(nilPointer), "nil pointer should be considered empty")

		// Test case 4: Different zero values of the same type
		var zeroInt interface{} = 0
		var zeroFloat interface{} = 0.0
		var zeroBool interface{} = false

		assert.True(t, IsEmptyValue(zeroInt), "zero int should be considered empty")
		assert.True(t, IsEmptyValue(zeroFloat), "zero float should be considered empty")
		assert.True(t, IsEmptyValue(zeroBool), "zero bool should be considered empty")
	})
}

// Helper function to create a pointer to a string
func stringPtr(s string) *string {
	return &s
}
