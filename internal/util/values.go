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

import "reflect"

// IsEmptyValue checks if a value is considered empty
func IsEmptyValue(value any) bool {
	if value == nil {
		return true
	}

	switch v := value.(type) {
	case string:
		return v == ""
	case []string:
		return len(v) == 0
	case []int:
		return len(v) == 0
	case []float64:
		return len(v) == 0
	case []bool:
		return len(v) == 0
	case map[string]string:
		return len(v) == 0
	case map[string]int:
		return len(v) == 0
	case map[string]any:
		return len(v) == 0
	default:
		// For other types, use reflection to check if it's the zero value
		// This handles slices, maps, and other types generically
		rv := reflect.ValueOf(value)
		switch rv.Kind() {
		case reflect.Slice, reflect.Map, reflect.Array:
			return rv.Len() == 0
		case reflect.Ptr, reflect.Interface:
			return rv.IsNil()
		default:
			return reflect.DeepEqual(value, reflect.Zero(reflect.TypeOf(value)).Interface())
		}
	}
}

// AreValuesEqual safely compares two values, handling slices and other uncomparable types
func AreValuesEqual(a, b any) bool {
	// Handle nil cases
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	// Use reflection for deep equality comparison
	return reflect.DeepEqual(a, b)
}
