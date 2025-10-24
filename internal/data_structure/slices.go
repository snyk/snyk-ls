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

package data_structure

// Unique returns a new slice containing only the unique elements of the input slice.
func Unique[T comparable](slice []T) []T {
	seen := make(map[T]struct{})
	result := make([]T, 0, len(slice))
	for _, v := range slice {
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			result = append(result, v)
		}
	}
	return result
}

// Filter returns a new slice containing only the elements of the input slice that satisfy the predicate.
// The input slice is not modified.
// Parameters:
//   - s: The input slice to filter.
//   - keep: A predicate function that returns true for elements to keep.
//
// Returns:
//   - A new slice containing only the elements that satisfy the predicate.
func Filter[S ~[]E, E any](s S, keep func(E) bool) S {
	var out S
	for _, e := range s {
		if keep(e) {
			out = append(out, e)
		}
	}
	return out
}

// Map returns a new slice containing the results of applying the function to each element of the input slice.
// The input slice is not modified.
// Parameters:
//   - s: The input slice to map.
//   - fn: A function that takes an element of the input slice and returns a result.
//
// Returns:
//   - A new slice containing the results of applying the function to each element of the input slice.
func Map[S ~[]E, E any, R any](s S, fn func(E) R) []R {
	out := make([]R, len(s))
	for i, e := range s {
		out[i] = fn(e)
	}
	return out
}
