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

// PtrOf creates a pointer on the heap for the value provided.
// Because in Go you can't do something like `takesPtr(&(returnsStruct()))`.
// So instead do `takesPtr(PtrOf(returnsStruct()))`.
func PtrOf[T any](value T) *T {
	pointerToValue := new(T) // Heap may be safer than `&value`
	*pointerToValue = value
	return pointerToValue
}
