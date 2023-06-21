/*
 * © 2023 Snyk Limited
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

import "fmt"

type InlineValue struct {
	Path  string
	Range Range
	Text  string
}

func (i InlineValue) String() string {
	return fmt.Sprintf("path: %s, range: %s, text: %s", i.Path, i.Range, i.Text)
}

// InlineValueProvider provides inline values.
type InlineValueProvider interface {
	// GetInlineValues returns inline values for a given path and range.
	// This should be a very fast operation.
	GetInlineValues(path string, myRange Range) ([]InlineValue, error)
}
